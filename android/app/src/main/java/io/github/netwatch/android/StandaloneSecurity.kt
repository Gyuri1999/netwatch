package io.github.netwatch.android

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.IDN
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.text.DateFormat
import java.util.Date
import javax.net.ssl.HttpsURLConnection

data class ScanRecord(
    val at: Long,
    val network: String,
    val devices: List<String>,
    val newDevices: List<String>
)

/** Local-only storage for the standalone app. No account or cloud sync is used. */
class StandaloneHistory(private val context: android.content.Context) {
    private val prefs = context.getSharedPreferences("standalone_history", android.content.Context.MODE_PRIVATE)

    @Synchronized fun records(): List<ScanRecord> {
        val raw = prefs.getString("scans", "[]") ?: "[]"
        return try {
            val a = JSONArray(raw)
            (0 until a.length()).map { i ->
                val o = a.getJSONObject(i)
                ScanRecord(o.optLong("at"), o.optString("network"), strings(o.optJSONArray("devices")), strings(o.optJSONArray("new")))
            }.sortedByDescending { it.at }
        } catch (_: Exception) { emptyList() }
    }

    @Synchronized fun record(network: String, devices: List<String>): ScanRecord {
        val prior = records().firstOrNull { it.network == network }
        val newcomers = if (prior == null) emptyList() else devices.filterNot { it in prior.devices }
        val entry = ScanRecord(System.currentTimeMillis(), network, devices.sorted(), newcomers.sorted())
        val all = (listOf(entry) + records()).take(30)
        val array = JSONArray()
        all.forEach { item ->
            array.put(JSONObject().put("at", item.at).put("network", item.network)
                .put("devices", JSONArray(item.devices)).put("new", JSONArray(item.newDevices)))
        }
        prefs.edit().putString("scans", array.toString()).apply()
        return entry
    }

    @Synchronized fun clear() { prefs.edit().remove("scans").apply() }

    fun report(): String = buildString {
        appendLine("NetWatch Mobile — local scan report")
        appendLine("Exported: ${DateFormat.getDateTimeInstance().format(Date())}")
        appendLine("History is stored only on this phone.")
        appendLine()
        records().forEach { item ->
            appendLine("${DateFormat.getDateTimeInstance().format(Date(item.at))} | ${item.network}")
            appendLine("Responding IPs (${item.devices.size}): ${item.devices.joinToString(", ").ifBlank { "none" }}")
            if (item.newDevices.isNotEmpty()) appendLine("New since previous scan: ${item.newDevices.joinToString(", ")}")
            appendLine()
        }
    }

    private fun strings(a: JSONArray?): List<String> = if (a == null) emptyList() else
        (0 until a.length()).mapNotNull { a.optString(it).takeIf(String::isNotBlank) }
}

object StandaloneSecurity {
    fun wifiSummary(cm: ConnectivityManager, wifi: WifiManager): String {
        val network = cm.activeNetwork
        val caps = network?.let(cm::getNetworkCapabilities)
        val props = network?.let(cm::getLinkProperties)
        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) != true || props == null) {
            return "Not connected to Wi-Fi."
        }
        val lines = mutableListOf<String>()
        val gateway = props.routes.firstOrNull { it.isDefaultRoute }?.gateway?.hostAddress
        val local = props.linkAddresses.firstOrNull { it.address.address.size == 4 }
        lines += "Local address: ${local?.let { "${it.address.hostAddress}/${it.prefixLength}" } ?: "unknown"}"
        lines += "Router: ${gateway ?: "not reported"}"
        lines += "DNS: ${props.dnsServers.joinToString(", ") { it.hostAddress ?: "" }.ifBlank { "not reported" }}"
        lines += if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) "Internet: Android reports a validated connection."
            else "Internet: Android has not validated this connection."
        val security = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try { wifi.connectionInfo.currentSecurityType } catch (_: Exception) { -1 }
        } else -1
        val label = when (security) {
            0 -> "Open Wi-Fi (no link encryption)"
            1 -> "WEP (outdated and unsafe)"
            2 -> "WPA2-Personal"
            3 -> "WPA2-Enterprise"
            4 -> "WPA3-Personal"
            5 -> "WPA3-Enterprise 192-bit"
            6 -> "Enhanced Open (OWE)"
            7, 8 -> "WAPI security"
            9 -> "WPA3-Enterprise"
            10 -> "OSEN security"
            11 -> "Passpoint R1/R2"
            12 -> "Passpoint R3"
            13 -> "DPP security"
            else -> "Wi-Fi encryption type unavailable on this Android version/device"
        }
        lines += "Wi-Fi protection: $label"
        lines += when (security) {
            0, 1 -> "Recommendation: switch the router to WPA2-AES or WPA3."
            in 2..13 -> "This link uses a protected Wi-Fi mode. Router/DNS checks are informational and cannot prove the access point is genuine."
            else -> "Check the router's security mode in its settings; this phone does not expose it here."
        }
        return lines.joinToString("\n")
    }

    fun inspectSite(raw: String): String {
        val url = try { URL(if (raw.contains("://")) raw else "https://$raw") }
            catch (_: Exception) { throw IllegalArgumentException("Enter a valid HTTPS site address.") }
        if (url.protocol.lowercase() != "https" || url.userInfo != null || url.query != null || url.ref != null || url.host.isBlank()) {
            throw IllegalArgumentException("Use an HTTPS address without credentials, query, or fragment.")
        }
        val addresses = InetAddress.getAllByName(url.host).mapNotNull { it.hostAddress }.distinct()
        val c = (url.openConnection() as? HttpsURLConnection) ?: throw IllegalArgumentException("Only HTTPS sites are supported.")
        c.requestMethod = "HEAD"
        c.instanceFollowRedirects = false
        c.connectTimeout = 5000
        c.readTimeout = 5000
        c.setRequestProperty("User-Agent", "NetWatch-Mobile/1.0")
        try {
            val status = c.responseCode
            val headers = listOf("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
                "X-Frame-Options", "Referrer-Policy", "Permissions-Policy")
            val missing = headers.filter { c.getHeaderField(it).isNullOrBlank() }
            val cert = c.serverCertificates.firstOrNull() as? java.security.cert.X509Certificate
            val certLine = cert?.let {
                val days = (it.notAfter.time - System.currentTimeMillis()) / 86_400_000
                "TLS certificate expires ${DateFormat.getDateInstance().format(it.notAfter)} ($days days)."
            } ?: "TLS certificate details unavailable."
            return buildString {
                appendLine("DNS addresses: ${addresses.joinToString(", ")}")
                appendLine("HTTPS response: $status${if (status in 300..399) " (redirect not followed)" else ""}")
                appendLine(certLine)
                append("Missing security headers: ${missing.ifEmpty { listOf("none of the checked headers") }.joinToString(", ")}.")
            }
        } finally { c.disconnect() }
    }

    fun emailPosture(domainInput: String, resolvers: List<InetAddress>): String {
        val domain = try { IDN.toASCII(domainInput.trim().trimEnd('.'), IDN.USE_STD3_ASCII_RULES).lowercase() }
            catch (_: Exception) { throw IllegalArgumentException("Enter a valid domain name.") }
        if (domain.length !in 3..253 || !domain.contains('.') || domain.split('.').any { it.isBlank() || it.length > 63 }) {
            throw IllegalArgumentException("Enter a valid domain name, such as example.com.")
        }
        if (resolvers.isEmpty()) throw IllegalStateException("No DNS resolver is available on the current connection.")
        val txt = queryTxt(domain, resolvers)
        val spf = txt.filter { it.trim().startsWith("v=spf1", true) }
        val dmarc = queryTxt("_dmarc.$domain", resolvers).filter { it.trim().startsWith("v=DMARC1", true) }
        return buildString {
            appendLine("Domain: $domain")
            appendLine("SPF:")
            when {
                spf.isEmpty() -> appendLine("• Missing — publish one SPF TXT record.")
                spf.size > 1 -> appendLine("• Multiple SPF records found; combine them into one.")
                else -> {
                    val record = spf.single()
                    appendLine("• $record")
                    appendLine(when {
                        record.contains("+all", true) -> "• Unsafe: +all allows any sender."
                        Regex("(?:^|\\s)-all(?:\\s|$)", RegexOption.IGNORE_CASE).containsMatchIn(record) -> "• Strict -all policy found."
                        Regex("(?:^|\\s)~all(?:\\s|$)", RegexOption.IGNORE_CASE).containsMatchIn(record) -> "• Soft-fail ~all; unauthorized senders are not strictly rejected."
                        else -> "• No final all mechanism found; review the policy."
                    })
                }
            }
            appendLine("DMARC:")
            when {
                dmarc.isEmpty() -> appendLine("• Missing at _dmarc.$domain.")
                dmarc.size > 1 -> appendLine("• Multiple DMARC records found; keep one.")
                else -> {
                    val record = dmarc.single()
                    val policy = Regex("(?:^|;)\\s*p\\s*=\\s*([^;]+)", RegexOption.IGNORE_CASE)
                        .find(record)?.groupValues?.getOrNull(1)?.trim()?.lowercase()
                    appendLine("• $record")
                    appendLine(when (policy) {
                        "reject" -> "• p=reject asks receivers to reject failing messages."
                        "quarantine" -> "• p=quarantine asks receivers to treat failing messages as suspicious."
                        "none" -> "• p=none is monitoring only; it does not ask receivers to enforce."
                        else -> "• No recognized DMARC p= policy found."
                    })
                }
            }
            append("DNS lookups only; no email was sent. Verify all legitimate senders before tightening a policy.")
        }
    }

    private fun queryTxt(name: String, resolvers: List<InetAddress>): List<String> {
        for (resolver in resolvers) {
            try { return queryTxt(name, resolver) } catch (_: Exception) { }
        }
        return emptyList()
    }

    private fun queryTxt(name: String, resolver: InetAddress): List<String> {
        val id = SecureRandom().nextInt(65536)
        val query = buildList<Byte> {
            add((id shr 8).toByte()); add(id.toByte()); add(1); add(0); add(0); add(1); add(0); add(0); add(0); add(0); add(0); add(0)
            name.split('.').forEach { label ->
                val b = label.toByteArray(StandardCharsets.US_ASCII)
                add(b.size.toByte()); b.forEach { add(it) }
            }
            add(0); add(0); add(16); add(0); add(1)
        }.toByteArray()
        val buffer = ByteArray(4096)
        DatagramSocket().use { socket ->
            socket.soTimeout = 2200
            socket.connect(InetSocketAddress(resolver, 53))
            socket.send(DatagramPacket(query, query.size))
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            if (packet.length < 12 || ((buffer[0].toInt() and 255) shl 8 or (buffer[1].toInt() and 255)) != id) return emptyList()
            val questions = u16(buffer, 4); val answers = u16(buffer, 6)
            var at = 12
            repeat(questions) { at = skipName(buffer, at) + 4 }
            val out = mutableListOf<String>()
            repeat(answers) {
                at = skipName(buffer, at)
                if (at + 10 > packet.length) return@repeat
                val type = u16(buffer, at); val cls = u16(buffer, at + 2); val size = u16(buffer, at + 8); at += 10
                if (at + size > packet.length) return@repeat
                if (type == 16 && cls == 1) {
                    val end = at + size; val chunks = StringBuilder()
                    while (at < end) {
                        val length = buffer[at++].toInt() and 255
                        if (at + length > end) break
                        chunks.append(String(buffer, at, length, StandardCharsets.UTF_8)); at += length
                    }
                    if (chunks.isNotEmpty()) out += chunks.toString()
                    at = end
                } else at += size
            }
            return out
        }
    }

    private fun skipName(bytes: ByteArray, start: Int): Int {
        var at = start
        while (at < bytes.size) {
            val length = bytes[at].toInt() and 255
            if (length == 0) return at + 1
            if ((length and 0xc0) == 0xc0) return at + 2
            if (length > 63) throw IllegalArgumentException("Invalid DNS response")
            at += length + 1
        }
        throw IllegalArgumentException("Invalid DNS response")
    }

    private fun u16(bytes: ByteArray, at: Int): Int = ((bytes[at].toInt() and 255) shl 8) or (bytes[at + 1].toInt() and 255)
}
