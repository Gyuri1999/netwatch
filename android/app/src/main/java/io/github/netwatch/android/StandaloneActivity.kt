package io.github.netwatch.android

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.IOException
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** Local-first Android dashboard. The agent remains an optional, separate view. */
class StandaloneActivity : AppCompatActivity() {
    private lateinit var content: LinearLayout
    private lateinit var networkCard: TextView
    private lateinit var scanResult: TextView
    private lateinit var scanButton: Button
    private lateinit var internetState: TextView
    private val worker = Executors.newFixedThreadPool(32)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = getString(R.string.app_name)
        val pad = dp(18)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        content.addView(text("NetWatch", 28f, true))
        content.addView(text(getString(R.string.standalone_subtitle), 14f, false).apply {
            setPadding(0, dp(4), 0, dp(14))
        })

        val statusCard = card()
        statusCard.addView(text(getString(R.string.standalone_phone_title), 18f, true))
        internetState = text("", 14f, false)
        statusCard.addView(internetState)
        content.addView(statusCard)

        val netCard = card()
        netCard.addView(text(getString(R.string.standalone_network_title), 18f, true))
        networkCard = text("", 14f, false)
        networkCard.setTextIsSelectable(true)
        netCard.addView(networkCard)
        content.addView(netCard)

        val scanCard = card()
        scanCard.addView(text(getString(R.string.standalone_scan_title), 18f, true))
        scanCard.addView(text(getString(R.string.standalone_scan_info), 14f, false))
        scanButton = Button(this).apply {
            text = getString(R.string.standalone_scan_button)
            setOnClickListener { scanLocalNetwork() }
        }
        scanCard.addView(scanButton)
        scanResult = text(getString(R.string.standalone_scan_idle), 14f, false)
        scanCard.addView(scanResult)
        content.addView(scanCard)

        val agentCard = card()
        agentCard.addView(text(getString(R.string.standalone_agent_title), 18f, true))
        agentCard.addView(text(getString(R.string.standalone_agent_info), 14f, false))
        agentCard.addView(Button(this).apply {
            text = getString(R.string.standalone_agent_button)
            setOnClickListener {
                val target = if (Store(this@StandaloneActivity).config == null) SetupActivity::class.java else MainActivity::class.java
                startActivity(Intent(this@StandaloneActivity, target))
            }
        })
        content.addView(agentCard)

        content.addView(TextView(this).apply {
            text = getString(R.string.standalone_limit)
            textSize = 12f
            alpha = .72f
            setPadding(dp(4), dp(8), dp(4), dp(12))
        })
        val scroll = ScrollView(this).apply { addView(content) }
        setContentView(scroll)
        refreshNetwork()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        if (::networkCard.isInitialized) refreshNetwork()
    }

    private fun refreshNetwork() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val active = cm.activeNetwork
        val caps = active?.let(cm::getNetworkCapabilities)
        val props = active?.let(cm::getLinkProperties)
        val validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        internetState.text = getString(if (validated) R.string.standalone_internet_yes else R.string.standalone_internet_no)
        networkCard.text = describeNetwork(caps, props)
    }

    private fun describeNetwork(caps: NetworkCapabilities?, props: LinkProperties?): String {
        if (caps == null || props == null) return getString(R.string.standalone_network_none)
        val transport = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> getString(R.string.standalone_wifi)
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> getString(R.string.standalone_cellular)
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> getString(R.string.standalone_ethernet)
            else -> getString(R.string.standalone_other)
        }
        val v4 = props.linkAddresses.firstOrNull { it.address is Inet4Address }
        val gateway = props.routes.firstOrNull { it.isDefaultRoute }?.gateway?.hostAddress ?: "—"
        val dns = props.dnsServers.joinToString(" · ") { it.hostAddress ?: "" }.ifBlank { "—" }
        return getString(R.string.standalone_network_details, transport,
            v4?.let { "${it.address.hostAddress}/${it.prefixLength}" } ?: "—", gateway, dns)
    }

    private fun scanLocalNetwork() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork
        val props = network?.let(cm::getLinkProperties)
        val isWifi = network?.let(cm::getNetworkCapabilities)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        val address = props?.linkAddresses?.firstOrNull { it.address is Inet4Address }
        if (!isWifi || address == null || address.prefixLength !in 24..30 || address.address.hostAddress?.let(::isPrivateIpv4) != true) {
            scanResult.text = getString(R.string.standalone_scan_unsupported)
            return
        }
        scanButton.isEnabled = false
        scanResult.text = getString(R.string.standalone_scan_working)
        thread {
            val found = scanSubnet(address.address as Inet4Address, address.prefixLength)
            runOnUiThread {
                scanButton.isEnabled = true
                scanResult.text = if (found.isEmpty()) getString(R.string.standalone_scan_empty)
                    else getString(R.string.standalone_scan_found, found.size, found.joinToString("\n") { "• $it" })
            }
        }
    }

    /** User-triggered TCP reachability check on the current private /24 or smaller subnet. */
    private fun scanSubnet(local: Inet4Address, prefix: Int): List<String> {
        val localLong = ipv4Long(local.address)
        val hostBits = 32 - prefix
        val mask = (0xffffffffL shl hostBits) and 0xffffffffL
        val first = (localLong and mask) + 1
        val last = (localLong or (0xffffffffL ushr prefix)) - 1
        val count = (last - first + 1).coerceAtMost(254).toInt()
        val done = AtomicInteger(0)
        val lock = Object()
        val found = mutableListOf<Pair<Long, String>>()
        for (offset in 0 until count) {
            val ip = first + offset
            if (ip == localLong) { done.incrementAndGet(); continue }
            worker.execute {
                val ipText = longIpv4(ip)
                var alive = false
                for (port in intArrayOf(80, 443, 22, 8080, 554)) {
                    val socket = Socket()
                    try {
                        socket.connect(InetSocketAddress(ipText, port), 220)
                        alive = true
                    } catch (_: ConnectException) {
                        // A refusal is still a response from that host.
                        alive = true
                    } catch (_: IOException) {
                        // Timeouts and unreachable hosts are omitted from this quick check.
                    } finally { try { socket.close() } catch (_: Exception) { } }
                    if (alive) break
                }
                if (alive) synchronized(lock) { found.add(ip to ipText) }
                if (done.incrementAndGet() == count) synchronized(lock) { lock.notifyAll() }
            }
        }
        synchronized(lock) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(18)
            while (done.get() < count) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) break
                TimeUnit.NANOSECONDS.timedWait(lock, remaining)
            }
        }
        return synchronized(lock) { found.sortedBy { it.first }.map { it.second } }
    }

    private fun isPrivateIpv4(value: String): Boolean {
        val parts = value.split('.').mapNotNull { it.toIntOrNull() }
        if (parts.size != 4) return false
        return parts[0] == 10 || (parts[0] == 192 && parts[1] == 168) ||
            (parts[0] == 172 && parts[1] in 16..31)
    }

    private fun ipv4Long(b: ByteArray): Long = b.fold(0L) { n, byte -> (n shl 8) or (byte.toInt() and 255).toLong() }
    private fun longIpv4(value: Long): String = "${(value shr 24) and 255}.${(value shr 16) and 255}.${(value shr 8) and 255}.${value and 255}"

    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(14), dp(12), dp(14), dp(12))
        background = getDrawable(android.R.drawable.dialog_holo_light_frame)
        val lp = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) }
        layoutParams = lp
    }

    private fun text(value: String, size: Float, bold: Boolean) = TextView(this).apply {
        text = value
        textSize = size
        if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
        setPadding(0, dp(3), 0, dp(3))
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}
