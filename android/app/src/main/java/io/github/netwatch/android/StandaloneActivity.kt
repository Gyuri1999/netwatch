package io.github.netwatch.android

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AlertDialog
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import java.io.IOException
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.text.DateFormat
import java.util.Date
import kotlin.concurrent.thread

/** Local-first Android dashboard. The agent remains an optional, separate view. */
class StandaloneActivity : AppCompatActivity() {
    private lateinit var content: LinearLayout
    private lateinit var networkCard: TextView
    private lateinit var scanResult: TextView
    private lateinit var scanButton: Button
    private lateinit var internetState: TextView
    private lateinit var wifiResult: TextView
    private lateinit var siteResult: TextView
    private lateinit var siteInput: EditText
    private lateinit var emailResult: TextView
    private lateinit var emailInput: EditText
    private lateinit var historyResult: TextView
    private val history by lazy { StandaloneHistory(this) }
    private var pendingNotification: List<String> = emptyList()
    private val worker = Executors.newFixedThreadPool(32)

    private val askNotifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) { allowed ->
        if (allowed && pendingNotification.isNotEmpty()) showNewDeviceNotification(pendingNotification)
        pendingNotification = emptyList()
    }
    private val exportReport = registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) writeReport(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = getString(R.string.app_name)
        val pad = dp(18)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            setBackgroundColor(0xFF0B1220.toInt())   // σταθερά σκούρο look (ανεξάρτητα light/dark κινητού)
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

        val wifiCard = card()
        wifiCard.addView(text(getString(R.string.standalone_wifi_check_title), 18f, true))
        wifiCard.addView(text(getString(R.string.standalone_wifi_check_info), 14f, false))
        wifiResult = text(getString(R.string.standalone_tool_idle), 14f, false)
        wifiCard.addView(wifiResult)
        wifiCard.addView(Button(this).apply {
            text = getString(R.string.standalone_wifi_check_button)
            setOnClickListener { checkWifi() }
        })
        content.addView(wifiCard)

        val siteCard = card()
        siteCard.addView(text(getString(R.string.standalone_site_title), 18f, true))
        siteCard.addView(text(getString(R.string.standalone_site_info), 14f, false))
        siteInput = EditText(this).apply {
            hint = getString(R.string.standalone_site_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
        }
        siteCard.addView(siteInput)
        siteResult = text(getString(R.string.standalone_tool_idle), 14f, false)
        siteCard.addView(siteResult)
        siteCard.addView(Button(this).apply {
            text = getString(R.string.standalone_site_button)
            setOnClickListener { runTool(siteResult, this) { StandaloneSecurity.inspectSite(siteInput.text.toString()) } }
        })
        content.addView(siteCard)

        val emailCard = card()
        emailCard.addView(text(getString(R.string.standalone_email_title), 18f, true))
        emailCard.addView(text(getString(R.string.standalone_email_info), 14f, false))
        emailInput = EditText(this).apply {
            hint = getString(R.string.standalone_email_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
        }
        emailCard.addView(emailInput)
        emailResult = text(getString(R.string.standalone_tool_idle), 14f, false)
        emailCard.addView(emailResult)
        emailCard.addView(Button(this).apply {
            text = getString(R.string.standalone_email_button)
            setOnClickListener { runTool(emailResult, this) { checkEmailDomain(emailInput.text.toString()) } }
        })
        content.addView(emailCard)

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

        val historyCard = card()
        historyCard.addView(text(getString(R.string.standalone_history_title), 18f, true))
        historyResult = text("", 13f, false)
        historyCard.addView(historyResult)
        val historyActions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL }
        historyActions.addView(Button(this).apply {
            text = getString(R.string.standalone_export_button)
            setOnClickListener { exportReport.launch("netwatch-mobile-report.txt") }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        historyActions.addView(Button(this).apply {
            text = getString(R.string.standalone_clear_button)
            setOnClickListener { confirmClearHistory() }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        historyCard.addView(historyActions)
        content.addView(historyCard)

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

        content.addView(Button(this).apply {
            text = getString(R.string.update_check)
            setOnClickListener { Updater.check(this@StandaloneActivity, silent = false) }
            val lp = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(6) }
            layoutParams = lp
        })

        content.addView(TextView(this).apply {
            text = getString(R.string.standalone_limit)
            textSize = 12f
            setTextColor(0xFF9FB0CC.toInt())   // υποσημείωση σε σκούρο φόντο — ευανάγνωστη
            setPadding(dp(4), dp(8), dp(4), dp(12))
        })
        val scroll = ScrollView(this).apply { addView(content) }
        setContentView(scroll)
        refreshNetwork()
        refreshHistory()
        Updater.check(this, silent = true)   // σιωπηλός έλεγχος· μιλάει μόνο αν υπάρχει νέα έκδοση
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

    private fun checkWifi() {
        wifiResult.text = StandaloneSecurity.wifiSummary(
            getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager,
            getSystemService(Context.WIFI_SERVICE) as WifiManager
        )
    }

    private fun checkEmailDomain(domain: String): String {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val resolvers = cm.activeNetwork?.let(cm::getLinkProperties)?.dnsServers.orEmpty()
        return StandaloneSecurity.emailPosture(domain, resolvers)
    }

    private fun runTool(output: TextView, button: Button, action: () -> String) {
        button.isEnabled = false
        output.text = getString(R.string.standalone_tool_working)
        thread {
            val result = try { action() } catch (e: Exception) {
                getString(R.string.standalone_tool_error, e.message ?: e.javaClass.simpleName)
            }
            runOnUiThread { output.text = result; button.isEnabled = true }
        }
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
            val found = try { scanSubnet(address.address as Inet4Address, address.prefixLength) }
                catch (e: Exception) {
                    runOnUiThread { scanButton.isEnabled = true; scanResult.text = getString(R.string.standalone_tool_error, e.message ?: "scan error") }
                    return@thread
                }
            val gateway = props.routes.firstOrNull { it.isDefaultRoute }?.gateway?.hostAddress ?: "unknown-router"
            val networkKey = "${address.address.hostAddress}/${address.prefixLength} via $gateway"
            val record = history.record(networkKey, found)
            runOnUiThread {
                scanButton.isEnabled = true
                scanResult.text = if (found.isEmpty()) getString(R.string.standalone_scan_empty)
                    else getString(R.string.standalone_scan_found, found.size, found.joinToString("\n") { "• $it" })
                refreshHistory()
                if (record.newDevices.isNotEmpty()) postNewDeviceNotification(record.newDevices)
            }
        }
    }

    private fun refreshHistory() {
        if (!::historyResult.isInitialized) return
        val recent = history.records().take(5)
        historyResult.text = if (recent.isEmpty()) getString(R.string.standalone_history_empty) else recent.joinToString("\n\n") {
            getString(R.string.standalone_history_entry,
                DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(it.at)),
                it.devices.size, it.newDevices.size, it.network)
        }
    }

    private fun confirmClearHistory() {
        AlertDialog.Builder(this)
            .setTitle(R.string.standalone_clear_title)
            .setMessage(R.string.standalone_clear_confirm)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.standalone_clear_button) { _, _ -> history.clear(); refreshHistory() }
            .show()
    }

    private fun writeReport(uri: Uri) {
        try {
            contentResolver.openOutputStream(uri)?.use { it.write(history.report().toByteArray(Charsets.UTF_8)) }
            Toast.makeText(this, R.string.standalone_export_done, Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.standalone_export_error, e.message ?: "unknown error"), Toast.LENGTH_LONG).show()
        }
    }

    private fun postNewDeviceNotification(hosts: List<String>) {
        ensureNotificationChannel()
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            pendingNotification = hosts
            askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else showNewDeviceNotification(hosts)
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = getSystemService(android.app.NotificationManager::class.java)
            manager.createNotificationChannel(android.app.NotificationChannel("standalone_devices", getString(R.string.standalone_notifications), android.app.NotificationManager.IMPORTANCE_DEFAULT))
        }
    }

    private fun showNewDeviceNotification(hosts: List<String>) {
        val notification = NotificationCompat.Builder(this, "standalone_devices")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(getString(R.string.standalone_new_devices_title, hosts.size))
            .setContentText(hosts.take(4).joinToString(", "))
            .setStyle(NotificationCompat.BigTextStyle().bigText(hosts.joinToString(", ")))
            .setAutoCancel(true)
            .build()
        try { NotificationManagerCompat.from(this).notify(3101, notification) } catch (_: SecurityException) { }
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
        setPadding(dp(16), dp(14), dp(16), dp(14))
        background = android.graphics.drawable.GradientDrawable().apply {
            cornerRadius = dp(14).toFloat()
            setColor(0xFF141C2E.toInt())           // σκούρα κάρτα
            setStroke(dp(1), 0xFF2A3A57.toInt())   // διακριτικό περίγραμμα
        }
        val lp = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) }
        layoutParams = lp
    }

    private fun text(value: String, size: Float, bold: Boolean) = TextView(this).apply {
        text = value
        textSize = size
        if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
        setTextColor(if (bold) 0xFFF2F6FF.toInt() else 0xFFC3D0E6.toInt())  // ανοιχτό κείμενο, ευανάγνωστο σε σκούρο
        setPadding(0, dp(4), 0, dp(4))
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
}
