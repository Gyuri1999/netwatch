package io.github.netwatch.android

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.http.SslError
import android.os.Build
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import java.net.URLEncoder

/** Ο πίνακας του agent σε WebView, μόνο με το καρφωμένο πιστοποιητικό. */
class MainActivity : AppCompatActivity() {
    private lateinit var store: Store
    private lateinit var cfg: AgentConfig
    private lateinit var web: WebView
    private lateinit var swipe: SwipeRefreshLayout

    private val askNotify = registerForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok && store.notify) AlertWorker.schedule(this)
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = Store(this)
        cfg = store.config ?: run {
            startActivity(Intent(this, SetupActivity::class.java))
            finish()
            return
        }
        web = WebView(this)
        web.settings.javaScriptEnabled = true  // ο πίνακας του NetWatch είναι εφαρμογή JavaScript
        web.settings.domStorageEnabled = true
        CookieManager.getInstance().setAcceptCookie(true)
        web.webViewClient = object : WebViewClient() {
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                val x = error.certificate.x509Certificate
                if (x != null && error.url.startsWith(cfg.base) && Fingerprint.of(x) == cfg.fingerprint) {
                    handler.proceed()  // self-signed, αλλά ΑΚΡΙΒΩΣ αυτό που επιβεβαίωσε ο χρήστης
                } else {
                    handler.cancel()
                    Toast.makeText(this@MainActivity, R.string.cert_mismatch, Toast.LENGTH_LONG).show()
                }
            }

            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (request.url.toString().startsWith(cfg.base)) return false
                try { startActivity(Intent(Intent.ACTION_VIEW, request.url)) } catch (e: Exception) { }
                return true  // εξωτερικοί σύνδεσμοι (OSINT, MITRE) στον κανονικό browser
            }

            override fun onPageFinished(view: WebView, url: String) {
                swipe.isRefreshing = false
            }
        }
        swipe = SwipeRefreshLayout(this).apply {
            addView(web)
            setOnRefreshListener { web.reload() }
            setOnChildScrollUpCallback { _, _ -> web.scrollY > 0 }
        }
        setContentView(swipe)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (web.canGoBack()) web.goBack() else finish()
            }
        })
        if (savedInstanceState != null) web.restoreState(savedInstanceState)
        else web.loadUrl("${cfg.base}/?token=" + URLEncoder.encode(cfg.token, "UTF-8"))  // → cookie HttpOnly
        setupNotifications()
    }

    private fun setupNotifications() {
        if (!store.notify) return
        Notifier.ensureChannel(this)
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            askNotify.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            AlertWorker.schedule(this)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (::web.isInitialized) web.saveState(outState)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(0, 1, 0, R.string.menu_reload)
        menu.add(0, 2, 1, R.string.menu_notify).setCheckable(true).isChecked = store.notify
        menu.add(0, 3, 2, R.string.menu_change)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            1 -> web.reload()
            2 -> {
                store.notify = !store.notify
                item.isChecked = store.notify
                if (store.notify) setupNotifications() else AlertWorker.cancel(this)
            }
            3 -> {
                AlertWorker.cancel(this)
                store.config = null
                CookieManager.getInstance().removeAllCookies(null)
                web.clearCache(true)
                startActivity(Intent(this, SetupActivity::class.java))
                finish()
            }
            else -> return super.onOptionsItemSelected(item)
        }
        return true
    }
}
