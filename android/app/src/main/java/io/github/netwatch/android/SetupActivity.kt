package io.github.netwatch.android

import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import kotlin.concurrent.thread

/** Πρώτη φορά: σύνδεσμος του agent → έλεγχος fingerprint από τον χρήστη → αποθήκευση (pin). */
class SetupActivity : AppCompatActivity() {
    private lateinit var url: EditText
    private lateinit var go: Button
    private lateinit var busy: ProgressBar
    private lateinit var msg: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = getString(R.string.setup_title)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }
        col.addView(TextView(this).apply { text = getString(R.string.setup_intro); textSize = 15f })
        url = EditText(this).apply {
            hint = getString(R.string.setup_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            typeface = Typeface.MONOSPACE
        }
        col.addView(url)
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        row.addView(Button(this).apply {
            text = getString(R.string.paste)
            setOnClickListener {
                val clip = getSystemService(ClipboardManager::class.java).primaryClip
                clip?.getItemAt(0)?.coerceToText(this@SetupActivity)?.let { url.setText(it.toString().trim()) }
            }
        })
        go = Button(this).apply { text = getString(R.string.connect); setOnClickListener { connect() } }
        row.addView(go)
        busy = ProgressBar(this).apply { visibility = View.GONE }
        row.addView(busy)
        col.addView(row)
        msg = TextView(this).apply { setPadding(0, pad, 0, 0) }
        col.addView(msg)
        setContentView(ScrollView(this).apply { addView(col) })
    }

    private fun setBusy(b: Boolean) {
        go.isEnabled = !b
        busy.visibility = if (b) View.VISIBLE else View.GONE
        if (b) msg.text = getString(R.string.connecting)
    }

    private fun connect() {
        val p = AgentUrl.parse(url.text.toString()) ?: run { msg.text = getString(R.string.bad_url); return }
        setBusy(true)
        thread {
            val result: () -> Unit = try {
                val fp = AgentClient.peekFingerprint(p.base)
                val cfg = AgentConfig(p.base, p.token, fp)
                AgentClient.status(cfg)  // το token δουλεύει; (στέλνεται μόνο στο ίδιο, καρφωμένο πιστοποιητικό)
                ({ confirm(cfg) })
            } catch (e: AuthException) {
                ({ msg.text = getString(R.string.bad_token) })
            } catch (e: Exception) {
                ({ msg.text = getString(R.string.conn_failed, e.message ?: e.javaClass.simpleName) })
            }
            runOnUiThread { setBusy(false); if (msg.text == getString(R.string.connecting)) msg.text = ""; result() }
        }
    }

    private fun confirm(cfg: AgentConfig) {
        val fpView = TextView(this).apply {
            text = getString(R.string.fp_message, cfg.fingerprint.chunked(24).joinToString("\n"))
            typeface = Typeface.MONOSPACE
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad / 2, pad, 0)
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.fp_title)
            .setView(fpView)
            .setPositiveButton(R.string.fp_yes) { _, _ ->
                Store(this).config = cfg
                startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK))
                finish()
            }
            .setNegativeButton(R.string.fp_no, null)
            .show()
    }
}
