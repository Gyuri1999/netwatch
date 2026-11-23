package io.github.netwatch.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Ενημέρωση της εφαρμογής εκτός Play Store: ελέγχει τα GitHub releases, κατεβάζει το νέο APK και
 * ανοίγει τον installer των Android. Όλα με προσοχή — καμία αποτυχία δεν ρίχνει την εφαρμογή.
 */
object Updater {
    private const val API = "https://api.github.com/repos/Gyuri1999/netwatch/releases/latest"

    data class Release(val version: String, val apkUrl: String?)

    /** JSON του GitHub release → (έκδοση χωρίς «v», URL του .apk). */
    fun parseRelease(json: String): Release {
        val o = JSONObject(json)
        val tag = o.optString("tag_name").trimStart('v', 'V')
        var apk: String? = null
        val assets = o.optJSONArray("assets")
        if (assets != null) {
            for (i in 0 until assets.length()) {
                val a = assets.getJSONObject(i)
                if (a.optString("name").endsWith(".apk", ignoreCase = true)) {
                    apk = a.optString("browser_download_url").ifEmpty { null }
                    break
                }
            }
        }
        return Release(tag, apk)
    }

    /** Σύγκριση εκδόσεων τύπου 1.14.1 — true αν η latest είναι νεότερη από την current. */
    fun isNewer(latest: String, current: String): Boolean {
        fun parts(s: String) = s.trim().trimStart('v', 'V').split(".", "-", "+").mapNotNull { it.toIntOrNull() }
        val a = parts(latest)
        val b = parts(current)
        if (a.isEmpty()) return false
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }

    fun currentVersion(act: Activity): String =
        try { act.packageManager.getPackageInfo(act.packageName, 0).versionName ?: "0" } catch (e: Exception) { "0" }

    /** Έλεγχος στο παρασκήνιο. silent=true: μιλάει μόνο αν υπάρχει νέα έκδοση. */
    fun check(act: Activity, silent: Boolean) {
        Thread {
            try {
                val rel = parseRelease(fetch(API))
                if (rel.apkUrl != null && isNewer(rel.version, currentVersion(act))) {
                    act.runOnUiThread { if (!act.isFinishing) prompt(act, rel) }
                } else if (!silent) {
                    act.runOnUiThread { toast(act, act.getString(R.string.update_none)) }
                }
            } catch (e: Exception) {
                if (!silent) act.runOnUiThread { toast(act, act.getString(R.string.update_failed)) }
            }
        }.apply { isDaemon = true }.start()
    }

    private fun prompt(act: Activity, rel: Release) {
        AlertDialog.Builder(act)
            .setTitle(act.getString(R.string.update_title))
            .setMessage(act.getString(R.string.update_message, rel.version))
            .setPositiveButton(act.getString(R.string.update_now)) { _, _ -> download(act, rel.apkUrl!!) }
            .setNegativeButton(act.getString(R.string.update_later), null)
            .show()
    }

    private fun download(act: Activity, url: String) {
        toast(act, act.getString(R.string.update_downloading))
        Thread {
            try {
                val f = File(act.getExternalFilesDir(null), "netwatch-update.apk")
                if (f.exists()) f.delete()
                (URL(url).openConnection() as HttpsURLConnection).apply {
                    setRequestProperty("User-Agent", "NetWatch")
                    connectTimeout = 15000
                    readTimeout = 30000
                }.inputStream.use { inp -> f.outputStream().use { inp.copyTo(it) } }
                act.runOnUiThread { if (!act.isFinishing) install(act, f) }
            } catch (e: Exception) {
                act.runOnUiThread { toast(act, act.getString(R.string.update_failed)) }
            }
        }.apply { isDaemon = true }.start()
    }

    private fun install(act: Activity, f: File) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !act.packageManager.canRequestPackageInstalls()) {
                toast(act, act.getString(R.string.update_allow))
                act.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + act.packageName)))
                return
            }
            val uri = FileProvider.getUriForFile(act, act.packageName + ".updates", f)
            act.startActivity(Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        } catch (e: Exception) {
            toast(act, act.getString(R.string.update_failed))
        }
    }

    private fun fetch(url: String): String {
        val c = (URL(url).openConnection() as HttpsURLConnection).apply {
            setRequestProperty("User-Agent", "NetWatch")
            setRequestProperty("Accept", "application/vnd.github+json")
            connectTimeout = 8000
            readTimeout = 8000
        }
        return c.inputStream.bufferedReader().use { it.readText() }
    }

    private fun toast(act: Activity, s: String) = Toast.makeText(act, s, Toast.LENGTH_SHORT).show()
}
