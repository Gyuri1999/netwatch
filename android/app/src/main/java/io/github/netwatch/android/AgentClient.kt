package io.github.netwatch.android

import org.json.JSONObject
import java.io.IOException
import java.net.URL
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

class AuthException : IOException("token rejected")

/**
 * HTTPS προς τον agent με «καρφωμένο» (pinned) πιστοποιητικό. Ο agent έχει self-signed πιστοποιητικό, οπότε
 * δεν εμπιστευόμαστε καμία CA: δεχόμαστε ΜΟΝΟ το πιστοποιητικό με το fingerprint που επιβεβαίωσε ο χρήστης.
 * Γι' αυτό ο έλεγχος hostname παραλείπεται: το pin είναι αυστηρότερο από αυτόν.
 */
object AgentClient {
    private class Pinned(private val fp: String?) : X509TrustManager {
        var seen: X509Certificate? = null
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = throw CertificateException()
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val leaf = chain.firstOrNull() ?: throw CertificateException("no certificate")
            seen = leaf
            if (fp != null && Fingerprint.of(leaf) != fp) throw CertificateException("fingerprint mismatch")
            if (fp == null) throw CertificateException("peek only")  // μόνο για να δούμε το πιστοποιητικό
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private fun open(url: String, tm: X509TrustManager): HttpsURLConnection {
        val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), null) }
        return (URL(url).openConnection() as HttpsURLConnection).apply {
            sslSocketFactory = ctx.socketFactory
            hostnameVerifier = HostnameVerifier { _, _ -> true }
            connectTimeout = 8000
            readTimeout = 8000
            instanceFollowRedirects = false
        }
    }

    /** Ποιο πιστοποιητικό δείχνει ο agent; Η σύνδεση κόβεται πριν σταλεί οτιδήποτε (ούτε το token). */
    fun peekFingerprint(base: String): String {
        val tm = Pinned(null)
        val c = open("$base/api/status", tm)
        try { c.responseCode } catch (e: IOException) { /* αναμενόμενο: το κόψαμε εμείς */ } finally { c.disconnect() }
        return Fingerprint.of(tm.seen ?: throw IOException("no TLS certificate from $base"))
    }

    fun status(cfg: AgentConfig): JSONObject {
        val c = open("${cfg.base}/api/status", Pinned(cfg.fingerprint))
        c.setRequestProperty("Authorization", "Bearer ${cfg.token}")
        c.setRequestProperty("Accept", "application/json")
        try {
            when (val code = c.responseCode) {
                200 -> return JSONObject(c.inputStream.bufferedReader().use { it.readText() })
                401, 403 -> throw AuthException()
                else -> throw IOException("HTTP $code")
            }
        } finally {
            c.disconnect()
        }
    }
}
