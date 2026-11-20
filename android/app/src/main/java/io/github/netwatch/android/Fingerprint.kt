package io.github.netwatch.android

import java.security.MessageDigest
import java.security.cert.X509Certificate

/** SHA-256 του πιστοποιητικού, στη μορφή που τυπώνει ο agent: «AB:CD:…» (32 ζεύγη). */
object Fingerprint {
    fun of(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der).joinToString(":") { "%02X".format(it) }

    fun of(cert: X509Certificate): String = of(cert.encoded)

    /** Δέχεται και «SHA256 Fingerprint=ab:cd…» ή σκέτο hex· → κανονική μορφή, ή null αν δεν είναι SHA-256. */
    fun normalize(s: String): String? {
        val hex = s.substringAfterLast('=').uppercase().filter { it in "0123456789ABCDEF" }
        return if (hex.length == 64) hex.chunked(2).joinToString(":") else null
    }
}
