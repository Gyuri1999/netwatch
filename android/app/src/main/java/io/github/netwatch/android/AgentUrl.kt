package io.github.netwatch.android

import java.net.URI
import java.net.URLDecoder

/** Ο σύνδεσμος που τυπώνει ο agent: https://<host>:8765/?token=… → βάση + token. */
object AgentUrl {
    const val DEFAULT_PORT = 8765

    data class Parsed(val base: String, val token: String)

    fun parse(input: String): Parsed? {
        var s = input.trim()
        if (s.isEmpty()) return null
        if (!s.contains("://")) s = "https://$s"
        val uri = try { URI(s) } catch (e: Exception) { return null }
        if (!uri.scheme.equals("https", ignoreCase = true)) return null  // ο agent μιλά μόνο HTTPS
        val host = uri.host?.takeIf { it.isNotEmpty() } ?: return null
        val port = if (uri.port == -1) DEFAULT_PORT else uri.port
        val token = (uri.rawQuery ?: "").split("&")
            .map { it.split("=", limit = 2) }
            .firstOrNull { it[0] == "token" && it.size == 2 }
            ?.let { URLDecoder.decode(it[1], "UTF-8").trim() }
            ?.takeIf { it.isNotEmpty() } ?: return null
        return Parsed("https://$host:$port", token)
    }
}
