package io.github.netwatch.android

import android.content.Context

data class AgentConfig(val base: String, val token: String, val fingerprint: String)

/** Ρυθμίσεις στη συσκευή (ιδιωτικά δεδομένα της εφαρμογής, χωρίς backup). */
class Store(ctx: Context) {
    private val p = ctx.applicationContext.getSharedPreferences("netwatch", Context.MODE_PRIVATE)

    var config: AgentConfig?
        get() {
            val b = p.getString("base", null) ?: return null
            val t = p.getString("token", null) ?: return null
            val f = p.getString("fp", null) ?: return null
            return AgentConfig(b, t, f)
        }
        set(c) {
            p.edit().apply {
                if (c == null) remove("base").remove("token").remove("fp")
                else putString("base", c.base).putString("token", c.token).putString("fp", c.fingerprint)
                putString("lastSeenD", "-1")  // νέος agent: ξεκίνα από το τώρα
            }.apply()
        }

    var notify: Boolean
        get() = p.getBoolean("notify", true)
        set(v) = p.edit().putBoolean("notify", v).apply()

    var lastSeen: Double
        get() = p.getString("lastSeenD", null)?.toDoubleOrNull() ?: -1.0
        set(v) = p.edit().putString("lastSeenD", v.toString()).apply()
}
