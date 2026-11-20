package io.github.netwatch.android

import org.json.JSONObject

data class AlertItem(val id: String, val t: Double, val type: String, val sev: String, val actor: String, val target: String)

/** Ανάγνωση του /api/status του agent και επιλογή του τι αξίζει ειδοποίηση. */
object Alerts {
    private val RANK = mapOf("low" to 0, "med" to 1, "high" to 2)

    fun recent(status: JSONObject): List<AlertItem> {
        val arr = status.optJSONArray("recent") ?: return emptyList()
        return (0 until arr.length()).mapNotNull { i ->
            val a = arr.optJSONObject(i) ?: return@mapNotNull null
            if (a.optBoolean("maint", false)) return@mapNotNull null  // σε παράθυρο συντήρησης: σιωπή
            AlertItem(a.opt("id")?.toString() ?: "", a.optDouble("t", 0.0), a.optString("type"),
                a.optString("sev", "low"), a.optString("actor"), a.optString("target"))
        }
    }

    /**
     * Τα νέα (μετά το [lastSeen]) με σοβαρότητα ≥ [minSev], παλαιότερο πρώτο, και το νέο lastSeen.
     * Πρώτη φορά (lastSeen < 0) δεν ειδοποιεί για τα παλιά· απλώς κρατά από πού να συνεχίσει.
     */
    fun fresh(status: JSONObject, lastSeen: Double, minSev: String = "high"): Pair<List<AlertItem>, Double> {
        val all = recent(status)
        val newest = all.maxOfOrNull { it.t } ?: 0.0
        if (lastSeen < 0) return emptyList<AlertItem>() to newest
        val floor = RANK[minSev] ?: 2
        val out = all.filter { it.t > lastSeen && (RANK[it.sev] ?: 0) >= floor }.sortedBy { it.t }
        return out to maxOf(newest, lastSeen)
    }

    /** Ίδια λογική με το εικονίδιο του Mac/Windows: bad, warn, ok ή idle. */
    fun level(status: JSONObject?): String {
        if (status == null || !status.has("high")) return "idle"
        val wifi = status.optJSONObject("wifi")?.optString("level")
        return when {
            status.optInt("high") > 0 || wifi == "bad" -> "bad"
            status.optInt("med") > 0 || wifi == "warn" -> "warn"
            else -> "ok"
        }
    }
}
