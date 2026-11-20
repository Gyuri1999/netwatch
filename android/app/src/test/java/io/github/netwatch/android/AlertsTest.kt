package io.github.netwatch.android

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AlertsTest {
    // Σχήμα όπως το /api/status του NetWatch (detect.NetState.status)
    private fun status(vararg recent: String, high: Int = 1, med: Int = 0, wifi: String? = null) = JSONObject(
        """{"mode":"live","alerts":3,"high":$high,"med":$med,"low":0,
            "wifi":${if (wifi == null) "null" else "{\"level\":\"$wifi\"}"},
            "recent":[${recent.joinToString(",")}]}""")

    private fun a(id: Int, t: Double, sev: String, type: String = "Port scan", maint: Boolean? = null) =
        """{"id":$id,"t":$t,"type":"$type","sev":"$sev","actor":"192.168.1.66","target":"192.168.1.50","maint":${maint ?: "null"}}"""

    @Test fun firstRunOnlySetsTheBaseline() {
        val (items, seen) = Alerts.fresh(status(a(2, 200.0, "high"), a(1, 100.0, "high")), -1.0)
        assertTrue(items.isEmpty())
        assertEquals(200.0, seen, 0.0)
    }

    @Test fun onlyNewSeriousOnesOldestFirst() {
        val st = status(a(4, 400.0, "high", "DNS rebinding"), a(3, 300.0, "med"), a(2, 250.0, "high", "ARP spoofing"), a(1, 100.0, "high"))
        val (items, seen) = Alerts.fresh(st, 200.0)
        assertEquals(listOf("ARP spoofing", "DNS rebinding"), items.map { it.type })
        assertEquals(400.0, seen, 0.0)
        assertEquals(listOf("2", "4"), items.map { it.id })
    }

    @Test fun mediumFloorAndMaintenanceSilence() {
        val st = status(a(3, 300.0, "med"), a(2, 250.0, "high", maint = true), a(1, 210.0, "low"))
        assertEquals(listOf("3"), Alerts.fresh(st, 200.0, "med").first.map { it.id })
    }

    @Test fun nothingNewKeepsLastSeen() {
        val (items, seen) = Alerts.fresh(status(), 500.0)
        assertTrue(items.isEmpty())
        assertEquals(500.0, seen, 0.0)
    }

    @Test fun levelLikeTheTrayIcon() {
        assertEquals("idle", Alerts.level(null))
        assertEquals("bad", Alerts.level(status(high = 2)))
        assertEquals("warn", Alerts.level(status(high = 0, med = 1)))
        assertEquals("ok", Alerts.level(status(high = 0)))
        assertEquals("bad", Alerts.level(status(high = 0, wifi = "bad")))
    }
}
