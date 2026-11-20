package io.github.netwatch.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AgentUrlTest {
    @Test fun fullLinkFromTheAgent() {
        val p = AgentUrl.parse("  https://192.168.1.10:8765/?token=abc_DEF-123  ")!!
        assertEquals("https://192.168.1.10:8765", p.base)
        assertEquals("abc_DEF-123", p.token)
    }

    @Test fun defaultsSchemeAndPort() {
        val p = AgentUrl.parse("netwatch.lan/?token=t0k")!!
        assertEquals("https://netwatch.lan:8765", p.base)
    }

    @Test fun ipv6AndOtherParams() {
        val p = AgentUrl.parse("https://[fd00::10]:9000/?x=1&token=a%2Bb")!!
        assertEquals("https://[fd00::10]:9000", p.base)
        assertEquals("a+b", p.token)
    }

    @Test fun rejectsHttpAndMissingToken() {
        assertNull(AgentUrl.parse("http://192.168.1.10:8765/?token=abc"))  // ο agent είναι μόνο HTTPS
        assertNull(AgentUrl.parse("https://192.168.1.10:8765/"))
        assertNull(AgentUrl.parse("https://192.168.1.10:8765/?token="))
        assertNull(AgentUrl.parse(""))
        assertNull(AgentUrl.parse("https://bad host/?token=a"))
    }
}
