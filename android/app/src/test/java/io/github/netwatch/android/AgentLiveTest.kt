package io.github.netwatch.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Απέναντι σε πραγματικό agent (προαιρετικό): NETWATCH_AGENT_URL=https://127.0.0.1:8765/?token=…
 * NETWATCH_AGENT_FP=AB:CD:… ./gradlew testDebugUnitTest. Χωρίς αυτά παραλείπεται.
 */
class AgentLiveTest {
    private val url = System.getenv("NETWATCH_AGENT_URL")
    private val fp = System.getenv("NETWATCH_AGENT_FP")

    @Test fun pinnedStatusWorksAndWrongPinOrTokenFails() {
        assumeTrue(!url.isNullOrBlank() && !fp.isNullOrBlank())
        val p = AgentUrl.parse(url!!)!!
        assertEquals(Fingerprint.normalize(fp!!), AgentClient.peekFingerprint(p.base))
        val st = AgentClient.status(AgentConfig(p.base, p.token, Fingerprint.normalize(fp)!!))
        assertTrue(st.has("high") && st.has("recent"))
        assertFalse(Alerts.level(st) == "idle")
        try {
            AgentClient.status(AgentConfig(p.base, p.token, "00:" + fp.substring(3)))
            fail("άλλο πιστοποιητικό πρέπει να απορρίπτεται")
        } catch (e: AuthException) {
            fail("δεν έπρεπε καν να σταλεί το token")
        } catch (e: java.io.IOException) { /* σωστά: σφάλμα TLS */ }
        try {
            AgentClient.status(AgentConfig(p.base, "wrong-token", Fingerprint.normalize(fp)!!))
            fail("λάθος token πρέπει να απορρίπτεται")
        } catch (e: AuthException) { /* σωστά */ }
    }
}
