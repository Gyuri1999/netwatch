package io.github.netwatch.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FingerprintTest {
    // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    private val abc = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"

    @Test fun sameFormatAsTheAgent() = assertEquals(abc, Fingerprint.of("abc".toByteArray()))

    @Test fun normalizesWhatPeopleCopy() {
        assertEquals(abc, Fingerprint.normalize(abc.lowercase()))
        assertEquals(abc, Fingerprint.normalize("SHA256 Fingerprint=" + abc))
        assertEquals(abc, Fingerprint.normalize(abc.replace(":", " ")))
        assertNull(Fingerprint.normalize("AB:CD"))
    }
}
