package io.github.netwatch.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdaterTest {
    @Test fun newerVersions() {
        assertTrue(Updater.isNewer("1.14.1", "1.14.0"))
        assertTrue(Updater.isNewer("v1.15.0", "1.14.9"))
        assertTrue(Updater.isNewer("2.0.0", "1.14.0"))
        assertTrue(Updater.isNewer("1.14.0", "1.13.12"))
    }

    @Test fun sameOrOlderIsNotNewer() {
        assertFalse(Updater.isNewer("1.14.0", "1.14.0"))
        assertFalse(Updater.isNewer("1.13.9", "1.14.0"))
        assertFalse(Updater.isNewer("v1.14.0", "1.14.0"))
    }

    @Test fun missingOrGarbageIsNotNewer() {
        assertFalse(Updater.isNewer("", "1.14.0"))
        assertFalse(Updater.isNewer("nightly", "1.14.0"))
        assertTrue(Updater.isNewer("1.14.1-beta", "1.14.0"))  // παίρνει το αριθμητικό μέρος
    }
}
