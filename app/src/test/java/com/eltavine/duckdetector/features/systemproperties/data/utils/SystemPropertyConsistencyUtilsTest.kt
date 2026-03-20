package com.eltavine.duckdetector.features.systemproperties.data.utils

import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPropertyConsistencyUtilsTest {

    private val utils = SystemPropertyConsistencyUtils()

    @Test
    fun `callback placeholder is ignored for source mismatch`() {
        val signals = utils.buildSourceMismatchSignals(
            listOf(
                MultiSourcePropertyRead(
                    property = "ro.system.build.fingerprint",
                    category = SystemPropertyCategory.BUILD_FINGERPRINT,
                    preferredValue = "Xiaomi/test/device:16/BUILD/123:user/release-keys",
                    preferredSource = SystemPropertySource.REFLECTION,
                    sourceValues = linkedMapOf(
                        SystemPropertySource.REFLECTION to "Xiaomi/test/device:16/BUILD/123:user/release-keys",
                        SystemPropertySource.GETPROP to "Xiaomi/test/device:16/BUILD/123:user/release-keys",
                        SystemPropertySource.NATIVE_LIBC to "Must use __system_property_read_callback() to read",
                        SystemPropertySource.JVM to "",
                    ),
                ),
            ),
        )

        assertTrue(signals.isEmpty())
    }

    @Test
    fun `real native divergence still produces mismatch`() {
        val signals = utils.buildSourceMismatchSignals(
            listOf(
                MultiSourcePropertyRead(
                    property = "ro.boot.verifiedbootstate",
                    category = SystemPropertyCategory.VERIFIED_BOOT,
                    preferredValue = "green",
                    preferredSource = SystemPropertySource.REFLECTION,
                    sourceValues = linkedMapOf(
                        SystemPropertySource.REFLECTION to "green",
                        SystemPropertySource.GETPROP to "green",
                        SystemPropertySource.NATIVE_LIBC to "orange",
                        SystemPropertySource.JVM to "",
                    ),
                ),
            ),
        )

        assertEquals(1, signals.size)
        assertEquals(SystemPropertySource.REFLECTION, signals.single().source)
    }
}
