package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TimingSideChannelThresholdTest {

    @Test
    fun `diff above 0_3ms is positive`() {
        assertTrue(isPositiveTimingSideChannelDiff(diffMillis = 0.3001))
    }

    @Test
    fun `diff below minus 0_3ms is positive`() {
        assertTrue(isPositiveTimingSideChannelDiff(diffMillis = -0.3001))
    }

    @Test
    fun `diff equal to 0_3ms is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = 0.3))
    }

    @Test
    fun `diff equal to minus 0_3ms is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = -0.3))
    }

    @Test
    fun `diff inside symmetric threshold is not positive`() {
        assertFalse(isPositiveTimingSideChannelDiff(diffMillis = 0.2999))
    }

    private fun isPositiveTimingSideChannelDiff(diffMillis: Double): Boolean {
        return diffMillis > 0.3 || diffMillis < -0.3
    }
}
