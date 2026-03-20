package com.eltavine.duckdetector.features.tee.data.verification.strongbox

import com.eltavine.duckdetector.features.tee.domain.TeeTier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StrongBoxProbeTest {

    @Test
    fun `pixel profile uses 128 concurrent signing handle threshold`() {
        assertEquals(
            128,
            expectedConcurrentSigningHandleLimit(
                brand = "google",
                manufacturer = "Google",
                model = "Pixel 9 Pro",
            ),
        )
    }

    @Test
    fun `non pixel profile keeps 16 concurrent signing handle threshold`() {
        assertEquals(
            16,
            expectedConcurrentSigningHandleLimit(
                brand = "samsung",
                manufacturer = "samsung",
                model = "SM-S9280",
            ),
        )
    }

    @Test
    fun `pixel device profile requires pixel model plus google brand or manufacturer`() {
        assertTrue(isPixelDeviceProfile("google", "Google", "Pixel 8"))
        assertTrue(isPixelDeviceProfile("android", "Google", "Pixel Fold"))
        assertFalse(isPixelDeviceProfile("google", "Google", "PixelExperience"))
        assertFalse(isPixelDeviceProfile("google", "xiaomi", "MIX 4"))
    }

    @Test
    fun `unknown strongbox attestation tier is downgraded to warning`() {
        val assessment = assessStrongBoxAttestation(
            available = true,
            attestationTier = TeeTier.UNKNOWN,
        )

        assertNull(assessment.hardFailure)
        assertEquals(
            "StrongBox key generation succeeded, but dedicated attestation did not expose a tier.",
            assessment.warning,
        )
    }

    @Test
    fun `non strongbox attestation tier still counts as hard failure`() {
        val assessment = assessStrongBoxAttestation(
            available = true,
            attestationTier = TeeTier.TEE,
        )

        assertEquals(
            "StrongBox key generation succeeded, but attestation tier came back as TEE.",
            assessment.hardFailure,
        )
        assertNull(assessment.warning)
    }

    @Test
    fun `attestation claiming strongbox without keyinfo confirmation stays a hard failure`() {
        val assessment = assessStrongBoxAttestation(
            available = false,
            attestationTier = TeeTier.STRONGBOX,
        )

        assertEquals(
            "Attestation claimed StrongBox, but local KeyInfo could not confirm a StrongBox key.",
            assessment.hardFailure,
        )
        assertNull(assessment.warning)
    }
}
