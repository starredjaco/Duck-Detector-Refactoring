package com.eltavine.duckdetector.features.memory.data.repository

import com.eltavine.duckdetector.features.memory.data.native.MemoryNativeFinding
import com.eltavine.duckdetector.features.memory.data.native.MemoryNativeSnapshot
import com.eltavine.duckdetector.features.memory.domain.MemoryMethodOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MemoryRepositoryTest {

    private val repository = MemoryRepository()

    @Test
    fun `sanitizes benign zygote jit swapped pages`() {
        val snapshot = MemoryNativeSnapshot(
            available = true,
            swappedExec = true,
            findings = listOf(
                MemoryNativeFinding(
                    section = "MAPS",
                    category = "SMAPS",
                    label = "Swapped executable pages",
                    severity = "MEDIUM",
                    detail = "[anon:dalvik-zygote-jit-code-cache] has 16 kB swapped executable pages",
                ),
            ),
        )

        val sanitized = repository.sanitizeSnapshot(snapshot)
        val mapsMethod = repository.buildMethods(sanitized).first { it.label == "maps + smaps" }

        assertFalse(sanitized.swappedExec)
        assertTrue(sanitized.findings.isEmpty())
        assertEquals("Clean", mapsMethod.summary)
        assertEquals(MemoryMethodOutcome.CLEAN, mapsMethod.outcome)
    }

    @Test
    fun `keeps swapped executable finding for non ART mapping`() {
        val snapshot = MemoryNativeSnapshot(
            available = true,
            swappedExec = true,
            findings = listOf(
                MemoryNativeFinding(
                    section = "MAPS",
                    category = "SMAPS",
                    label = "Swapped executable pages",
                    severity = "MEDIUM",
                    detail = "/system/lib64/libc.so has 4 kB swapped executable pages",
                ),
            ),
        )

        val sanitized = repository.sanitizeSnapshot(snapshot)
        val mapsMethod = repository.buildMethods(sanitized).first { it.label == "maps + smaps" }

        assertTrue(sanitized.swappedExec)
        assertEquals(1, sanitized.findings.size)
        assertEquals("Review", mapsMethod.summary)
        assertEquals(MemoryMethodOutcome.REVIEW, mapsMethod.outcome)
    }

    @Test
    fun `sanitizes ashmem zygote jit swapped pages variant`() {
        val finding = MemoryNativeFinding(
            section = "MAPS",
            category = "SMAPS",
            label = "Swapped executable pages",
            severity = "MEDIUM",
            detail = "/dev/ashmem/dalvik-zygote-jit-code-cache has 8 kB swapped executable pages",
        )

        assertTrue(repository.isBenignArtCodeCacheSwapFinding(finding))
    }
}
