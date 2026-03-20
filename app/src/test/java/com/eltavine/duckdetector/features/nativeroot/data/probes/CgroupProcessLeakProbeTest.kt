package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeEntry
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativePath
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CgroupProcessLeakProbeTest {

    private val probe = CgroupProcessLeakProbe()

    @Test
    fun `uid mismatch and selective visibility escalate to danger`() {
        val result = probe.evaluate(
            nativeSnapshot = CgroupProcessLeakNativeSnapshot(
                available = true,
                pathCheckCount = 32,
                accessiblePathCount = 1,
                processCount = 1,
                procDeniedCount = 0,
                paths = listOf(
                    CgroupProcessLeakNativePath(
                        path = "/sys/fs/cgroup/uid_0",
                        uid = 0,
                        accessible = true,
                        pidCount = 1,
                    ),
                ),
                entries = listOf(
                    CgroupProcessLeakNativeEntry(
                        uidPath = "/sys/fs/cgroup/uid_0",
                        cgroupUid = 0,
                        pid = 4242,
                        procUid = 2000,
                        comm = "lspd",
                        cmdline = "/system/bin/lspd",
                    ),
                ),
            ),
            javaView = CgroupProcessJavaView(
                checkedPathCount = 32,
                accessiblePaths = emptySet(),
                pidEntriesByPath = emptyMap(),
            ),
        )

        assertEquals(3, result.findings.size)
        assertTrue(
            result.findings.any {
                it.label == "Cgroup UID mismatch" &&
                        it.severity == NativeRootFindingSeverity.DANGER
            },
        )
        assertTrue(
            result.findings.any {
                it.label == "LSPosed companion residue" &&
                        it.severity == NativeRootFindingSeverity.WARNING
            },
        )
        assertTrue(
            result.findings.any {
                it.label == "Selective cgroup visibility" &&
                        it.severity == NativeRootFindingSeverity.DANGER
            },
        )
        assertEquals(3, result.hitCount)
    }

    @Test
    fun `clean snapshot stays clean`() {
        val result = probe.evaluate(
            nativeSnapshot = CgroupProcessLeakNativeSnapshot(
                available = true,
                pathCheckCount = 32,
                accessiblePathCount = 1,
                processCount = 1,
                procDeniedCount = 0,
                paths = listOf(
                    CgroupProcessLeakNativePath(
                        path = "/sys/fs/cgroup/uid_2000",
                        uid = 2000,
                        accessible = true,
                        pidCount = 1,
                    ),
                ),
                entries = listOf(
                    CgroupProcessLeakNativeEntry(
                        uidPath = "/sys/fs/cgroup/uid_2000",
                        cgroupUid = 2000,
                        pid = 5151,
                        procUid = 2000,
                        comm = "app_process64",
                        cmdline = "com.eltavine.duckdetector",
                    ),
                ),
            ),
            javaView = CgroupProcessJavaView(
                checkedPathCount = 32,
                accessiblePaths = setOf("/sys/fs/cgroup/uid_2000"),
                pidEntriesByPath = mapOf("/sys/fs/cgroup/uid_2000" to setOf(5151)),
            ),
        )

        assertTrue(result.available)
        assertTrue(result.findings.isEmpty())
        assertEquals(0, result.hitCount)
    }
}
