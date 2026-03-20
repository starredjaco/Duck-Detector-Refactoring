package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodOutcome
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootMethodResult
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRootCardModelMapperTest {

    private val mapper = NativeRootCardModelMapper()

    @Test
    fun `cgroup leakage contributes method and scan rows`() {
        val report = NativeRootReport(
            stage = NativeRootStage.READY,
            findings = listOf(
                NativeRootFinding(
                    id = "cgroup_visibility_4242",
                    label = "Selective cgroup visibility",
                    value = "PID 4242",
                    detail = "Java File view missed a PID that native getdents exposed.",
                    group = NativeRootGroup.PROCESS,
                    severity = NativeRootFindingSeverity.DANGER,
                ),
            ),
            kernelSuDetected = false,
            aPatchDetected = false,
            magiskDetected = false,
            susfsDetected = false,
            kernelSuVersion = 0L,
            nativeAvailable = true,
            prctlProbeHit = false,
            susfsProbeHit = false,
            pathHitCount = 0,
            pathCheckCount = 12,
            processHitCount = 0,
            processCheckedCount = 4,
            processDeniedCount = 1,
            cgroupAvailable = true,
            cgroupPathCheckCount = 32,
            cgroupAccessiblePathCount = 2,
            cgroupProcessCheckedCount = 3,
            cgroupProcDeniedCount = 1,
            cgroupHitCount = 1,
            kernelHitCount = 0,
            kernelSourceCount = 3,
            propertyHitCount = 0,
            propertyCheckCount = 5,
            methods = listOf(
                NativeRootMethodResult(
                    label = "cgroupLeakage",
                    summary = "1 hit(s)",
                    outcome = NativeRootMethodOutcome.DETECTED,
                    detail = "Enumerate per-UID cgroup trees and compare native vs Java visibility.",
                ),
            ),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.subtitle.contains("cgroup", ignoreCase = true))
        assertTrue(model.methodRows.any { it.label == "cgroupLeakage" && it.value == "1 hit(s)" })
        assertEquals("32", model.scanRows.single { it.label == "Cgroup paths" }.value)
        assertEquals("1", model.scanRows.single { it.label == "Cgroup hits" }.value)
        assertTrue(model.runtimeRows.any { it.label == "Selective cgroup visibility" })
    }
}
