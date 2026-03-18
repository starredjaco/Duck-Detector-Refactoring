package com.eltavine.duckdetector.core.notifications

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardOverviewMetricModel
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardOverviewModel
import org.junit.Assert.assertEquals
import org.junit.Test

class ScanProgressNotificationFormatterTest {

    private val formatter = ScanProgressNotificationFormatter()

    @Test
    fun `scanning snapshot uses progress title and dashboard summary`() {
        val model = formatter.format(
            ScanProgressNotificationSnapshot(
                totalDetectorCount = 15,
                readyDetectorCount = 6,
                dashboardOverview = overview(
                    title = "Security overview",
                    headline = "Danger",
                    summary = "Start with Mount and TEE.",
                ),
                scanning = true,
            ),
        )

        assertEquals("Scanning 6/15", model.title)
        assertEquals("Danger · Start with Mount and TEE.", model.text)
        assertEquals("6/15", model.shortCriticalText)
        assertEquals(40, model.progressPercent)
    }

    @Test
    fun `finished snapshot reuses dashboard headline and summary`() {
        val model = formatter.format(
            ScanProgressNotificationSnapshot(
                totalDetectorCount = 15,
                readyDetectorCount = 15,
                dashboardOverview = overview(
                    title = "Scan time 4.2s",
                    headline = "OK",
                    summary = "Use the detector cards below to inspect local evidence in detail.",
                ),
                scanning = false,
            ),
        )

        assertEquals("OK", model.title)
        assertEquals(
            "Use the detector cards below to inspect local evidence in detail.",
            model.text,
        )
        assertEquals("Scan time 4.2s", model.subText)
        assertEquals("OK", model.shortCriticalText)
        assertEquals(100, model.progressPercent)
    }

    private fun overview(
        title: String,
        headline: String,
        summary: String,
    ) = DashboardOverviewModel(
        title = title,
        headline = headline,
        summary = summary,
        status = DetectorStatus.allClear(),
        metrics = listOf(
            DashboardOverviewMetricModel(
                label = "Ready",
                value = "15",
                status = DetectorStatus.allClear(),
            ),
        ),
    )
}
