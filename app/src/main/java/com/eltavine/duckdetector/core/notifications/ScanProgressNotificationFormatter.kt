package com.eltavine.duckdetector.core.notifications

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardOverviewModel
import kotlin.math.roundToInt

data class ScanProgressNotificationSnapshot(
    val totalDetectorCount: Int,
    val readyDetectorCount: Int,
    val dashboardOverview: DashboardOverviewModel,
    val scanning: Boolean,
)

data class ScanProgressNotificationModel(
    val title: String,
    val text: String,
    val subText: String?,
    val shortCriticalText: String?,
    val progressPercent: Int,
)

class ScanProgressNotificationFormatter {

    fun format(snapshot: ScanProgressNotificationSnapshot): ScanProgressNotificationModel {
        val clampedTotal = snapshot.totalDetectorCount.coerceAtLeast(1)
        val clampedReady = snapshot.readyDetectorCount.coerceIn(0, clampedTotal)
        val progressPercent = ((clampedReady * 100f) / clampedTotal)
            .roundToInt()
            .coerceIn(0, 100)
        val overview = snapshot.dashboardOverview
        return if (snapshot.scanning) {
            ScanProgressNotificationModel(
                title = "Scanning $clampedReady/$clampedTotal",
                text = "${overview.headline} \u00b7 ${overview.summary}",
                subText = "Duck Detector",
                shortCriticalText = "$clampedReady/$clampedTotal",
                progressPercent = progressPercent,
            )
        } else {
            ScanProgressNotificationModel(
                title = overview.headline,
                text = overview.summary,
                subText = overview.title.takeIf { it.isNotBlank() && it != "Security overview" },
                shortCriticalText = shortCriticalTextFor(overview.headline),
                progressPercent = progressPercent,
            )
        }
    }

    private fun shortCriticalTextFor(
        headline: String,
    ): String? {
        return when (headline) {
            "Danger",
            "Warning",
            "Info",
            "OK" -> headline

            else -> null
        }
    }
}
