package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.core.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs

enum class AppDestination {
    MAIN,
    SETTINGS,
}

enum class StartupGateState {
    LOADING,
    REQUIRES_NOTIFICATION_DECISION,
    REQUIRES_LIVE_UPDATE_DECISION,
    REQUIRES_CRL_DECISION,
    READY,
}

fun resolveStartupGateState(
    teePrefs: TeeNetworkPrefs?,
    notificationPrefs: ScanNotificationPrefs?,
    notificationPermissionState: ScanNotificationPermissionState,
): StartupGateState {
    return when {
        teePrefs == null || notificationPrefs == null -> StartupGateState.LOADING
        !notificationPrefs.notificationsPrompted &&
                !notificationPermissionState.notificationsGranted -> {
            StartupGateState.REQUIRES_NOTIFICATION_DECISION
        }

        notificationPermissionState.notificationsGranted &&
                notificationPermissionState.liveUpdatesSupported &&
                !notificationPermissionState.liveUpdatesGranted &&
                !notificationPrefs.liveUpdatesPrompted -> {
            StartupGateState.REQUIRES_LIVE_UPDATE_DECISION
        }

        !teePrefs.consentAsked -> StartupGateState.REQUIRES_CRL_DECISION
        else -> StartupGateState.READY
    }
}

fun shouldCreateDetectorViewModels(gateState: StartupGateState): Boolean {
    return gateState == StartupGateState.READY
}
