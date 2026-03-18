package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.core.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppShellStateTest {

    @Test
    fun `null prefs stay in loading gate`() {
        val gateState = resolveStartupGateState(
            teePrefs = null,
            notificationPrefs = null,
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = false,
                liveUpdatesSupported = true,
                liveUpdatesGranted = false,
            ),
        )

        assertEquals(StartupGateState.LOADING, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `missing notification permission requires notification decision`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = false,
                liveUpdatesPrompted = false,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = false,
                liveUpdatesSupported = true,
                liveUpdatesGranted = false,
            ),
        )

        assertEquals(StartupGateState.REQUIRES_NOTIFICATION_DECISION, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `missing promoted access requires live update decision`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = true,
                liveUpdatesPrompted = false,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = true,
                liveUpdatesSupported = true,
                liveUpdatesGranted = false,
            ),
        )

        assertEquals(StartupGateState.REQUIRES_LIVE_UPDATE_DECISION, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `unanswered CRL prefs still block after notification onboarding`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = false,
                consentGranted = false,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = true,
                liveUpdatesPrompted = true,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = true,
                liveUpdatesSupported = true,
                liveUpdatesGranted = true,
            ),
        )

        assertEquals(StartupGateState.REQUIRES_CRL_DECISION, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `answered prefs unlock detector creation`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = true,
                liveUpdatesPrompted = true,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = true,
                liveUpdatesSupported = true,
                liveUpdatesGranted = true,
            ),
        )

        assertEquals(StartupGateState.READY, gateState)
        assertTrue(shouldCreateDetectorViewModels(gateState))
    }
}
