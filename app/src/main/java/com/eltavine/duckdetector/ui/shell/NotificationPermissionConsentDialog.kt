package com.eltavine.duckdetector.ui.shell

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import com.eltavine.duckdetector.core.ui.components.WrapSafeText

@Composable
fun NotificationPermissionConsentDialog(
    onAllowNotifications: () -> Unit,
    onSkipNotifications: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = {},
        title = {
            WrapSafeText(
                text = "Allow scan notifications?",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        },
        text = {
            WrapSafeText(
                text = "Duck Detector can publish a scan-progress notification while detector cards collect evidence. Startup scanning waits for this choice.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        confirmButton = {
            TextButton(onClick = onAllowNotifications) {
                WrapSafeText(
                    text = "Allow notifications",
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onSkipNotifications) {
                WrapSafeText(
                    text = "Skip",
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
    )
}
