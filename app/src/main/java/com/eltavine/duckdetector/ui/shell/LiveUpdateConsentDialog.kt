package com.eltavine.duckdetector.ui.shell

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import com.eltavine.duckdetector.core.ui.components.WrapSafeText

@Composable
fun LiveUpdateConsentDialog(
    onOpenSettings: () -> Unit,
    onUseRegularNotifications: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = {},
        title = {
            WrapSafeText(
                text = "Enable Live Updates?",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        },
        text = {
            WrapSafeText(
                text = "On Android 16 and above, Duck Detector can request promoted ongoing notifications for richer scan-progress updates. If you skip this, scan progress falls back to a regular notification.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        confirmButton = {
            TextButton(onClick = onOpenSettings) {
                WrapSafeText(
                    text = "Open settings",
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onUseRegularNotifications) {
                WrapSafeText(
                    text = "Use regular",
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
    )
}
