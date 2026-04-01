package com.eltavine.duckdetector.features.tee.data.native

data class TeeRegisterTimerSelection(
    val registerTimerAvailable: Boolean = false,
    val timerSource: String = "clock_monotonic",
    val fallbackReason: String? = null,
    val affinityStatus: String = "not_requested",
)
