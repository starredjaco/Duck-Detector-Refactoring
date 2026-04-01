package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Keystore2PrivateBinderClientTest {

    private val client = Keystore2PrivateBinderClient()

    @Test
    fun `request builder keeps alias and interface descriptor`() {
        val request = client.buildGetKeyEntryRequest("duck_alias")

        assertEquals(Keystore2PrivateBinderClient.INTERFACE_DESCRIPTOR, request.interfaceDescriptor)
        assertEquals(Keystore2PrivateBinderClient.TRANSACTION_GET_KEY_ENTRY, request.transactionCode)
        assertEquals("duck_alias", request.alias)
    }

    @Test
    fun `selection parser keeps register timer metadata`() {
        val selection = com.eltavine.duckdetector.features.tee.data.native.TeeRegisterTimerNativeBridge()
            .parseSelection(
                "REGISTER_TIMER_AVAILABLE=1\n" +
                        "TIMER_SOURCE=arm64_cntvct\n" +
                        "AFFINITY=bound_cpu0\n"
            )

        assertTrue(selection.registerTimerAvailable)
        assertEquals("arm64_cntvct", selection.timerSource)
        assertEquals("bound_cpu0", selection.affinityStatus)
        assertNull(selection.fallbackReason)
    }

    @Test
    fun `reply snapshot and failure types keep expected metadata`() {
        val failure = BinderTransactionResult(
            success = false,
            replyFailureReason = "boom",
            throwable = IllegalStateException("boom"),
        )
        val success = BinderTransactionResult(
            success = true,
            replySnapshot = Keystore2ReplySnapshot(
                rawPrefix = "F8 FF FF FF 07 00 00 00",
                exceptionCode = -8,
                secondWord = 7,
                dataSize = 8,
            ),
        )

        assertFalse(failure.success)
        assertNotNull(failure.throwable)
        assertTrue(failure.replyFailureReason!!.contains("boom"))

        assertTrue(success.success)
        val snapshot = success.replySnapshot
        assertNotNull(snapshot)
        snapshot!!
        assertEquals(-8, snapshot.exceptionCode)
        assertEquals(7, snapshot.secondWord)
        assertTrue(snapshot.rawPrefix!!.isNotBlank())
    }

    @Test
    fun `hook result classifier detects java style key not found response`() {
        val snapshot = Keystore2ReplySnapshot(
            rawPrefix = "F8 FF FF FF 07 00 00 00",
            exceptionCode = -8,
            secondWord = 7,
            dataSize = 8,
        )

        val result = classifyKeystore2HookReply(snapshot)

        assertTrue(result.available)
        assertTrue(result.javaHookDetected)
        assertFalse(result.nativeStyleResponse)
        assertEquals(7, result.errorCode)
    }

    @Test
    fun `hook result classifier detects native style response`() {
        val snapshot = Keystore2ReplySnapshot(
            rawPrefix = "F8 FF FF FF FF FF FF FF 00 00 00 00 07 00 00 00",
            exceptionCode = -8,
            secondWord = -1,
            trailingInts = listOf(0, 7),
            dataSize = 16,
        )

        val result = classifyKeystore2HookReply(snapshot)

        assertTrue(result.available)
        assertFalse(result.javaHookDetected)
        assertTrue(result.nativeStyleResponse)
        assertEquals(7, result.errorCode)
    }

    @Test
    fun `positive diff helper is symmetric around threshold`() {
        assertTrue(isPositiveTimingSideChannelDiff(0.3001))
        assertTrue(isPositiveTimingSideChannelDiff(-0.3001))
        assertFalse(isPositiveTimingSideChannelDiff(0.3))
        assertFalse(isPositiveTimingSideChannelDiff(-0.3))
    }
}
