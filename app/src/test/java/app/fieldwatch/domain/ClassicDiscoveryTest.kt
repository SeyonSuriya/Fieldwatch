package app.fieldwatch.domain

import org.junit.Assert.*
import org.junit.Test

class ClassicDiscoveryTest {
    private class Port : ClassicDiscoveryPort {
        var problem: String? = null
        var discovering = false
        var allowStart = true
        var allowCancel = true
        var denyReads = false
        var starts = 0
        var cancels = 0
        var paired = emptyList<InventoryRadio>()
        override fun unavailableReason() = problem
        override fun isDiscovering() = discovering
        override fun startDiscovery(): Boolean { starts++; if (allowStart) discovering = true; return allowStart }
        override fun cancelDiscovery(): Boolean { cancels++; if (allowCancel) discovering = false; return allowCancel }
        override fun pairedDevices(): List<InventoryRadio> {
            if (denyReads) throw SecurityException()
            return paired
        }
    }
    private var wall = 1000L
    private var monotonic = 0L
    private fun controller(port: Port) = ClassicDiscovery(port, now = { wall }, elapsed = { monotonic })
    private fun found() = InventoryRadio("AA:BB:CC:00:00:01", "Speaker", AssessmentTransport.BLUETOOTH_CLASSIC,
        InventorySource.CLASSIC_INQUIRY, firstSeen = 1000, lastSeen = 1000, rssi = -50)

    @Test fun noInquiryOrPairingBeginsWhenScreenActivates() {
        val port = Port()
        val controller = controller(port)
        controller.activate()
        assertEquals(0, port.starts)
        assertEquals(0, port.cancels)
        assertFalse(controller.state.value.ownsInquiry)
        assertEquals(1000L, controller.state.value.pairedReadAt)
    }

    @Test fun externalInquiryIsNotAdoptedOrCancelled() {
        val port = Port().apply { discovering = true }
        val controller = controller(port)
        controller.activate(); controller.start(); controller.deactivate()
        assertEquals(0, port.starts)
        assertEquals(0, port.cancels)
        assertFalse(controller.state.value.ownsInquiry)
        assertEquals(ClassicInquiryStatus.BLOCKED, controller.state.value.status)
    }

    @Test fun refusedStartDoesNotClaimScanningOrRetryAutomatically() {
        val port = Port().apply { allowStart = false }
        val controller = controller(port)
        controller.activate(); controller.start(); controller.expire(); controller.deactivate()
        assertEquals(1, port.starts)
        assertEquals(0, port.cancels)
        assertFalse(controller.state.value.ownsInquiry)
        assertEquals(ClassicInquiryStatus.BLOCKED, controller.state.value.status)
    }

    @Test fun successfulCycleCollectsOnlyWhileOwnedAndFinishesWithoutRetry() {
        val port = Port()
        val controller = controller(port)
        controller.activate(); controller.onFound(found())
        assertTrue(controller.state.value.radios.isEmpty())
        controller.start(); controller.onStarted(); controller.onFound(found()); controller.onFinished()
        controller.onFound(found().copy(identifier = "AA:BB:CC:00:00:02"))
        assertEquals(1, controller.state.value.radios.size)
        assertEquals(1, port.starts)
        assertEquals(ClassicInquiryStatus.FINISHED, controller.state.value.status)
        assertFalse(controller.state.value.ownsInquiry)
    }

    @Test fun timeoutUsesMonotonicTimeEvenIfWallClockMovesBackwards() {
        val port = Port()
        val controller = controller(port)
        controller.activate(); controller.start()
        wall = -100000
        monotonic = 29999
        controller.expire()
        assertTrue(controller.state.value.ownsInquiry)
        monotonic = 30000
        controller.expire()
        assertEquals(1, port.cancels)
        assertEquals(ClassicInquiryStatus.TIMED_OUT, controller.state.value.status)
        assertFalse(controller.state.value.ownsInquiry)
    }

    @Test fun leavingScreenCancelsOwnedInquiryAndIgnoresLateEvents() {
        val port = Port()
        val controller = controller(port)
        controller.activate(); controller.start(); controller.deactivate(); controller.onFound(found()); controller.onStarted()
        assertEquals(1, port.cancels)
        assertTrue(controller.state.value.radios.isEmpty())
        assertFalse(controller.state.value.ownsInquiry)
        controller.deactivate()
        assertEquals(1, port.cancels)
    }

    @Test fun unavailablePermissionsBlockStartAndCanRecoverWithoutAutostart() {
        val port = Port().apply { problem = "Permission missing" }
        val controller = controller(port)
        controller.activate(); controller.start()
        assertEquals(0, port.starts)
        assertEquals(ClassicInquiryStatus.BLOCKED, controller.state.value.status)
        port.problem = null
        controller.refreshPaired()
        assertEquals(ClassicInquiryStatus.IDLE, controller.state.value.status)
        assertEquals(0, port.starts)
    }

    @Test fun pairingReadFailureDoesNotWipeExistingObservations() {
        val port = Port()
        val controller = controller(port)
        controller.activate(); controller.start(); controller.onFound(found()); controller.onFinished()
        port.denyReads = true
        controller.refreshPaired()
        assertEquals(1, controller.state.value.radios.size)
        assertEquals(ClassicInquiryStatus.BLOCKED, controller.state.value.status)
    }

    @Test fun cancellationFailureIsReportedWithoutClaimingRadioStopped() {
        val port = Port().apply { allowCancel = false }
        val controller = controller(port)
        controller.activate(); controller.start(); controller.stop()
        assertFalse(controller.state.value.ownsInquiry)
        assertTrue(controller.state.value.message.contains("did not confirm cancellation"))
        assertTrue(port.discovering)
    }

    @Test fun duplicateStartAndStopAreIdempotent() {
        val port = Port()
        val controller = controller(port)
        controller.activate(); controller.start(); controller.start(); controller.stop(); controller.stop()
        assertEquals(1, port.starts)
        assertEquals(1, port.cancels)
    }

    @Test fun invalidEventsAreCountedOnlyDuringAnOwnedCycle() {
        val port = Port()
        val controller = controller(port)
        controller.activate(); controller.onMalformedObservation()
        assertEquals(0, controller.state.value.rejected)
        controller.start(); controller.onMalformedObservation(); controller.onFound(found().copy(identifier = "invalid"))
        assertEquals(2, controller.state.value.rejected)
        assertTrue(controller.state.value.radios.isEmpty())
    }

    @Test fun clearDoesNotInterruptRunningInquiryOrDeletePairedInventory() {
        val port = Port().apply { paired = listOf(InventoryRadio("AA:BB:CC:00:00:02", "Paired", AssessmentTransport.BLE,
            InventorySource.BONDED_RECORD, paired = true)) }
        val controller = controller(port)
        controller.activate(); controller.start(); controller.onFound(found()); controller.clear()
        assertEquals(2, controller.state.value.radios.size)
        controller.stop(); controller.clear()
        assertEquals(1, controller.state.value.radios.size)
        assertEquals(AssessmentTransport.BLE, controller.state.value.radios.single().transport)
        assertNull(controller.state.value.radios.single().lastSeen)
    }
}
