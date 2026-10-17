package app.fieldwatch.domain

import org.junit.Assert.*
import org.junit.Test

class BluetoothToolSessionTest {
    private class Port : BluetoothToolPort {
        var accepted = true
        var closes = 0
        var connects = 0
        var reads = mutableListOf<String>()
        var writes = mutableListOf<ByteArray>()
        var withoutResponse = false
        var mtuRequests = 0
        var subscriptions = 0
        var secure = true
        var uuids = listOf("1101")
        override fun close() { closes++ }
        override fun connectBle(session: Long): Boolean { connects++; return accepted }
        override fun discoverGatt() = accepted
        override fun readCharacteristic(key: String): Boolean { reads += key; return accepted }
        override fun readDescriptor(key: String): Boolean { reads += key; return accepted }
        override fun writeCharacteristic(key: String, bytes: ByteArray, withoutResponse: Boolean): Boolean {
            writes += bytes.copyOf(); this.withoutResponse = withoutResponse; return accepted
        }
        override fun notifications(key: String, enable: Boolean, indicate: Boolean): Boolean { subscriptions++; return accepted }
        override fun requestMtu(): Boolean { mtuRequests++; return accepted }
        override fun cachedUuids() = uuids
        override fun fetchSdp(session: Long) = accepted
        override fun connectRfcomm(session: Long, uuid: String, secure: Boolean): Boolean { connects++; this.secure = secure; return accepted }
        override fun sendRfcomm(session: Long, bytes: ByteArray): Boolean { writes += bytes.copyOf(); return accepted }
    }
    private var elapsed = 0L
    private var wall = 1000L
    private fun session(port: Port, classic: Boolean = false) = BluetoothToolSession(BluetoothToolTarget("AA:BB:CC:00:00:01",
        if (classic) AssessmentTransport.BLUETOOTH_CLASSIC else AssessmentTransport.BLE), port, { wall }, { elapsed })
    private fun service(properties: Int = 0x3E) = GattServiceInfo("s0", BluetoothToolValues.uuid("1800"), true, listOf(
        GattCharacteristicInfo("s0/c0", BluetoothToolValues.uuid("2A00"), properties, listOf(GattDescriptorInfo("s0/c0/d0", BluetoothToolValues.CCCD))),
        GattCharacteristicInfo("s0/c1", BluetoothToolValues.uuid("2A00"), BluetoothToolValues.READ),
    ))
    private fun connected(port: Port = Port()): BluetoothToolSession {
        val session = session(port)
        session.connectBle()
        session.connected(session.state.value.session)
        session.discoverGatt()
        session.gattDiscovered(session.state.value.session, listOf(service()), 0)
        return session
    }

    @Test fun constructionDoesNotConnectOrReadAnything() {
        val port = Port(); val session = session(port)
        assertEquals(0, port.connects); assertTrue(port.reads.isEmpty())
        assertEquals(BluetoothLinkState.DISCONNECTED, session.state.value.link)
        assertTrue(session.state.value.events.isEmpty())
    }

    @Test fun onlyOneOperationCanBeInFlight() {
        val port = Port(); val session = connected(port)
        session.readCharacteristic("s0/c0")
        session.readCharacteristic("s0/c1")
        assertEquals(listOf("s0/c0"), port.reads)
        assertEquals(BluetoothToolOperation.READ_CHARACTERISTIC, session.state.value.pending)
    }

    @Test fun duplicateUuidsUseDistinctAttributeKeysAndWrongCallbacksAreIgnored() {
        val port = Port(); val session = connected(port); val token = session.state.value.session
        session.readCharacteristic("s0/c1")
        session.result(token, BluetoothToolOperation.READ_CHARACTERISTIC, "s0/c0", 0, byteArrayOf(1))
        assertEquals(BluetoothToolOperation.READ_CHARACTERISTIC, session.state.value.pending)
        session.result(token, BluetoothToolOperation.READ_CHARACTERISTIC, "s0/c1", 0, byteArrayOf(2))
        assertEquals("02", session.state.value.values["s0/c1"]?.hex)
        assertNull(session.state.value.values["s0/c0"])
    }

    @Test fun timeoutInvalidatesLateCallbacksAndDoesNotRetry() {
        val port = Port(); val session = connected(port); val old = session.state.value.session
        session.readCharacteristic("s0/c0")
        wall = -100000
        elapsed = 20000
        session.expire()
        assertEquals(BluetoothLinkState.DISCONNECTED, session.state.value.link)
        assertNull(session.state.value.pending)
        session.result(old, BluetoothToolOperation.READ_CHARACTERISTIC, "s0/c0", 0, byteArrayOf(99))
        assertTrue(session.state.value.values.isEmpty())
        assertEquals(1, port.connects)
        assertEquals(old, session.state.value.events.last().session)
    }

    @Test fun remoteAuthenticationFailureIsAnErrorNotAReadValueOrAccessVerdict() {
        val session = connected(); val token = session.state.value.session
        session.readCharacteristic("s0/c0")
        session.result(token, BluetoothToolOperation.READ_CHARACTERISTIC, "s0/c0", 5, byteArrayOf())
        assertTrue(session.state.value.values.isEmpty())
        assertEquals(BluetoothEventKind.ERROR, session.state.value.events.last().kind)
        assertEquals(5, session.state.value.events.last().status)
        assertEquals(BluetoothLinkState.CONNECTED, session.state.value.link)
    }

    @Test fun readOnlyCharacteristicCannotBeWritten() {
        val port = Port(); val session = connected(port)
        session.writeCharacteristic("s0/c1", byteArrayOf(1), false)
        assertTrue(port.writes.isEmpty())
        assertNull(session.state.value.pending)
    }

    @Test fun defaultMtuRejectsOversizedWritesWithoutAutomaticSplitting() {
        val port = Port(); val session = connected(port)
        session.writeCharacteristic("s0/c0", ByteArray(21), false)
        assertTrue(port.writes.isEmpty())
        session.writeCharacteristic("s0/c0", ByteArray(20), false)
        assertEquals(1, port.writes.size)
    }

    @Test fun negotiatedMtuIsUsedAndRepeatedRequestsArePrevented() {
        val port = Port(); val session = connected(port); val token = session.state.value.session
        session.requestMtu()
        session.result(token, BluetoothToolOperation.REQUEST_MTU, null, 0, mtu = 247)
        assertEquals(247, session.state.value.mtu)
        session.requestMtu()
        assertEquals(1, port.mtuRequests)
        session.writeCharacteristic("s0/c0", ByteArray(244), false)
        assertEquals(1, port.writes.size)
    }

    @Test fun writeIntentIsRecordedBeforeTransmissionAndNoResponseIsNotClaimedAsRemoteAck() {
        val port = Port(); val session = connected(port); val token = session.state.value.session
        session.writeCharacteristic("s0/c0", byteArrayOf(0x12, 0x34), true)
        assertTrue(port.withoutResponse)
        assertEquals("1234", session.state.value.events.last().payloadHex)
        assertEquals(BluetoothEventKind.REQUEST, session.state.value.events.last().kind)
        session.result(token, BluetoothToolOperation.WRITE_CHARACTERISTIC, "s0/c0", 0)
        assertTrue(session.state.value.message.contains("no remote write response"))
    }

    @Test fun subscriptionsRequireSuccessfulDescriptorResultAndPreventRediscovery() {
        val session = connected(); val token = session.state.value.session
        session.notifications("s0/c0", true)
        assertTrue(session.state.value.subscribed.isEmpty())
        session.result(token, BluetoothToolOperation.SET_NOTIFICATIONS, "s0/c0", 0)
        assertEquals(setOf("s0/c0"), session.state.value.subscribed)
        session.discoverGatt()
        assertNull(session.state.value.pending)
        session.notifications("s0/c0", false)
        session.result(token, BluetoothToolOperation.SET_NOTIFICATIONS, "s0/c0", 0)
        assertTrue(session.state.value.subscribed.isEmpty())
    }

    @Test fun failedSubscriptionDoesNotMarkCharacteristicSubscribed() {
        val session = connected(); val token = session.state.value.session
        session.notifications("s0/c0", true)
        session.result(token, BluetoothToolOperation.SET_NOTIFICATIONS, "s0/c0", 3)
        assertTrue(session.state.value.subscribed.isEmpty())
    }

    @Test fun ambiguousCccdAndRepeatedEnableDoNotWriteRemoteConfiguration() {
        val port = Port(); val session = connected(port); val token = session.state.value.session
        session.discoverGatt()
        val ambiguous = service().copy(characteristics = service().characteristics.map {
            if (it.key == "s0/c0") it.copy(descriptors = it.descriptors + GattDescriptorInfo("s0/c0/d1", BluetoothToolValues.CCCD)) else it
        })
        session.gattDiscovered(token, listOf(ambiguous), 0)
        session.notifications("s0/c0", true)
        assertEquals(0, port.subscriptions)
        session.discoverGatt()
        session.gattDiscovered(token, listOf(service()), 0)
        session.notifications("s0/c0", true)
        session.result(token, BluetoothToolOperation.SET_NOTIFICATIONS, "s0/c0", 0)
        session.notifications("s0/c0", true)
        assertEquals(1, port.subscriptions)
        assertTrue("s0/c0" in session.state.value.subscribed)
    }

    @Test fun descriptorReadUsesItsOwnHandleAndRetainsReturnedValue() {
        val port = Port(); val session = connected(port); val token = session.state.value.session
        session.readDescriptor("s0/c0/d0")
        session.result(token, BluetoothToolOperation.READ_DESCRIPTOR, "s0/c0/d0", 0, byteArrayOf(1, 0))
        assertEquals(listOf("s0/c0/d0"), port.reads)
        assertEquals("0100", session.state.value.values["s0/c0/d0"]?.hex)
    }

    @Test fun cachedAndRequestedSdpResultsHaveExplicitDifferentSources() {
        val port = Port(); val session = session(port, true)
        session.cachedUuids()
        assertEquals("android-cache", session.state.value.classicUuidSource)
        session.fetchSdp(); val token = session.state.value.session
        session.sdpResult(token, emptyList())
        assertEquals("android-sdp-response-possibly-cached", session.state.value.classicUuidSource)
        assertTrue(session.state.value.message.contains("absence does not prove"))
    }

    @Test fun rfcommModeIsExplicitAndOutputSuccessDoesNotClaimPeerProcessing() {
        val port = Port(); val session = session(port, true)
        session.connectRfcomm("1101", false)
        val token = session.state.value.session
        session.connected(token)
        assertFalse(port.secure)
        session.sendRfcomm(byteArrayOf(1, 2, 3))
        assertEquals(0L, session.state.value.sentBytes)
        session.result(token, BluetoothToolOperation.SEND_RFCOMM, null, 0)
        assertEquals(3L, session.state.value.sentBytes)
        assertTrue(session.state.value.message.contains("peer processing is unverified"))
    }

    @Test fun boundedHistoryAndPayloadLossAreVisible() {
        val session = connected(); val token = session.state.value.session
        repeat(100) { session.incoming(token, true, "s0/c0", ByteArray(1024)) }
        session.notificationLoss(token, 7)
        assertEquals(64, session.state.value.events.size)
        assertTrue(session.state.value.discardedEvents > 0)
        assertEquals(7L, session.state.value.droppedNotifications)
        assertEquals(102400L, session.state.value.receivedBytes)
        val event = session.state.value.events.last()
        assertEquals(1024, event.payloadHex!!.length)
        assertEquals(1024, event.byteCount)
        assertTrue(event.truncated)
    }

    @Test fun disconnectRejectsLateInputAndPreservesHistoryUntilExplicitClear() {
        val session = connected(); val token = session.state.value.session
        session.disconnect()
        val count = session.state.value.events.size
        session.incoming(token, true, "s0/c0", byteArrayOf(1))
        assertEquals(count, session.state.value.events.size)
        session.clearHistory()
        assertTrue(session.state.value.events.isEmpty())
        assertTrue(session.state.value.services.isEmpty())
    }

    @Test fun immediateRefusalClosesSessionWithoutRetries() {
        val port = Port().apply { accepted = false }; val session = session(port)
        session.connectBle()
        assertEquals(BluetoothLinkState.DISCONNECTED, session.state.value.link)
        assertNull(session.state.value.pending)
        assertEquals(1, port.connects)
        assertEquals(BluetoothEventKind.ERROR, session.state.value.events.last().kind)
    }
}
