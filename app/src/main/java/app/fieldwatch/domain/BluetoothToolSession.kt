package app.fieldwatch.domain

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

class BluetoothToolFailure(message: String, val status: Int? = null) : Exception(message)

interface BluetoothToolPort {
    fun close()
    fun connectBle(session: Long): Boolean
    fun discoverGatt(): Boolean
    fun readCharacteristic(key: String): Boolean
    fun readDescriptor(key: String): Boolean
    fun writeCharacteristic(key: String, bytes: ByteArray, withoutResponse: Boolean): Boolean
    fun notifications(key: String, enable: Boolean, indicate: Boolean): Boolean
    fun requestMtu(): Boolean
    fun cachedUuids(): List<String>
    fun fetchSdp(session: Long): Boolean
    fun connectRfcomm(session: Long, uuid: String, secure: Boolean): Boolean
    fun sendRfcomm(session: Long, bytes: ByteArray): Boolean
}

/** One outstanding command. Timeouts invalidate the session before another command is allowed. */
class BluetoothToolSession(
    target: BluetoothToolTarget,
    private val port: BluetoothToolPort,
    private val now: () -> Long = System::currentTimeMillis,
    private val elapsed: () -> Long = { System.nanoTime() / 1_000_000L },
) {
    private val mutableState = MutableStateFlow(BluetoothToolState(target.validated()))
    val state = mutableState.asStateFlow()
    private var deadline = 0L
    private var pendingKey: String? = null
    private var pendingNotificationEnabled = false
    private var pendingWrite: ByteArray? = null
    private var pendingWithoutResponse = false
    private var sequence = 0L

    fun connectBle() = command {
        require(state.value.target.transport == AssessmentTransport.BLE) { "Select a BLE target." }
        beginConnection(BluetoothToolOperation.CONNECT_BLE)
        accepted(port.connectBle(state.value.session))
    }

    fun connectRfcomm(uuid: String, secure: Boolean) = command {
        require(state.value.target.transport == AssessmentTransport.BLUETOOTH_CLASSIC) { "Select a Classic target." }
        val normalized = BluetoothToolValues.uuid(uuid)
        beginConnection(BluetoothToolOperation.CONNECT_RFCOMM)
        event(BluetoothEventKind.INFO, if (secure) "Authenticated/encrypted RFCOMM requested; Android may ask to pair." else "Insecure RFCOMM requested; pairing may still occur. No automatic secure/insecure fallback.", normalized)
        accepted(port.connectRfcomm(state.value.session, normalized, secure))
    }

    fun discoverGatt() = command {
        requireBle()
        check(state.value.subscribed.isEmpty()) { "Disable active notifications before rediscovering services." }
        begin(BluetoothToolOperation.DISCOVER_GATT)
        accepted(port.discoverGatt())
    }

    fun readCharacteristic(key: String) = command {
        val characteristic = characteristic(key)
        require(characteristic.properties and BluetoothToolValues.READ != 0) { "The characteristic does not declare read support." }
        begin(BluetoothToolOperation.READ_CHARACTERISTIC, key)
        accepted(port.readCharacteristic(key))
    }

    fun readDescriptor(key: String) = command {
        requireBle()
        check(state.value.services.flatMap { it.characteristics }.flatMap { it.descriptors }.any { it.key == key }) { "Descriptor is not in this session's inventory." }
        begin(BluetoothToolOperation.READ_DESCRIPTOR, key)
        accepted(port.readDescriptor(key))
    }

    fun writeCharacteristic(key: String, bytes: ByteArray, withoutResponse: Boolean) = command {
        val characteristic = characteristic(key)
        val property = if (withoutResponse) BluetoothToolValues.WRITE_NO_RESPONSE else BluetoothToolValues.WRITE
        require(characteristic.properties and property != 0) { "The selected write type is not declared by this characteristic." }
        require(bytes.isNotEmpty() && bytes.size <= minOf(512, state.value.mtu - 3)) { "Payload exceeds the current ATT write limit; request MTU or shorten it. No automatic splitting is performed." }
        begin(BluetoothToolOperation.WRITE_CHARACTERISTIC, key)
        pendingWrite = bytes.copyOf()
        pendingWithoutResponse = withoutResponse
        event(BluetoothEventKind.REQUEST, "Characteristic write payload queued; transmission is not yet confirmed.", key, bytes = bytes)
        accepted(port.writeCharacteristic(key, bytes.copyOf(), withoutResponse))
    }

    fun notifications(key: String, enable: Boolean) = command {
        val characteristic = characteristic(key)
        val notify = characteristic.properties and BluetoothToolValues.NOTIFY != 0
        val indicate = characteristic.properties and BluetoothToolValues.INDICATE != 0
        require(notify || indicate) { "This characteristic declares no notification or indication support." }
        require(characteristic.descriptors.count { it.uuid.equals(BluetoothToolValues.CCCD, true) } == 1) { "A unique client configuration descriptor was not discovered." }
        check(enable != (key in state.value.subscribed)) { "The requested subscription state is already confirmed." }
        begin(BluetoothToolOperation.SET_NOTIFICATIONS, key)
        pendingNotificationEnabled = enable
        event(BluetoothEventKind.REQUEST, if (enable) "Enable value-change subscription requested." else "Disable value-change subscription requested.", key)
        accepted(port.notifications(key, enable, !notify && indicate))
    }

    fun requestMtu() = command {
        requireBle()
        check(!state.value.mtuRequested) { "An MTU request was already made in this connection. Reconnect before requesting again." }
        begin(BluetoothToolOperation.REQUEST_MTU)
        mutableState.value = state.value.copy(mtuRequested = true)
        event(BluetoothEventKind.REQUEST, "Request larger MTU (247); Android may negotiate a different size.")
        accepted(port.requestMtu())
    }

    fun cachedUuids() = command {
        requireClassicDisconnected()
        check(state.value.pending == null) { "Wait for the current operation." }
        setUuids(port.cachedUuids(), "android-cache", 0)
    }

    fun fetchSdp() = command {
        requireClassicDisconnected()
        check(state.value.pending == null) { "Wait for the current operation." }
        newSession()
        begin(BluetoothToolOperation.FETCH_SDP)
        accepted(port.fetchSdp(state.value.session))
    }

    fun sendRfcomm(bytes: ByteArray) = command {
        check(state.value.target.transport == AssessmentTransport.BLUETOOTH_CLASSIC && state.value.link == BluetoothLinkState.CONNECTED) { "Connect the RFCOMM service first." }
        require(bytes.isNotEmpty() && bytes.size <= BluetoothToolValues.MAX_BYTES) { "Send 1–512 bytes per action." }
        begin(BluetoothToolOperation.SEND_RFCOMM)
        pendingWrite = bytes.copyOf()
        event(BluetoothEventKind.REQUEST, "RFCOMM payload queued; transmission is not yet confirmed.", bytes = bytes)
        accepted(port.sendRfcomm(state.value.session, bytes.copyOf()))
    }

    fun connected(session: Long) {
        if (!current(session) || state.value.pending !in listOf(BluetoothToolOperation.CONNECT_BLE, BluetoothToolOperation.CONNECT_RFCOMM)) return
        complete()
        mutableState.value = state.value.copy(link = BluetoothLinkState.CONNECTED, message = "Connected. No vulnerability or unrestricted access is implied.")
        event(BluetoothEventKind.RESULT, "Transport connection established.")
    }

    fun gattDiscovered(session: Long, services: List<GattServiceInfo>, omitted: Int) {
        if (!matches(session, BluetoothToolOperation.DISCOVER_GATT, null)) return
        complete()
        mutableState.value = state.value.copy(services = services, omittedAttributes = omitted, values = emptyMap(), message = "GATT inventory received. Properties do not establish authentication requirements.")
        event(BluetoothEventKind.RESULT, "Discovered ${services.size} services; $omitted attributes omitted by inventory limits.")
    }

    fun result(session: Long, operation: BluetoothToolOperation, key: String?, status: Int, bytes: ByteArray? = null, mtu: Int? = null) {
        if (!matches(session, operation, key)) return
        val requested = pendingWrite
        val noResponse = pendingWithoutResponse
        val enabled = pendingNotificationEnabled
        complete()
        if (status == 0) {
            when (operation) {
                BluetoothToolOperation.REQUEST_MTU -> if (mtu != null && mtu in 23..517) mutableState.value = state.value.copy(mtu = mtu)
                BluetoothToolOperation.SET_NOTIFICATIONS -> if (key != null) mutableState.value = state.value.copy(subscribed =
                    if (enabled) state.value.subscribed + key else state.value.subscribed - key)
                BluetoothToolOperation.READ_CHARACTERISTIC, BluetoothToolOperation.READ_DESCRIPTOR -> if (key != null && bytes != null) {
                    mutableState.value = state.value.copy(values = state.value.values + (key to value(bytes)), receivedBytes = state.value.receivedBytes + bytes.size)
                }
                BluetoothToolOperation.SEND_RFCOMM -> mutableState.value = state.value.copy(sentBytes = state.value.sentBytes + (requested?.size ?: 0))
                else -> Unit
            }
        }
        val description = if (status != 0) "${operation.name}: Android status $status (${BluetoothToolValues.statusLabel(status)}); no success inferred."
            else if (operation == BluetoothToolOperation.WRITE_CHARACTERISTIC && noResponse) "Write callback completed; no remote write response was requested. Device state change is unverified."
            else if (operation == BluetoothToolOperation.WRITE_CHARACTERISTIC) "Write response received. Application-level effects are unverified."
            else if (operation == BluetoothToolOperation.SEND_RFCOMM) "Bytes written to the RFCOMM output stream; peer processing is unverified."
            else "${operation.name} completed with Android status 0."
        mutableState.value = state.value.copy(message = description)
        event(if (status != 0) BluetoothEventKind.ERROR else if (operation == BluetoothToolOperation.SEND_RFCOMM) BluetoothEventKind.TX else BluetoothEventKind.RESULT,
            description, key, status, bytes ?: requested)
    }

    fun sdpResult(session: Long, uuids: List<String>) {
        if (!matches(session, BluetoothToolOperation.FETCH_SDP, null)) return
        complete()
        setUuids(uuids, "android-sdp-response-possibly-cached", 0)
    }

    fun incoming(session: Long, notification: Boolean, key: String?, bytes: ByteArray, originalBytes: Int = bytes.size) {
        if (!current(session) || state.value.link != BluetoothLinkState.CONNECTED) return
        if (notification && state.value.services.flatMap { it.characteristics }.none { it.key == key }) return
        mutableState.value = state.value.copy(receivedBytes = state.value.receivedBytes + originalBytes.coerceAtLeast(bytes.size))
        event(if (notification) BluetoothEventKind.NOTIFICATION else BluetoothEventKind.RX,
            if (notification) "GATT value change reported." else "RFCOMM bytes received.", key, bytes = bytes, originalBytes = originalBytes)
    }

    fun notificationLoss(session: Long, count: Long) {
        if (current(session) && count > 0) mutableState.value = state.value.copy(droppedNotifications = state.value.droppedNotifications + count)
    }

    fun transportFailure(session: Long, message: String, status: Int? = null) {
        if (!current(session)) return
        invalidate()
        mutableState.value = state.value.copy(message = message)
        event(BluetoothEventKind.ERROR, message, status = status, session = session)
    }

    fun disconnect(message: String = "Disconnected by operator.") {
        val session = state.value.session
        val active = state.value.link != BluetoothLinkState.DISCONNECTED || state.value.pending != null
        invalidate()
        if (active) { mutableState.value = state.value.copy(message = message); event(BluetoothEventKind.INFO, message, session = session) }
    }

    fun expire() {
        if (state.value.pending != null && elapsed() >= deadline) {
            val operation = state.value.pending!!
            val session = state.value.session
            invalidate()
            val message = "$operation timed out. Session closed; remote side effects may already have occurred. No automatic retry."
            mutableState.value = state.value.copy(message = message)
            event(BluetoothEventKind.ERROR, message, session = session)
        }
    }

    fun clearHistory() {
        check(state.value.pending == null && state.value.link == BluetoothLinkState.DISCONNECTED) { "Disconnect before clearing session history." }
        mutableState.value = BluetoothToolState(state.value.target, session = state.value.session)
    }

    private fun beginConnection(operation: BluetoothToolOperation) {
        check(state.value.link == BluetoothLinkState.DISCONNECTED && state.value.pending == null) { "Disconnect or finish the current operation first." }
        newSession()
        mutableState.value = state.value.copy(link = BluetoothLinkState.CONNECTING, services = emptyList(), values = emptyMap(), subscribed = emptySet(), mtu = 23, mtuRequested = false, omittedAttributes = 0)
        begin(operation)
    }
    private fun begin(operation: BluetoothToolOperation, key: String? = null) {
        check(state.value.pending == null) { "Wait for the current operation." }
        pendingKey = key
        pendingWrite = null
        pendingWithoutResponse = false
        deadline = elapsed() + 20_000L
        mutableState.value = state.value.copy(pending = operation, message = "$operation requested.")
        event(BluetoothEventKind.REQUEST, "$operation requested.", key)
    }
    private fun complete() { pendingKey = null; pendingWrite = null; mutableState.value = state.value.copy(pending = null) }
    private fun newSession() { mutableState.value = state.value.copy(session = state.value.session + 1); runCatching { port.close() } }
    private fun invalidate() {
        newSession()
        complete()
        mutableState.value = state.value.copy(link = BluetoothLinkState.DISCONNECTED, subscribed = emptySet())
    }
    private fun current(session: Long) = state.value.session == session
    private fun matches(session: Long, operation: BluetoothToolOperation, key: String?) = current(session) && state.value.pending == operation && pendingKey == key
    private fun requireBle() { check(state.value.target.transport == AssessmentTransport.BLE && state.value.link == BluetoothLinkState.CONNECTED) { "Connect the BLE target first." } }
    private fun requireClassicDisconnected() { check(state.value.target.transport == AssessmentTransport.BLUETOOTH_CLASSIC && state.value.link == BluetoothLinkState.DISCONNECTED) { "Use service discovery while the Classic terminal is disconnected." } }
    private fun characteristic(key: String): GattCharacteristicInfo {
        requireBle()
        return state.value.services.flatMap { it.characteristics }.singleOrNull { it.key == key } ?: error("Characteristic is not in this session's inventory.")
    }
    private fun accepted(result: Boolean) { if (!result) throw BluetoothToolFailure("Android rejected the operation before a result was available.") }
    private fun setUuids(raw: List<String>, source: String, omitted: Int) {
        val normalized = raw.mapNotNull { runCatching { BluetoothToolValues.uuid(it) }.getOrNull() }.distinct().sorted()
        mutableState.value = state.value.copy(classicUuids = normalized.take(128), classicUuidSource = source, classicUuidReadAt = now(),
            omittedUuids = omitted + (normalized.size - 128).coerceAtLeast(0), message = "Android reported ${normalized.size} service UUIDs. Results may be cached; absence does not prove no services exist.")
        event(BluetoothEventKind.RESULT, "Service UUIDs read from $source; ${normalized.size} UUIDs reported.")
    }
    private fun value(bytes: ByteArray) = GattValue(BluetoothToolValues.hex(bytes), bytes.size, bytes.size > BluetoothToolValues.MAX_BYTES, now())
    private fun event(kind: BluetoothEventKind, message: String, handle: String? = null, status: Int? = null, bytes: ByteArray? = null, originalBytes: Int = bytes?.size ?: 0, session: Long = state.value.session) {
        val event = BluetoothToolEvent(++sequence, session, now(), kind, message.take(300), handle, status,
            bytes?.let(BluetoothToolValues::hex), originalBytes, originalBytes > BluetoothToolValues.MAX_BYTES)
        val events = state.value.events + event
        mutableState.value = state.value.copy(events = events.takeLast(BluetoothToolValues.MAX_EVENTS),
            discardedEvents = state.value.discardedEvents + (events.size - BluetoothToolValues.MAX_EVENTS).coerceAtLeast(0))
    }
    private inline fun command(block: () -> Unit) {
        try { block() }
        catch (e: BluetoothToolFailure) { val session = state.value.session; invalidate(); mutableState.value = state.value.copy(message = e.message.orEmpty()); event(BluetoothEventKind.ERROR, e.message.orEmpty(), status = e.status, session = session) }
        catch (e: IllegalArgumentException) { mutableState.value = state.value.copy(message = e.message.orEmpty()); event(BluetoothEventKind.ERROR, e.message.orEmpty()) }
        catch (e: IllegalStateException) { mutableState.value = state.value.copy(message = e.message.orEmpty()); event(BluetoothEventKind.ERROR, e.message.orEmpty()) }
        catch (_: Exception) { val session = state.value.session; invalidate(); mutableState.value = state.value.copy(message = "Bluetooth operation failed. Check permissions and the target."); event(BluetoothEventKind.ERROR, state.value.message, session = session) }
    }
}
