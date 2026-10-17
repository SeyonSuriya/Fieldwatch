package app.fieldwatch.domain

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.UUID

@Serializable
data class BluetoothToolTarget(val address: String, val transport: AssessmentTransport) {
    fun validated(): BluetoothToolTarget {
        require(transport == AssessmentTransport.BLE || transport == AssessmentTransport.BLUETOOTH_CLASSIC) { "Select a Bluetooth transport." }
        val normalized = address.trim().uppercase()
        require(Regex("(?:[0-9A-F]{2}:){5}[0-9A-F]{2}").matches(normalized)) { "Invalid Bluetooth address." }
        return copy(address = normalized)
    }
}

@Serializable enum class BluetoothToolOperation {
    CONNECT_BLE, DISCOVER_GATT, READ_CHARACTERISTIC, READ_DESCRIPTOR, WRITE_CHARACTERISTIC,
    SET_NOTIFICATIONS, REQUEST_MTU, FETCH_SDP, CONNECT_RFCOMM, SEND_RFCOMM
}
@Serializable enum class BluetoothLinkState { DISCONNECTED, CONNECTING, CONNECTED }
@Serializable enum class BluetoothEventKind { REQUEST, RESULT, ERROR, NOTIFICATION, RX, TX, INFO }

@Serializable data class GattDescriptorInfo(val key: String, val uuid: String)
@Serializable data class GattCharacteristicInfo(
    val key: String, val uuid: String, val properties: Int,
    val descriptors: List<GattDescriptorInfo> = emptyList(),
)
@Serializable data class GattServiceInfo(val key: String, val uuid: String, val primary: Boolean,
    val characteristics: List<GattCharacteristicInfo> = emptyList())

@Serializable data class BluetoothToolEvent(
    val sequence: Long, val session: Long, val at: Long, val kind: BluetoothEventKind,
    val message: String, val handle: String? = null, val status: Int? = null,
    val payloadHex: String? = null, val byteCount: Int = 0, val truncated: Boolean = false,
)

@Serializable data class GattValue(val hex: String, val byteCount: Int, val truncated: Boolean, val at: Long)

data class BluetoothToolState(
    val target: BluetoothToolTarget,
    val session: Long = 0,
    val link: BluetoothLinkState = BluetoothLinkState.DISCONNECTED,
    val pending: BluetoothToolOperation? = null,
    val message: String = "No connection has been requested.",
    val mtu: Int = 23,
    val mtuRequested: Boolean = false,
    val services: List<GattServiceInfo> = emptyList(),
    val omittedAttributes: Int = 0,
    val values: Map<String, GattValue> = emptyMap(),
    val subscribed: Set<String> = emptySet(),
    val classicUuids: List<String> = emptyList(),
    val classicUuidSource: String? = null,
    val classicUuidReadAt: Long? = null,
    val omittedUuids: Int = 0,
    val events: List<BluetoothToolEvent> = emptyList(),
    val discardedEvents: Long = 0,
    val droppedNotifications: Long = 0,
    val receivedBytes: Long = 0,
    val sentBytes: Long = 0,
)

object BluetoothToolValues {
    const val MAX_BYTES = 512
    const val MAX_EVENTS = 64
    const val READ = 0x02
    const val WRITE_NO_RESPONSE = 0x04
    const val WRITE = 0x08
    const val NOTIFY = 0x10
    const val INDICATE = 0x20
    const val CCCD = "00002902-0000-1000-8000-00805F9B34FB"

    fun bytes(input: String, hex: Boolean): ByteArray {
        val result = if (!hex) input.toByteArray(Charsets.UTF_8) else {
            val value = input.filterNot { it.isWhitespace() || it == ':' }
            require(value.length % 2 == 0 && value.all { it in "0123456789abcdefABCDEF" }) { "Hex must contain complete byte pairs, with optional spaces or colons." }
            require(value.length <= MAX_BYTES * 2) { "Send at most 512 bytes per action." }
            value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }
        require(result.isNotEmpty() && result.size <= MAX_BYTES) { "Send 1–512 bytes per action." }
        return result
    }

    fun uuid(input: String): String {
        val value = input.trim()
        val full = if (Regex("[0-9a-fA-F]{4}").matches(value)) "0000$value-0000-1000-8000-00805F9B34FB" else value
        require(Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").matches(full)) { "Enter a 16-bit service UUID or a complete 128-bit UUID." }
        return UUID.fromString(full).toString().uppercase()
    }

    fun hex(bytes: ByteArray): String {
        val digits = "0123456789ABCDEF"
        val count = minOf(bytes.size, MAX_BYTES)
        val chars = CharArray(count * 2)
        for (index in 0 until count) {
            val value = bytes[index].toInt() and 255
            chars[index * 2] = digits[value ushr 4]
            chars[index * 2 + 1] = digits[value and 15]
        }
        return String(chars)
    }

    fun statusLabel(status: Int): String = when (status) {
        0 -> "success reported"
        2 -> "read not permitted"
        3 -> "write not permitted"
        5 -> "insufficient authentication"
        15 -> "insufficient encryption"
        else -> "see Android status code"
    }
    fun preview(hex: String): String = runCatching {
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray().toString(Charsets.UTF_8)
            .map { if (it.isISOControl() && it != '\n' && it != '\t') '·' else it }.joinToString("")
    }.getOrDefault("")

    fun properties(bits: Int): String = listOf(READ to "read", WRITE to "write with response", WRITE_NO_RESPONSE to "write without response",
        NOTIFY to "notify", INDICATE to "indicate").filter { bits and it.first != 0 }.joinToString { it.second }.ifBlank { "no supported operation declared" }
}

@Serializable data class BluetoothEvidenceReport(
    val format: String = "fieldwatch-bluetooth-session",
    val formatVersion: Int = 1,
    val target: BluetoothToolTarget,
    val capturedAt: Long,
    val link: BluetoothLinkState,
    val pending: BluetoothToolOperation?,
    val services: List<GattServiceInfo>,
    val omittedAttributes: Int,
    val classicUuids: List<String>,
    val classicUuidSource: String?,
    val classicUuidReadAt: Long?,
    val omittedUuids: Int,
    val events: List<BluetoothToolEvent>,
    val omittedEvents: Long,
    val droppedNotifications: Long,
    val receivedBytes: Long,
    val sentBytes: Long,
    val limitation: String = "Operator-requested protocol observations, not a vulnerability or access verdict. UUIDs may be cached. Writes do not prove device state changed. Payload/history limits are explicit; this is not a complete capture.",
)

object BluetoothToolReports {
    private val json = Json { encodeDefaults = true }
    fun report(state: BluetoothToolState, at: Long): String {
        var services = state.services
        var events = state.events
        var uuids = state.classicUuids
        fun attributeCount(list: List<GattServiceInfo>) = list.sumOf { service -> 1 + service.characteristics.sumOf { 1 + it.descriptors.size } }
        while (true) {
            val report = BluetoothEvidenceReport(target = state.target, capturedAt = at, link = state.link, pending = state.pending,
                services = services, omittedAttributes = state.omittedAttributes + attributeCount(state.services) - attributeCount(services),
                classicUuids = uuids, classicUuidSource = state.classicUuidSource, classicUuidReadAt = state.classicUuidReadAt,
                omittedUuids = state.omittedUuids + state.classicUuids.size - uuids.size, events = events,
                omittedEvents = state.discardedEvents + state.events.size - events.size, droppedNotifications = state.droppedNotifications,
                receivedBytes = state.receivedBytes, sentBytes = state.sentBytes)
            val encoded = json.encodeToString(report)
            if (encoded.toByteArray(Charsets.UTF_8).size <= AssessmentRules.MAX_NOTE_BYTES) return encoded
            when {
                events.size > 1 -> events = events.drop(1)
                services.isNotEmpty() -> services = services.dropLast(1)
                uuids.isNotEmpty() -> uuids = uuids.dropLast(1)
                else -> error("Bluetooth report exceeds the evidence limit.")
            }
        }
    }
}
