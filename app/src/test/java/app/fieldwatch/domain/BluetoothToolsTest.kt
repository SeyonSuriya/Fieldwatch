package app.fieldwatch.domain

import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class BluetoothToolsTest {
    @Test fun hexParsingIsStrictAndPreservesExactBytes() {
        assertArrayEquals(byteArrayOf(0, 0x12, 0x7F, 0xFF.toByte()), BluetoothToolValues.bytes("00:12 7f ff", true))
        listOf("", "1", "00zz", "0x12", "12-34").forEach { input ->
            assertThrows(IllegalArgumentException::class.java) { BluetoothToolValues.bytes(input, true) }
        }
    }

    @Test fun textLimitUsesUtf8BytesRatherThanCharacters() {
        assertArrayEquals("hello\r\n".toByteArray(), BluetoothToolValues.bytes("hello\r\n", false))
        assertThrows(IllegalArgumentException::class.java) { BluetoothToolValues.bytes("界".repeat(200), false) }
        assertEquals(512, BluetoothToolValues.bytes("FF".repeat(512), true).size)
        assertThrows(IllegalArgumentException::class.java) { BluetoothToolValues.bytes("FF".repeat(513), true) }
    }

    @Test fun uuidParsingAcceptsBluetoothAliasesButRejectsLenientJavaForms() {
        assertEquals("00001101-0000-1000-8000-00805F9B34FB", BluetoothToolValues.uuid("1101"))
        assertEquals("12345678-1234-1234-1234-123456789ABC", BluetoothToolValues.uuid("12345678-1234-1234-1234-123456789abc"))
        assertThrows(IllegalArgumentException::class.java) { BluetoothToolValues.uuid("1-1-1-1-1") }
    }

    @Test fun unsupportedTransportAndInvalidAddressAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { BluetoothToolTarget("AA:BB:CC:00:00:01", AssessmentTransport.WIFI).validated() }
        assertThrows(IllegalArgumentException::class.java) { BluetoothToolTarget("invalid", AssessmentTransport.BLE).validated() }
    }

    @Test fun reportFitsEvidenceLimitAndExplicitlyCountsOmittedHistory() {
        val target = BluetoothToolTarget("AA:BB:CC:00:00:01", AssessmentTransport.BLE)
        val events = (1..64).map { BluetoothToolEvent(it.toLong(), 1, 1000, BluetoothEventKind.RX,
            "Received bytes", payloadHex = "FF".repeat(512), byteCount = 512) }
        val services = (0..31).map { service -> GattServiceInfo("s$service", BluetoothToolValues.uuid("1800"), true,
            (0..3).map { characteristic -> GattCharacteristicInfo("s$service/c$characteristic", BluetoothToolValues.uuid("2A00"), 2,
                listOf(GattDescriptorInfo("s$service/c$characteristic/d0", BluetoothToolValues.CCCD))) }) }
        val state = BluetoothToolState(target, services = services, events = events, discardedEvents = 20, droppedNotifications = 3)
        val encoded = BluetoothToolReports.report(state, 2000)
        assertTrue(encoded.toByteArray().size <= AssessmentRules.MAX_NOTE_BYTES)
        val parsed = Json.decodeFromString<BluetoothEvidenceReport>(encoded)
        assertTrue(parsed.omittedEvents > 20)
        assertEquals(target, parsed.target)
        assertEquals(3L, parsed.droppedNotifications)
        assertTrue(parsed.limitation.contains("not a vulnerability"))
    }

    @Test fun reportKeepsDistinctObservationAndCaptureTimes() {
        val target = BluetoothToolTarget("AA:BB:CC:00:00:01", AssessmentTransport.BLUETOOTH_CLASSIC)
        val state = BluetoothToolState(target, classicUuids = listOf(BluetoothToolValues.uuid("1101")),
            classicUuidSource = "android-cache", classicUuidReadAt = 1000)
        val report = Json.decodeFromString<BluetoothEvidenceReport>(BluetoothToolReports.report(state, 3000))
        assertEquals(1000L, report.classicUuidReadAt)
        assertEquals(3000L, report.capturedAt)
        assertEquals("android-cache", report.classicUuidSource)
    }
}
