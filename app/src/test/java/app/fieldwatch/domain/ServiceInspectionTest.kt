package app.fieldwatch.domain

import org.junit.Assert.*
import org.junit.Test

class ServiceInspectionTest {
    private fun rejected(action: () -> Unit) { try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } }
    private fun report() = ServiceInspectionReport(address = "192.168.1.2", port = 80, probe = ServiceProbe.HTTP_HEAD,
        network = "Wi-Fi lab", startedAt = 10, endedAt = 20, outcome = "eof")
    private fun wifi() = WifiSecurityReport(bssid = "AA:BB:CC:DD:EE:01", ssid = "Lab", channel = 6, frequencyMhz = 2437,
        firstSeen = 1, lastSeen = 10, capturedAt = 20, capabilities = "[ESS]", parsedSecurity = null, analysis = WifiSecurityAnalysis.describe("[ESS]"))

    @Test fun invalidEndpointCannotInjectHttpHeadersOrTriggerDns() {
        listOf("lab.local", "192.168.1.2\r\nX: yes", "192.168.1.2/32", "192.168.1.2/path", "127.0.0.1").forEach { address -> rejected { ServiceInspection.request(address, 80) } }
        rejected { ServiceInspection.request("192.168.1.2", 0) }
    }
    @Test fun fingerprintsRequireResponseBytesNotPortGuesses() {
        assertEquals("No application bytes captured", ServiceInspection.identify(""))
        assertEquals("SMTP greeting advertised", ServiceInspection.identify(ServiceInspection.hex("220 Lab SMTP\r\n".toByteArray())))
        assertEquals("FTP greeting advertised", ServiceInspection.identify(ServiceInspection.hex("220 FTP ready\r\n".toByteArray())))
        assertTrue(ServiceInspection.identify(ServiceInspection.hex("custom protocol".toByteArray())).startsWith("Unclassified"))
    }
    @Test fun previewReplacesControlsAndHexPreservesBytes() {
        val bytes = byteArrayOf(0, 27, 65, -1, 10)
        assertArrayEquals(bytes, ServiceInspection.bytes(ServiceInspection.hex(bytes)))
        assertEquals("··A·\n", ServiceInspection.display(ServiceInspection.hex(bytes)))
    }
    @Test fun rejectsForgedRequestAndOversizedResponse() {
        rejected { report().copy(attemptedRequestHex = "474554").validate() }
        rejected { report().copy(receivedHex = "aa".repeat(4097)).validate() }
        rejected { report().copy(receivedHex = "zz").validate() }
        rejected { report().copy(captureLimitReached = true).validate() }
    }
    @Test fun rejectsInconsistentTlsEvidence() {
        rejected { report().copy(tlsProtocol = "TLSv1.3").validate() }
        rejected { report().copy(probe = ServiceProbe.TLS, outcome = "observed").validate() }
        report().copy(probe = ServiceProbe.TLS, outcome = "tls-validation-or-handshake-failed").validate()
    }
    @Test fun wifiPreservesUnknownAndRejectsInventedAnalysis() {
        wifi().validate()
        wifi().copy(capabilities = null, analysis = WifiSecurityAnalysis.describe(null)).validate()
        rejected { wifi().copy(analysis = "Confirmed exploitable").validate() }
    }
    @Test fun wifiRejectsInvalidIdentifiersTimesAndOversizedFlags() {
        rejected { wifi().copy(bssid = "not-a-bssid").validate() }
        rejected { wifi().copy(lastSeen = 0).validate() }
        rejected { wifi().copy(capabilities = "x".repeat(8193)).validate() }
    }
}
