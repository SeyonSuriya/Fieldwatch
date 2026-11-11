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
    @Test fun advertisedLabelsRequireUnambiguousHeadersOrPrintableBanners() {
        val base = report()
        val http = base.copy(attemptedRequestHex = ServiceInspection.hex(ServiceInspection.request(base.address, base.port)))
        fun hex(text: String) = ServiceInspection.hex(text.toByteArray(Charsets.ISO_8859_1))
        assertEquals("LabServer/1", ServiceInspection.advertisedLabel(http.copy(receivedHex =
            hex("HTTP/1.1 200 OK\r\nServer: LabServer/1\r\n\r\n"))))
        assertNull(ServiceInspection.advertisedLabel(http.copy(receivedHex =
            hex("HTTP/1.1 200 OK\r\nServer: One\r\nServer: Two\r\n\r\n"))))
        val banner = base.copy(probe = ServiceProbe.BANNER, outcome = "observed")
        assertEquals("SSH-2.0-OpenSSH_9.6", ServiceInspection.advertisedLabel(banner.copy(receivedHex = hex("SSH-2.0-OpenSSH_9.6\r\n"))))
        assertNull(ServiceInspection.advertisedLabel(banner.copy(receivedHex = hex("incomplete"))))
        assertNull(ServiceInspection.advertisedLabel(banner.copy(receivedHex = hex("\u0000binary\n"))))
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

    @Test fun certificateDetailsRequireVerifiedTlsAndAnOrderedValidityPeriod() {
        val details = TlsCertificateDetails("CN=Lab issuer", 1, 30)
        val verified = report().copy(probe = ServiceProbe.TLS, outcome = "observed", tlsProtocol = "TLSv1.3",
            tlsCipher = "TLS_AES_128_GCM_SHA256", certificateSha256 = "a".repeat(64), certificateDetails = details)
        verified.validate()
        rejected { report().copy(certificateDetails = details).validate() }
        rejected { verified.copy(outcome = "tls-validation-or-handshake-failed").validate() }
        rejected { verified.copy(certificateDetails = details.copy(notAfter = 0)).validate() }
        rejected { verified.copy(certificateDetails = details.copy(issuer = "CN=Lab\nIssuer")).validate() }
    }

    @Test fun certificateValidityDistinguishesExpiryAndTheThirtyDayBoundary() {
        val day = 86_400_000L
        val certificate = TlsCertificateDetails("CN=Lab issuer", day, 90 * day)
        assertEquals(TlsCertificateValidity.NOT_YET_VALID, certificate.validityAt(day - 1))
        assertEquals(TlsCertificateValidity.VALID, certificate.validityAt(60 * day - 1))
        assertEquals(TlsCertificateValidity.EXPIRING_SOON, certificate.validityAt(60 * day))
        assertEquals(TlsCertificateValidity.EXPIRING_SOON, certificate.validityAt(90 * day))
        assertEquals(TlsCertificateValidity.EXPIRED, certificate.validityAt(90 * day + 1))
        assertEquals(TlsCertificateValidity.VALID, certificate.copy(notAfter = Long.MAX_VALUE).validityAt(day))
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
