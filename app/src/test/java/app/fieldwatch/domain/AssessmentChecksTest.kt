package app.fieldwatch.domain

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class AssessmentChecksTest {
    private fun engagement(body: String, source: String, transport: AssessmentTransport, identifier: String) = AssessmentEngagement(
        "eng", "Lab", "Authorized fixtures", 1,
        assets = listOf(AssessmentAsset("asset", "Fixture", identifier, transport, 1)),
        runs = listOf(AssessmentRun("run", "asset", 1, status = AssessmentRunStatus.RECORDED, endedAt = 2)),
        evidence = listOf(AssessmentEvidence("evidence", "asset", "run", "Fixture", body, AssessmentRules.sha256(body.toByteArray()), 2,
            source = source, appVersion = "test", catalogVersion = 1)))
    private fun wifi(flags: String?): CheckEvaluation {
        val body = Json.encodeToString(WifiSecurityReport(bssid = "AA:BB:CC:DD:EE:01", ssid = "Lab", channel = 6, frequencyMhz = 2437,
            firstSeen = 1, lastSeen = 2, capturedAt = 3, capabilities = flags, parsedSecurity = null, analysis = WifiSecurityAnalysis.describe(flags)))
        return AssessmentChecks.evaluate(engagement(body, "wifi-security-advertisement", AssessmentTransport.WIFI, "AA:BB:CC:DD:EE:01"), "evidence", 10)
    }
    private fun serviceReport(response: String, mode: ServiceProbe = ServiceProbe.HTTP_HEAD, outcome: String = "observed") = ServiceInspectionReport(
        address = "192.168.1.2", port = 80, probe = mode, network = "Wi-Fi lab", startedAt = 1, endedAt = 2, outcome = outcome,
        attemptedRequestHex = if (mode == ServiceProbe.HTTP_HEAD || mode == ServiceProbe.HTTPS_HEAD) ServiceInspection.hex(ServiceInspection.request("192.168.1.2", 80)) else "",
        receivedHex = ServiceInspection.hex(response.toByteArray(Charsets.ISO_8859_1)))
    private fun evaluate(report: ServiceInspectionReport): CheckEvaluation = AssessmentChecks.evaluate(
        engagement(Json.encodeToString(report), "service-inspection", AssessmentTransport.NETWORK, report.address), "evidence", 10)
    private fun CheckEvaluation.outcome(id: String) = results.single { it.checkId == id }.outcome
    private fun rejected(action: () -> Unit) { try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } }

    @Test fun registryIdentifiersAreUniqueAndVersioned() {
        assertEquals(AssessmentChecks.definitions.size, AssessmentChecks.definitions.map { it.id }.distinct().size)
        assertEquals(2, wifi("[ESS]").registryVersion)
        assertTrue(wifi("[ESS]").results.all { it.checkVersion == 1 })
    }
    @Test fun legacyFindingJsonWithoutCheckMetadataRemainsReadable() {
        val original = AssessmentFinding("finding", "asset", "Operator finding", "Manual assessment", FindingSeverity.LOW,
            evidenceIds = listOf("evidence"), createdAt = 1)
        val body = Json.encodeToString(original)
        assertFalse(body.contains("checkId"))
        val decoded = Json.decodeFromString<AssessmentFinding>(body)
        assertEquals(original, decoded)
        assertNull(decoded.checkVersion)
    }
    @Test fun wepAndFixedWpa2FixturesDiffer() {
        assertEquals(CheckOutcome.CONDITION_OBSERVED, wifi("[WEP][ESS]").outcome("wifi-wep"))
        assertEquals(CheckOutcome.NOT_OBSERVED, wifi("[RSN-PSK-CCMP][ESS]").outcome("wifi-wep"))
        assertEquals(FindingConfidence.SUSPECTED, AssessmentChecks.definition("wifi-wep").confidence)
    }
    @Test fun wpa1TransitionIsFlaggedButWpa2AndSaeAreNotWpa1() {
        assertEquals(CheckOutcome.CONDITION_OBSERVED, wifi("[WPA-PSK-TKIP][RSN-PSK-CCMP][ESS]").outcome("wifi-wpa1"))
        assertEquals(CheckOutcome.NOT_OBSERVED, wifi("[WPA2-PSK-CCMP][RSN-SAE-CCMP][ESS]").outcome("wifi-wpa1"))
    }
    @Test fun openIsAnAdvertisementConcernNotConfirmedVulnerability() {
        assertEquals(CheckOutcome.CONDITION_OBSERVED, wifi("[ESS]").outcome("wifi-open"))
        assertEquals(CheckOutcome.CONDITION_OBSERVED, wifi("[WPS][ESS]").outcome("wifi-open"))
        assertEquals(FindingConfidence.SUSPECTED, AssessmentChecks.definition("wifi-open").confidence)
    }
    @Test fun missingUnknownMalformedAndOweDoNotBecomeOpenFindings() {
        listOf(null, "", "[FUTURE][ESS]", "[RSN-OWE-CCMP][ESS]", "[OWE_TRANSITION][ESS]", "prefix[ESS]", "[ESS][").forEach {
            assertNotEquals(CheckOutcome.CONDITION_OBSERVED, wifi(it).outcome("wifi-open"))
        }
    }
    @Test fun wpsNeverBecomesAnAutomaticVulnerabilityFinding() {
        assertEquals(CheckOutcome.INCONCLUSIVE, wifi("[WPS][ESS]").outcome("wifi-wps"))
        assertEquals(CheckOutcome.NOT_OBSERVED, wifi("[ESS]").outcome("wifi-wps"))
    }
    @Test fun tokenBoundariesPreventSubstringWepFalsePositives() {
        assertEquals(CheckOutcome.NOT_OBSERVED, wifi("[NOTWEP][ESS]").outcome("wifi-wep"))
    }
    @Test fun cleartextHttpRequiresCompleteResponseAndAttemptedRequest() {
        val report = serviceReport("HTTP/1.1 200 OK\r\nServer: Lab\r\n\r\n")
        assertEquals(CheckOutcome.CONDITION_OBSERVED, evaluate(report).outcome("http-cleartext"))
        assertEquals(CheckOutcome.INCONCLUSIVE, evaluate(report.copy(attemptedRequestHex = "")).outcome("http-cleartext"))
        assertEquals(FindingConfidence.CONFIRMED, AssessmentChecks.definition("http-cleartext").confidence)
    }
    @Test fun httpsIsNotCleartext() {
        val report = serviceReport("HTTP/1.1 200 OK\r\n\r\n", ServiceProbe.HTTPS_HEAD).copy(tlsProtocol = "TLSv1.3", tlsCipher = "TLS_AES_128_GCM_SHA256", certificateSha256 = "a".repeat(64))
        assertEquals(CheckOutcome.NOT_OBSERVED, evaluate(report).outcome("http-cleartext"))
    }
    @Test fun partialMalformedInterimAndBinaryHeadersStayInconclusive() {
        listOf("HTTP/1.1 200 OK\r\nServer: Lab", "HTTP/1.1 200 OK\r\n folded: x\r\n\r\n", "HTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX: \u0000\r\n\r\n", "HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n").forEach {
            assertEquals(CheckOutcome.INCONCLUSIVE, evaluate(serviceReport(it)).outcome("http-cleartext"))
        }
    }
    @Test fun timeoutAndIoErrorNeverCreateHttpFindings() {
        listOf("timeout", "connection-or-io-error").forEach {
            assertEquals(CheckOutcome.INCONCLUSIVE, evaluate(serviceReport("HTTP/1.1 200 OK\r\n\r\n", outcome = it)).outcome("http-cleartext"))
        }
    }
    @Test fun basicChallengeNeedsActual401AuthenticateHeader() {
        assertEquals(CheckOutcome.CONDITION_OBSERVED, evaluate(serviceReport("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Lab\"\r\n\r\n")).outcome("http-basic-cleartext"))
        listOf("HTTP/1.1 200 OK\r\nWWW-Authenticate: Basic realm=\"Lab\"\r\n\r\n", "HTTP/1.1 401 Unauthorized\r\nX-Note: WWW-Authenticate: Basic realm=\"Lab\"\r\n\r\n",
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"Basic\"\r\n\r\n").forEach {
            assertEquals(CheckOutcome.NOT_OBSERVED, evaluate(serviceReport(it)).outcome("http-basic-cleartext"))
        }
    }
    @Test fun negotiatedLegacyTlsAndModernTlsDiffer() {
        val base = serviceReport("", ServiceProbe.TLS).copy(tlsCipher = "TEST_CIPHER", certificateSha256 = "a".repeat(64))
        assertEquals(CheckOutcome.CONDITION_OBSERVED, evaluate(base.copy(tlsProtocol = "TLSv1.1")).outcome("tls-legacy"))
        assertEquals(CheckOutcome.NOT_OBSERVED, evaluate(base.copy(tlsProtocol = "TLSv1.3")).outcome("tls-legacy"))
    }
    @Test fun failedTlsNeverConfirmsCertificateVulnerability() {
        val evaluation = evaluate(serviceReport("", ServiceProbe.TLS, "tls-validation-or-handshake-failed"))
        assertEquals(CheckOutcome.INCONCLUSIVE, evaluation.outcome("tls-legacy"))
        assertFalse(evaluation.results.any { it.outcome == CheckOutcome.CONDITION_OBSERVED })
    }
    @Test fun ssh1AndFixedSsh2AndCompatibility199Differ() {
        assertEquals(CheckOutcome.CONDITION_OBSERVED, evaluate(serviceReport("SSH-1.5-Lab\r\n", ServiceProbe.BANNER)).outcome("ssh-v1"))
        listOf("SSH-1.99-Lab\r\n", "SSH-2.0-Lab\r\n").forEach {
            assertEquals(CheckOutcome.NOT_OBSERVED, evaluate(serviceReport(it, ServiceProbe.BANNER)).outcome("ssh-v1"))
        }
        assertEquals(CheckOutcome.INCONCLUSIVE, evaluate(serviceReport("SSH-1.5-Lab", ServiceProbe.BANNER)).outcome("ssh-v1"))
    }
    @Test fun productVersionAndStatus200DoNotProveCveOrMissingAuthorization() {
        val evaluation = evaluate(serviceReport("HTTP/1.1 200 OK\r\nServer: OldCam/1.0\r\n\r\n"))
        assertEquals(listOf("http-cleartext"), evaluation.results.filter { it.outcome == CheckOutcome.CONDITION_OBSERVED }.map { it.checkId })
        val observation = requireNotNull(evaluation.httpAccess)
        assertEquals(200, observation.status)
        assertTrue(observation.interpretation.contains("remains unknown"))
    }

    @Test fun accessReviewDistinguishesChallengeRefusalAndMalformedHeaders() {
        val challenged = evaluate(serviceReport("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"Lab\"\r\n\r\n"))
        val denied = evaluate(serviceReport("HTTP/1.1 403 Forbidden\r\n\r\n"))
        assertTrue(challenged.httpAccess!!.interpretation.contains("with a WWW-Authenticate"))
        assertTrue(denied.httpAccess!!.interpretation.contains("refused"))
        assertNull(evaluate(serviceReport("HTTP/1.1 401 Unauthorized\r\nX: a\nWWW-Authenticate: Basic\r\n\r\n")).httpAccess)
    }

    @Test fun downgradeRequiresVerifiedHttpsAndOneValidRedirectDestination() {
        fun check(headers: String, tls: Boolean = true): CheckOutcome {
            val report = serviceReport("HTTP/1.1 302 Found\r\n$headers\r\n\r\n", ServiceProbe.HTTPS_HEAD)
            val verified = if (tls) report.copy(tlsProtocol = "TLSv1.3", tlsCipher = "TLS_AES_128_GCM_SHA256",
                certificateSha256 = "a".repeat(64)) else report
            return evaluate(verified).outcome("https-redirect-to-http")
        }
        assertEquals(CheckOutcome.CONDITION_OBSERVED, check("Location: http://192.168.1.2/login"))
        assertEquals(CheckOutcome.NOT_OBSERVED, check("Location: /login"))
        assertEquals(CheckOutcome.INCONCLUSIVE, check("Location: http:/login"))
        assertEquals(CheckOutcome.INCONCLUSIVE, check("Location: http://192.168.1.2/login", tls = false))
        assertEquals(CheckOutcome.INCONCLUSIVE, check("Location: http://192.168.1.2/login\r\nLocation: /other"))
    }
    @Test fun targetMismatchAndDigestTamperingAreRejected() {
        val report = serviceReport("HTTP/1.1 200 OK\r\n\r\n")
        val base = engagement(Json.encodeToString(report), "service-inspection", AssessmentTransport.NETWORK, "192.168.1.8")
        rejected { AssessmentChecks.evaluate(base, "evidence", 10) }
        rejected { AssessmentChecks.evaluate(base.copy(evidence = base.evidence.map { it.copy(sha256 = "0".repeat(64)) }), "evidence", 10) }
    }
    @Test fun unsupportedOperatorEvidenceCannotImpersonateACollector() {
        assertFalse(AssessmentChecks.supports("operator-note"))
        rejected { AssessmentChecks.evaluate(engagement("manual", "operator-note", AssessmentTransport.NETWORK, "192.168.1.2"), "evidence", 10) }
    }
}
