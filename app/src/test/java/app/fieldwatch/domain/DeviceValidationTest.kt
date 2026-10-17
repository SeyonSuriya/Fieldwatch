package app.fieldwatch.domain

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class DeviceValidationTest {
    private val fixture = Json.parseToJsonElement(requireNotNull(javaClass.getResourceAsStream("/device-validation/reference-fixtures.json"))
        .bufferedReader().use { it.readText() }).jsonObject
    private fun response(mode: String): String {
        val selected = fixture.getValue("modes").jsonObject.getValue(mode).jsonObject
        val status = selected.getValue("status").jsonPrimitive.int
        return "HTTP/1.0 $status Fixture\r\n" +
            "X-Fieldwatch-Lab-Product: ${fixture.getValue("product").jsonPrimitive.content}\r\n" +
            "X-Fieldwatch-Lab-Build: ${selected.getValue("build").jsonPrimitive.content}\r\n" +
            "X-Fieldwatch-Lab-Protocol: ${fixture.getValue("protocol").jsonPrimitive.content}\r\n" +
            (if (mode == "exposed") "X-Fieldwatch-Lab-Canary: ${fixture.getValue("marker").jsonPrimitive.content}\r\n"
             else "WWW-Authenticate: Basic realm=\"FieldwatchLab\"\r\n") + "Content-Length: 0\r\n\r\n"
    }
    private fun inspection(body: String) = ServiceInspectionReport(address = "192.168.1.2", port = 8081, probe = ServiceProbe.HTTP_HEAD,
        network = "Wi-Fi lab", startedAt = 1, endedAt = 2, outcome = "observed",
        attemptedRequestHex = ServiceInspection.hex(ServiceInspection.request("192.168.1.2", 8081)), receivedHex = ServiceInspection.hex(body.toByteArray()))
    private fun engagement(report: ServiceInspectionReport): AssessmentEngagement {
        val text = Json.encodeToString(report)
        return AssessmentEngagement("eng", "Lab", "Authorized fixture", 1,
            assets = listOf(AssessmentAsset("asset", "Reference", report.address, AssessmentTransport.NETWORK, 1)),
            runs = listOf(AssessmentRun("run", "asset", 1, status = AssessmentRunStatus.RECORDED, endedAt = 2)),
            evidence = listOf(AssessmentEvidence("evidence", "asset", "run", "Response", text, AssessmentRules.sha256(text.toByteArray()), 2,
                source = "service-inspection", appVersion = "test", catalogVersion = 1)))
    }
    private fun evaluate(body: String) = DeviceValidation.evaluate(engagement(inspection(body)), "evidence", 10)
    private fun rejected(action: () -> Unit) { try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } }

    @Test fun sharedFixtureAndModuleVersionsAgree() {
        assertEquals(fixture.getValue("fixture_revision").jsonPrimitive.int, DeviceValidation.reference.fixtureRevision)
        assertEquals(fixture.getValue("product").jsonPrimitive.content, DeviceValidation.reference.product)
        assertEquals(fixture.getValue("marker").jsonPrimitive.content, DeviceValidation.MARKER)
        val modes = fixture.getValue("modes").jsonObject
        assertEquals(setOf(modes.getValue("exposed").jsonObject.getValue("build").jsonPrimitive.content), DeviceValidation.reference.affectedBuilds)
        assertEquals(setOf(modes.getValue("protected").jsonObject.getValue("build").jsonPrimitive.content), DeviceValidation.reference.fixedBuilds)
        assertEquals(DeviceModuleSupport.LAB_ONLY, DeviceValidation.modules.single().support)
    }
    @Test fun exposedAndProtectedSharedFixturesHaveDifferentVerdicts() {
        assertEquals(DeviceValidationOutcome.LAB_MARKER_EXPOSED, evaluate(response("exposed")).outcome)
        assertEquals(DeviceValidationOutcome.LAB_PROTECTION_OBSERVED, evaluate(response("protected")).outcome)
    }
    @Test fun realProductAndGenericHttp200AreNotApplicable() {
        assertEquals(DeviceValidationOutcome.NOT_APPLICABLE, evaluate("HTTP/1.1 200 OK\r\nServer: CommercialCamera/1.0\r\n\r\n").outcome)
        assertEquals(DeviceValidationOutcome.NOT_APPLICABLE, evaluate(response("exposed").replace("fieldwatch-reference-camera", "other-camera")).outcome)
    }
    @Test fun unknownBuildOrProtocolIsInconclusive() {
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("exposed").replace("1.0-exposed", "9.0-unknown")).outcome)
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("exposed").replace("Protocol: 1", "Protocol: 2")).outcome)
    }
    @Test fun wrongOrMissingCanaryDoesNotConfirmExposure() {
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("exposed").replace(DeviceValidation.MARKER, "wrong")).outcome)
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("exposed").replace("X-Fieldwatch-Lab-Canary: ${DeviceValidation.MARKER}\r\n", "")).outcome)
    }
    @Test fun inconsistentBuildAndBehaviorRemainInconclusive() {
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("exposed").replace("1.0-exposed", "1.1-protected")).outcome)
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("protected").replace("1.1-protected", "1.0-exposed")).outcome)
    }
    @Test fun duplicateIdentityAndCanaryHeadersAreRejectedAsAmbiguous() {
        listOf("Product: fieldwatch-reference-camera", "Build: 1.0-exposed", "Protocol: 1", "Canary: ${DeviceValidation.MARKER}").forEach { header ->
            assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("exposed").replace("Content-Length:", "X-Fieldwatch-Lab-$header\r\nContent-Length:")).outcome)
        }
    }
    @Test fun redirectAndPartialResponseDoNotConfirmExposure() {
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("exposed").replace("200 Fixture", "302 Redirect")).outcome)
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("exposed").dropLast(3)).outcome)
    }
    @Test fun requestAttemptAndSuccessfulCaptureAreRequired() {
        val report = inspection(response("exposed"))
        listOf(report.copy(attemptedRequestHex = ""), report.copy(outcome = "timeout"), report.copy(outcome = "connection-or-io-error")).forEach {
            assertEquals(DeviceValidationOutcome.INCONCLUSIVE, DeviceValidation.evaluate(engagement(it), "evidence", 10).outcome)
        }
    }
    @Test fun unsupportedProbeModesCannotProduceALabVerdict() {
        val report = inspection(response("exposed"))
        val banner = report.copy(probe = ServiceProbe.BANNER, attemptedRequestHex = "")
        val https = report.copy(probe = ServiceProbe.HTTPS_HEAD, tlsProtocol = "TLSv1.3", tlsCipher = "TEST", certificateSha256 = "a".repeat(64))
        listOf(banner, https).forEach {
            assertEquals(DeviceValidationOutcome.INCONCLUSIVE, DeviceValidation.evaluate(engagement(it), "evidence", 10).outcome)
        }
    }
    @Test fun protectedResponseWithMarkerIsNotAcceptedAsNegativeControl() {
        assertEquals(DeviceValidationOutcome.INCONCLUSIVE, evaluate(response("protected").replace("Content-Length:", "X-Fieldwatch-Lab-Canary: wrong\r\nContent-Length:")).outcome)
    }
    @Test fun sourceDigestTargetAndTransportMustMatch() {
        val source = engagement(inspection(response("exposed")))
        rejected { DeviceValidation.evaluate(source.copy(evidence = source.evidence.map { it.copy(sha256 = "0".repeat(64)) }), "evidence", 10) }
        rejected { DeviceValidation.evaluate(source.copy(evidence = source.evidence.map { it.copy(source = "operator-note") }), "evidence", 10) }
        rejected { DeviceValidation.evaluate(source.copy(assets = source.assets.map { it.copy(identifier = "192.168.1.8") }), "evidence", 10) }
        rejected { DeviceValidation.evaluate(source.copy(assets = source.assets.map { it.copy(transport = AssessmentTransport.BLE) }), "evidence", 10) }
    }
    @Test fun provenanceAndLimitsAreExplicit() {
        val report = evaluate(response("exposed"))
        assertEquals(1, report.moduleVersion)
        assertEquals("LAB_ONLY", report.support)
        assertEquals("evidence", report.sourceEvidenceId)
        assertTrue(report.explanation.contains("unauthenticated server claims"))
        assertEquals(report, Json.decodeFromString<DeviceValidationReport>(Json.encodeToString(report)))
    }
}
