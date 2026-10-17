package app.fieldwatch.domain

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class FixtureComparisonTest {
    private val fixture = Json.parseToJsonElement(requireNotNull(javaClass.getResourceAsStream("/device-validation/reference-fixtures.json"))
        .bufferedReader().use { it.readText() }).jsonObject
    private fun report(exposed: Boolean, port: Int = if (exposed) 8081 else 8082, network: String = "Wi-Fi lab", started: Long = 100): ServiceInspectionReport {
        val mode = fixture.getValue("modes").jsonObject.getValue(if (exposed) "exposed" else "protected").jsonObject
        val body = "HTTP/1.0 ${mode.getValue("status").jsonPrimitive.int} Fixture\r\n" +
            "X-Fieldwatch-Lab-Product: ${fixture.getValue("product").jsonPrimitive.content}\r\n" +
            "X-Fieldwatch-Lab-Build: ${mode.getValue("build").jsonPrimitive.content}\r\nX-Fieldwatch-Lab-Protocol: 1\r\n" +
            (if (exposed) "X-Fieldwatch-Lab-Canary: ${fixture.getValue("marker").jsonPrimitive.content}\r\n" else "WWW-Authenticate: Basic realm=\"FieldwatchLab\"\r\n") + "\r\n"
        return ServiceInspectionReport(address = "192.168.1.2", port = port, probe = ServiceProbe.HTTP_HEAD, network = network,
            startedAt = started, endedAt = started + 1, outcome = "observed", receivedHex = ServiceInspection.hex(body.toByteArray()),
            attemptedRequestHex = ServiceInspection.hex(ServiceInspection.request("192.168.1.2", port)))
    }
    private fun engagement(first: ServiceInspectionReport = report(true), second: ServiceInspectionReport = report(false)): AssessmentEngagement {
        val sources = listOf(first, second).mapIndexed { index, report ->
            val body = Json.encodeToString(report)
            AssessmentEvidence("e$index", "asset", "run", "Fixture", body, AssessmentRules.sha256(body.toByteArray()), report.endedAt,
                source = "service-inspection", appVersion = "test", catalogVersion = 1)
        }
        return AssessmentEngagement("eng", "Lab", "Authorized lab", 1,
            assets = listOf(AssessmentAsset("asset", "Fixture", "192.168.1.2", AssessmentTransport.NETWORK, 1)),
            runs = listOf(AssessmentRun("run", "asset", 1, status = AssessmentRunStatus.RECORDED, endedAt = 2)), evidence = sources)
    }
    private fun compare(engagement: AssessmentEngagement = engagement()) = FixtureComparison.compare(engagement, "e0", "e1", 1000)

    @Test fun expectedSharedFixturePairPreservesBothSourcesAndVersions() {
        val result = compare()
        assertEquals(FixtureComparisonOutcome.EXPECTED_REFERENCE_PAIR, result.outcome)
        assertEquals("192.168.1.2:8081", result.exposedEndpoint)
        assertEquals("192.168.1.2:8082", result.protectedEndpoint)
        assertEquals("e0", result.exposed.sourceEvidenceId)
        assertEquals("e1", result.protectedControl.sourceEvidenceId)
        assertEquals(1, result.exposed.fixtureRevision)
        assertEquals(result, Json.decodeFromString<FixtureComparisonReport>(Json.encodeToString(result)))
    }
    @Test fun reversedRolesAreInconclusive() {
        assertEquals(FixtureComparisonOutcome.INCONCLUSIVE, FixtureComparison.compare(engagement(), "e1", "e0", 1000).outcome)
    }
    @Test fun aSingleSourceCannotFillBothRoles() {
        try { FixtureComparison.compare(engagement(), "e0", "e0", 1000); fail("Expected distinct evidence rejection") }
        catch (_: IllegalArgumentException) { }
    }
    @Test fun sameEndpointAndDifferentNetworksCannotPass() {
        assertEquals(FixtureComparisonOutcome.INCONCLUSIVE, compare(engagement(second = report(false, port = 8081))).outcome)
        assertEquals(FixtureComparisonOutcome.INCONCLUSIVE, compare(engagement(second = report(false, network = "other network"))).outcome)
    }
    @Test fun collectionWindowHasAnExplicitBoundary() {
        val latestAllowed = 100 + FixtureComparison.MAX_COLLECTION_SPAN_MS - 1
        assertEquals(FixtureComparisonOutcome.EXPECTED_REFERENCE_PAIR, compare(engagement(second = report(false, started = latestAllowed))).outcome)
        assertEquals(FixtureComparisonOutcome.INCONCLUSIVE, compare(engagement(second = report(false, started = latestAllowed + 1))).outcome)
    }
    @Test fun incompleteControlRemainsInconclusive() {
        assertEquals(FixtureComparisonOutcome.INCONCLUSIVE, compare(engagement(second = report(false).copy(outcome = "timeout"))).outcome)
    }
    @Test fun corruptedSourceDigestIsRejected() {
        val original = engagement()
        try { compare(original.copy(evidence = original.evidence.map { it.copy(sha256 = "0".repeat(64)) })); fail("Expected digest rejection") }
        catch (_: IllegalArgumentException) { }
    }
    @Test fun oldObservationsRemainHistoricalRatherThanPretendingFreshTraffic() {
        val report = FixtureComparison.compare(engagement(), "e0", "e1", 90000000)
        assertEquals(FixtureComparisonOutcome.EXPECTED_REFERENCE_PAIR, report.outcome)
        assertTrue(report.explanation.contains("not fresh traffic"))
    }
}
