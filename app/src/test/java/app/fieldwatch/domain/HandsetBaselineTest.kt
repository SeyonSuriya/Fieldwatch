package app.fieldwatch.domain

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class HandsetBaselineTest {
    private fun baseline(sdk: Int = 36) = HandsetBaseline(capturedAt = 1, manufacturer = "FixtureBrand", model = "FixtureModel",
        androidRelease = "16", sdk = sdk, securityPatch = "2026-09-05", buildDisplay = "fixture-build", appVersion = "test-dev", appTargetSdk = 35,
        hardwareReported = HandsetBaseline.FEATURES.associateWith { true },
        permissions = HandsetBaseline.PERMISSION_MIN_SDK.mapValues { if (sdk < it.value) BaselinePermission.NOT_APPLICABLE else BaselinePermission.DENIED })
    private fun rejected(action: () -> Unit) { try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } }

    @Test fun android13Through16MetadataRoundTripsWithoutClaimingCompatibility() {
        (33..36).forEach { sdk ->
            val report = baseline(sdk)
            report.validate()
            assertEquals(report, Json.decodeFromString<HandsetBaseline>(Json.encodeToString(report)))
        }
    }
    @Test fun missingMetadataRemainsMissingRatherThanInvented() {
        baseline().copy(manufacturer = null, model = null, androidRelease = null, securityPatch = null, buildDisplay = null).validate()
        listOf(null, "", " unknown ", "bad\u0000value", "x".repeat(201)).forEach { assertNull(HandsetBaseline.metadata(it)) }
        assertEquals("fixture", HandsetBaseline.metadata(" fixture "))
    }
    @Test fun impossibleDatesControlsAndUnknownFormatsAreRejected() {
        listOf("2026-02-30", "2026-9-5", "unknown").forEach { patch -> rejected { baseline().copy(securityPatch = patch).validate() } }
        rejected { baseline().copy(model = "name\nspoof").validate() }
        rejected { baseline().copy(version = 2).validate() }
    }
    @Test fun fieldWhitelistsExcludeUnexpectedIdentifiers() {
        rejected { baseline().copy(hardwareReported = baseline().hardwareReported + ("serial" to true)).validate() }
        rejected { baseline().copy(permissions = baseline().permissions + ("phone_state" to BaselinePermission.GRANTED)).validate() }
        rejected { baseline().copy(permissions = baseline().permissions - "notifications").validate() }
    }
    @Test fun permissionApplicabilityIsSdkSpecificAndDeniedIsNotMissing() {
        baseline(29).validate(); baseline(31).validate(); baseline(33).validate()
        rejected { baseline(36).copy(permissions = baseline().permissions + ("notifications" to BaselinePermission.NOT_APPLICABLE)).validate() }
        rejected { baseline(29).copy(permissions = baseline(29).permissions + ("nearby_wifi" to BaselinePermission.GRANTED)).validate() }
    }
    @Test fun fullExportIncludesBaselineButSummaryContainsOnlyCount() {
        val engagement = AssessmentEngagement("eng", "Lab", "Authorized fixture", 1, operatorBaselines = listOf(baseline()))
        val summary = AssessmentReports.export(engagement, false, 10, "test")
        listOf("FixtureBrand", "FixtureModel", "fixture-build", "2026-09-05").forEach { assertFalse(summary.contains(it)) }
        assertEquals(1, Json.decodeFromString<AssessmentReport>(summary).summary!!.operatorBaselineCount)
        val full = AssessmentReports.export(engagement, true, 10, "test")
        assertEquals(baseline(), Json.decodeFromString<AssessmentReport>(full).engagement!!.operatorBaselines.single())
    }
    @Test fun legacyEngagementJsonHasAnEmptyBaselineList() {
        val original = AssessmentEngagement("eng", "Lab", "Authorized fixture", 1)
        val body = Json.encodeToString(original)
        assertFalse(body.contains("operatorBaselines"))
        assertTrue(Json.decodeFromString<AssessmentEngagement>(body).operatorBaselines.isEmpty())
    }
    @Test fun archiveRejectsExcessiveBaselines() {
        rejected { AssessmentRules.validate(AssessmentArchive(engagements = listOf(AssessmentEngagement("eng", "Lab", "Fixture", 1,
            operatorBaselines = List(21) { baseline() })))) }
    }
}
