package app.fieldwatch.domain

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
enum class FixtureComparisonOutcome { EXPECTED_REFERENCE_PAIR, INCONCLUSIVE }

@Serializable
data class FixtureComparisonReport(
    val format: String = "fieldwatch-reference-comparison",
    val formatVersion: Int = 1,
    val comparedAt: Long,
    val exposedEndpoint: String,
    val protectedEndpoint: String,
    val exposed: DeviceValidationReport,
    val protectedControl: DeviceValidationReport,
    val outcome: FixtureComparisonOutcome,
    val explanation: String,
)

object FixtureComparison {
    const val VERSION = 1
    const val MAX_COLLECTION_SPAN_MS = 15 * 60 * 1000L

    fun compare(engagement: AssessmentEngagement, exposedId: String, protectedId: String, now: Long): FixtureComparisonReport {
        require(exposedId != protectedId) { "Choose two different saved service observations." }
        // Both evaluations revalidate source hashes, completed requests and target attribution.
        val exposed = DeviceValidation.evaluate(engagement, exposedId, now)
        val control = DeviceValidation.evaluate(engagement, protectedId, now)
        fun source(id: String) = Json.decodeFromString<ServiceInspectionReport>(engagement.evidence.single { it.id == id }.text)
        val first = source(exposedId)
        val second = source(protectedId)
        val distinctEndpoints = first.address != second.address || first.port != second.port
        val sameNetwork = first.network == second.network
        val closeInTime = maxOf(first.endedAt, second.endedAt) - minOf(first.startedAt, second.startedAt) <= MAX_COLLECTION_SPAN_MS
        val sameModule = exposed.moduleId == control.moduleId && exposed.moduleVersion == control.moduleVersion && exposed.fixtureRevision == control.fixtureRevision
        val expected = exposed.outcome == DeviceValidationOutcome.LAB_MARKER_EXPOSED && control.outcome == DeviceValidationOutcome.LAB_PROTECTION_OBSERVED
        val outcome = if (distinctEndpoints && sameNetwork && closeInTime && sameModule && expected)
            FixtureComparisonOutcome.EXPECTED_REFERENCE_PAIR else FixtureComparisonOutcome.INCONCLUSIVE
        val reasons = buildList {
            if (!distinctEndpoints) add("The two roles use the same endpoint; collect separate exposed/protected fixtures on different ports or hosts.")
            if (!sameNetwork) add("The recorded Wi-Fi network handles differ.")
            if (!closeInTime) add("The saved captures span more than 15 minutes; recollect both fixtures together.")
            if (!sameModule) add("Module/fixture versions differ.")
            if (!expected) add("The selected exposed/protected observations do not have their expected reference outcomes.")
        }
        return FixtureComparisonReport(comparedAt = now, exposedEndpoint = "${first.address}:${first.port}", protectedEndpoint = "${second.address}:${second.port}",
            exposed = exposed, protectedControl = control, outcome = outcome,
            explanation = if (outcome == FixtureComparisonOutcome.EXPECTED_REFERENCE_PAIR)
                "The saved synthetic exposed/protected responses form the expected reference pair on distinct endpoints, with matching network handles and captures within 15 minutes. This is an offline comparison, not fresh traffic, authenticated hardware identity, manufacturer validation, exploitation or device access."
            else reasons.joinToString(" ") + " No product vulnerability or access conclusion is made.")
    }
}
