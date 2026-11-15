package app.fieldwatch.domain

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

enum class DeviceModuleSupport { LAB_ONLY }

data class DeviceModuleDefinition(
    val id: String, val version: Int, val product: String, val affectedBuilds: Set<String>, val fixedBuilds: Set<String>,
    val support: DeviceModuleSupport, val fixtureRevision: Int, val prerequisites: String, val sideEffects: String, val recovery: String,
)

@Serializable
enum class DeviceValidationOutcome { LAB_MARKER_EXPOSED, LAB_PROTECTION_OBSERVED, NOT_APPLICABLE, INCONCLUSIVE }

@Serializable
data class DeviceValidationReport(
    val format: String = "fieldwatch-device-validation",
    val formatVersion: Int = 1,
    val moduleId: String,
    val moduleVersion: Int,
    val fixtureRevision: Int,
    val support: String = "LAB_ONLY",
    val sourceEvidenceId: String,
    val sourceSha256: String,
    val assetId: String,
    val evaluatedAt: Long,
    val claimedProduct: String?,
    val claimedBuild: String?,
    val outcome: DeviceValidationOutcome,
    val explanation: String,
)

object DeviceValidation {
    const val MARKER = "FW-LAB-CANARY-1"
    val reference = DeviceModuleDefinition("fieldwatch-reference-authz", 1, "fieldwatch-reference-camera",
        setOf("1.0-exposed"), setOf("1.1-protected"), DeviceModuleSupport.LAB_ONLY, 1,
        "Saved HTTP HEAD / evidence from the Fieldwatch reference fixture. Exact lab product/build/protocol headers and a completed request/response are required. Manufacturer devices are unsupported.",
        "Review is offline. Collecting the source performs one HEAD / request, which is logged. The fixture serves only a synthetic marker header, never real media, files or credentials.",
        "No target state is changed. Stop the reference server to remove the fixture; collect fresh evidence after changing its mode.")
    val modules = listOf(reference)

    fun evaluate(engagement: AssessmentEngagement, evidenceId: String, now: Long): DeviceValidationReport {
        val evidence = engagement.evidence.singleOrNull { it.id == evidenceId } ?: error("Select saved service evidence.")
        require(evidence.source == "service-inspection") { "This module accepts saved service inspections only." }
        require(evidence.text.toByteArray(Charsets.UTF_8).size <= AssessmentRules.MAX_NOTE_BYTES &&
            AssessmentRules.sha256(evidence.text.toByteArray(Charsets.UTF_8)) == evidence.sha256) { "Evidence integrity check failed." }
        val asset = engagement.assets.single { it.id == evidence.assetId }
        require(engagement.runs.any { it.id == evidence.runId && it.assetId == asset.id && it.status == AssessmentRunStatus.RECORDED })
        val inspection = Json.decodeFromString<ServiceInspectionReport>(evidence.text).also { it.validate() }
        require(asset.transport == AssessmentTransport.NETWORK && asset.identifier == inspection.address) { "Service evidence target mismatch." }
        require(now > 0)
        val http = if (inspection.probe == ServiceProbe.HTTP_HEAD && inspection.httpPath == "/") HttpEvidence.read(inspection) else null
        val headers = http?.headers.orEmpty()
        fun values(name: String) = headers.filter { it.first == name }.map { it.second }
        fun single(name: String) = values(name).singleOrNull()
        val product = single("x-fieldwatch-lab-product")
        val build = single("x-fieldwatch-lab-build")
        val protocol = single("x-fieldwatch-lab-protocol")
        val marker = single("x-fieldwatch-lab-canary")
        val ambiguous = listOf("x-fieldwatch-lab-product", "x-fieldwatch-lab-build", "x-fieldwatch-lab-protocol", "x-fieldwatch-lab-canary").any { values(it).size > 1 }
        val outcome = when {
            http == null || ambiguous -> DeviceValidationOutcome.INCONCLUSIVE
            product != reference.product -> DeviceValidationOutcome.NOT_APPLICABLE
            protocol != "1" || build !in reference.affectedBuilds + reference.fixedBuilds -> DeviceValidationOutcome.INCONCLUSIVE
            build in reference.affectedBuilds && http.status == 200 && marker == MARKER -> DeviceValidationOutcome.LAB_MARKER_EXPOSED
            build in reference.fixedBuilds && http.status == 401 && values("x-fieldwatch-lab-canary").isEmpty() &&
                values("www-authenticate") == listOf("Basic realm=\"FieldwatchLab\"") -> DeviceValidationOutcome.LAB_PROTECTION_OBSERVED
            else -> DeviceValidationOutcome.INCONCLUSIVE
        }
        val explanation = when (outcome) {
            DeviceValidationOutcome.LAB_MARKER_EXPOSED -> "The synthetic exposed fixture returned its exact canary header to HEAD / without an Authorization header. This confirms only the recorded lab-marker exposure, not a manufacturer vulnerability or device access. Identity/build headers are unauthenticated server claims."
            DeviceValidationOutcome.LAB_PROTECTION_OBSERVED -> "The synthetic protected fixture returned HTTP 401 with the expected challenge and no canary header. Only this HEAD request was blocked; other methods, paths and authentication bypasses were not tested."
            DeviceValidationOutcome.NOT_APPLICABLE -> "The response does not claim the exact reference product. No commercial product or CVE is supported by this module."
            DeviceValidationOutcome.INCONCLUSIVE -> "Complete unambiguous reference identity/build/protocol and expected response behavior were not established. Partial replies, unknown builds and inconsistent markers are not vulnerability verdicts."
        }
        return DeviceValidationReport(moduleId = reference.id, moduleVersion = reference.version, fixtureRevision = reference.fixtureRevision,
            sourceEvidenceId = evidence.id, sourceSha256 = evidence.sha256, assetId = asset.id, evaluatedAt = now,
            claimedProduct = product, claimedBuild = build, outcome = outcome, explanation = explanation)
    }
}
