package app.fieldwatch.domain

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.time.Instant

@Serializable
enum class AssessmentTransport { WIFI, BLE, BLUETOOTH_CLASSIC, NETWORK }

@Serializable
enum class AssessmentRunStatus { RUNNING, RECORDED, CANCELLED, INTERRUPTED, FAILED }

@Serializable
enum class FindingConfidence { SUSPECTED, CONFIRMED }

@Serializable
enum class FindingSeverity { INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL }

@Serializable
data class AssessmentAsset(
    val id: String,
    val label: String,
    val identifier: String,
    val transport: AssessmentTransport,
    val addedAt: Long,
)

@Serializable
data class AssessmentRun(
    val id: String,
    val assetId: String,
    val startedAt: Long,
    val checkId: String = "operator-observation",
    val checkVersion: Int = 1,
    val status: AssessmentRunStatus = AssessmentRunStatus.RUNNING,
    val endedAt: Long? = null,
)

@Serializable
data class AssessmentEvidence(
    val id: String,
    val assetId: String,
    val runId: String,
    val title: String,
    val text: String,
    val sha256: String,
    val capturedAt: Long,
    val source: String = "operator-note",
    val appVersion: String,
    val catalogVersion: Int,
)

@Serializable
data class AssessmentFinding(
    val id: String,
    val assetId: String,
    val title: String,
    val description: String,
    val severity: FindingSeverity,
    val confidence: FindingConfidence = FindingConfidence.SUSPECTED,
    val evidenceIds: List<String>,
    val createdAt: Long,
    val checkId: String? = null,
    val checkVersion: Int? = null,
)

/** Schema for future validated access; a recorded observation never creates access. */
@Serializable
data class AssessmentAccess(
    val id: String,
    val assetId: String,
    val runId: String,
    val service: String,
    val demonstratedOperations: List<String>,
    val evidenceIds: List<String>,
    val recordedAt: Long,
)

@Serializable
data class AssessmentEngagement(
    val id: String,
    val name: String,
    val scope: String,
    val createdAt: Long,
    val closedAt: Long? = null,
    val assets: List<AssessmentAsset> = emptyList(),
    val runs: List<AssessmentRun> = emptyList(),
    val evidence: List<AssessmentEvidence> = emptyList(),
    val findings: List<AssessmentFinding> = emptyList(),
    val access: List<AssessmentAccess> = emptyList(),
    val operatorBaselines: List<HandsetBaseline> = emptyList(),
)

@Serializable
data class AssessmentArchive(
    val formatVersion: Int = 1,
    val engagements: List<AssessmentEngagement> = emptyList(),
)

object AssessmentRules {
    const val MAX_ENGAGEMENTS = 100
    const val MAX_ASSETS = 500
    const val MAX_RUNS = 2000
    const val MAX_EVIDENCE = 2000
    const val MAX_FINDINGS = 1000
    const val MAX_OPERATOR_BASELINES = 20
    const val MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
    const val MAX_NOTE_BYTES = 64 * 1024

    fun text(value: String, max: Int, message: String): String {
        val clean = value.trim()
        require(clean.isNotEmpty() && clean.length <= max) { message }
        require(clean.none { it == '\u0000' }) { "Text cannot contain null characters." }
        return clean
    }

    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }

    /** Reject inconsistent evidence rather than silently accepting an incomplete archive. */
    fun validate(archive: AssessmentArchive) {
        require(archive.formatVersion == 1) { "Unsupported assessment archive version." }
        require(archive.engagements.size <= MAX_ENGAGEMENTS) { "Too many engagements." }
        unique(archive.engagements.map { it.id })
        for (engagement in archive.engagements) {
            require(engagement.operatorBaselines.size <= MAX_OPERATOR_BASELINES) { "Operator baseline limit reached (20)." }
            engagement.operatorBaselines.forEach { it.validate() }
            require(engagement.assets.size <= MAX_ASSETS && engagement.runs.size <= MAX_RUNS &&
                engagement.evidence.size <= MAX_EVIDENCE && engagement.findings.size <= MAX_FINDINGS) {
                "Engagement storage limit reached."
            }
            text(engagement.name, 100, "Engagement name must be 1–100 characters.")
            text(engagement.scope, 4000, "Scope must be 1–4000 characters.")
            unique(engagement.assets.map { it.id })
            unique(engagement.runs.map { it.id })
            unique(engagement.evidence.map { it.id })
            unique(engagement.findings.map { it.id })
            unique(engagement.access.map { it.id })
            val assets = engagement.assets.associateBy { it.id }
            val runs = engagement.runs.associateBy { it.id }
            val evidence = engagement.evidence.associateBy { it.id }
            require(engagement.closedAt == null || engagement.runs.none { it.status == AssessmentRunStatus.RUNNING }) {
                "A closed engagement cannot contain running observations."
            }
            engagement.assets.forEach {
                text(it.label, 100, "Target label must be 1–100 characters.")
                text(it.identifier, 512, "Target identifier must be 1–512 characters.")
            }
            engagement.runs.forEach {
                require(it.assetId in assets) { "Run has no matching target." }
                require((it.status == AssessmentRunStatus.RUNNING) == (it.endedAt == null)) {
                    "Run status and end time disagree."
                }
                require(it.endedAt == null || it.endedAt >= it.startedAt) { "Invalid run timestamps." }
            }
            engagement.evidence.forEach {
                require(it.assetId in assets && runs[it.runId]?.assetId == it.assetId) { "Evidence target/run mismatch." }
                text(it.title, 120, "Evidence title must be 1–120 characters.")
                val bytes = it.text.toByteArray(Charsets.UTF_8)
                require(bytes.isNotEmpty() && bytes.size <= MAX_NOTE_BYTES) { "Evidence note must be 1–65536 bytes." }
                require(sha256(bytes) == it.sha256) { "Evidence digest mismatch." }
            }
            engagement.findings.forEach {
                require((it.checkId == null) == (it.checkVersion == null)) { "Finding check metadata is incomplete." }
                require(it.checkId == null || (it.checkId.isNotBlank() && it.checkId.length <= 100 && it.checkVersion!! > 0))
                text(it.title, 120, "Finding title must be 1–120 characters.")
                text(it.description, 4000, "Finding description must be 1–4000 characters.")
                require(it.assetId in assets && it.evidenceIds.isNotEmpty() &&
                    it.evidenceIds.all { id -> evidence[id]?.assetId == it.assetId }) { "Finding needs evidence from its target." }
            }
            engagement.access.forEach {
                text(it.service, 512, "Access service must be 1–512 characters.")
                require(it.demonstratedOperations.isNotEmpty() && it.demonstratedOperations.size <= 100) {
                    "An access result must describe demonstrated operations."
                }
                it.demonstratedOperations.forEach { operation -> text(operation, 512, "Invalid access operation description.") }
                require(it.assetId in assets && runs[it.runId]?.assetId == it.assetId &&
                    it.evidenceIds.isNotEmpty() && it.evidenceIds.all { id ->
                        evidence[id]?.let { e -> e.assetId == it.assetId && e.runId == it.runId } == true
                    }) { "Access result needs evidence from its run and target." }
            }
        }
    }

    private fun unique(ids: List<String>) {
        require(ids.all { it.isNotBlank() } && ids.toSet().size == ids.size) { "Invalid or duplicate record identifiers." }
    }
}

@Serializable
data class AssessmentReport(
    val format: String = "fieldwatch-assessment-report",
    val formatVersion: Int = 1,
    val exportedAt: Long,
    val appVersion: String,
    val disclosure: String,
    val engagement: AssessmentEngagement? = null,
    val summary: AssessmentSummary? = null,
)

/** A structural summary intentionally excludes all operator-supplied strings and hashes. */
@Serializable
data class AssessmentSummary(
    val assetCount: Int,
    val runStatuses: Map<AssessmentRunStatus, Int>,
    val evidenceCount: Int,
    val findingSeverities: Map<FindingSeverity, Int>,
    val findingConfidences: Map<FindingConfidence, Int>,
    val accessResultCount: Int,
    val operatorBaselineCount: Int = 0,
)

object AssessmentReports {
    private val json = Json { prettyPrint = true; encodeDefaults = true }

    fun export(engagement: AssessmentEngagement, full: Boolean, now: Long, appVersion: String): String {
        AssessmentRules.validate(AssessmentArchive(engagements = listOf(engagement)))
        return json.encodeToString(AssessmentReport(
            exportedAt = now,
            appVersion = appVersion,
            disclosure = if (full) "Full report: contains scope, identifiers, notes, evidence and operator-phone metadata. Export is unencrypted."
                else "Summary only: identifiers, scope, free text, evidence content and hashes are omitted.",
            engagement = engagement.takeIf { full },
            summary = if (full) null else AssessmentSummary(
                assetCount = engagement.assets.size,
                runStatuses = engagement.runs.groupingBy { it.status }.eachCount(),
                evidenceCount = engagement.evidence.size,
                findingSeverities = engagement.findings.groupingBy { it.severity }.eachCount(),
                findingConfidences = engagement.findings.groupingBy { it.confidence }.eachCount(),
                accessResultCount = engagement.access.size,
                operatorBaselineCount = engagement.operatorBaselines.size,
            ),
        ))
    }

    fun exportAssessmentText(engagement: AssessmentEngagement, now: Long, appVersion: String): String {
        AssessmentRules.validate(AssessmentArchive(engagements = listOf(engagement)))
        val findings = engagement.findings.sortedByDescending { it.severity }
        val coverage = AssessmentCoverage.summarize(engagement)
        val coverageSources = coverage.flatMap { target ->
            target.services.flatMap { service ->
                val inspections = listOfNotNull(service.latestTcpEvidenceId, service.latestInspection?.evidenceId)
                val certificates = service.certificateHistories.flatMap { history ->
                    listOf(history.latest.evidenceId) + history.changes.flatMap {
                        listOf(it.previous.evidenceId, it.current.evidenceId)
                    }
                }
                inspections + certificates
            } + target.pendingReviews.map { it.evidenceId }
        }
        val sourceIds = (findings.flatMap { it.evidenceIds } + coverageSources).distinct()
        val references = sourceIds.withIndex().associate { it.value to "E${it.index + 1}" }
        val evidenceById = engagement.evidence.associateBy { it.id }
        val assetsById = engagement.assets.associateBy { it.id }
        return buildString {
            appendLine("Fieldwatch assessment report")
            appendField("Exported (UTC)", Instant.ofEpochMilli(now).toString())
            appendField("App version", appVersion)
            appendField("Engagement", engagement.name)
            appendField("Authorized scope", engagement.scope)
            appendCoverage(coverage, references)
            appendLine()
            appendLine("Findings (${findings.size})")
            if (findings.isEmpty()) appendLine("No findings recorded.")
            findings.forEachIndexed { index, finding ->
                val asset = assetsById.getValue(finding.assetId)
                appendLine()
                appendLine("F${index + 1}  ${finding.severity} / ${finding.confidence}")
                appendField("Title", finding.title)
                appendField("Target", asset.label)
                appendField("Target identifier", asset.identifier)
                appendField("Transport", asset.transport.name)
                appendField("Recorded (UTC)", Instant.ofEpochMilli(finding.createdAt).toString())
                finding.checkId?.let { appendField("Check", "$it v${finding.checkVersion}") }
                appendField("Description", finding.description)
                appendField("Evidence references", finding.evidenceIds.distinct().joinToString(", ") { references.getValue(it) })
            }
            if (sourceIds.isNotEmpty()) {
                appendLine()
                appendLine("Evidence references (${sourceIds.size})")
                for (id in sourceIds) {
                    val evidence = evidenceById.getValue(id)
                    appendLine()
                    appendLine(references.getValue(id))
                    appendField("Title", evidence.title)
                    appendField("Evidence ID", evidence.id)
                    appendField("Source", evidence.source)
                    appendField("Captured (UTC)", Instant.ofEpochMilli(evidence.capturedAt).toString())
                    appendField("SHA-256", evidence.sha256)
                }
            }
        }
    }

    private fun StringBuilder.appendCoverage(coverage: List<TargetCoverage>, references: Map<String, String>) {
        appendLine()
        appendLine("Target coverage (${coverage.size})")
        appendLine("Coverage reflects saved evidence.")
        for (target in coverage) {
            appendLine()
            appendField("Target", target.asset.label)
            appendField("Target identifier", target.asset.identifier)
            appendField("Transport", target.asset.transport.name)
            appendLine("Saved evidence records: ${target.savedEvidenceCount}")
            appendLine("TCP endpoints: ${target.services.size}")
            appendLine("Records awaiting review: ${target.pendingReviews.size}")
            appendLine("Pending checks: ${target.pendingReviews.count { it.checks }}")
            appendLine("Pending software discovery: ${target.pendingReviews.count { it.discovery }}")
            if (target.unreadableNetworkRecords > 0) {
                appendLine("Unreadable network records: ${target.unreadableNetworkRecords}")
            }
            for (service in target.services) {
                appendLine()
                appendLine("TCP port ${service.port}")
                service.latestTcp?.let { tcp ->
                    val reference = service.latestTcpEvidenceId?.let(references::getValue)
                    appendField("Latest TCP check", listOfNotNull(tcp.outcome.replace('-', ' '),
                        Instant.ofEpochMilli(tcp.observedAt).toString(), reference).joinToString(" · "))
                }
                service.latestInspection?.let { inspection ->
                    inspection.advertisedLabel?.let { appendField("Advertised service", it) }
                    appendField("Latest service inspection",
                        "${inspection.probe.name.replace('_', ' ')} · ${inspection.outcome.replace('-', ' ')} · ${Instant.ofEpochMilli(inspection.endedAt)} · ${references.getValue(inspection.evidenceId)}")
                } ?: appendLine("No service inspection saved.")
                appendLine("Saved responses: ${service.capturedResponses}")
                for (history in service.certificateHistories) {
                    appendLine()
                    appendLine("TLS certificate history")
                    appendField("Saved Wi-Fi network", history.latest.network)
                    appendField("TLS context", "${history.latest.probe.name.replace('_', ' ')} · ${history.latest.protocol}")
                    appendLine("Verified captures: ${history.captureCount}")
                    appendLine("Fingerprint changes: ${history.changes.size}")
                    appendCertificateCapture("Latest certificate", history.latest, references)
                    for (change in history.changes) {
                        appendCertificateCapture("Previous certificate", change.previous, references)
                        appendCertificateCapture("Changed certificate", change.current, references)
                    }
                }
            }
            for (pending in target.pendingReviews) {
                val actions = listOfNotNull("checks".takeIf { pending.checks }, "software discovery".takeIf { pending.discovery })
                appendField("Pending ${actions.joinToString(" and ")} (${references.getValue(pending.evidenceId)})", pending.title)
            }
        }
    }

    private fun StringBuilder.appendCertificateCapture(label: String, capture: CertificateCapture, references: Map<String, String>) {
        appendField(label, "${Instant.ofEpochMilli(capture.endedAt)} · ${references.getValue(capture.evidenceId)}\nSHA-256 ${capture.sha256}")
    }

    private fun StringBuilder.appendField(label: String, value: String) {
        appendLine(label)
        value.lineSequence().forEach { line ->
            append("  ")
            line.forEach { char -> append(if (char.isISOControl()) ' ' else char) }
            appendLine()
        }
    }
}
