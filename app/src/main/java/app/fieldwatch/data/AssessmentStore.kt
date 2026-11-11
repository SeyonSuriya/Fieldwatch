package app.fieldwatch.data

import app.fieldwatch.domain.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

data class EvidenceReviewBatch(val savedReviews: Int, val existingReviews: Int, val newFindings: Int)

/** Serialized, bounded, encrypted persistence. Failed reads never seed over an existing vault. */
class AssessmentStore(
    private val file: File,
    private val cipher: AssessmentCipher,
    private val appVersion: String,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val json = Json { encodeDefaults = true }
    private val mutex = Mutex()
    private var loaded = false
    private val mutableArchive = MutableStateFlow(AssessmentArchive())
    val archive = mutableArchive.asStateFlow()

    suspend fun load() = mutex.withLock {
        if (loaded) return@withLock
        withContext(Dispatchers.IO) {
            val original = if (!file.exists()) AssessmentArchive() else {
                require(file.length() <= AssessmentRules.MAX_ARCHIVE_BYTES + 128) { "Assessment vault exceeds storage limit." }
                val bytes = cipher.decrypt(file.readBytes())
                require(bytes.size <= AssessmentRules.MAX_ARCHIVE_BYTES) { "Assessment vault exceeds storage limit." }
                json.decodeFromString<AssessmentArchive>(bytes.toString(Charsets.UTF_8))
            }
            AssessmentRules.validate(original)
            val restored = original.copy(engagements = original.engagements.map { engagement ->
                engagement.copy(runs = engagement.runs.map { run ->
                    if (run.status == AssessmentRunStatus.RUNNING) run.copy(
                        status = AssessmentRunStatus.INTERRUPTED, endedAt = maxOf(now(), run.startedAt),
                    ) else run
                })
            })
            if (restored != original) persist(restored)
            mutableArchive.value = restored
            loaded = true
        }
    }

    suspend fun create(name: String, scope: String): String {
        val engagement = AssessmentEngagement(
            id = id(), name = AssessmentRules.text(name, 100, "Engagement name must be 1–100 characters."),
            scope = AssessmentRules.text(scope, 4000, "Describe the authorized scope (1–4000 characters)."), createdAt = now(),
        )
        update { it.copy(engagements = it.engagements + engagement) }
        return engagement.id
    }

    suspend fun addAsset(engagementId: String, label: String, identifier: String, transport: AssessmentTransport): String {
        val asset = AssessmentAsset(id(), AssessmentRules.text(label, 100, "Target label must be 1–100 characters."),
            AssessmentRules.text(identifier, 512, "Target identifier must be 1–512 characters."), transport, now())
        edit(engagementId) { engagement ->
            require(engagement.assets.none { it.transport == transport && it.identifier.equals(asset.identifier, true) }) {
                "This target is already in the engagement."
            }
            engagement.copy(assets = engagement.assets + asset)
        }
        return asset.id
    }

    suspend fun startObservation(engagementId: String, assetId: String): String {
        val run = AssessmentRun(id(), assetId, now())
        edit(engagementId) {
            require(it.assets.any { asset -> asset.id == assetId }) { "Select a target in this engagement." }
            require(it.runs.none { r -> r.assetId == assetId && r.status == AssessmentRunStatus.RUNNING }) {
                "An observation for this target is already running."
            }
            it.copy(runs = it.runs + run)
        }
        return run.id
    }

    /** An explicit import saves a frozen collector snapshot, not a vulnerability/access claim. */
    suspend fun saveInventorySnapshot(engagementId: String, radio: InventoryRadio, catalogVersion: Int): String {
        val row = RadioInventory.normalized(radio)
        var savedAssetId = ""
        edit(engagementId) { engagement ->
            val capturedAt = now()
            val asset = engagement.assets.firstOrNull {
                it.transport == row.transport && it.identifier.equals(row.identifier, true)
            } ?: AssessmentAsset(id(), row.label, row.identifier, row.transport, capturedAt)
            savedAssetId = asset.id
            val run = AssessmentRun(id(), asset.id, capturedAt, checkId = "inventory-snapshot",
                status = AssessmentRunStatus.RECORDED, endedAt = capturedAt)
            val body = json.encodeToString(row)
            val evidence = AssessmentEvidence(id(), asset.id, run.id, "Inventory snapshot: ${row.label}", body,
                AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), capturedAt,
                source = "inventory-${row.source.name.lowercase()}", appVersion = appVersion, catalogVersion = catalogVersion)
            engagement.copy(assets = if (engagement.assets.any { it.id == asset.id }) engagement.assets else engagement.assets + asset,
                runs = engagement.runs + run, evidence = engagement.evidence + evidence)
        }
        return savedAssetId
    }

    suspend fun addEvidence(engagementId: String, runId: String, title: String, text: String, catalogVersion: Int): String {
        val evidenceId = id()
        edit(engagementId) { engagement ->
            val run = engagement.runs.singleOrNull { it.id == runId } ?: error("Observation not found.")
            require(run.status == AssessmentRunStatus.RUNNING) { "Evidence can only be added to a running observation." }
            val body = AssessmentRules.text(text, AssessmentRules.MAX_NOTE_BYTES, "Enter an evidence note (up to 64 KiB).")
            require(body.toByteArray(Charsets.UTF_8).size <= AssessmentRules.MAX_NOTE_BYTES) { "Evidence exceeds 64 KiB." }
            val evidence = AssessmentEvidence(
                evidenceId, run.assetId, runId,
                AssessmentRules.text(title, 120, "Evidence title must be 1–120 characters."), body,
                AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), now(),
                appVersion = appVersion, catalogVersion = catalogVersion,
            )
            engagement.copy(evidence = engagement.evidence + evidence)
        }
        return evidenceId
    }

    suspend fun saveBluetoothSession(engagementId: String, body: String, catalogVersion: Int) {
        require(body.toByteArray(Charsets.UTF_8).size <= AssessmentRules.MAX_NOTE_BYTES) { "Bluetooth evidence exceeds 64 KiB." }
        val report = json.decodeFromString<BluetoothEvidenceReport>(body)
        require(report.format == "fieldwatch-bluetooth-session" && report.formatVersion == 1) { "Unsupported Bluetooth evidence format." }
        val target = report.target.validated()
        edit(engagementId) { engagement ->
            val asset = engagement.assets.firstOrNull { it.transport == target.transport && it.identifier.equals(target.address, true) }
                ?: error("Add this Bluetooth target to the engagement before saving protocol evidence.")
            val recordedAt = now()
            val run = AssessmentRun(id(), asset.id, recordedAt, checkId = "bluetooth-tools", status = AssessmentRunStatus.RECORDED, endedAt = recordedAt)
            val evidence = AssessmentEvidence(id(), asset.id, run.id, "Bluetooth protocol session", body,
                AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), recordedAt, source = "bluetooth-protocol-session",
                appVersion = appVersion, catalogVersion = catalogVersion)
            engagement.copy(runs = engagement.runs + run, evidence = engagement.evidence + evidence)
        }
    }

    suspend fun saveNetworkReport(engagementId: String, report: app.fieldwatch.domain.NetworkEvidenceReport, catalogVersion: Int) {
        report.validate()
        // Each endpoint is retained once; evidence is grouped by host for accurate asset attribution.
        edit(engagementId) { engagement ->
            var next = engagement
            report.observations.groupBy { it.address }.forEach { (address, observations) ->
                val capturedAt = now()
                val asset = next.assets.firstOrNull { it.transport == AssessmentTransport.NETWORK && it.identifier == address }
                    ?: AssessmentAsset(id(), address, address, AssessmentTransport.NETWORK, capturedAt)
                val run = AssessmentRun(id(), asset.id, report.startedAt, checkId = "network-tcp-connect",
                    status = if (report.cancelled) AssessmentRunStatus.CANCELLED else AssessmentRunStatus.RECORDED,
                    endedAt = report.endedAt)
                val body = json.encodeToString(report.copy(observations = observations))
                require(body.toByteArray(Charsets.UTF_8).size <= AssessmentRules.MAX_NOTE_BYTES)
                val evidence = AssessmentEvidence(id(), asset.id, run.id, "TCP connection observations", body,
                    AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), capturedAt,
                    source = "network-tcp-connect", appVersion = appVersion, catalogVersion = catalogVersion)
                next = next.copy(assets = if (next.assets.any { it.id == asset.id }) next.assets else next.assets + asset,
                    runs = next.runs + run, evidence = next.evidence + evidence)
            }
            require(report.observations.isNotEmpty()) { "No completed observations to save." }
            next
        }
    }

    suspend fun saveServiceReport(engagementId: String, report: ServiceInspectionReport, catalogVersion: Int) {
        report.validate()
        saveStructuredSnapshot(engagementId, report.address, report.address, AssessmentTransport.NETWORK,
            "service-inspection", json.encodeToString(report), report.startedAt, report.endedAt, catalogVersion)
    }

    suspend fun saveServiceDiscovery(engagementId: String, evidenceId: String): Boolean =
        saveServiceDiscoveries(engagementId, listOf(evidenceId)) == 1

    suspend fun saveServiceDiscoveries(engagementId: String, evidenceIds: List<String>): Int {
        val sourceIds = evidenceIds.distinct()
        require(sourceIds.isNotEmpty()) { "Select saved service inspections." }
        var recorded = 0
        edit(engagementId) { engagement ->
            val inspectionIds = engagement.evidence.filter { it.source == "service-inspection" }.map { it.id }.toSet()
            require(sourceIds.all { it in inspectionIds }) { "Select saved service inspections from this engagement." }
            val existing = engagement.evidence.filter { it.source == "service-discovery" }
                .map { json.decodeFromString<ServiceDiscoveryReport>(it.text) }
                .filter { it.version == ServiceDiscovery.VERSION && it.catalogVersion == ServiceDiscovery.CATALOG_VERSION }
                .map { it.sourceEvidenceId to it.sourceSha256 }.toSet()
            val evaluatedAt = now()
            val reports = sourceIds.map { ServiceDiscovery.evaluate(engagement, it, evaluatedAt) }
                .filterNot { (it.sourceEvidenceId to it.sourceSha256) in existing }
            if (reports.isEmpty()) return@edit engagement

            val runs = ArrayList<AssessmentRun>(reports.size)
            val evidence = ArrayList<AssessmentEvidence>(reports.size)
            val findings = mutableListOf<AssessmentFinding>()
            for (report in reports) {
                val run = AssessmentRun(id(), report.assetId, evaluatedAt, checkId = "service-discovery",
                    checkVersion = ServiceDiscovery.VERSION, status = AssessmentRunStatus.RECORDED, endedAt = evaluatedAt)
                val body = json.encodeToString(report)
                val review = AssessmentEvidence(id(), report.assetId, run.id, "Service identity and advisory candidates", body,
                    AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), evaluatedAt,
                    source = "service-discovery", appVersion = appVersion, catalogVersion = ServiceDiscovery.CATALOG_VERSION)
                runs += run
                evidence += review
                findings += report.candidates.map { candidate -> AssessmentFinding(
                    id(), report.assetId, "Unverified candidate: ${candidate.cve}",
                    "${candidate.title}. Advertised ${report.product} ${report.advertisedVersion}. ${candidate.requirements} Vendor notice: ${candidate.reference}. No exploit or access validation was performed.",
                    FindingSeverity.HIGH, FindingConfidence.SUSPECTED, listOf(report.sourceEvidenceId, review.id), evaluatedAt,
                    checkId = candidate.cve, checkVersion = ServiceDiscovery.CATALOG_VERSION)
                }
            }
            recorded = reports.size
            engagement.copy(runs = engagement.runs + runs, evidence = engagement.evidence + evidence,
                findings = engagement.findings + findings)
        }
        return recorded
    }

    suspend fun saveWifiSecurity(engagementId: String, report: WifiSecurityReport, catalogVersion: Int) {
        report.validate()
        saveStructuredSnapshot(engagementId, report.bssid.uppercase(), report.ssid.ifBlank { report.bssid }.take(100), AssessmentTransport.WIFI,
            "wifi-security-advertisement", json.encodeToString(report), report.capturedAt, report.capturedAt, catalogVersion)
    }

    private suspend fun saveStructuredSnapshot(engagementId: String, identifier: String, label: String, transport: AssessmentTransport,
        source: String, body: String, startedAt: Long, endedAt: Long, catalogVersion: Int) {
        require(body.toByteArray(Charsets.UTF_8).size <= AssessmentRules.MAX_NOTE_BYTES) { "Evidence exceeds 64 KiB." }
        edit(engagementId) { engagement ->
            val capturedAt = now()
            val asset = engagement.assets.firstOrNull { it.transport == transport && it.identifier.equals(identifier, true) }
                ?: AssessmentAsset(id(), label, identifier, transport, capturedAt)
            val run = AssessmentRun(id(), asset.id, startedAt, checkId = source,
                status = AssessmentRunStatus.RECORDED, endedAt = endedAt)
            val evidence = AssessmentEvidence(id(), asset.id, run.id, source, body,
                AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), capturedAt, source = source,
                appVersion = appVersion, catalogVersion = catalogVersion)
            engagement.copy(assets = if (engagement.assets.any { it.id == asset.id }) engagement.assets else engagement.assets + asset,
                runs = engagement.runs + run, evidence = engagement.evidence + evidence)
        }
    }

    suspend fun evaluateEvidence(engagementId: String, evidenceId: String, catalogVersion: Int): Int =
        evaluateEvidenceBatch(engagementId, listOf(evidenceId), catalogVersion).newFindings

    suspend fun evaluateEvidenceBatch(engagementId: String, evidenceIds: List<String>, catalogVersion: Int): EvidenceReviewBatch {
        val sourceIds = evidenceIds.distinct()
        require(sourceIds.isNotEmpty()) { "Select saved evidence with supported checks." }
        var batch = EvidenceReviewBatch(0, 0, 0)
        edit(engagementId) { engagement ->
            val supportedIds = engagement.evidence.filter { AssessmentChecks.supports(it.source) }.map { it.id }.toSet()
            require(sourceIds.all { it in supportedIds }) { "Select supported evidence from this engagement." }
            val existing = engagement.evidence.filter { it.source == "versioned-check-evaluation" }
                .map { json.decodeFromString<CheckEvaluation>(it.text) }
                .filter { it.registryVersion == AssessmentChecks.VERSION }
                .map { it.sourceEvidenceId to it.sourceSha256 }.toSet()
            val evaluatedAt = now()
            val evaluations = sourceIds.map { AssessmentChecks.evaluate(engagement, it, evaluatedAt) }
                .filterNot { (it.sourceEvidenceId to it.sourceSha256) in existing }
            if (evaluations.isEmpty()) {
                batch = EvidenceReviewBatch(0, sourceIds.size, 0)
                return@edit engagement
            }

            val newRuns = ArrayList<AssessmentRun>(evaluations.size)
            val newEvidence = ArrayList<AssessmentEvidence>(evaluations.size)
            val newFindings = mutableListOf<AssessmentFinding>()
            for (evaluation in evaluations) {
                val run = AssessmentRun(id(), evaluation.assetId, evaluation.evaluatedAt, checkId = "observation-checks",
                    checkVersion = AssessmentChecks.VERSION, status = AssessmentRunStatus.RECORDED, endedAt = evaluation.evaluatedAt)
                val body = json.encodeToString(evaluation)
                val evidence = AssessmentEvidence(id(), evaluation.assetId, run.id, "Versioned observation checks", body,
                    AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), evaluation.evaluatedAt,
                    source = "versioned-check-evaluation", appVersion = appVersion, catalogVersion = catalogVersion)
                val priorChecks = engagement.findings.filter { evaluation.sourceEvidenceId in it.evidenceIds }
                    .map { it.checkId to it.checkVersion }.toSet()
                val findings = evaluation.results.filter {
                    it.outcome == CheckOutcome.CONDITION_OBSERVED && (it.checkId to it.checkVersion) !in priorChecks
                }.map { result ->
                    val check = AssessmentChecks.definition(result.checkId)
                    AssessmentFinding(id(), evaluation.assetId, check.title,
                        "${result.explanation}\nRecommended action: ${check.remediation}\nReferences: ${check.references.joinToString()}\nBased only on the saved observation; not a CVE, exploitation or access verdict.",
                        check.severity, check.confidence, listOf(evaluation.sourceEvidenceId, evidence.id), evaluation.evaluatedAt,
                        checkId = result.checkId, checkVersion = result.checkVersion)
                }
                newRuns += run
                newEvidence += evidence
                newFindings += findings
            }
            batch = EvidenceReviewBatch(evaluations.size, sourceIds.size - evaluations.size, newFindings.size)
            engagement.copy(runs = engagement.runs + newRuns, evidence = engagement.evidence + newEvidence,
                findings = engagement.findings + newFindings)
        }
        return batch
    }

    suspend fun validateDeviceEvidence(engagementId: String, evidenceId: String, catalogVersion: Int): Boolean {
        var recorded = false
        edit(engagementId) { engagement ->
            val report = DeviceValidation.evaluate(engagement, evidenceId, now())
            val existing = engagement.evidence.filter { it.source == "device-validation" }.any {
                val previous = json.decodeFromString<DeviceValidationReport>(it.text)
                previous.sourceEvidenceId == report.sourceEvidenceId && previous.sourceSha256 == report.sourceSha256 &&
                    previous.moduleId == report.moduleId && previous.moduleVersion == report.moduleVersion && previous.fixtureRevision == report.fixtureRevision
            }
            if (existing) return@edit engagement
            val run = AssessmentRun(id(), report.assetId, report.evaluatedAt, checkId = report.moduleId,
                checkVersion = report.moduleVersion, status = AssessmentRunStatus.RECORDED, endedAt = report.evaluatedAt)
            val body = json.encodeToString(report)
            val evidence = AssessmentEvidence(id(), report.assetId, run.id, "Reference lab validation (LAB ONLY)", body,
                AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), report.evaluatedAt,
                source = "device-validation", appVersion = appVersion, catalogVersion = catalogVersion)
            val findings = if (report.outcome == DeviceValidationOutcome.LAB_MARKER_EXPOSED) listOf(AssessmentFinding(
                id(), report.assetId, "Reference lab canary exposed without credentials (LAB ONLY)",
                "${report.explanation}\nUse the protected fixture mode and collect a fresh observation for comparison. No real device files, media, credentials or CVE are involved.",
                FindingSeverity.LOW, FindingConfidence.CONFIRMED, listOf(evidenceId, evidence.id), report.evaluatedAt,
                checkId = report.moduleId, checkVersion = report.moduleVersion)) else emptyList()
            recorded = true
            engagement.copy(runs = engagement.runs + run, evidence = engagement.evidence + evidence, findings = engagement.findings + findings)
        }
        return recorded
    }

    suspend fun saveFixtureComparison(engagementId: String, exposedId: String, protectedId: String, catalogVersion: Int): Boolean {
        var recorded = false
        edit(engagementId) { engagement ->
            val report = FixtureComparison.compare(engagement, exposedId, protectedId, now())
            val existing = engagement.evidence.filter { it.source == "reference-fixture-comparison" }.any {
                val old = json.decodeFromString<FixtureComparisonReport>(it.text)
                old.formatVersion == FixtureComparison.VERSION && old.exposed.sourceEvidenceId == exposedId && old.protectedControl.sourceEvidenceId == protectedId &&
                    old.exposed.moduleId == report.exposed.moduleId && old.protectedControl.moduleId == report.protectedControl.moduleId &&
                    old.exposed.sourceSha256 == report.exposed.sourceSha256 && old.protectedControl.sourceSha256 == report.protectedControl.sourceSha256 &&
                    old.exposed.moduleVersion == report.exposed.moduleVersion && old.protectedControl.moduleVersion == report.protectedControl.moduleVersion &&
                    old.exposed.fixtureRevision == report.exposed.fixtureRevision && old.protectedControl.fixtureRevision == report.protectedControl.fixtureRevision
            }
            if (existing) return@edit engagement
            val run = AssessmentRun(id(), report.exposed.assetId, report.comparedAt, checkId = "reference-fixture-comparison",
                checkVersion = FixtureComparison.VERSION, status = AssessmentRunStatus.RECORDED, endedAt = report.comparedAt)
            val body = json.encodeToString(report)
            val evidence = AssessmentEvidence(id(), report.exposed.assetId, run.id, "Reference fixture comparison (LAB ONLY)", body,
                AssessmentRules.sha256(body.toByteArray(Charsets.UTF_8)), report.comparedAt, source = "reference-fixture-comparison",
                appVersion = appVersion, catalogVersion = catalogVersion)
            recorded = true
            engagement.copy(runs = engagement.runs + run, evidence = engagement.evidence + evidence)
        }
        return recorded
    }

    suspend fun saveOperatorBaseline(engagementId: String, baseline: HandsetBaseline) {
        val frozen = baseline.copy(hardwareReported = baseline.hardwareReported.toMap(), permissions = baseline.permissions.toMap())
        frozen.validate()
        edit(engagementId) { engagement ->
            require(engagement.operatorBaselines.size < AssessmentRules.MAX_OPERATOR_BASELINES) { "Operator baseline limit reached (20). Use another engagement for additional baselines." }
            engagement.copy(operatorBaselines = engagement.operatorBaselines + frozen)
        }
    }

    suspend fun finishObservation(engagementId: String, runId: String, cancelled: Boolean = false) {
        edit(engagementId) { engagement ->
            val run = engagement.runs.singleOrNull { it.id == runId } ?: error("Observation not found.")
            require(run.status == AssessmentRunStatus.RUNNING) { "Observation is already finished." }
            require(cancelled || engagement.evidence.any { it.runId == runId }) { "Record evidence before finishing." }
            engagement.copy(runs = engagement.runs.map {
                if (it.id == runId) it.copy(status = if (cancelled) AssessmentRunStatus.CANCELLED else AssessmentRunStatus.RECORDED,
                    endedAt = maxOf(now(), it.startedAt)) else it
            })
        }
    }

    /** Operator notes start as suspected; automated validation is not implemented by this method. */
    suspend fun recordFinding(engagementId: String, evidenceId: String, title: String, description: String, severity: FindingSeverity) {
        edit(engagementId) { engagement ->
            val evidence = engagement.evidence.singleOrNull { it.id == evidenceId } ?: error("Select supporting evidence.")
            engagement.copy(findings = engagement.findings + AssessmentFinding(
                id(), evidence.assetId, AssessmentRules.text(title, 120, "Finding title must be 1–120 characters."),
                AssessmentRules.text(description, 4000, "Finding description must be 1–4000 characters."),
                severity, evidenceIds = listOf(evidenceId), createdAt = now(),
            ))
        }
    }

    suspend fun close(engagementId: String) {
        edit(engagementId) {
            require(it.runs.none { r -> r.status == AssessmentRunStatus.RUNNING }) { "Finish or cancel running observations first." }
            it.copy(closedAt = now())
        }
    }

    suspend fun delete(engagementId: String) {
        update { archive ->
            val engagement = archive.engagements.singleOrNull { it.id == engagementId } ?: error("Engagement not found.")
            require(engagement.runs.none { it.status == AssessmentRunStatus.RUNNING }) { "Finish or cancel running observations first." }
            archive.copy(engagements = archive.engagements.filterNot { it.id == engagementId })
        }
    }

    private suspend fun edit(engagementId: String, transform: (AssessmentEngagement) -> AssessmentEngagement) {
        update { archive ->
            val engagement = archive.engagements.singleOrNull { it.id == engagementId } ?: error("Engagement not found.")
            require(engagement.closedAt == null) { "This engagement is closed and read-only." }
            val next = transform(engagement)
            archive.copy(engagements = archive.engagements.map { if (it.id == engagementId) next else it })
        }
    }

    private suspend fun update(transform: (AssessmentArchive) -> AssessmentArchive) = mutex.withLock {
        check(loaded) { "Assessment vault has not loaded. Retry loading before making changes." }
        withContext(Dispatchers.IO) {
            val next = transform(mutableArchive.value)
            AssessmentRules.validate(next)
            persist(next)
            // Publish only after the durable write succeeds.
            mutableArchive.value = next
        }
    }

    private fun persist(archive: AssessmentArchive) {
        val plain = json.encodeToString(archive).toByteArray(Charsets.UTF_8)
        require(plain.size <= AssessmentRules.MAX_ARCHIVE_BYTES) { "Assessment storage is full (8 MiB). Export and delete an engagement." }
        val sealed = cipher.encrypt(plain)
        val parent = requireNotNull(file.parentFile)
        check(parent.isDirectory || parent.mkdirs()) { "Could not create assessment storage." }
        val temp = File(parent, "${file.name}.${id()}.tmp")
        try {
            FileOutputStream(temp).use { output -> output.write(sealed); output.fd.sync() }
            try {
                Files.move(temp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            temp.delete()
        }
    }

    private fun id() = UUID.randomUUID().toString()
}
