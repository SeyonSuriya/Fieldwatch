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
