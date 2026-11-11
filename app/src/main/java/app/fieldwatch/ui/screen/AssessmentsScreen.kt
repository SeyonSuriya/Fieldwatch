package app.fieldwatch.ui.screen

import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import app.fieldwatch.domain.*
import app.fieldwatch.ui.AssessmentExportFormat
import app.fieldwatch.ui.AssessmentViewModel
import app.fieldwatch.ui.ProtectAssessmentScreen
import app.fieldwatch.ui.NestedTopBar
import app.fieldwatch.ui.component.SectionCard
import java.text.DateFormat
import java.util.Date

@Composable
fun AssessmentsScreen(onBack: () -> Unit, onInventory: () -> Unit, onNetwork: () -> Unit, vm: AssessmentViewModel = viewModel()) {
    ProtectAssessmentScreen()
    val context = LocalContext.current
    val archive by vm.archive.collectAsStateWithLifecycle()
    val selectedId by vm.selected.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val ready by vm.ready.collectAsStateWithLifecycle()
    val notice by vm.notice.collectAsStateWithLifecycle()
    val exportRequested by vm.exportRequested.collectAsStateWithLifecycle()
    val selected = archive.engagements.firstOrNull { it.id == selectedId }
    var dialog by remember(selectedId) { mutableStateOf<String?>(null) }
    var targetRun by remember(selectedId) { mutableStateOf<String?>(null) }
    var targetEvidence by remember(selectedId) { mutableStateOf<String?>(null) }
    var checkPreview by remember(selectedId) { mutableStateOf<CheckEvaluation?>(null) }
    var openedEvidenceId by remember(selectedId) { mutableStateOf<String?>(null) }
    var checkError by remember(selectedId) { mutableStateOf<String?>(null) }
    var discoveryPreview by remember(selectedId) { mutableStateOf<ServiceDiscoveryReport?>(null) }
    var devicePreview by remember(selectedId) { mutableStateOf<DeviceValidationReport?>(null) }
    var operatorPreview by remember(selectedId) { mutableStateOf<HandsetBaseline?>(null) }
    val jsonExporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(AssessmentExportFormat.JSON.mimeType), vm::writeReport)
    val textExporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(AssessmentExportFormat.TEXT.mimeType), vm::writeReport)
    LaunchedEffect(exportRequested) {
        val format = exportRequested ?: return@LaunchedEffect
        vm.exportLaunched()
        try {
            val timestamp = System.currentTimeMillis()
            when (format) {
                AssessmentExportFormat.JSON -> jsonExporter.launch("fieldwatch-assessment-$timestamp.${format.extension}")
                AssessmentExportFormat.TEXT -> textExporter.launch("fieldwatch-assessment-$timestamp.${format.extension}")
            }
        } catch (_: android.content.ActivityNotFoundException) {
            vm.exportFailed()
        }
    }

    Scaffold(topBar = { NestedTopBar("Assessments", navigationIcon = {
        TextButton(onClick = onBack) { Text("Back") }
    }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionCard("Assessment workspace") {
                Text("Create an authorized scope and record targets, observations and evidence. Versioned checks review saved service/Wi-Fi evidence without contacting targets. Device-specific validation and access modules remain later milestones.")
                Text("Evidence is encrypted locally with a key in Android Keystore. Full exports are unencrypted. Existing scan logs are separate.", style = MaterialTheme.typography.bodySmall)
            }
            if (Build.VERSION.SDK_INT < 33) {
                Text("Assessments require Android 13 or newer. Existing reconnaissance remains available.")
                return@Column
            }
            CapabilitySummary()
            OutlinedButton(onClick = onInventory, enabled = !busy) { Text("Open radio inventory") }
            OutlinedButton(onClick = onNetwork, enabled = !busy) { Text("Network and Wi-Fi assessment") }
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (!ready) {
                Text("The assessment vault has not loaded. Existing files will not be replaced if loading fails.")
                OutlinedButton(onClick = vm::reload, enabled = !busy) { Text("Retry loading") }
            } else {
                if (selected == null) {
                    Button(onClick = { dialog = "create" }, enabled = !busy) { Text("New engagement") }
                    if (archive.engagements.isEmpty()) Text("No engagements yet.")
                    archive.engagements.asReversed().forEach { engagement ->
                        SectionCard(engagement.name) {
                            Text(if (engagement.closedAt == null) "Open · ${engagement.assets.size} targets" else "Closed · ${engagement.assets.size} targets")
                            Text(engagement.scope)
                            OutlinedButton(onClick = { vm.select(engagement.id) }, enabled = !busy) { Text("Open record") }
                        }
                    }
                } else {
                    val editable = selected.closedAt == null && !busy
                    TextButton(onClick = { vm.select(null) }, enabled = !busy) { Text("All engagements") }
                    SectionCard(selected.name) {
                        Text(selected.scope)
                        Text("${selected.assets.size} targets · ${selected.runs.size} observations · ${selected.evidence.size} evidence notes · ${selected.findings.size} findings")
                        Text(if (selected.closedAt == null) "Open" else "Closed · read-only")
                        OutlinedButton(onClick = { dialog = "target-coverage" }, enabled = !busy) { Text("View target coverage") }
                        OutlinedButton(onClick = { dialog = "asset" }, enabled = editable) { Text("Add target") }
                        OutlinedButton(onClick = { dialog = "fixture-comparison" }, enabled = editable) { Text("Compare reference lab fixtures") }
                        OutlinedButton(onClick = {
                            runCatching { app.fieldwatch.data.HandsetBaselineCollector.capture(context) }
                                .onSuccess { operatorPreview = it }.onFailure { checkError = "Handset baseline unavailable: ${it.message}" }
                        }, enabled = editable) { Text("Review this phone's baseline") }
                        val reviewableEvidence = selected.evidence.filter { AssessmentChecks.supports(it.source) }
                        if (reviewableEvidence.isNotEmpty()) {
                            OutlinedButton(onClick = { vm.evaluateEvidenceBatch(selected.id, reviewableEvidence.map { it.id }) },
                                enabled = editable) { Text("Save evidence reviews (${reviewableEvidence.size})") }
                        }
                        val serviceEvidence = selected.evidence.filter { it.source == "service-inspection" }
                        if (serviceEvidence.isNotEmpty()) {
                            OutlinedButton(onClick = { vm.saveServiceDiscoveries(selected.id, serviceEvidence.map { it.id }) },
                                enabled = editable) { Text("Save discovery reviews (${serviceEvidence.size})") }
                        }
                        OutlinedButton(onClick = { vm.prepareReport(false) }, enabled = !busy) { Text("Export summary") }
                        OutlinedButton(onClick = { dialog = "full-export" }, enabled = !busy) { Text("Export full report") }
                        OutlinedButton(onClick = { dialog = "text-export" }, enabled = !busy) { Text("Export assessment as text") }
                        if (selected.closedAt == null) TextButton(onClick = { dialog = "close" }, enabled = editable) { Text("Close engagement") }
                        TextButton(onClick = { dialog = "delete" }, enabled = !busy) { Text("Delete engagement") }
                    }
                    if (selected.operatorBaselines.isNotEmpty()) SectionCard("Operator handset baselines (${selected.operatorBaselines.size}/20)") {
                        Text("These records describe phones running Fieldwatch, not remote targets. Hardware/permission reports do not verify radio operation, root or external hardware.")
                        selected.operatorBaselines.asReversed().forEach { baseline ->
                            HorizontalDivider()
                            OperatorBaselineDetails(baseline)
                        }
                    }
                    EngagementFindings(selected, onOpenEvidence = { openedEvidenceId = it })
                    if (selected.assets.isEmpty()) Text("Add a target identifier such as a MAC address, hostname or service endpoint. Adding a record does not connect to it.")
                    selected.assets.forEach { asset ->
                        SectionCard(asset.label) {
                            Text("${asset.transport.displayName()} · ${asset.identifier}")
                            val running = selected.runs.firstOrNull { it.assetId == asset.id && it.status == AssessmentRunStatus.RUNNING }
                            if (running == null) {
                                OutlinedButton(onClick = { vm.startObservation(asset.id) }, enabled = editable) { Text("Start manual observation") }
                            } else {
                                Text("Manual observation running · no network or radio test is being executed")
                                OutlinedButton(onClick = { targetRun = running.id; dialog = "evidence" }, enabled = editable) { Text("Record evidence note") }
                                OutlinedButton(onClick = { vm.finishObservation(running.id, false) }, enabled = editable) { Text("Finish observation") }
                                TextButton(onClick = { vm.finishObservation(running.id, true) }, enabled = editable) { Text("Cancel observation") }
                            }
                            selected.runs.filter { it.assetId == asset.id }.asReversed().forEach { run ->
                                Text("${run.status.name.lowercase()} · ${DateFormat.getDateTimeInstance().format(Date(run.startedAt))}", style = MaterialTheme.typography.bodySmall)
                            }
                            selected.evidence.filter { it.assetId == asset.id }.forEach { evidence ->
                                HorizontalDivider()
                                Text(evidence.title, style = MaterialTheme.typography.titleSmall)
                                when (evidence.source) {
                                    "reference-fixture-comparison" -> SavedFixtureComparison(evidence)
                                    "versioned-check-evaluation", "service-discovery" -> {
                                        OutlinedButton(onClick = { openedEvidenceId = evidence.id }) { Text("Open saved review") }
                                    }
                                    "service-inspection" -> {
                                        OutlinedButton(onClick = { openedEvidenceId = evidence.id }) { Text("Open inspection") }
                                    }
                                    else -> Text(evidence.text)
                                }
                                Text("Source: ${evidence.source} · catalog ${evidence.catalogVersion}\nSHA-256: ${evidence.sha256}", style = MaterialTheme.typography.bodySmall)
                                if (AssessmentChecks.supports(evidence.source)) OutlinedButton(onClick = {
                                    runCatching { AssessmentChecks.evaluate(selected, evidence.id, System.currentTimeMillis()) }
                                        .onSuccess { checkPreview = it }.onFailure { checkError = "This evidence cannot be evaluated: ${it.message}" }
                                }, enabled = editable) { Text("Review versioned checks") }
                                if (evidence.source == "service-inspection") OutlinedButton(onClick = {
                                    runCatching { ServiceDiscovery.evaluate(selected, evidence.id, System.currentTimeMillis()) }
                                        .onSuccess { discoveryPreview = it }.onFailure { checkError = "Service discovery unavailable: ${it.message}" }
                                }, enabled = editable) { Text("Discover software and advisory candidates") }
                                if (evidence.source == "service-inspection") OutlinedButton(onClick = {
                                    runCatching { DeviceValidation.evaluate(selected, evidence.id, System.currentTimeMillis()) }
                                        .onSuccess { devicePreview = it }.onFailure { checkError = "Device validation unavailable: ${it.message}" }
                                }, enabled = editable) { Text("Review reference lab module") }
                                TextButton(onClick = { targetEvidence = evidence.id; dialog = "finding" }, enabled = editable) { Text("Record suspected finding") }
                            }
                        }
                    }
                }
            }
        }
    }
    selected?.let { engagement ->
        engagement.evidence.firstOrNull { it.id == openedEvidenceId }?.let { evidence ->
            SavedEvidenceDialog(engagement, evidence, onDismiss = { openedEvidenceId = null })
        }
    }
    discoveryPreview?.let { report ->
        AlertDialog(onDismissRequest = { discoveryPreview = null }, title = { Text("Software and vulnerability candidates") },
            text = { Column(Modifier.verticalScroll(rememberScrollState())) {
                DiscoveryReviewContent(report)
                Text("Saving adds evidence-linked suspected findings for candidates. No exploit is executed.")
            } },
            confirmButton = { TextButton(onClick = { vm.saveServiceDiscovery(report.sourceEvidenceId); discoveryPreview = null }, enabled = !busy) { Text("Save discovery review") } },
            dismissButton = { TextButton(onClick = { discoveryPreview = null }) { Text("Cancel") } })
    }
    if (notice != null) AlertDialog(onDismissRequest = vm::dismissNotice, title = { Text("Assessment notice") },
        text = { Text(notice.orEmpty()) }, confirmButton = { TextButton(onClick = vm::dismissNotice) { Text("OK") } })
    if (checkError != null) AlertDialog(onDismissRequest = { checkError = null }, title = { Text("Check unavailable") },
        text = { Text(checkError.orEmpty()) }, confirmButton = { TextButton(onClick = { checkError = null }) { Text("OK") } })
    operatorPreview?.let { preview -> AlertDialog(onDismissRequest = { operatorPreview = null }, title = { Text("This phone's operator baseline") },
        text = { Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Captured locally from the phone running Fieldwatch. This does not identify or inspect a remote target.")
            OperatorBaselineDetails(preview)
            Text("No IMEI, serial, Android ID, addresses, location, accounts or radio traffic are collected. Root/external-radio operation and Android 16 compatibility remain unverified. Model/patch data does not prove vulnerability status.")
            Text("Saving encrypts this frozen snapshot in the selected engagement. Full exports include it; summaries include only the count. Limit: 20 snapshots per engagement.")
        } },
        confirmButton = { TextButton(onClick = { vm.saveOperatorBaseline(preview); operatorPreview = null }, enabled = !busy) { Text("Save encrypted baseline") } },
        dismissButton = { TextButton(onClick = { operatorPreview = null }) { Text("Cancel") } }) }
    checkPreview?.let { preview -> AlertDialog(onDismissRequest = { checkPreview = null }, title = { Text("Saved-observation checks v${preview.registryVersion}") },
        text = { Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            CheckReviewContent(preview)
            Text(if (preview.bluetoothAccess != null) "Saving links these observations to the Bluetooth session."
                else "Saving links this review to the inspection and records new findings for observed conditions.")
        } },
        confirmButton = { TextButton(onClick = { vm.evaluateEvidence(preview.sourceEvidenceId); checkPreview = null }, enabled = !busy) { Text("Save check results") } },
        dismissButton = { TextButton(onClick = { checkPreview = null }) { Text("Cancel") } }) }
    devicePreview?.let { preview -> AlertDialog(onDismissRequest = { devicePreview = null }, title = { Text("Reference module · LAB ONLY") },
        text = { Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            val module = DeviceValidation.reference
            Text("${module.id} v${module.version} · fixture revision ${module.fixtureRevision}")
            Text("Prerequisites: ${module.prerequisites}")
            Text("Exposed builds: ${module.affectedBuilds.joinToString()}\nProtected controls: ${module.fixedBuilds.joinToString()}")
            Text("Claimed product: ${preview.claimedProduct ?: "unavailable"}\nClaimed build: ${preview.claimedBuild ?: "unavailable"}")
            Text(preview.outcome.name, style = MaterialTheme.typography.titleSmall)
            Text(preview.explanation)
            Text("Effects: ${module.sideEffects}\nRecovery: ${module.recovery}")
            Text("This review sends no traffic. Saving retains the original evidence link and this result. A finding is created only for the synthetic exposed marker; no access record is created.")
        } },
        confirmButton = { TextButton(onClick = { vm.validateDeviceEvidence(preview.sourceEvidenceId); devicePreview = null }, enabled = !busy) { Text("Save lab validation") } },
        dismissButton = { TextButton(onClick = { devicePreview = null }) { Text("Cancel") } }) }
    when (dialog) {
        "target-coverage" -> selected?.let { engagement ->
            AssessmentCoverageDialog(
                engagement = engagement,
                canSave = engagement.closedAt == null && !busy,
                onDismiss = { dialog = null },
                onOpenEvidence = { evidenceId ->
                    dialog = null
                    openedEvidenceId = evidenceId
                },
                onSaveChecks = { ids ->
                    dialog = null
                    vm.evaluateEvidenceBatch(engagement.id, ids)
                },
                onSaveDiscovery = { ids ->
                    dialog = null
                    vm.saveServiceDiscoveries(engagement.id, ids)
                },
            )
        }
        "fixture-comparison" -> selected?.let { engagement -> FixtureComparisonDialog(engagement, onDismiss = { dialog = null }) { exposedId, protectedId ->
            vm.saveFixtureComparison(exposedId, protectedId); dialog = null
        } }
        "create" -> TextEntryDialog("New engagement", "Name", "Authorized targets, boundaries and assessment notes", 100, 4000,
            onDismiss = { dialog = null }) { name, scope -> vm.create(name, scope); dialog = null }
        "asset" -> AssetDialog(onDismiss = { dialog = null }) { label, identifier, transport ->
            vm.addAsset(label, identifier, transport); dialog = null
        }
        "evidence" -> TextEntryDialog("Record operator evidence", "Title", "Observed facts (up to 64 KiB)", 120, 65536,
            onDismiss = { dialog = null }) { title, body -> targetRun?.let { vm.addEvidence(it, title, body) }; dialog = null }
        "finding" -> FindingDialog(onDismiss = { dialog = null }) { title, body, severity ->
            targetEvidence?.let { vm.recordFinding(it, title, body, severity) }; dialog = null
        }
        "full-export" -> ConfirmAssessmentDialog("Export full report?",
            "Includes target identifiers, scope, findings, all evidence notes and saved operator-phone metadata in unencrypted JSON. Save only to a destination you intend to trust.",
            "Export", { dialog = null }) { vm.prepareReport(true); dialog = null }
        "text-export" -> ConfirmAssessmentDialog("Export assessment as text?",
            "The unencrypted text file includes scope, target identifiers, coverage, findings and evidence references.",
            "Export", { dialog = null }) { vm.prepareTextReport(); dialog = null }
        "close" -> ConfirmAssessmentDialog("Close engagement?", "Finish or cancel running observations first. Closed records remain exportable but cannot be edited.",
            "Close", { dialog = null }) { vm.close(); dialog = null }
        "delete" -> ConfirmAssessmentDialog("Delete engagement?", "Permanently removes this record and its evidence from the app. Export a full report first if you need a copy. Existing exported copies are not deleted.",
            "Delete", { dialog = null }) { vm.delete(); dialog = null }
    }
}

@Composable
private fun EngagementFindings(engagement: AssessmentEngagement, onOpenEvidence: (String) -> Unit) {
    if (engagement.findings.isEmpty()) return
    var targetId by remember(engagement.id) { mutableStateOf<String?>(null) }
    var severity by remember(engagement.id) { mutableStateOf<FindingSeverity?>(null) }
    var confidence by remember(engagement.id) { mutableStateOf<FindingConfidence?>(null) }
    val assets = remember(engagement.assets) { engagement.assets.associateBy { it.id } }
    val evidence = remember(engagement.evidence) { engagement.evidence.associateBy { it.id } }
    val targets = remember(engagement.findings, engagement.assets) {
        engagement.findings.map { it.assetId }.distinct().filter { it in assets }
            .sortedBy { assets.getValue(it).label.lowercase() }
    }
    val visible = remember(engagement.findings, targetId, severity, confidence) {
        engagement.findings.filter {
            (targetId == null || it.assetId == targetId) && (severity == null || it.severity == severity) &&
                (confidence == null || it.confidence == confidence)
        }.sortedByDescending { it.severity }
    }
    SectionCard("Findings") {
        FindingFilterMenu("Target", targets, targetId, { id ->
            assets[id]?.let { "${it.label} · ${it.identifier}" } ?: id
        }) { targetId = it }
        FindingFilterMenu("Severity", FindingSeverity.entries, severity, { it.name.lowercase() }) { severity = it }
        FindingFilterMenu("Confidence", FindingConfidence.entries, confidence, { it.name.lowercase() }) { confidence = it }
        if (targetId != null || severity != null || confidence != null) {
            TextButton(onClick = { targetId = null; severity = null; confidence = null }) { Text("Clear finding filters") }
        }
        Text("Showing ${visible.size} of ${engagement.findings.size} findings")
        if (visible.isEmpty()) Text("No findings match these filters.")
        for (finding in visible) {
            HorizontalDivider()
            Text(finding.title, style = MaterialTheme.typography.titleSmall)
            Text("${finding.confidence} · ${finding.severity}")
            assets[finding.assetId]?.let { Text("${it.label} · ${it.identifier}") }
            Text(finding.description)
            finding.checkId?.let { Text("Check $it v${finding.checkVersion}", style = MaterialTheme.typography.bodySmall) }
            finding.evidenceIds.forEach { id ->
                evidence[id]?.let { linked ->
                    TextButton(onClick = { onOpenEvidence(id) }) { Text(linked.title) }
                }
            }
        }
    }
}

@Composable
private fun <T : Any> FindingFilterMenu(
    label: String,
    choices: List<T>,
    selected: T?,
    display: (T) -> String,
    onSelect: (T?) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { expanded = true }, modifier = Modifier.fillMaxWidth()) {
            Text("$label · ${selected?.let(display) ?: "All"}", maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            DropdownMenuItem(text = { Text("All") }, onClick = { onSelect(null); expanded = false })
            choices.forEach { choice ->
                DropdownMenuItem(text = { Text(display(choice)) }, onClick = { onSelect(choice); expanded = false })
            }
        }
    }
}

@Composable
private fun DiscoveryReviewContent(report: ServiceDiscoveryReport) {
    Text("${report.address}:${report.port} | ${report.protocol}")
    Text("Advertised software: ${report.product ?: "Unknown"} ${report.advertisedVersion.orEmpty()}")
    Text(report.explanation)
    report.candidates.forEach { candidate ->
        HorizontalDivider()
        Text("${candidate.cve} | UNVERIFIED VERSION MATCH", style = MaterialTheme.typography.titleSmall)
        Text(candidate.title)
        Text(candidate.requirements)
        Text("Vendor fix release: ${candidate.vendorFixRelease} | ${candidate.reference}")
    }
}

@Composable
private fun CheckReviewContent(preview: CheckEvaluation, sourceInspectionEndedAt: Long? = null) {
    preview.certificateDetails?.let {
        TlsCertificateDetailsContent(it, preview.certificateInspectionEndedAt ?: sourceInspectionEndedAt)
    }
    preview.httpAccess?.let { observation ->
        Text("HTTP ${observation.status} on HEAD /", style = MaterialTheme.typography.titleSmall)
        Text(observation.interpretation)
    }
    when (val observation = preview.bluetoothAccess) {
        is BluetoothAccessObservation.Ble -> {
            Text("BLE GATT properties", style = MaterialTheme.typography.titleSmall)
            Text("${observation.services} services and ${observation.characteristics} characteristics retained. ${observation.omittedAttributes} attributes omitted.")
            Text("${observation.readable} readable, ${observation.writeWithResponse} writable with response, ${observation.writeWithoutResponse} writable without response, ${observation.subscriptions} supporting notifications or indications.")
            Text("Declared properties describe available operations. Authentication and encryption requirements can vary by attribute.")
            Text("Recorded GATT rejections: ${observation.authenticationRejections} authentication, ${observation.encryptionRejections} encryption. ${observation.omittedEvents} events omitted.")
        }
        is BluetoothAccessObservation.Classic -> {
            Text("Classic Bluetooth service identities", style = MaterialTheme.typography.titleSmall)
            Text(observation.source ?: "UUID source unavailable")
            observation.observedAt?.let { Text(DateFormat.getDateTimeInstance().format(Date(it))) }
            observation.recognizedServices.forEach { Text(it) }
            Text("${observation.otherUuids} other UUIDs retained. ${observation.omittedUuids} omitted.")
            Text("Service availability and authorization require separate verification.")
        }
        null -> Unit
    }
    preview.results.forEach { result ->
        val check = AssessmentChecks.definitions.firstOrNull { it.id == result.checkId && it.version == result.checkVersion }
        Text("${check?.title ?: result.checkId} · ${result.outcome.name.lowercase().replace('_', ' ')}", style = MaterialTheme.typography.titleSmall)
        Text(result.explanation)
        if (check != null && result.outcome == CheckOutcome.CONDITION_OBSERVED) Text("${check.severity} · ${check.confidence}\n${check.remediation}")
    }
}

@Composable
private fun SavedEvidenceDialog(engagement: AssessmentEngagement, evidence: AssessmentEvidence, onDismiss: () -> Unit) {
    val isReview = evidence.source == "versioned-check-evaluation" || evidence.source == "service-discovery"
    val check = remember(evidence) {
        if (evidence.source == "versioned-check-evaluation") runCatching {
            kotlinx.serialization.json.Json.decodeFromString<CheckEvaluation>(evidence.text)
                .takeIf { it.format == "fieldwatch-check-evaluation" && it.formatVersion == 1 }
        }.getOrNull() else null
    }
    val discovery = remember(evidence) {
        if (evidence.source == "service-discovery") runCatching {
            kotlinx.serialization.json.Json.decodeFromString<ServiceDiscoveryReport>(evidence.text)
                .takeIf { it.format == "fieldwatch-service-discovery" && it.version == 1 }
        }.getOrNull() else null
    }
    val sourceId = check?.sourceEvidenceId ?: discovery?.sourceEvidenceId
    val sourceHash = check?.sourceSha256 ?: discovery?.sourceSha256
    val reviewAssetId = check?.assetId ?: discovery?.assetId
    val source = remember(engagement.evidence, evidence) {
        engagement.evidence.firstOrNull {
            it.id == sourceId && it.id != evidence.id && it.assetId == evidence.assetId &&
                reviewAssetId == evidence.assetId && it.sha256 == sourceHash
        }
    }
    val sourceInspection = remember(source) { source?.decodeServiceInspection() }
    val directInspection = remember(evidence) { evidence.decodeServiceInspection() }
    var showSource by remember(evidence.id) { mutableStateOf(false) }
    var showRaw by remember(evidence.id) { mutableStateOf(false) }
    val viewed = if (showSource) source ?: evidence else evidence
    val close = { if (showSource) showSource = false else onDismiss() }
    val reviewScroll = rememberScrollState()
    val sourceScroll = rememberScrollState()
    AlertDialog(
        onDismissRequest = close,
        title = { Text(viewed.title) },
        text = {
            Column(Modifier.verticalScroll(if (showSource) sourceScroll else reviewScroll),
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(DateFormat.getDateTimeInstance().format(Date(viewed.capturedAt)), style = MaterialTheme.typography.bodySmall)
                if (!showSource && (check != null || discovery != null)) {
                    if (source != null) {
                        OutlinedButton(onClick = { showSource = true }) { Text("Open source evidence") }
                    } else {
                        Text("The linked source is unavailable or its recorded hash differs.")
                    }
                }
                when {
                    showSource -> {
                        sourceInspection?.let { report -> report.certificateDetails?.let { TlsCertificateDetailsContent(it, report.endedAt) } }
                        Text(viewed.text)
                    }
                    check != null -> {
                        Text("Check registry version ${check.registryVersion}")
                        CheckReviewContent(check, sourceInspection?.endedAt)
                    }
                    discovery != null -> {
                        Text("Advisory catalog version ${discovery.catalogVersion}")
                        DiscoveryReviewContent(discovery)
                    }
                    else -> {
                        if (isReview) Text("Showing the stored record because this review format could not be opened.")
                        directInspection?.let { report -> report.certificateDetails?.let { TlsCertificateDetailsContent(it, report.endedAt) } }
                        Text(viewed.text)
                    }
                }
                if (!showSource && (check != null || discovery != null)) {
                    TextButton(onClick = { showRaw = !showRaw }) { Text(if (showRaw) "Hide saved JSON" else "Show saved JSON") }
                    if (showRaw) Text(evidence.text)
                }
                Text("SHA-256: ${viewed.sha256}", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = close) { Text(if (showSource) "Back to review" else "Done") } },
    )
}

private fun AssessmentEvidence.decodeServiceInspection(): ServiceInspectionReport? =
    if (source == "service-inspection") runCatching {
        kotlinx.serialization.json.Json.decodeFromString<ServiceInspectionReport>(text).also { it.validate() }
    }.getOrNull() else null

@Composable
private fun SavedFixtureComparison(evidence: AssessmentEvidence) {
    val report = remember(evidence.id, evidence.sha256) { runCatching { kotlinx.serialization.json.Json.decodeFromString<FixtureComparisonReport>(evidence.text) }.getOrNull() }
    var showRaw by remember(evidence.id) { mutableStateOf(false) }
    if (report == null) {
        Text("Comparison could not be decoded. Original evidence is retained.")
        Text(evidence.text)
    } else {
        Text("LAB ONLY · ${report.outcome}", style = MaterialTheme.typography.titleSmall)
        Text("Exposed ${report.exposedEndpoint}: ${report.exposed.outcome}\nControl ${report.protectedEndpoint}: ${report.protectedControl.outcome}")
        Text(report.explanation)
        Text("Exposed source: ${report.exposed.sourceEvidenceId}\nControl source: ${report.protectedControl.sourceEvidenceId}", style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = { showRaw = !showRaw }) { Text(if (showRaw) "Hide raw comparison" else "Show raw comparison and hashes") }
        if (showRaw) Text(evidence.text)
    }
}

@Composable
private fun FixtureComparisonDialog(engagement: AssessmentEngagement, onDismiss: () -> Unit, onSave: (String, String) -> Unit) {
    val candidates = remember(engagement) { engagement.evidence.filter { it.source == "service-inspection" }.asReversed().take(100) }
    var exposedId by remember(engagement.id) { mutableStateOf<String?>(null) }
    var protectedId by remember(engagement.id) { mutableStateOf<String?>(null) }
    var exposedMenu by remember { mutableStateOf(false) }
    var protectedMenu by remember { mutableStateOf(false) }
    var preview by remember { mutableStateOf<FixtureComparisonReport?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    fun label(id: String?): String {
        val evidence = candidates.firstOrNull { it.id == id } ?: return "Choose saved observation"
        val endpoint = runCatching { kotlinx.serialization.json.Json.decodeFromString<ServiceInspectionReport>(evidence.text).let { "${it.address}:${it.port}" } }.getOrDefault("Unreadable response")
        return "$endpoint · ${DateFormat.getDateTimeInstance().format(Date(evidence.capturedAt))} · ${evidence.id.take(8)}"
    }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Reference fixture pair · LAB ONLY") }, text = {
        Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Select the exposed fixture capture and protected control explicitly. Reviews saved evidence only; no target traffic is sent. Showing the newest ${candidates.size} service observations (maximum 100).")
            Text("Expected: exposed 1.0-exposed returns the synthetic marker; protected 1.1-protected blocks HEAD /. Use distinct endpoints on the same recorded Wi-Fi network and collect within 15 minutes.")
            Text("Exposed fixture")
            Box { OutlinedButton(onClick = { exposedMenu = true }) { Text(label(exposedId)) }
                DropdownMenu(expanded = exposedMenu, onDismissRequest = { exposedMenu = false }) {
                    candidates.forEach { evidence -> DropdownMenuItem(text = { Text(label(evidence.id)) }, onClick = { exposedId = evidence.id; exposedMenu = false; preview = null; error = null }) }
                }
            }
            Text("Protected control")
            Box { OutlinedButton(onClick = { protectedMenu = true }) { Text(label(protectedId)) }
                DropdownMenu(expanded = protectedMenu, onDismissRequest = { protectedMenu = false }) {
                    candidates.forEach { evidence -> DropdownMenuItem(text = { Text(label(evidence.id)) }, onClick = { protectedId = evidence.id; protectedMenu = false; preview = null; error = null }) }
                }
            }
            OutlinedButton(onClick = {
                runCatching { FixtureComparison.compare(engagement, exposedId!!, protectedId!!, System.currentTimeMillis()) }
                    .onSuccess { preview = it; error = null }.onFailure { error = it.message ?: "Comparison unavailable."; preview = null }
            }, enabled = exposedId != null && protectedId != null && exposedId != protectedId) { Text("Review comparison") }
            error?.let { Text(it) }
            preview?.let { report ->
                Text(report.outcome.name, style = MaterialTheme.typography.titleSmall)
                Text("Exposed ${report.exposedEndpoint}: ${report.exposed.outcome}\nControl ${report.protectedEndpoint}: ${report.protectedControl.outcome}")
                Text(report.explanation)
                Text("Module ${report.exposed.moduleId} v${report.exposed.moduleVersion} · fixture revision ${report.exposed.fixtureRevision}")
                Text("Saving records both original evidence IDs/hashes and outcomes under the exposed fixture's asset. It creates no finding or access record and does not certify a physical device.")
            }
        }
    }, confirmButton = { TextButton(onClick = { preview?.let { onSave(it.exposed.sourceEvidenceId, it.protectedControl.sourceEvidenceId) } }, enabled = preview != null) { Text("Save encrypted comparison") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
private fun OperatorBaselineDetails(baseline: HandsetBaseline) {
    Text("${baseline.manufacturer ?: "Unknown manufacturer"} · ${baseline.model ?: "Unknown model"}")
    Text("Android ${baseline.androidRelease ?: "unknown"} · SDK ${baseline.sdk}\nSecurity patch: ${baseline.securityPatch ?: "unavailable"}\nBuild display: ${baseline.buildDisplay ?: "unavailable"}\nBuild incremental: ${baseline.buildIncremental ?: "unavailable"}")
    Text("Fieldwatch ${baseline.appVersion} · app target SDK ${baseline.appTargetSdk}\nCaptured: ${DateFormat.getDateTimeInstance().format(Date(baseline.capturedAt))}")
    baseline.hardwareReported.forEach { (feature, reported) -> Text("${feature.replace('_', ' ')} hardware: ${if (reported) "reported" else "not reported"}", style = MaterialTheme.typography.bodySmall) }
    baseline.permissions.forEach { (name, status) -> Text("${name.replace('_', ' ')} permission: ${status.name.lowercase().replace('_', ' ')}", style = MaterialTheme.typography.bodySmall) }
    Text("Reported metadata only; no operational radio, root, external-hardware or vulnerability verification.", style = MaterialTheme.typography.bodySmall)
}

@Composable
private fun CapabilitySummary() {
    val manager = LocalContext.current.packageManager
    SectionCard("Phone capabilities") {
        Text("Android ${Build.VERSION.RELEASE} · assessment workspace available")
        listOf("Wi-Fi" to PackageManager.FEATURE_WIFI, "Bluetooth Classic" to PackageManager.FEATURE_BLUETOOTH,
            "Bluetooth LE" to PackageManager.FEATURE_BLUETOOTH_LE, "USB host" to PackageManager.FEATURE_USB_HOST).forEach { (name, feature) ->
            Text("$name: ${if (manager.hasSystemFeature(feature)) "hardware reported" else "not reported"}", style = MaterialTheme.typography.bodySmall)
        }
        Text("Root and external-radio capabilities have not been verified. Hardware presence does not establish monitor mode, injection or protocol support.", style = MaterialTheme.typography.bodySmall)
    }
}

private fun AssessmentTransport.displayName() = when (this) {
    AssessmentTransport.WIFI -> "Wi-Fi"
    AssessmentTransport.BLE -> "BLE"
    AssessmentTransport.BLUETOOTH_CLASSIC -> "Bluetooth Classic"
    AssessmentTransport.NETWORK -> "Network service"
}

@Composable
private fun TextEntryDialog(title: String, firstLabel: String, secondLabel: String, firstMax: Int, secondMax: Int,
    onDismiss: () -> Unit, extra: @Composable () -> Unit = {}, onSave: (String, String) -> Unit) {
    var first by remember { mutableStateOf("") }
    var second by remember { mutableStateOf("") }
    val noteTooLarge = secondMax == AssessmentRules.MAX_NOTE_BYTES &&
        second.toByteArray(Charsets.UTF_8).size > AssessmentRules.MAX_NOTE_BYTES
    AlertDialog(onDismissRequest = onDismiss, title = { Text(title) }, text = {
        Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedTextField(first, { if (it.length <= firstMax) first = it }, label = { Text(firstLabel) }, singleLine = true)
            OutlinedTextField(second, { if (it.length <= secondMax) second = it }, label = { Text(secondLabel) }, minLines = 3, maxLines = 8)
            if (noteTooLarge) Text("This note exceeds 64 KiB in UTF-8. Shorten it before saving.", color = MaterialTheme.colorScheme.error)
            extra()
        }
    }, confirmButton = { TextButton(onClick = { onSave(first, second) }, enabled = first.isNotBlank() && second.isNotBlank() && !noteTooLarge) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
private fun AssetDialog(onDismiss: () -> Unit, onSave: (String, String, AssessmentTransport) -> Unit) {
    var transport by remember { mutableStateOf(AssessmentTransport.NETWORK) }
    TextEntryDialog("Add target record", "Label", "Identifier (MAC, host or endpoint)", 100, 512, onDismiss,
        extra = {
            AssessmentTransport.entries.forEach { item ->
                Row {
                    RadioButton(selected = item == transport, onClick = { transport = item })
                    TextButton(onClick = { transport = item }) { Text(item.displayName()) }
                }
            }
        }) { label, identifier -> onSave(label, identifier, transport) }
}

@Composable
private fun FindingDialog(onDismiss: () -> Unit, onSave: (String, String, FindingSeverity) -> Unit) {
    var severity by remember { mutableStateOf(FindingSeverity.INFORMATIONAL) }
    TextEntryDialog("Suspected finding", "Title", "Explanation and limitations", 120, 4000, onDismiss,
        extra = {
            Text("This is an operator assessment, not an automated confirmation.")
            FindingSeverity.entries.forEach { item ->
                Row {
                    RadioButton(selected = item == severity, onClick = { severity = item })
                    TextButton(onClick = { severity = item }) { Text(item.name.lowercase().replaceFirstChar { it.uppercase() }) }
                }
            }
        }) { title, description -> onSave(title, description, severity) }
}

@Composable
private fun ConfirmAssessmentDialog(title: String, body: String, confirm: String, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(onDismissRequest = onDismiss, title = { Text(title) }, text = { Text(body) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}
