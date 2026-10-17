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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import app.fieldwatch.domain.*
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
    var checkError by remember(selectedId) { mutableStateOf<String?>(null) }
    var devicePreview by remember(selectedId) { mutableStateOf<DeviceValidationReport?>(null) }
    var operatorPreview by remember(selectedId) { mutableStateOf<HandsetBaseline?>(null) }
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json"), vm::writeReport)
    LaunchedEffect(exportRequested) {
        if (exportRequested) {
            vm.exportLaunched()
            try { exporter.launch("fieldwatch-assessment-${System.currentTimeMillis()}.json") }
            catch (_: android.content.ActivityNotFoundException) { vm.exportFailed() }
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
                        OutlinedButton(onClick = { dialog = "asset" }, enabled = editable) { Text("Add target") }
                        OutlinedButton(onClick = {
                            runCatching { app.fieldwatch.data.HandsetBaselineCollector.capture(context) }
                                .onSuccess { operatorPreview = it }.onFailure { checkError = "Handset baseline unavailable: ${it.message}" }
                        }, enabled = editable) { Text("Review this phone's baseline") }
                        OutlinedButton(onClick = { vm.prepareReport(false) }, enabled = !busy) { Text("Export summary") }
                        OutlinedButton(onClick = { dialog = "full-export" }, enabled = !busy) { Text("Export full report") }
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
                                Text(evidence.text)
                                Text("Source: ${evidence.source} · catalog ${evidence.catalogVersion}\nSHA-256: ${evidence.sha256}", style = MaterialTheme.typography.bodySmall)
                                if (AssessmentChecks.supports(evidence.source)) OutlinedButton(onClick = {
                                    runCatching { AssessmentChecks.evaluate(selected, evidence.id, System.currentTimeMillis()) }
                                        .onSuccess { checkPreview = it }.onFailure { checkError = "This evidence cannot be evaluated: ${it.message}" }
                                }, enabled = editable) { Text("Review versioned checks") }
                                if (evidence.source == "service-inspection") OutlinedButton(onClick = {
                                    runCatching { DeviceValidation.evaluate(selected, evidence.id, System.currentTimeMillis()) }
                                        .onSuccess { devicePreview = it }.onFailure { checkError = "Device validation unavailable: ${it.message}" }
                                }, enabled = editable) { Text("Review reference lab module") }
                                TextButton(onClick = { targetEvidence = evidence.id; dialog = "finding" }, enabled = editable) { Text("Record suspected finding") }
                            }
                            selected.findings.filter { it.assetId == asset.id }.forEach { finding ->
                                HorizontalDivider()
                                Text("${finding.confidence} · ${finding.severity}")
                                Text(finding.title, style = MaterialTheme.typography.titleSmall)
                                Text(finding.description)
                                Text(if (finding.checkId == null) "Supported by ${finding.evidenceIds.size} evidence note(s). Operator assessment."
                                    else "Check ${finding.checkId} v${finding.checkVersion} · ${finding.evidenceIds.size} evidence links. Confidence applies only to the stated condition.", style = MaterialTheme.typography.bodySmall)
                                finding.evidenceIds.forEach { id -> Text("Evidence: $id", style = MaterialTheme.typography.bodySmall) }
                            }
                        }
                    }
                }
            }
        }
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
            Text("Offline review only. No target traffic, credential attempts or exploitation. Not observed is not a security pass; confirmed applies only to the narrow recorded condition.")
            preview.results.forEach { result ->
                val check = AssessmentChecks.definition(result.checkId)
                Text("${check.title} · ${result.outcome}", style = MaterialTheme.typography.titleSmall)
                Text(result.explanation)
                if (result.outcome == CheckOutcome.CONDITION_OBSERVED) Text("${check.severity} · ${check.confidence}\n${check.remediation}")
            }
            Text("Saving records every result and creates findings only for observed conditions. Raw evidence and evaluation are linked; no access record is created.")
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
        "close" -> ConfirmAssessmentDialog("Close engagement?", "Finish or cancel running observations first. Closed records remain exportable but cannot be edited.",
            "Close", { dialog = null }) { vm.close(); dialog = null }
        "delete" -> ConfirmAssessmentDialog("Delete engagement?", "Permanently removes this record and its evidence from the app. Export a full report first if you need a copy. Existing exported copies are not deleted.",
            "Delete", { dialog = null }) { vm.delete(); dialog = null }
    }
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
