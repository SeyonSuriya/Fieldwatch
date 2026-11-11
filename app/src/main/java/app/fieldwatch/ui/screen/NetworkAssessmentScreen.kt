package app.fieldwatch.ui.screen

import android.os.Build
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import app.fieldwatch.domain.*
import app.fieldwatch.ui.NetworkAssessmentViewModel
import app.fieldwatch.ui.NestedTopBar
import app.fieldwatch.ui.ProtectAssessmentScreen
import app.fieldwatch.ui.component.SectionCard
import java.util.Date

@Composable
fun NetworkAssessmentScreen(onBack: () -> Unit, vm: NetworkAssessmentViewModel = viewModel()) {
    ProtectAssessmentScreen()
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner, vm) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_STOP) vm.stop() }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer); vm.stop() }
    }
    val archive by vm.archive.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val notice by vm.notice.collectAsStateWithLifecycle()
    val report by vm.report.collectAsStateWithLifecycle()
    val reportEngagement by vm.reportEngagement.collectAsStateWithLifecycle()
    val service by vm.service.collectAsStateWithLifecycle()
    val tlsAudit by vm.tlsAudit.collectAsStateWithLifecycle()
    val serviceEngagement by vm.serviceEngagement.collectAsStateWithLifecycle()
    val wifi by vm.wifi.collectAsStateWithLifecycle()
    var engagement by remember { mutableStateOf<String?>(null) }
    var scope by remember { mutableStateOf("") }
    var ports by remember { mutableStateOf("80,443,22,8080") }
    var confirm by remember { mutableStateOf(false) }
    var serviceAddress by remember { mutableStateOf("") }
    var servicePort by remember { mutableStateOf("80") }
    var probe by remember { mutableStateOf(ServiceProbe.BANNER) }
    var pendingInspection by remember { mutableStateOf<PendingInspection?>(null) }
    var pendingWifi by remember { mutableStateOf<Pair<String, WifiSecurityReport>?>(null) }
    var validationMessage by remember { mutableStateOf<String?>(null) }
    Scaffold(topBar = { NestedTopBar("Network assessment", navigationIcon = { TextButton(onClick = onBack) { Text("Back") } }) }) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding).padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                if (Build.VERSION.SDK_INT < 33) { Text("Assessments require Android 13+."); return@item }
                SectionCard("Connected Wi-Fi checks") {
                    Text("Choose an authorized engagement, then enter a numeric IPv4 address or /24–/32 range on this Wi-Fi subnet. Up to 16 TCP ports and 256 address/port pairs; four simultaneous connections, 800 ms each.")
                    Text("Connections may be logged by targets. No-response does not establish that a device is offline. These checks send no application payloads.")
                    archive.engagements.filter { it.closedAt == null }.forEach { row ->
                        OutlinedButton(onClick = { engagement = row.id }, enabled = !busy) { Text(if (engagement == row.id) "Selected: ${row.name}" else row.name) }
                        if (engagement == row.id) Text(row.scope)
                    }
                    OutlinedTextField(scope, { scope = it }, label = { Text("IPv4 address or CIDR scope") }, enabled = !busy, singleLine = true)
                    OutlinedTextField(ports, { ports = it }, label = { Text("TCP ports, comma-separated") }, enabled = !busy, singleLine = true)
                    Button(onClick = { confirm = true }, enabled = !busy && engagement != null) { Text("Review and start") }
                    OutlinedButton(onClick = vm::stop, enabled = busy) { Text("Stop") }
                    Text(notice)
                    if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                    if (report != null) {
                        Text("Result scope: ${report!!.scope} · TCP ${report!!.ports.joinToString()} · ${Date(report!!.startedAt)}")
                        Text("Evidence destination: $reportEngagement (fixed when this run started)")
                        Text("${report!!.observations.size} completed probes · ${if (report!!.cancelled) "partial/stopped" else "complete"} · ${report!!.network}")
                        Button(onClick = vm::save, enabled = !busy && report!!.observations.isNotEmpty()) { Text("Save encrypted evidence") }
                    }
                }
            }
            items(report?.observations.orEmpty()) { row ->
                Column {
                    Text("${row.address}:${row.port} · ${row.outcome}")
                    if (row.outcome == "open") TextButton(onClick = { serviceAddress = row.address; servicePort = row.port.toString() }, enabled = !busy) { Text("Select for inspection") }
                }
            }
            if (Build.VERSION.SDK_INT >= 33) item { SectionCard("Inspect one service") {
                Text("Uses the selected open engagement above. Choose the protocol explicitly; port numbers do not identify services. Banner mode sends no application payload. HTTP sends HEAD /; redirects, bodies, credentials and cookies are not requested or followed.")
                Text("TLS requires a trusted certificate valid for the numeric IP address. Self-signed or hostname-only certificates may fail; no insecure retry is made. Capture limit: 4 KiB; deadline: five seconds.")
                OutlinedTextField(serviceAddress, { serviceAddress = it }, label = { Text("Numeric IPv4 target") }, enabled = !busy, singleLine = true)
                OutlinedTextField(servicePort, { servicePort = it }, label = { Text("TCP port") }, enabled = !busy, singleLine = true)
                ServiceProbe.entries.forEach { mode -> OutlinedButton(onClick = { probe = mode }, enabled = !busy) {
                    Text((if (probe == mode) "Selected: " else "") + when (mode) {
                        ServiceProbe.BANNER -> "Read banner"
                        ServiceProbe.HTTP_HEAD -> "HTTP HEAD /"
                        ServiceProbe.TLS -> "TLS handshake"
                        ServiceProbe.HTTPS_HEAD -> "HTTPS HEAD /"
                    })
                } }
                Button(onClick = { engagement?.let { pendingInspection = PendingInspection(it, serviceAddress.trim(), servicePort.trim(), probe) } }, enabled = !busy && engagement != null) { Text("Review inspection") }
                OutlinedButton(onClick = {
                    engagement?.let { pendingInspection = PendingInspection(it, serviceAddress.trim(), servicePort.trim(), ServiceProbe.TLS, audit = true) }
                }, enabled = !busy && engagement != null) { Text("Review TLS version audit") }
                tlsAudit.firstOrNull()?.let { endpoint ->
                    Text("TLS versions on ${endpoint.address}:${endpoint.port}", style = MaterialTheme.typography.titleMedium)
                    Text("Evidence destination: $serviceEngagement")
                    for (attempt in tlsAudit) {
                        val result = when (attempt.outcome) {
                            "observed" -> "Verified handshake"
                            "tls-version-unavailable" -> "Version disabled on this phone"
                            "timeout" -> "Timed out"
                            "connection-or-io-error" -> "Connection or I/O error"
                            else -> "Handshake or certificate validation failed"
                        }
                        Text("${attempt.requestedTlsProtocol} · $result")
                        attempt.tlsCipher?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                    }
                    Button(onClick = vm::saveTlsAudit, enabled = !busy) { Text("Save TLS audit evidence") }
                }
                service?.let { result ->
                    val label = remember(result) { ServiceInspection.advertisedLabel(result) }
                    Text(label ?: ServiceInspection.identify(result.receivedHex), style = MaterialTheme.typography.titleMedium)
                    Text("${result.address}:${result.port} · ${result.probe} · ${result.outcome} · ${Date(result.startedAt)}")
                    Text("Evidence destination: $serviceEngagement (fixed when inspection started)")
                    if (result.attemptedRequestHex.isNotEmpty()) Text("Request attempted:\n${ServiceInspection.display(result.attemptedRequestHex)}")
                    if (result.tlsProtocol != null) Text("Verified TLS session: ${result.tlsProtocol} · ${result.tlsCipher}\nLeaf certificate SHA-256: ${result.certificateSha256}")
                    if (result.captureLimitReached) Text("Capture limit reached; additional bytes may exist.")
                    if (result.receivedHex.isNotEmpty()) {
                        Text("Response preview (control bytes replaced):\n${ServiceInspection.display(result.receivedHex)}")
                        Text("Authoritative bytes (hex): ${result.receivedHex}", style = MaterialTheme.typography.bodySmall)
                    }
                    Button(onClick = vm::saveService, enabled = !busy) { Text("Save inspection evidence") }
                }
            } }
            item { SectionCard("Wi-Fi security inventory") {
                Text("Existing scan observations; no new scan is started here. Advertisement flags may be incomplete or retained from an earlier sighting. Configuration concerns do not confirm a vulnerability.")
                Text("Showing ${wifi.size} Wi-Fi records (up to 100). Save a frozen security snapshot to the selected engagement. Raw flags and observation times are retained; full JSON export includes them.")
                validationMessage?.let { Text(it) }
            } }
            items(wifi, key = { it.key }) { row -> SectionCard(row.name.ifBlank { "Hidden SSID" }) {
                Text("${row.mac} · channel ${row.channel} · last seen ${Date(row.lastSeen)}")
                Text(WifiSecurityAnalysis.describe(row.facts.capabilities))
                Text("Capabilities: ${row.facts.capabilities ?: "unavailable"}")
                Text("Parsed security: ${row.facts.security ?: "unavailable"}")
                OutlinedButton(onClick = {
                    runCatching { WifiSecurityReport.from(row, System.currentTimeMillis()) }
                        .onSuccess { snapshot -> engagement?.let { pendingWifi = it to snapshot }; validationMessage = null }
                        .onFailure { validationMessage = "This Wi-Fi record cannot be saved: ${it.message}" }
                }, enabled = !busy && engagement != null && Build.VERSION.SDK_INT >= 33) { Text("Review security snapshot") }
            } }
        }
    }
    if (confirm) AlertDialog(onDismissRequest = { confirm = false }, title = { Text("Confirm authorized scope") },
        text = { Text("Engagement: ${archive.engagements.firstOrNull { it.id == engagement }?.name}\nScope: $scope\nTCP ports: $ports\n\nI am authorized to connect to every target in this scope. TCP handshakes may affect or be logged by devices.") },
        confirmButton = { TextButton(onClick = { confirm = false; engagement?.let { vm.start(it, scope, ports) } }) { Text("Start checks") } },
        dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } })
    pendingInspection?.let { pending ->
        val method = if (pending.audit) "Up to four connections to check TLS 1.0 through 1.3. Each version enabled on this phone gets one handshake with certificate verification."
            else "Mode: ${pending.probe}. HTTP modes send HEAD /. TLS modes verify the certificate."
        AlertDialog(onDismissRequest = { pendingInspection = null },
            title = { Text(if (pending.audit) "Confirm TLS version audit" else "Confirm service inspection") },
            text = { Text("Engagement: ${archive.engagements.firstOrNull { it.id == pending.engagement }?.name}\nTarget: ${pending.address}:${pending.port}\n\n$method\n\nI am authorized to inspect this target. Connections may be logged by the service.") },
            confirmButton = { TextButton(onClick = {
                pendingInspection = null
                if (pending.audit) vm.auditTls(pending.engagement, pending.address, pending.port)
                else vm.inspect(pending.engagement, pending.address, pending.port, pending.probe)
            }) { Text(if (pending.audit) "Start audit" else "Inspect") } },
            dismissButton = { TextButton(onClick = { pendingInspection = null }) { Text("Cancel") } })
    }
    pendingWifi?.let { (destination, snapshot) ->
        AlertDialog(onDismissRequest = { pendingWifi = null }, title = { Text("Save Wi-Fi security evidence") },
            text = { Text("Engagement: ${archive.engagements.firstOrNull { it.id == destination }?.name}\nBSSID: ${snapshot.bssid}\nSSID: ${snapshot.ssid}\nLast observed: ${Date(snapshot.lastSeen)}\n\n${snapshot.analysis}\n\nThis target is within the engagement's authorized scope. This saves the frozen advertisement; no active test is performed.") },
            confirmButton = { TextButton(onClick = { pendingWifi = null; vm.saveWifi(destination, snapshot) }) { Text("Save encrypted snapshot") } },
            dismissButton = { TextButton(onClick = { pendingWifi = null }) { Text("Cancel") } })
    }
}

private data class PendingInspection(val engagement: String, val address: String, val port: String, val probe: ServiceProbe, val audit: Boolean = false)
