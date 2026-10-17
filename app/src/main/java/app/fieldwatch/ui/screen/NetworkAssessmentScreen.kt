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
    val wifi by vm.wifi.collectAsStateWithLifecycle()
    var engagement by remember { mutableStateOf<String?>(null) }
    var scope by remember { mutableStateOf("") }
    var ports by remember { mutableStateOf("80,443,22,8080") }
    var confirm by remember { mutableStateOf(false) }
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
            items(report?.observations.orEmpty()) { row -> Text("${row.address}:${row.port} · ${row.outcome}") }
            item { SectionCard("Wi-Fi security inventory") {
                Text("Existing scan observations; no new scan is started here. Advertisement flags may be incomplete or retained from an earlier sighting. Configuration concerns do not confirm a vulnerability.")
                Text("Showing ${wifi.size} Wi-Fi records (up to 100). Save radio metadata through the radio inventory; security analysis evidence export follows in the next M4 step.")
            } }
            items(wifi, key = { it.key }) { row -> SectionCard(row.name.ifBlank { "Hidden SSID" }) {
                Text("${row.mac} · channel ${row.channel} · last seen ${Date(row.lastSeen)}")
                Text(WifiSecurityAnalysis.describe(row.facts.capabilities))
                Text("Capabilities: ${row.facts.capabilities ?: "unavailable"}")
                Text("Parsed security: ${row.facts.security ?: "unavailable"}")
            } }
        }
    }
    if (confirm) AlertDialog(onDismissRequest = { confirm = false }, title = { Text("Confirm authorized scope") },
        text = { Text("Engagement: ${archive.engagements.firstOrNull { it.id == engagement }?.name}\nScope: $scope\nTCP ports: $ports\n\nI am authorized to connect to every target in this scope. TCP handshakes may affect or be logged by devices.") },
        confirmButton = { TextButton(onClick = { confirm = false; engagement?.let { vm.start(it, scope, ports) } }) { Text("Start checks") } },
        dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } })
}
