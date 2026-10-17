package app.fieldwatch.ui.screen

import android.os.Build
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import app.fieldwatch.ui.InventoryViewModel
import app.fieldwatch.ui.NestedTopBar
import app.fieldwatch.ui.ProtectAssessmentScreen
import app.fieldwatch.ui.component.SectionCard
import java.text.DateFormat
import java.util.Date

@Composable
fun InventoryScreen(onBack: () -> Unit, onOpenTools: (InventoryRadio) -> Unit, vm: InventoryViewModel = viewModel()) {
    ProtectAssessmentScreen()
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, vm) {
        val observer = LifecycleEventObserver { _, event ->
            if (Build.VERSION.SDK_INT >= 33) when (event) {
                Lifecycle.Event.ON_START -> vm.activate()
                Lifecycle.Event.ON_STOP -> vm.deactivate()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        if (Build.VERSION.SDK_INT >= 33 && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) vm.activate()
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer); vm.deactivate() }
    }
    val rows by vm.rows.collectAsStateWithLifecycle()
    val discovery by vm.discovery.collectAsStateWithLifecycle()
    val archive by vm.archive.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val ready by vm.ready.collectAsStateWithLifecycle()
    val notice by vm.notice.collectAsStateWithLifecycle()
    val stats by vm.scanStats.collectAsStateWithLifecycle()
    var query by remember { mutableStateOf("") }
    var transport by remember { mutableStateOf<AssessmentTransport?>(null) }
    var observedOnly by remember { mutableStateOf(false) }
    var pairedOnly by remember { mutableStateOf(false) }
    var snapshot by remember { mutableStateOf<InventoryRadio?>(null) }
    var clearConfirm by remember { mutableStateOf(false) }
    val visible = remember(rows, query, transport, observedOnly, pairedOnly) {
        RadioInventory.filter(rows, query, transport, observedOnly, pairedOnly)
    }

    Scaffold(topBar = { NestedTopBar("Radio inventory", navigationIcon = {
        TextButton(onClick = onBack) { Text("Back") }
    }) }) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                SectionCard("Unified radio records") {
                    Text("Wi-Fi and BLE use the existing collectors. Classic inquiry is active, finds discoverable devices, and can affect Bluetooth audio or BLE scanning.")
                    Text("Records represent radio interfaces, not unique physical devices. Paired records alone do not prove presence.", style = MaterialTheme.typography.bodySmall)
                    Text(if (stats.scanning) "Existing Wi-Fi/BLE collection is enabled." else "Existing Wi-Fi/BLE collection is stopped. Start it from Live to receive updates.")
                }
            }
            if (Build.VERSION.SDK_INT < 33) {
                item { Text("Assessment inventory requires Android 13 or newer.") }
                return@LazyColumn
            }
            item {
                SectionCard("Bluetooth Classic inquiry") {
                    Text(discovery.message)
                    if (discovery.ownsInquiry) {
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                        Button(onClick = vm::stopInquiry) { Text("Stop inquiry") }
                    } else {
                        Button(onClick = vm::startInquiry) { Text("Start one Classic inquiry") }
                    }
                    Text("One cycle, at most 30 seconds. Leaving this screen cancels Fieldwatch's inquiry; it does not cancel a discovery already owned elsewhere.", style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = vm::refreshPaired) { Text("Refresh paired records") }
                    Text("Pairing history read: ${discovery.pairedReadAt?.let(::inventoryTime) ?: "not read"}", style = MaterialTheme.typography.bodySmall)
                    Text("Bluetooth cache limit: 500 records · omitted/evicted events: ${discovery.dropped} · rejected observations: ${discovery.rejected}", style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = { clearConfirm = true }, enabled = !discovery.ownsInquiry) { Text("Clear Bluetooth session history") }
                }
            }
            item {
                SectionCard("Filter inventory") {
                    Text("${rows.size} total records · ${rows.count { it.lastSeen != null }} observed · ${rows.count { it.paired }} paired · ${visible.size} shown")
                    OutlinedTextField(query, { if (it.length <= 100) query = it }, label = { Text("Search name, address or vendor") },
                        singleLine = true, modifier = Modifier.fillMaxWidth())
                    Row {
                        TextButton(onClick = { transport = null }) { Text(if (transport == null) "All ✓" else "All") }
                        listOf(AssessmentTransport.WIFI, AssessmentTransport.BLE, AssessmentTransport.BLUETOOTH_CLASSIC).forEach { item ->
                            TextButton(onClick = { transport = item }) { Text(item.inventoryLabel() + if (transport == item) " ✓" else "") }
                        }
                    }
                    Row { Checkbox(observedOnly, { observedOnly = it }); TextButton(onClick = { observedOnly = !observedOnly }) { Text("Observed records only") } }
                    Row { Checkbox(pairedOnly, { pairedOnly = it }); TextButton(onClick = { pairedOnly = !pairedOnly }) { Text("Paired records only") } }
                    Text("Observed means a collector reported it at the displayed time. It does not guarantee the radio is still present.", style = MaterialTheme.typography.bodySmall)
                }
            }
            if (!ready) item {
                Text("Engagement storage is not loaded. Discovery remains available.")
                OutlinedButton(onClick = vm::load, enabled = !busy) { Text("Retry loading engagement storage") }
            }
            if (busy) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
            if (visible.isEmpty()) item { Text("No matching records. Classic devices generally need to be discoverable to appear in an inquiry.") }
            items(visible, key = { it.key }) { row ->
                SectionCard(row.label) {
                    Text("${row.transport.inventoryLabel()} · ${row.identifier}")
                    Text("Source: ${row.source.inventoryLabel()}")
                    Text(row.lastSeen?.let { "Last observed: ${inventoryTime(it)}" } ?: "Not observed by a collector in this session")
                    row.rssi?.let { Text("Reported RSSI: $it dBm") }
                    if (row.paired) Text("Listed in pairing history; connection state is not checked")
                    if (row.dualMode) Text("Android reports dual-mode Bluetooth; BLE/Classic records are kept separate")
                    if (!row.transportConfirmed) Text("Android has not confirmed this record's Bluetooth transport")
                    row.deviceClass?.let { code ->
                        Text("Device class: ${CodDecoder.decode(code).summary()} (0x${code.toString(16)})", style = MaterialTheme.typography.bodySmall)
                    }
                    row.vendor?.let { Text("Vendor lookup: $it", style = MaterialTheme.typography.bodySmall) }
                    if (row.transport == AssessmentTransport.BLE || row.transport == AssessmentTransport.BLUETOOTH_CLASSIC) {
                        OutlinedButton(onClick = { vm.stopInquiry(); onOpenTools(row) }, enabled = !busy) { Text("Open Bluetooth service tools") }
                    }
                    OutlinedButton(onClick = { snapshot = row }, enabled = ready && !busy && archive.engagements.any { it.closedAt == null }) {
                        Text("Save snapshot to engagement")
                    }
                }
            }
            item { Text("Snapshots are saved only when selected. Bluetooth service tools open a separate connection screen. Network host discovery remains a later milestone.", style = MaterialTheme.typography.bodySmall) }
        }
    }
    snapshot?.let { frozen ->
        AlertDialog(onDismissRequest = { snapshot = null }, title = { Text("Choose an open engagement") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    Text("Save the displayed ${frozen.transport.inventoryLabel()} record (${frozen.identifier}) as encrypted evidence. This does not connect to the radio or confirm a vulnerability.")
                    archive.engagements.filter { it.closedAt == null }.asReversed().forEach { engagement ->
                        TextButton(onClick = { vm.save(engagement.id, frozen); snapshot = null }, enabled = !busy) { Text(engagement.name) }
                    }
                }
            }, confirmButton = { TextButton(onClick = { snapshot = null }) { Text("Cancel") } })
    }
    if (clearConfirm) AlertDialog(onDismissRequest = { clearConfirm = false }, title = { Text("Clear Bluetooth session history?") },
        text = { Text("Clears this screen's Bluetooth observations and counters, then reads pairing history again. Saved engagement evidence and existing Wi-Fi/BLE scan history are unchanged.") },
        confirmButton = { TextButton(onClick = { vm.clearClassic(); clearConfirm = false }) { Text("Clear") } },
        dismissButton = { TextButton(onClick = { clearConfirm = false }) { Text("Cancel") } })
    if (notice != null) AlertDialog(onDismissRequest = vm::dismissNotice, title = { Text("Inventory notice") }, text = { Text(notice.orEmpty()) },
        confirmButton = { TextButton(onClick = vm::dismissNotice) { Text("OK") } })
}

private fun inventoryTime(timestamp: Long): String = DateFormat.getDateTimeInstance().format(Date(timestamp))
private fun AssessmentTransport.inventoryLabel(): String = when (this) {
    AssessmentTransport.WIFI -> "Wi-Fi"
    AssessmentTransport.BLE -> "BLE"
    AssessmentTransport.BLUETOOTH_CLASSIC -> "Classic"
    AssessmentTransport.NETWORK -> "Network"
}
private fun InventorySource.inventoryLabel(): String = when (this) {
    InventorySource.WIFI_SCAN -> "Wi-Fi scan"
    InventorySource.BLE_ADVERTISEMENT -> "BLE advertisement"
    InventorySource.CLASSIC_INQUIRY -> "Classic inquiry"
    InventorySource.BONDED_RECORD -> "Android pairing history"
}
