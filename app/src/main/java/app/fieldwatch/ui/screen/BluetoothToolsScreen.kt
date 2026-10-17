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
import app.fieldwatch.ui.BluetoothToolsViewModel
import app.fieldwatch.ui.NestedTopBar
import app.fieldwatch.ui.ProtectAssessmentScreen
import app.fieldwatch.ui.component.SectionCard
import java.text.DateFormat
import java.util.Date

private data class ToolConfirmation(val title: String, val body: String, val action: () -> Unit)

@Composable
fun BluetoothToolsScreen(target: BluetoothToolTarget, onBack: () -> Unit, vm: BluetoothToolsViewModel = viewModel()) {
    ProtectAssessmentScreen()
    LaunchedEffect(target) { vm.selectTarget(target) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner, vm) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) { Lifecycle.Event.ON_START -> vm.activate(); Lifecycle.Event.ON_STOP -> vm.deactivate(); else -> Unit }
        }
        owner.lifecycle.addObserver(observer)
        if (owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) vm.activate()
        onDispose { owner.lifecycle.removeObserver(observer); vm.deactivate() }
    }
    val state by vm.state.collectAsStateWithLifecycle()
    val archive by vm.archive.collectAsStateWithLifecycle()
    val engagementId by vm.engagement.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val notice by vm.notice.collectAsStateWithLifecycle()
    var confirmation by remember { mutableStateOf<ToolConfirmation?>(null) }
    var chooseEngagement by remember { mutableStateOf(false) }
    var serialUuid by remember { mutableStateOf("1101") }
    var secure by remember { mutableStateOf(true) }
    var inputError by remember { mutableStateOf<String?>(null) }
    val selectedEngagement = archive.engagements.firstOrNull { it.id == engagementId && it.closedAt == null }
    val current = state
    val canOperate = selectedEngagement != null && !busy && current?.pending == null
    val connected = current?.link == BluetoothLinkState.CONNECTED

    Scaffold(topBar = { NestedTopBar("Bluetooth service tools", navigationIcon = { TextButton(onClick = onBack) { Text("Back") } }) }) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding), contentPadding = PaddingValues(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                SectionCard("${target.transport} · ${target.address}") {
                    Text("Explicit service inspection for this target. Android may request pairing. Operations and returned data are not automatic vulnerability or unrestricted-access verdicts.")
                    Text("Leaving or backgrounding this screen closes Fieldwatch's connection. Writes may affect the device; disconnecting cannot guarantee rollback.", style = MaterialTheme.typography.bodySmall)
                    Text("Scope: ${selectedEngagement?.name ?: "select an open engagement"}")
                    OutlinedButton(onClick = { chooseEngagement = true }, enabled = !busy && current?.pending == null && !connected && current?.link != BluetoothLinkState.CONNECTING) { Text("Choose engagement scope") }
                    TextButton(onClick = vm::reload, enabled = !busy) { Text("Reload engagements") }
                }
            }
            if (Build.VERSION.SDK_INT < 33) { item { Text("These tools require Android 13 or newer.") }; return@LazyColumn }
            if (busy) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
            if (current == null) { item { Text("Preparing target tools…") }; return@LazyColumn }
            item {
                SectionCard("Connection and operation status") {
                    Text("${current.link} · ${current.pending?.name ?: "no operation pending"}")
                    Text(current.message)
                    if (current.pending != null) LinearProgressIndicator(Modifier.fillMaxWidth())
                    if (connected || current.pending != null || current.link == BluetoothLinkState.CONNECTING) {
                        Button(onClick = vm::disconnect) { Text("Disconnect / cancel operation") }
                    }
                    OutlinedButton(onClick = vm::saveEvidence, enabled = selectedEngagement != null && !busy && current.events.isNotEmpty()) { Text("Save protocol snapshot as evidence") }
                    TextButton(onClick = { confirmation = ToolConfirmation("Clear unsaved session history?", "Clears this screen's transcript, service inventory and values. Saved engagement evidence is unchanged.", vm::clearHistory) },
                        enabled = !busy && current.link == BluetoothLinkState.DISCONNECTED && current.pending == null) { Text("Clear session history") }
                }
            }
            if (target.transport == AssessmentTransport.BLE) {
                item {
                    SectionCard("BLE GATT") {
                        Button(onClick = { confirmation = ToolConfirmation("Connect to BLE target?", "Connect to ${target.address} within ${selectedEngagement?.name}. Pairing may be requested by Android. No automatic service reads or writes are sent.", vm::connectBle) },
                            enabled = canOperate && current.link == BluetoothLinkState.DISCONNECTED) { Text("Connect BLE") }
                        OutlinedButton(onClick = vm::discoverGatt, enabled = canOperate && connected && current.subscribed.isEmpty()) { Text("Discover GATT services") }
                        Text("Negotiated MTU: ${current.mtu} · single-write limit: ${minOf(512, current.mtu - 3)} bytes")
                        OutlinedButton(onClick = vm::requestMtu, enabled = canOperate && connected && !current.mtuRequested) { Text("Request larger MTU") }
                        Text("Last discovered inventory: ${current.services.size} services · omitted attributes: ${current.omittedAttributes}", style = MaterialTheme.typography.bodySmall)
                        Text("Properties describe advertised operations, not access control. Reads and writes report the actual Android result. Disable subscriptions before rediscovering services.", style = MaterialTheme.typography.bodySmall)
                    }
                }
                current.services.forEach { service ->
                    item(key = "service-${service.key}") { Text("${service.key} · ${service.uuid}\n${if (service.primary) "Primary" else "Secondary"} service", style = MaterialTheme.typography.titleSmall) }
                    items(service.characteristics, key = { "characteristic-${it.key}" }) { characteristic ->
                        GattCharacteristicPanel(characteristic, current, canOperate && connected, vm) { confirmation = it }
                    }
                }
            } else {
                item {
                    SectionCard("Classic service UUIDs") {
                        OutlinedButton(onClick = vm::cachedUuids, enabled = canOperate && current.link == BluetoothLinkState.DISCONNECTED) { Text("Read cached service UUIDs") }
                        OutlinedButton(onClick = vm::fetchSdp, enabled = canOperate && current.link == BluetoothLinkState.DISCONNECTED) { Text("Request SDP service discovery") }
                        Text("Source: ${current.classicUuidSource ?: "none"} · read at: ${current.classicUuidReadAt?.let(::toolTime) ?: "not read"}")
                        Text("Android may return cached UUIDs even after an SDP request. An empty list does not prove no services exist. Not every UUID is an RFCOMM service.", style = MaterialTheme.typography.bodySmall)
                        Text("Omitted UUIDs: ${current.omittedUuids}", style = MaterialTheme.typography.bodySmall)
                        current.classicUuids.forEach { uuid -> TextButton(onClick = { serialUuid = uuid }, enabled = !connected && current.pending == null) { Text(uuid) } }
                    }
                }
                item {
                    SectionCard("RFCOMM serial terminal") {
                        OutlinedTextField(serialUuid, { if (it.length <= 36) serialUuid = it }, label = { Text("Service UUID (1101 is the Serial Port example)") }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                            enabled = current.link == BluetoothLinkState.DISCONNECTED && current.pending == null)
                        Row { Checkbox(secure, { secure = it }, enabled = current.link == BluetoothLinkState.DISCONNECTED && current.pending == null); Text("Authenticated/encrypted socket") }
                        Text("Unchecked requests Android's insecure RFCOMM API. Pairing can still occur; this is not a pairing bypass. There is no automatic fallback or fixed-channel guessing.", style = MaterialTheme.typography.bodySmall)
                        Button(onClick = {
                            runCatching { BluetoothToolValues.uuid(serialUuid) }.onSuccess { uuid ->
                                val requestedSecure = secure
                                confirmation = ToolConfirmation("Connect RFCOMM service?", "Target ${target.address}\nService $uuid\n${if (requestedSecure) "Authenticated/encrypted" else "Insecure"} socket requested. Android may ask to pair.") { vm.connectRfcomm(uuid, requestedSecure) }
                            }.onFailure { inputError = it.message }
                        }, enabled = canOperate && current.link == BluetoothLinkState.DISCONNECTED) { Text("Connect serial service") }
                        PayloadEntry("Send serial bytes", enabled = canOperate && connected) { bytes, _ ->
                            confirmation = ToolConfirmation("Send ${bytes.size} bytes?", "To ${target.address} using the connected RFCOMM service. Bytes may act as commands. Peer processing and rollback are not guaranteed.\nHex: ${BluetoothToolValues.hex(bytes)}") { vm.send(bytes) }
                        }
                    }
                }
            }
            item {
                SectionCard("Bounded protocol transcript") {
                    Text("${current.events.size}/64 retained events · ${current.discardedEvents} history events omitted · ${current.droppedNotifications} notification queue overflows")
                    Text("Reported payload received: ${current.receivedBytes} bytes · serial writes completed: ${current.sentBytes} bytes")
                    Text("Payload preview is limited to 512 bytes per event. Hex is authoritative; UTF-8 previews may split characters at packet boundaries. Save snapshots before clearing or leaving the target.", style = MaterialTheme.typography.bodySmall)
                }
            }
            items(current.events.asReversed(), key = { "event-${it.sequence}" }) { event ->
                SectionCard("${event.kind} · ${toolTime(event.at)}") {
                    Text("Session ${event.session} · ${event.message}")
                    event.handle?.let { Text("Attribute: $it") }
                    event.status?.let { Text("Android status: $it (${BluetoothToolValues.statusLabel(it)})") }
                    event.payloadHex?.let { hex ->
                        Text("${event.byteCount} bytes${if (event.truncated) " (preview truncated)" else ""}\nHex: $hex")
                        Text("UTF-8 preview: ${BluetoothToolValues.preview(hex)}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
    if (chooseEngagement) AlertDialog(onDismissRequest = { chooseEngagement = false }, title = { Text("Confirm target scope") }, text = {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Text("Choose the authorized scope for ${target.address}. This adds its target record; it does not connect. Save or clear transcript history before switching scopes.")
            archive.engagements.filter { it.closedAt == null }.asReversed().forEach { engagement ->
                Text(engagement.name, style = MaterialTheme.typography.titleSmall)
                Text(engagement.scope)
                TextButton(onClick = { vm.selectEngagement(engagement.id); chooseEngagement = false }, enabled = !busy) { Text("Use this scope") }
            }
            if (archive.engagements.none { it.closedAt == null }) Text("Create an open engagement in Assessments first.")
        }
    }, confirmButton = { TextButton(onClick = { chooseEngagement = false }) { Text("Cancel") } })
    confirmation?.let { frozen -> AlertDialog(onDismissRequest = { confirmation = null }, title = { Text(frozen.title) },
        text = { Text(frozen.body, Modifier.verticalScroll(rememberScrollState())) }, confirmButton = { TextButton(onClick = { confirmation = null; frozen.action() }) { Text("Proceed") } },
        dismissButton = { TextButton(onClick = { confirmation = null }) { Text("Cancel") } }) }
    val displayedNotice = notice ?: inputError
    if (displayedNotice != null) AlertDialog(onDismissRequest = { vm.dismissNotice(); inputError = null }, title = { Text("Bluetooth tools notice") },
        text = { Text(displayedNotice) }, confirmButton = { TextButton(onClick = { vm.dismissNotice(); inputError = null }) { Text("OK") } })
}

@Composable
private fun GattCharacteristicPanel(characteristic: GattCharacteristicInfo, state: BluetoothToolState, enabled: Boolean,
    vm: BluetoothToolsViewModel, confirm: (ToolConfirmation) -> Unit) {
    SectionCard("${characteristic.key} · ${characteristic.uuid}") {
        Text(BluetoothToolValues.properties(characteristic.properties))
        state.values[characteristic.key]?.let { Text("Last successful value at ${toolTime(it.at)}: ${it.byteCount} bytes${if (it.truncated) " (truncated)" else ""}\nHex: ${it.hex}") }
        OutlinedButton(onClick = { vm.readCharacteristic(characteristic.key) }, enabled = enabled && characteristic.properties and BluetoothToolValues.READ != 0) { Text("Read characteristic") }
        if (characteristic.properties and (BluetoothToolValues.WRITE or BluetoothToolValues.WRITE_NO_RESPONSE) != 0) {
            key(state.session, characteristic.key, characteristic.uuid) {
            PayloadEntry("Write characteristic", enabled, characteristic.properties and BluetoothToolValues.WRITE_NO_RESPONSE != 0,
                responseAvailable = characteristic.properties and BluetoothToolValues.WRITE != 0) { bytes, noResponse ->
                confirm(ToolConfirmation("Write ${bytes.size} bytes?", "Target ${state.target.address}\nAttribute ${characteristic.key} · ${characteristic.uuid}\n${if (noResponse) "No remote write response requested." else "Write response requested."}\nMay change device state; rollback is not guaranteed.\nHex: ${BluetoothToolValues.hex(bytes)}") {
                    vm.writeCharacteristic(characteristic.key, bytes, noResponse)
                })
            }
            }
        }
        if (characteristic.properties and (BluetoothToolValues.NOTIFY or BluetoothToolValues.INDICATE) != 0) {
            val enable = characteristic.key !in state.subscribed
            OutlinedButton(onClick = { confirm(ToolConfirmation(if (enable) "Enable value changes?" else "Disable value changes?",
                "Changes the remote client configuration for ${characteristic.key}. Disconnect stops this app's subscription; persistent remote configuration may not roll back.") { vm.notifications(characteristic.key, enable) }) }, enabled = enabled) {
                Text(if (enable) "Enable notifications / indications" else "Disable notifications / indications")
            }
        }
        characteristic.descriptors.forEach { descriptor ->
            Text("${descriptor.key} · ${descriptor.uuid}", style = MaterialTheme.typography.bodySmall)
            state.values[descriptor.key]?.let { Text("Descriptor value at ${toolTime(it.at)}: ${it.hex}", style = MaterialTheme.typography.bodySmall) }
            TextButton(onClick = { vm.readDescriptor(descriptor.key) }, enabled = enabled) { Text("Read descriptor") }
        }
    }
}

@Composable
private fun PayloadEntry(label: String, enabled: Boolean, noResponseAvailable: Boolean = false, responseAvailable: Boolean = true,
    send: (ByteArray, Boolean) -> Unit) {
    var input by remember { mutableStateOf("") }
    var hex by remember { mutableStateOf(true) }
    var crlf by remember { mutableStateOf(false) }
    var noResponse by remember { mutableStateOf(!responseAvailable) }
    var error by remember { mutableStateOf<String?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        OutlinedTextField(input, { if (it.length <= 2048) input = it }, label = { Text(if (hex) "Hex bytes" else "UTF-8 text") }, modifier = Modifier.fillMaxWidth(), maxLines = 4)
        Row { Checkbox(hex, { hex = it }); Text("Hex input") }
        if (!hex) Row { Checkbox(crlf, { crlf = it }); Text("Append CRLF") }
        if (noResponseAvailable && responseAvailable) Row { Checkbox(noResponse, { noResponse = it }); Text("Write without response") }
        OutlinedButton(onClick = {
            runCatching { BluetoothToolValues.bytes(input + if (!hex && crlf) "\r\n" else "", hex) }
                .onSuccess { error = null; send(it.copyOf(), noResponse) }.onFailure { error = it.message }
        }, enabled = enabled && input.isNotEmpty()) { Text(label) }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}

private fun toolTime(at: Long): String = DateFormat.getDateTimeInstance().format(Date(at))
