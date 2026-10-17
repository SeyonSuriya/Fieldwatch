package app.fieldwatch.ui

import android.app.Application
import android.annotation.SuppressLint
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.fieldwatch.FieldwatchApp
import app.fieldwatch.domain.*
import app.fieldwatch.radio.BluetoothToolClient
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

// The client is constructed only after the SDK 33 check in selectTarget.
@SuppressLint("NewApi")
class BluetoothToolsViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application as FieldwatchApp
    private var client: BluetoothToolClient? = null
    private var collector: Job? = null
    private var ticker: Job? = null
    val archive = app.assessments.archive
    private val mutableState = MutableStateFlow<BluetoothToolState?>(null)
    val state = mutableState.asStateFlow()
    private val mutableEngagement = MutableStateFlow<String?>(null)
    val engagement = mutableEngagement.asStateFlow()
    private val mutableBusy = MutableStateFlow(false)
    val busy = mutableBusy.asStateFlow()
    private val mutableNotice = MutableStateFlow<String?>(null)
    val notice = mutableNotice.asStateFlow()
    private var ready = false

    init { reload() }
    fun reload() = persistAction { app.assessments.load(); ready = true }

    fun selectTarget(target: BluetoothToolTarget) {
        if (Build.VERSION.SDK_INT < 33 || client?.state?.value?.target == target) return
        client?.close(); collector?.cancel()
        client = BluetoothToolClient(app, target, viewModelScope)
        mutableState.value = client!!.state.value
        mutableEngagement.value = null
        collector = viewModelScope.launch { client!!.state.collect { mutableState.value = it } }
    }

    fun activate() {
        if (ticker?.isActive == true) return
        ticker = viewModelScope.launch { while (isActive) { delay(1000); client?.controller?.expire() } }
    }
    fun deactivate() { ticker?.cancel(); ticker = null; client?.close() }
    fun dismissNotice() { mutableNotice.value = null }
    fun selectEngagement(id: String) = persistAction {
        check(ready) { "Engagement storage has not loaded." }
        val current = client?.state?.value ?: error("Select a Bluetooth target.")
        check(current.link == BluetoothLinkState.DISCONNECTED && current.pending == null) { "Disconnect before changing engagement." }
        check(mutableEngagement.value == null || mutableEngagement.value == id || current.events.isEmpty()) {
            "Save or clear this target's transcript before switching engagement."
        }
        val engagement = archive.value.engagements.singleOrNull { it.id == id && it.closedAt == null } ?: error("Select an open engagement.")
        if (engagement.assets.none { it.transport == current.target.transport && it.identifier.equals(current.target.address, true) }) {
            app.assessments.addAsset(id, "${current.target.transport} ${current.target.address}", current.target.address, current.target.transport)
        }
        mutableEngagement.value = id
    }

    fun connectBle() = tool { it.connectBle() }
    fun connectRfcomm(uuid: String, secure: Boolean) = tool { it.connectRfcomm(uuid, secure) }
    fun discoverGatt() = tool { it.discoverGatt() }
    fun readCharacteristic(key: String) = tool { it.readCharacteristic(key) }
    fun readDescriptor(key: String) = tool { it.readDescriptor(key) }
    fun writeCharacteristic(key: String, bytes: ByteArray, withoutResponse: Boolean) = tool { it.writeCharacteristic(key, bytes, withoutResponse) }
    fun notifications(key: String, enabled: Boolean) = tool { it.notifications(key, enabled) }
    fun requestMtu() = tool { it.requestMtu() }
    fun cachedUuids() = tool { it.cachedUuids() }
    fun fetchSdp() = tool { it.fetchSdp() }
    fun send(bytes: ByteArray) = tool { it.sendRfcomm(bytes) }
    fun disconnect() { client?.controller?.disconnect() }
    fun clearHistory() {
        runCatching { client?.controller?.clearHistory() }.onFailure { mutableNotice.value = it.message }
    }

    fun saveEvidence() {
        val frozen = client?.state?.value ?: return
        val destination = mutableEngagement.value ?: return
        persistAction {
            val report = withContext(Dispatchers.Default) { BluetoothToolReports.report(frozen, System.currentTimeMillis()) }
            app.assessments.saveBluetoothSession(destination, report, app.config.config.value.version)
            mutableNotice.value = "Protocol snapshot saved as encrypted evidence. No vulnerability or access verdict was created."
        }
    }

    private fun tool(action: (BluetoothToolSession) -> Unit) {
        if (mutableBusy.value) return
        val destination = mutableEngagement.value
        val selected = archive.value.engagements.firstOrNull { it.id == destination && it.closedAt == null }
        if (selected == null) { mutableNotice.value = "Select an open engagement and confirm this target is within its scope."; return }
        client?.controller?.let(action)
    }

    private fun persistAction(action: suspend () -> Unit) {
        if (mutableBusy.value) return
        mutableBusy.value = true
        viewModelScope.launch {
            try { action() }
            catch (e: CancellationException) { throw e }
            catch (e: IllegalArgumentException) { mutableNotice.value = e.message ?: "Invalid Bluetooth record." }
            catch (e: IllegalStateException) { mutableNotice.value = e.message ?: "This action is unavailable." }
            catch (_: Exception) { mutableNotice.value = "The assessment vault could not be accessed. Existing evidence was preserved." }
            finally { mutableBusy.value = false }
        }
    }
    override fun onCleared() { deactivate(); super.onCleared() }
}
