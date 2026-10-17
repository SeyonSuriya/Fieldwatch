package app.fieldwatch.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.fieldwatch.FieldwatchApp
import app.fieldwatch.domain.*
import app.fieldwatch.radio.NetworkConnectClient
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

class NetworkAssessmentViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application as FieldwatchApp
    val archive = app.assessments.archive
    val wifi = app.devices.devices.map { rows -> rows.filter { it.kind == RadioKind.WIFI }.take(100) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    private val mutableBusy = MutableStateFlow(false)
    val busy = mutableBusy.asStateFlow()
    private val mutableNotice = MutableStateFlow("Select an open engagement and explicitly confirm the numeric scope before connecting.")
    val notice = mutableNotice.asStateFlow()
    private val mutableReport = MutableStateFlow<NetworkEvidenceReport?>(null)
    val report = mutableReport.asStateFlow()
    private val mutableReportEngagement = MutableStateFlow("")
    val reportEngagement = mutableReportEngagement.asStateFlow()
    private var destination: String? = null
    private var job: Job? = null
    private var client: NetworkConnectClient? = null

    init { viewModelScope.launch { runCatching { app.assessments.load() }.onFailure { mutableNotice.value = "Vault load failed; existing records preserved." } } }

    fun start(engagementId: String, scope: String, ports: String) {
        if (mutableBusy.value) return
        job = viewModelScope.launch {
            mutableBusy.value = true
            val observations = mutableListOf<TcpObservation>()
            var started = 0L
            var selected: NetworkConnectClient? = null
            var checkedPorts = emptyList<Int>()
            var cancelled = false
            try {
                check(android.os.Build.VERSION.SDK_INT >= 33) { "Assessments require Android 13+." }
                check(archive.value.engagements.any { it.id == engagementId && it.closedAt == null }) { "Select an open engagement." }
                val hosts = NetworkScope.hosts(scope)
                checkedPorts = NetworkScope.ports(ports)
                require(hosts.size * checkedPorts.size <= 256) { "Limit each run to 256 address/port pairs. Narrow the scope or choose fewer ports." }
                selected = NetworkConnectClient(app)
                client = selected
                val eligibleHosts = selected.validateTargets(hosts)
                destination = engagementId
                mutableReportEngagement.value = archive.value.engagements.single { it.id == engagementId }.name
                mutableReport.value = null
                started = System.currentTimeMillis()
                val endpoints = eligibleHosts.flatMap { host -> checkedPorts.map { host to it } }
                for (batch in endpoints.chunked(4)) {
                    val results = coroutineScope { batch.map { (host, port) -> async { selected.probe(host, port) } }.awaitAll() }
                    observations.addAll(results)
                    mutableNotice.value = "Checked ${observations.size}/${endpoints.size} endpoints."
                }
                mutableNotice.value = "Run complete. Open means TCP connection accepted; no service, vulnerability or access is confirmed."
            } catch (e: CancellationException) {
                cancelled = true
                mutableNotice.value = "Stopped. Partial results can be saved; uncompleted probes have no verdict."
            } catch (e: Exception) {
                cancelled = true
                mutableNotice.value = e.message ?: "Network run failed."
            } finally {
                selected?.close(); client = null
                if (started > 0) mutableReport.value = NetworkEvidenceReport(scope = scope.trim(), ports = checkedPorts,
                    network = selected!!.description, startedAt = started, endedAt = maxOf(started, System.currentTimeMillis()),
                    cancelled = cancelled, observations = observations.toList())
                mutableBusy.value = false
            }
        }
    }

    fun stop() { job?.cancel(); client?.close() }
    fun save() {
        if (mutableBusy.value) return
        val frozen = mutableReport.value ?: return
        val engagement = destination ?: return
        mutableBusy.value = true
        viewModelScope.launch {
            try { app.assessments.saveNetworkReport(engagement, frozen, app.config.config.value.version)
                mutableNotice.value = "Network observations saved as encrypted evidence." }
            catch (e: CancellationException) { throw e }
            catch (e: Exception) { mutableNotice.value = e.message ?: "Save failed." }
            finally { mutableBusy.value = false }
        }
    }
    override fun onCleared() { stop(); super.onCleared() }
}
