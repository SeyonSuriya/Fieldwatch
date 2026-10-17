package app.fieldwatch.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.fieldwatch.FieldwatchApp
import app.fieldwatch.domain.InventoryRadio
import app.fieldwatch.domain.RadioInventory
import app.fieldwatch.radio.ClassicRadio
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class InventoryViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application as FieldwatchApp
    private val classic = ClassicRadio(app)
    val discovery = classic.state
    val archive = app.assessments.archive
    val scanStats = app.devices.stats
    val rows = combine(app.devices.devices, classic.state) { live, bluetooth ->
        RadioInventory.merge(live.mapNotNull { runCatching { RadioInventory.fromSighting(it) }.getOrNull() }, bluetooth.radios)
    }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    private val mutableBusy = MutableStateFlow(false)
    val busy = mutableBusy.asStateFlow()
    private val mutableNotice = MutableStateFlow<String?>(null)
    val notice = mutableNotice.asStateFlow()
    private val mutableReady = MutableStateFlow(false)
    val ready = mutableReady.asStateFlow()

    init { load() }

    fun load() {
        if (mutableBusy.value) return
        mutableBusy.value = true
        viewModelScope.launch {
            try { app.assessments.load(); mutableReady.value = true }
            catch (e: CancellationException) { throw e }
            catch (_: Exception) { mutableNotice.value = "The assessment vault could not be loaded. Existing files were preserved. Discovery is still available." }
            finally { mutableBusy.value = false }
        }
    }

    fun activate() { classic.activate() }
    fun deactivate() { classic.deactivate() }
    fun startInquiry() { classic.activate(); classic.startInquiry() }
    fun stopInquiry() = classic.stopInquiry()
    fun refreshPaired() { classic.activate(); classic.refreshPaired() }
    fun clearClassic() = classic.clear()
    fun dismissNotice() { mutableNotice.value = null }

    fun save(engagementId: String, radio: InventoryRadio) {
        if (mutableBusy.value || !mutableReady.value) return
        mutableBusy.value = true
        // Freeze both destination and collector row at the time of the operator's action.
        viewModelScope.launch {
            try {
                app.assessments.saveInventorySnapshot(engagementId, radio, app.config.config.value.version)
                mutableNotice.value = "Snapshot saved as encrypted engagement evidence. It does not confirm a vulnerability or access."
            } catch (e: CancellationException) { throw e }
            catch (e: IllegalArgumentException) { mutableNotice.value = e.message ?: "Invalid inventory snapshot." }
            catch (e: IllegalStateException) { mutableNotice.value = e.message ?: "The selected engagement is unavailable." }
            catch (_: Exception) { mutableNotice.value = "The snapshot could not be saved. Existing vault records were preserved." }
            finally { mutableBusy.value = false }
        }
    }

    override fun onCleared() { classic.deactivate(); super.onCleared() }
}
