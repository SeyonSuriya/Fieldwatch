package app.fieldwatch.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.fieldwatch.BuildConfig
import app.fieldwatch.FieldwatchApp
import app.fieldwatch.domain.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Assessment actions are separate from the live scanning ViewModel. */
class AssessmentViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application as FieldwatchApp
    private val store = app.assessments
    val archive = store.archive
    private val mutableSelected = MutableStateFlow<String?>(null)
    val selected = mutableSelected.asStateFlow()
    private val mutableBusy = MutableStateFlow(false)
    val busy = mutableBusy.asStateFlow()
    private val mutableReady = MutableStateFlow(false)
    val ready = mutableReady.asStateFlow()
    private val mutableNotice = MutableStateFlow<String?>(null)
    val notice = mutableNotice.asStateFlow()
    private val mutableExportRequested = MutableStateFlow(false)
    val exportRequested = mutableExportRequested.asStateFlow()
    private var pendingReport: String? = null

    init { reload() }

    fun reload() = action {
        store.load()
        mutableReady.value = true
        if (mutableSelected.value == null) mutableSelected.value = archive.value.engagements.lastOrNull()?.id
    }

    fun select(id: String?) { mutableSelected.value = id }
    fun dismissNotice() { mutableNotice.value = null }

    fun create(name: String, scope: String) = action {
        mutableSelected.value = store.create(name, scope)
    }

    fun addAsset(label: String, identifier: String, transport: AssessmentTransport) = action {
        store.addAsset(selectedId(), label, identifier, transport)
    }

    fun startObservation(assetId: String) = action { store.startObservation(selectedId(), assetId) }

    fun addEvidence(runId: String, title: String, text: String) = action {
        store.addEvidence(selectedId(), runId, title, text, app.config.config.value.version)
    }

    fun finishObservation(runId: String, cancelled: Boolean) = action {
        store.finishObservation(selectedId(), runId, cancelled)
    }

    fun recordFinding(evidenceId: String, title: String, description: String, severity: FindingSeverity) = action {
        store.recordFinding(selectedId(), evidenceId, title, description, severity)
    }

    fun evaluateEvidence(evidenceId: String) = action {
        val added = store.evaluateEvidence(selectedId(), evidenceId, app.config.config.value.version)
        mutableNotice.value = "Checks recorded: $added new finding(s). Repeating checks on the same evidence/version adds no duplicates. Inconclusive and not-observed results are retained in the evaluation evidence."
    }

    fun close() = action { store.close(selectedId()) }
    fun delete() = action { store.delete(selectedId()); mutableSelected.value = null }

    fun prepareReport(full: Boolean) = action {
        check(pendingReport == null) { "Finish or cancel the current export first." }
        val engagement = archive.value.engagements.single { it.id == selectedId() }
        pendingReport = withContext(Dispatchers.Default) {
            AssessmentReports.export(engagement, full, System.currentTimeMillis(), BuildConfig.VERSION_NAME)
        }
        mutableExportRequested.value = true
    }

    fun exportLaunched() { mutableExportRequested.value = false }

    fun writeReport(uri: Uri?) {
        val report = pendingReport
        pendingReport = null
        mutableExportRequested.value = false
        if (uri == null || report == null) return
        action {
            withContext(Dispatchers.IO) {
                val output = app.contentResolver.openOutputStream(uri, "wt") ?: error("Could not open export destination.")
                output.bufferedWriter(Charsets.UTF_8).use { it.write(report) }
            }
            mutableNotice.value = "Report exported. The destination contains an unencrypted JSON report."
        }
    }

    fun exportFailed() { pendingReport = null; mutableExportRequested.value = false; mutableNotice.value = "No document picker is available." }

    private fun selectedId(): String = checkNotNull(mutableSelected.value) { "Select an engagement first." }

    private fun action(block: suspend () -> Unit) {
        if (mutableBusy.value) return
        mutableBusy.value = true
        viewModelScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: IllegalArgumentException) {
                mutableNotice.value = e.message ?: "Invalid assessment request."
            } catch (e: IllegalStateException) {
                mutableNotice.value = e.message ?: "Assessment action is unavailable."
            } catch (_: Exception) {
                mutableNotice.value = "Assessment storage or export could not be accessed. Existing vault files were preserved. Retry loading; do not uninstall if you need the evidence."
            } finally {
                mutableBusy.value = false
            }
        }
    }
}
