package app.fieldwatch

import android.os.Build
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.fieldwatch.domain.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Each phase is invoked separately by test-emulator.ps1, with force-stop between phases. */
@RunWith(AndroidJUnit4::class)
class SimulationRestartTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val app get() = context.applicationContext as FieldwatchApp
    private val store get() = app.assessments
    private lateinit var token: String
    private lateinit var metadata: File

    @Before fun requireSimulationEmulatorAndToken() {
        check(BuildConfig.BUILD_TYPE == "simulation" && context.packageName == "app.fieldwatch.simulation")
        check(Build.VERSION.SDK_INT >= 33 && Build.HARDWARE in setOf("ranchu", "goldfish"))
        token = requireNotNull(InstrumentationRegistry.getArguments().getString("restartToken"))
        require(Regex("[0-9a-f]{32}").matches(token))
        val directory = File(context.noBackupFilesDir, "simulation-restart").apply { check(isDirectory || mkdirs()) }
        metadata = File(directory, "$token.json")
        check(metadata.canonicalPath.startsWith(directory.canonicalPath + File.separator))
    }

    @Test fun seedInterruptedEngagement() = runBlocking {
        check(!metadata.exists()) { "Restart fixture already exists" }
        store.load()
        val id = store.create("Simulation restart $token", "Synthetic persistence fixture only: $token")
        try {
            // The handoff contains IDs, PIDs and hashes only, never a plaintext report copy.
            val handoff = JSONObject().put("id", id).put("seedPid", Process.myPid())
            metadata.writeText(handoff.toString())
            val asset = store.addAsset(id, "Synthetic target", "simulation:$token", AssessmentTransport.NETWORK)
            val completed = store.startObservation(id, asset)
            store.addEvidence(id, completed, "Completed fixture", "Synthetic completed evidence $token", 1)
            store.finishObservation(id, completed)
            val interrupted = store.startObservation(id, asset)
            store.addEvidence(id, interrupted, "Interrupted fixture", "Synthetic pending evidence $token", 1)
            val snapshot = store.archive.value.engagements.single { it.id == id }
            assertEquals(AssessmentRunStatus.RUNNING, snapshot.runs.single { it.id == interrupted }.status)
            handoff.put("runningId", interrupted).put("completedId", completed).put("originalHash", digest(snapshot))
            metadata.writeText(handoff.toString())
            assertEncrypted()
            // Deliberately leave the observation running; do not call finish or close here.
        } catch (failure: Throwable) {
            // Recovery cleanup cannot delete an engagement while it has a running observation.
            store.archive.value.engagements.single { it.id == id }.runs.filter { it.status == AssessmentRunStatus.RUNNING }
                .forEach { store.finishObservation(id, it.id, cancelled = true) }
            store.delete(id)
            metadata.delete()
            throw failure
        }
    }

    @Test fun verifyRecoveredEngagement() = runBlocking {
        val handoff = readHandoff()
        assertNotEquals("Recovery reused the seed process", handoff.getInt("seedPid"), Process.myPid())
        store.load()
        val id = handoff.getString("id")
        val snapshot = store.archive.value.engagements.single { it.id == id }
        val interrupted = snapshot.runs.single { it.id == handoff.getString("runningId") }
        assertEquals(AssessmentRunStatus.INTERRUPTED, interrupted.status)
        assertNotNull(interrupted.endedAt)
        assertTrue(interrupted.endedAt!! >= interrupted.startedAt)
        assertEquals(AssessmentRunStatus.RECORDED, snapshot.runs.single { it.id == handoff.getString("completedId") }.status)
        assertTrue(snapshot.runs.none { it.status == AssessmentRunStatus.RUNNING })
        val originalShape = snapshot.copy(runs = snapshot.runs.map {
            if (it.id == interrupted.id) it.copy(status = AssessmentRunStatus.RUNNING, endedAt = null) else it
        })
        assertEquals("Recovery changed data beyond the interrupted status/timestamp", handoff.getString("originalHash"), digest(originalShape))
        snapshot.evidence.forEach { assertEquals(it.sha256, AssessmentRules.sha256(it.text.toByteArray(Charsets.UTF_8))) }
        assertTrue(snapshot.findings.isEmpty())
        assertTrue(snapshot.access.isEmpty())
        try {
            store.addEvidence(id, interrupted.id, "Rejected late evidence", "Must not be appended", 1)
            fail("An interrupted observation accepted new evidence")
        } catch (_: IllegalArgumentException) { }
        assertEquals(snapshot, store.archive.value.engagements.single { it.id == id })
        assertEncrypted()
        handoff.put("recoveredHash", digest(snapshot)).put("recoveryPid", Process.myPid())
        metadata.writeText(handoff.toString())
    }

    @Test fun verifyRecoveryIsDurableAndCleanup() = runBlocking {
        val handoff = readHandoff()
        try {
            assertNotEquals("Durability check reused the recovery process", handoff.getInt("recoveryPid"), Process.myPid())
            store.load()
            val snapshot = store.archive.value.engagements.single { it.id == handoff.getString("id") }
            assertEquals("Second restart altered the recovered record", handoff.getString("recoveredHash"), digest(snapshot))
            assertEncrypted()
        } finally {
            cleanup()
        }
    }

    /** Failure-path cleanup is invoked independently and is not counted as a validation pass. */
    @Test fun cleanupRestartFixture() = runBlocking { cleanup() }

    private suspend fun cleanup() {
        if (!metadata.exists()) return
        val handoff = readHandoff()
        store.load()
        val id = handoff.getString("id")
        val snapshot = store.archive.value.engagements.singleOrNull { it.id == id }
        if (snapshot != null) {
            check(snapshot.name == "Simulation restart $token" && snapshot.scope == "Synthetic persistence fixture only: $token")
            snapshot.runs.filter { it.status == AssessmentRunStatus.RUNNING }.forEach { store.finishObservation(id, it.id, cancelled = true) }
            store.delete(id)
            assertFalse(store.archive.value.engagements.any { it.id == id })
        }
        check(metadata.delete())
    }

    private fun readHandoff() = JSONObject(metadata.readText())
    private fun digest(snapshot: AssessmentEngagement) = AssessmentRules.sha256(Json.encodeToString(snapshot).toByteArray(Charsets.UTF_8))
    private fun assertEncrypted() {
        val vault = File(context.noBackupFilesDir, "assessments/vault.bin")
        assertTrue(vault.isFile)
        assertFalse("Synthetic evidence appeared in plaintext in the vault", vault.readBytes().toString(Charsets.ISO_8859_1).contains(token))
    }
}
