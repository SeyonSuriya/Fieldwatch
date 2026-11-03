package app.fieldwatch

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.activity.ComponentActivity
import androidx.lifecycle.Lifecycle
import app.fieldwatch.ui.NetworkAssessmentViewModel
import app.fieldwatch.ui.screen.NetworkAssessmentScreen
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.fieldwatch.data.*
import app.fieldwatch.domain.*
import app.fieldwatch.radio.NetworkConnectClient
import app.fieldwatch.ui.AssessmentViewModel
import app.fieldwatch.ui.screen.AssessmentsScreen
import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Emulator-only suite against synthetic host services. Never points at a real router. */
@RunWith(AndroidJUnit4::class)
class SimulationAssessmentTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val host = "10.0.2.2"
    private val basePort = 18081

    @Before fun requireSimulationEmulator() {
        check(BuildConfig.BUILD_TYPE == "simulation" && context.packageName == "app.fieldwatch.simulation")
        Assume.assumeTrue("Emulator API 33+ required", Build.VERSION.SDK_INT >= 33 && Build.HARDWARE in setOf("ranchu", "goldfish"))
    }

    @Test fun networkFixturesKeystoreEvidenceReloadAndReports() = runBlocking {
        val client = NetworkConnectClient(context)
        val directory = File(context.noBackupFilesDir, "simulation-tests/${UUID.randomUUID()}").apply { check(mkdirs()) }
        val alias = "fieldwatch-simulation-${UUID.randomUUID()}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
            }.generateKey()
            val cipher = AesGcmAssessmentCipher { keyStore.getKey(alias, null) as SecretKey }
            val file = File(directory, "vault.bin")
            val store = AssessmentStore(file, cipher, BuildConfig.VERSION_NAME)
            store.load()
            val engagement = store.create("Emulator reference lab", "Synthetic loopback services via emulator host alias only")
            assertEquals("open", client.probe(host, basePort).outcome)
            val exposed = client.inspect(host, basePort, ServiceProbe.HTTP_HEAD)
            val protectedReport = client.inspect(host, basePort + 1, ServiceProbe.HTTP_HEAD)
            assertEquals("observed", exposed.outcome)
            assertEquals("observed", protectedReport.outcome)
            store.saveServiceReport(engagement, exposed, 1)
            store.saveServiceReport(engagement, protectedReport, 1)
            val sources = store.archive.value.engagements.single().evidence.toList()
            assertEquals(DeviceValidationOutcome.LAB_MARKER_EXPOSED, DeviceValidation.evaluate(store.archive.value.engagements.single(), sources[0].id, System.currentTimeMillis()).outcome)
            assertEquals(DeviceValidationOutcome.LAB_PROTECTION_OBSERVED, DeviceValidation.evaluate(store.archive.value.engagements.single(), sources[1].id, System.currentTimeMillis()).outcome)
            assertTrue(store.saveFixtureComparison(engagement, sources[0].id, sources[1].id, 1))
            val snapshot = HandsetBaselineCollector.capture(context)
            store.saveOperatorBaseline(engagement, snapshot)
            val saved = store.archive.value.engagements.single()
            val pair = Json.decodeFromString<FixtureComparisonReport>(saved.evidence.single { it.source == "reference-fixture-comparison" }.text)
            assertEquals(FixtureComparisonOutcome.EXPECTED_REFERENCE_PAIR, pair.outcome)
            assertTrue(saved.findings.isEmpty()); assertTrue(saved.access.isEmpty())
            assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains(DeviceValidation.MARKER))
            val reopened = AssessmentStore(file, cipher, BuildConfig.VERSION_NAME)
            reopened.load()
            assertEquals(store.archive.value, reopened.archive.value)
            assertFalse(reopened.saveFixtureComparison(engagement, sources[0].id, sources[1].id, 1))
            val summary = AssessmentReports.export(saved, false, System.currentTimeMillis(), BuildConfig.VERSION_NAME)
            assertFalse(summary.contains(host)); assertFalse(summary.contains(sources[0].id))
            assertEquals(1, Json.decodeFromString<AssessmentReport>(summary).summary!!.operatorBaselineCount)
            val export = File(directory, "full-report.json")
            export.writeText(AssessmentReports.export(saved, true, System.currentTimeMillis(), BuildConfig.VERSION_NAME))
            assertEquals(saved, Json.decodeFromString<AssessmentReport>(export.readText()).engagement)
            store.close(engagement)
            try { store.saveFixtureComparison(engagement, sources[1].id, sources[0].id, 1); fail("Closed engagement accepted a write") }
            catch (_: IllegalArgumentException) { }
        } finally {
            client.close()
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
            check(directory.canonicalPath.startsWith(File(context.noBackupFilesDir, "simulation-tests").canonicalPath + File.separator))
            directory.deleteRecursively()
        }
    }

    @Test fun closingOwnedSocketCancelsSlowInspection() = runBlocking {
        val client = NetworkConnectClient(context)
        try {
            val request = async { client.inspect(host, basePort + 2, ServiceProbe.HTTP_HEAD) }
            delay(300)
            val stoppedAt = System.nanoTime()
            request.cancel()
            client.close()
            try { withTimeout(3000) { request.await() }; fail("Cancelled inspection returned a report") }
            catch (_: CancellationException) { }
            request.join()
            assertTrue("Owned socket did not close promptly", (System.nanoTime() - stoppedAt) / 1_000_000 < 3000)
        } finally { client.close() }
    }

    @Test fun invalidTlsDoesNotFallBackToHttp() = runBlocking {
        val client = NetworkConnectClient(context)
        try {
            val report = client.inspect(host, basePort + 3, ServiceProbe.HTTPS_HEAD)
            assertEquals("tls-validation-or-handshake-failed", report.outcome)
            assertEquals("", report.attemptedRequestHex)
            assertEquals("", report.receivedHex)
            assertNull(report.tlsProtocol)
        } finally { client.close() }
    }

    @Test fun documentPickerCancellationThenSummaryExport() = withExportEngagement { vm, snapshot, picker ->
        compose.onNodeWithText("Export summary").performScrollTo().performClick()
        compose.waitUntil(15000) { !vm.busy.value }
        compose.waitForIdle()
        picker.awaitOpen()
        val cancelledName = picker.setUniqueName()
        picker.cancel()
        compose.waitUntil(15000) { !vm.busy.value }
        assertNull(vm.notice.value)
        assertFalse(picker.exists(cancelledName))
        assertEquals(snapshot, vm.archive.value.engagements.single { it.id == snapshot.id })

        // A real cancellation result must clear the pending report and permit a new export.
        compose.onNodeWithText("Export summary").performScrollTo().performClick()
        compose.waitUntil(15000) { !vm.busy.value }
        compose.waitForIdle()
        picker.awaitOpen()
        val name = picker.setUniqueName()
        picker.save()
        compose.waitUntil(15000) { vm.notice.value?.startsWith("Report exported.") == true && !vm.busy.value }
        val text = picker.read(name)
        val report = Json.decodeFromString<AssessmentReport>(text)
        assertNull(report.engagement)
        assertNotNull(report.summary)
        assertEquals(1, report.summary!!.operatorBaselineCount)
        assertFalse(text.contains(snapshot.name))
        assertFalse(text.contains(snapshot.scope))
        assertFalse(text.contains(snapshot.id))
    }

    @Test fun documentPickerFullExportUsesFrozenEngagement() = withExportEngagement { vm, snapshot, picker ->
        compose.onNodeWithText("Export full report").performScrollTo().performClick()
        compose.onNodeWithText("Export full report?").assertIsDisplayed()
        compose.onNodeWithText("Export", useUnmergedTree = true).performClick()
        compose.waitUntil(15000) { !vm.busy.value }
        compose.waitForIdle()
        picker.awaitOpen()
        val name = picker.setUniqueName()
        // Changing selection while the picker is open must not redirect a frozen report.
        InstrumentationRegistry.getInstrumentation().runOnMainSync { vm.select(null) }
        picker.save()
        compose.waitUntil(15000) { vm.notice.value?.startsWith("Report exported.") == true && !vm.busy.value }
        val report = Json.decodeFromString<AssessmentReport>(picker.read(name))
        assertEquals(snapshot, report.engagement)
        assertNull(report.summary)
    }

    private fun withExportEngagement(test: (AssessmentViewModel, AssessmentEngagement, SimulationDocumentPicker) -> Unit) {
        val app = context.applicationContext as FieldwatchApp
        val vm = AssessmentViewModel(app)
        val picker = SimulationDocumentPicker()
        var id: String? = null
        try {
            picker.use {
                compose.waitUntil(15000) { vm.ready.value && !vm.busy.value }
                id = runBlocking {
                    app.assessments.create("Synthetic export ${UUID.randomUUID()}", "Synthetic private scope ${UUID.randomUUID()}")
                }
                runBlocking { app.assessments.saveOperatorBaseline(id, HandsetBaselineCollector.capture(context)) }
                val snapshot = app.assessments.archive.value.engagements.single { it.id == id }
                compose.runOnIdle { vm.select(id) }
                compose.setContent { MaterialTheme { AssessmentsScreen(onBack = {}, onInventory = {}, onNetwork = {}, vm = vm) } }
                test(vm, snapshot, picker)
            }
        } finally {
            if (id != null) runBlocking { app.assessments.delete(id) }
        }
    }

    @Test fun backgroundingNetworkScreenCancelsInspection() {
        val app = context.applicationContext as FieldwatchApp
        val vm = NetworkAssessmentViewModel(app)
        val id = runBlocking {
            app.assessments.load()
            app.assessments.create("Simulation lifecycle", "Synthetic slow loopback service only")
        }
        try {
            compose.setContent { MaterialTheme { NetworkAssessmentScreen(onBack = {}, vm = vm) } }
            compose.runOnIdle { vm.inspect(id, host, (basePort + 2).toString(), ServiceProbe.HTTP_HEAD) }
            compose.waitUntil(5000) { vm.busy.value && vm.notice.value.startsWith("Inspecting") }
            // Exercise the screen's ON_STOP observer, rather than calling stop directly.
            compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
            runBlocking { withTimeout(3000) { while (vm.busy.value) delay(25) } }
            assertNull(vm.service.value)
            assertEquals("Inspection stopped; no completed report was recorded.", vm.notice.value)
            compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
            assertTrue(app.assessments.archive.value.engagements.single { it.id == id }.evidence.isEmpty())
        } finally {
            compose.runOnIdle { vm.stop() }
            runBlocking { app.assessments.delete(id) }
        }
    }

    @Test fun simulatedBluetoothFailuresAndStaleCallbacks() {
        // A fake transport exercises controller logic on Android, never GATT/RFCOMM hardware.
        val port = SimulatedBluetoothPort()
        val ble = BluetoothToolSession(BluetoothToolTarget("02:00:00:00:00:01", AssessmentTransport.BLE), port)
        ble.connectBle()
        val token = ble.state.value.session
        ble.connected(token)
        ble.discoverGatt()
        ble.gattDiscovered(token, listOf(GattServiceInfo("s0", BluetoothToolValues.uuid("1800"), true,
            listOf(GattCharacteristicInfo("s0/c0", BluetoothToolValues.uuid("2A00"), BluetoothToolValues.READ)))), 0)
        ble.writeCharacteristic("s0/c0", byteArrayOf(1), false)
        assertEquals(0, port.writes)
        ble.readCharacteristic("s0/c0")
        ble.result(token, BluetoothToolOperation.READ_CHARACTERISTIC, "s0/c0", 5)
        assertTrue(ble.state.value.values.isEmpty())
        assertEquals(BluetoothEventKind.ERROR, ble.state.value.events.last().kind)
        ble.disconnect()
        val disconnected = ble.state.value
        ble.result(token, BluetoothToolOperation.READ_CHARACTERISTIC, "s0/c0", 0, byteArrayOf(99))
        ble.connected(token)
        assertEquals(disconnected, ble.state.value)

        val classic = BluetoothToolSession(BluetoothToolTarget("02:00:00:00:00:02", AssessmentTransport.BLUETOOTH_CLASSIC), port)
        classic.connectRfcomm("1101", true)
        val classicToken = classic.state.value.session
        classic.connected(classicToken)
        classic.sendRfcomm(byteArrayOf(1, 2))
        assertEquals(0L, classic.state.value.sentBytes)
        classic.result(classicToken, BluetoothToolOperation.SEND_RFCOMM, null, 0)
        assertEquals(2L, classic.state.value.sentBytes)
        classic.disconnect()
        val closed = classic.state.value
        classic.incoming(classicToken, false, null, byteArrayOf(3))
        assertEquals(closed, classic.state.value)
        assertEquals(1, port.writes)
    }

    private class SimulatedBluetoothPort : BluetoothToolPort {
        var writes = 0
        override fun close() = Unit
        override fun connectBle(session: Long) = true
        override fun discoverGatt() = true
        override fun readCharacteristic(key: String) = true
        override fun readDescriptor(key: String) = true
        override fun writeCharacteristic(key: String, bytes: ByteArray, withoutResponse: Boolean): Boolean { writes++; return true }
        override fun notifications(key: String, enable: Boolean, indicate: Boolean) = true
        override fun requestMtu() = true
        override fun cachedUuids() = listOf("1101")
        override fun fetchSdp(session: Long) = true
        override fun connectRfcomm(session: Long, uuid: String, secure: Boolean) = true
        override fun sendRfcomm(session: Long, bytes: ByteArray): Boolean { writes++; return true }
    }

    @Test fun assessmentUiCreatesEngagementAndSavesLocalBaseline() {
        val app = context.applicationContext as FieldwatchApp
        val name = "Simulation UI ${UUID.randomUUID()}"
        var created: String? = null
        val vm = AssessmentViewModel(app)
        try {
            compose.setContent { MaterialTheme { AssessmentsScreen(onBack = {}, onInventory = {}, onNetwork = {}, vm = vm) } }
            compose.waitUntil(15000) { vm.ready.value }
            compose.runOnIdle { vm.select(null) }
            compose.onNodeWithText("New engagement").performScrollTo().performClick()
            compose.onAllNodes(hasSetTextAction())[0].performTextInput(name)
            compose.onAllNodes(hasSetTextAction())[1].performTextInput("Synthetic emulator lab only")
            compose.onNodeWithText("Save", useUnmergedTree = true).performClick()
            compose.waitUntil(15000) { app.assessments.archive.value.engagements.any { it.name == name } && !vm.busy.value }
            created = app.assessments.archive.value.engagements.single { it.name == name }.id
            compose.onNodeWithText("Review this phone's baseline").performScrollTo().performClick()
            compose.onNodeWithText("This phone's operator baseline").assertIsDisplayed()
            compose.onNodeWithText("Save encrypted baseline").performClick()
            compose.waitUntil(15000) { app.assessments.archive.value.engagements.single { it.id == created }.operatorBaselines.size == 1 && !vm.busy.value }
            val saved = app.assessments.archive.value.engagements.single { it.id == created }
            assertEquals(Build.VERSION.SDK_INT, saved.operatorBaselines.single().sdk)
            assertTrue(saved.assets.isEmpty()); assertTrue(saved.findings.isEmpty())
        } finally {
            val cleanup = created ?: app.assessments.archive.value.engagements.firstOrNull { it.name == name }?.id
            if (cleanup != null) runBlocking { app.assessments.delete(cleanup) }
        }
    }
}
