package app.fieldwatch.data

import app.fieldwatch.domain.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.spec.SecretKeySpec

class AssessmentStoreTest {
    @get:Rule val temp = TemporaryFolder()
    private val key = SecretKeySpec(ByteArray(32) { 7 }, "AES")
    private var time = 1000L
    private fun store(file: File, cipher: AssessmentCipher = AesGcmAssessmentCipher { key }) =
        AssessmentStore(file, cipher, "test-version") { time }

    @Test fun encryptedRecordsSurviveReloadWithoutPlaintextFiles() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val first = store(file)
        first.load()
        val engagement = first.create("Private assessment", "Only lab camera 192.0.2.15")
        val asset = first.addAsset(engagement, "Camera", "192.0.2.15", AssessmentTransport.NETWORK)
        val run = first.startObservation(engagement, asset)
        val evidence = first.addEvidence(engagement, run, "Inspection", "secret-camera-response", 94)
        first.recordFinding(engagement, evidence, "Possible issue", "Needs validation", FindingSeverity.MEDIUM)
        first.finishObservation(engagement, run)
        val disk = file.readBytes().toString(Charsets.ISO_8859_1)
        assertFalse(disk.contains("secret-camera-response"))
        assertFalse(disk.contains("192.0.2.15"))
        assertEquals(listOf("vault.bin"), file.parentFile!!.list()!!.toList())
        val second = store(file)
        second.load()
        assertEquals(first.archive.value, second.archive.value)
        val saved = second.archive.value.engagements.single()
        assertEquals(FindingConfidence.SUSPECTED, saved.findings.single().confidence)
        assertTrue(saved.access.isEmpty())
        assertEquals("test-version", saved.evidence.single().appVersion)
    }

    @Test fun unfinishedRunBecomesInterruptedAfterRestart() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val first = store(file)
        first.load()
        val engagement = first.create("Lab", "Authorized lab devices")
        val asset = first.addAsset(engagement, "Sensor", "AA:BB:CC:00:00:01", AssessmentTransport.BLE)
        first.startObservation(engagement, asset)
        time = 2000
        val second = store(file)
        second.load()
        val restored = second.archive.value.engagements.single().runs.single()
        assertEquals(AssessmentRunStatus.INTERRUPTED, restored.status)
        assertEquals(2000L, restored.endedAt)
        val third = store(file)
        third.load()
        assertEquals(second.archive.value, third.archive.value)
    }

    @Test fun tamperedVaultCannotBeOverwrittenByAnEmptySession() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val first = store(file)
        first.load()
        first.create("Lab", "Authorized lab")
        val broken = file.readBytes().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        file.writeBytes(broken)
        val second = store(file)
        rejects { second.load() }
        rejects { second.create("New", "Do not overwrite original") }
        assertArrayEquals(broken, file.readBytes())
    }

    @Test fun failedEncryptionLeavesPublishedAndStoredStateUntouched() = runBlocking {
        var failWrites = false
        val delegate = AesGcmAssessmentCipher { key }
        val cipher = object : AssessmentCipher {
            override fun encrypt(plain: ByteArray): ByteArray {
                check(!failWrites) { "Injected write failure" }
                return delegate.encrypt(plain)
            }
            override fun decrypt(sealed: ByteArray) = delegate.decrypt(sealed)
        }
        val file = File(temp.newFolder(), "vault.bin")
        val first = store(file, cipher)
        first.load()
        first.create("Original", "Authorized lab")
        val snapshot = first.archive.value
        val bytes = file.readBytes()
        failWrites = true
        rejects { first.create("Failed", "Authorized lab") }
        assertEquals(snapshot, first.archive.value)
        assertArrayEquals(bytes, file.readBytes())
    }

    @Test fun closedEngagementRejectsEditsAndStillAllowsExplicitDeletion() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val first = store(file)
        first.load()
        val id = first.create("Lab", "Authorized lab")
        first.close(id)
        rejects { first.addAsset(id, "Target", "192.0.2.1", AssessmentTransport.NETWORK) }
        assertEquals(0, first.archive.value.engagements.single().assets.size)
        first.delete(id)
        assertTrue(first.archive.value.engagements.isEmpty())
        val second = store(file)
        second.load()
        assertTrue(second.archive.value.engagements.isEmpty())
    }

    @Test fun observationNeedsEvidenceToFinishAndCannotCloseWhileRunning() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val id = first.create("Lab", "Authorized lab")
        val asset = first.addAsset(id, "Target", "192.0.2.1", AssessmentTransport.NETWORK)
        val run = first.startObservation(id, asset)
        rejects { first.finishObservation(id, run) }
        rejects { first.close(id) }
        rejects { first.delete(id) }
        first.finishObservation(id, run, cancelled = true)
        first.close(id)
        assertEquals(AssessmentRunStatus.CANCELLED, first.archive.value.engagements.single().runs.single().status)
    }

    @Test fun evidenceCannotCrossEngagementBoundariesOrBeAddedAfterCompletion() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val a = first.create("Lab A", "Authorized A")
        val b = first.create("Lab B", "Authorized B")
        val asset = first.addAsset(a, "Target", "192.0.2.1", AssessmentTransport.NETWORK)
        val run = first.startObservation(a, asset)
        rejects { first.addEvidence(b, run, "Title", "Observed response", 94) }
        val evidence = first.addEvidence(a, run, "Title", "Observed response", 94)
        rejects { first.recordFinding(b, evidence, "Title", "Details", FindingSeverity.HIGH) }
        first.finishObservation(a, run)
        rejects { first.addEvidence(a, run, "Late", "Not part of the run", 94) }
    }

    @Test fun concurrentCreatesDoNotLoseUpdates() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        coroutineScope { (1..20).map { async { first.create("Engagement $it", "Authorized lab") } }.awaitAll() }
        assertEquals(20, first.archive.value.engagements.size)
    }

    @Test fun oversizedUtf8NoteIsRejectedWithoutLosingExistingEvidence() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val id = first.create("Lab", "Authorized lab")
        val asset = first.addAsset(id, "Target", "192.0.2.1", AssessmentTransport.NETWORK)
        val run = first.startObservation(id, asset)
        rejects { first.addEvidence(id, run, "Large", "界".repeat(30000), 94) }
        assertTrue(first.archive.value.engagements.single().evidence.isEmpty())
    }

    @Test fun inventorySnapshotAtomicallyCreatesTargetRunAndProvenanceEvidence() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val id = first.create("Lab", "Authorized lab")
        val radio = InventoryRadio("aa:bb:cc:00:00:01", "Speaker", AssessmentTransport.BLUETOOTH_CLASSIC,
            InventorySource.CLASSIC_INQUIRY, firstSeen = 500, lastSeen = 700, rssi = -60)
        val assetId = first.saveInventorySnapshot(id, radio, 94)
        val engagement = first.archive.value.engagements.single()
        assertEquals(assetId, engagement.assets.single().id)
        assertEquals("AA:BB:CC:00:00:01", engagement.assets.single().identifier)
        assertEquals(AssessmentRunStatus.RECORDED, engagement.runs.single().status)
        assertEquals("inventory-snapshot", engagement.runs.single().checkId)
        assertEquals("inventory-classic_inquiry", engagement.evidence.single().source)
        val captured = kotlinx.serialization.json.Json.decodeFromString<InventoryRadio>(engagement.evidence.single().text)
        assertEquals(700L, captured.lastSeen)
        assertEquals(1000L, engagement.evidence.single().capturedAt)
        assertTrue(engagement.findings.isEmpty())
        assertTrue(engagement.access.isEmpty())
    }

    @Test fun repeatedInventoryImportsReuseTargetButKeepSeparateEvidence() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val id = first.create("Lab", "Authorized lab")
        val radio = InventoryRadio("AA:BB:CC:00:00:01", "Paired speaker", AssessmentTransport.BLUETOOTH_CLASSIC,
            InventorySource.BONDED_RECORD, paired = true)
        first.saveInventorySnapshot(id, radio, 94)
        first.saveInventorySnapshot(id, radio.copy(identifier = radio.identifier.lowercase()), 94)
        val engagement = first.archive.value.engagements.single()
        assertEquals(1, engagement.assets.size)
        assertEquals(2, engagement.evidence.size)
        assertEquals(2, engagement.runs.size)
        val captured = kotlinx.serialization.json.Json.decodeFromString<InventoryRadio>(engagement.evidence.first().text)
        assertNull(captured.lastSeen)
        assertNull(captured.rssi)
        assertEquals(InventorySource.BONDED_RECORD, captured.source)
    }

    @Test fun closedEngagementRejectsInventoryImportWithoutPartialTargetOrRun() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val id = first.create("Lab", "Authorized lab")
        first.close(id)
        val before = first.archive.value
        rejects {
            first.saveInventorySnapshot(id, InventoryRadio("AA:BB:CC:00:00:01", "Paired", AssessmentTransport.BLE,
                InventorySource.BONDED_RECORD, paired = true), 94)
        }
        assertEquals(before, first.archive.value)
    }

    @Test fun identicalAddressAcrossTransportsCreatesSeparateTargets() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val id = first.create("Lab", "Authorized lab")
        val radio = InventoryRadio("AA:BB:CC:00:00:01", "Paired speaker", AssessmentTransport.BLUETOOTH_CLASSIC,
            InventorySource.BONDED_RECORD, paired = true)
        first.saveInventorySnapshot(id, radio, 94)
        first.saveInventorySnapshot(id, radio.copy(transport = AssessmentTransport.BLE), 94)
        assertEquals(2, first.archive.value.engagements.single().assets.size)
    }

    @Test fun bluetoothProtocolEvidencePreservesPayloadAndCreatesNoVulnerabilityOrAccessVerdict() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val first = store(file)
        first.load()
        val id = first.create("Lab", "Authorized lab")
        first.addAsset(id, "Sensor", "AA:BB:CC:00:00:01", AssessmentTransport.BLE)
        val event = BluetoothToolEvent(1, 1, 500, BluetoothEventKind.RESULT, "Read returned bytes", payloadHex = "AABBCC", byteCount = 3)
        val state = BluetoothToolState(BluetoothToolTarget("AA:BB:CC:00:00:01", AssessmentTransport.BLE), events = listOf(event))
        val body = BluetoothToolReports.report(state, 700)
        first.saveBluetoothSession(id, body, 94)
        val saved = first.archive.value.engagements.single()
        assertEquals("bluetooth-tools", saved.runs.single().checkId)
        assertEquals("bluetooth-protocol-session", saved.evidence.single().source)
        assertEquals(body, saved.evidence.single().text)
        assertTrue(saved.findings.isEmpty())
        assertTrue(saved.access.isEmpty())
        assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("AABBCC"))
        val second = store(file)
        second.load()
        assertEquals(first.archive.value, second.archive.value)
    }

    @Test fun protocolEvidenceRequiresMatchingTransportAndTargetInTheChosenEngagement() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val id = first.create("Lab", "Authorized lab")
        first.addAsset(id, "Sensor", "AA:BB:CC:00:00:01", AssessmentTransport.BLE)
        val before = first.archive.value
        val wrongTransport = BluetoothToolState(BluetoothToolTarget("AA:BB:CC:00:00:01", AssessmentTransport.BLUETOOTH_CLASSIC))
        rejects { first.saveBluetoothSession(id, BluetoothToolReports.report(wrongTransport, 1000), 94) }
        assertEquals(before, first.archive.value)
    }

    @Test fun closedEngagementCannotReceiveBluetoothProtocolEvidence() = runBlocking {
        val first = store(File(temp.newFolder(), "vault.bin"))
        first.load()
        val id = first.create("Lab", "Authorized lab")
        first.addAsset(id, "Sensor", "AA:BB:CC:00:00:01", AssessmentTransport.BLE)
        first.close(id)
        val before = first.archive.value
        val state = BluetoothToolState(BluetoothToolTarget("AA:BB:CC:00:00:01", AssessmentTransport.BLE))
        rejects { first.saveBluetoothSession(id, BluetoothToolReports.report(state, 1000), 94) }
        assertEquals(before, first.archive.value)
    }

    private suspend fun rejects(block: suspend () -> Unit) {
        try { block(); fail("Expected rejection") } catch (_: Exception) { /* expected */ }
    }
}
