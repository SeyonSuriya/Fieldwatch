package app.fieldwatch.data

import app.fieldwatch.domain.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
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

    private fun networkReport() = NetworkEvidenceReport(scope = "192.168.1.0/30", ports = listOf(80), network = "Wi-Fi lab",
        startedAt = 10, endedAt = 20, cancelled = false, observations = listOf(
            TcpObservation("192.168.1.1", 80, "open", 15), TcpObservation("192.168.1.2", 80, "timeout", 16)))

    private fun serviceReport() = ServiceInspectionReport(address = "192.168.1.1", port = 80, probe = ServiceProbe.HTTP_HEAD,
        network = "Wi-Fi lab", startedAt = 10, endedAt = 20, outcome = "observed",
        receivedHex = ServiceInspection.hex("HTTP/1.1 200 OK\r\nServer: private-lab-name\r\n\r\n".toByteArray()))
    private fun wifiReport() = WifiSecurityReport(bssid = "AA:BB:CC:DD:EE:01", ssid = "Private lab", channel = 6, frequencyMhz = 2437,
        firstSeen = 10, lastSeen = 20, capturedAt = 30, capabilities = "[ESS]", parsedSecurity = null, analysis = WifiSecurityAnalysis.describe("[ESS]"))

    private fun operatorBaseline() = HandsetBaseline(capturedAt = 1, manufacturer = "FixtureBrand", model = "FixtureModel", androidRelease = "16", sdk = 36,
        securityPatch = "2026-09-05", buildDisplay = "private-build-label", appVersion = "test", appTargetSdk = 35,
        hardwareReported = HandsetBaseline.FEATURES.associateWith { true }, permissions = HandsetBaseline.PERMISSIONS.associateWith { BaselinePermission.DENIED })

    @Test fun operatorBaselineIsEncryptedAndSeparateFromTargetsAndFindings() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        store.saveOperatorBaseline(engagement, operatorBaseline())
        val saved = store.archive.value.engagements.single()
        assertEquals(operatorBaseline(), saved.operatorBaselines.single())
        assertTrue(saved.assets.isEmpty()); assertTrue(saved.runs.isEmpty()); assertTrue(saved.evidence.isEmpty())
        assertTrue(saved.findings.isEmpty()); assertTrue(saved.access.isEmpty())
        assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("private-build-label"))
        val reopened = store(file)
        reopened.load()
        assertEquals(store.archive.value, reopened.archive.value)
    }

    @Test fun invalidAndClosedBaselineWritesDoNotMutateVault() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        val before = file.readBytes()
        try { store.saveOperatorBaseline(engagement, operatorBaseline().copy(securityPatch = "2026-02-30")); fail("Expected invalid baseline rejection") }
        catch (_: IllegalArgumentException) { }
        assertArrayEquals(before, file.readBytes())
        store.close(engagement)
        try { store.saveOperatorBaseline(engagement, operatorBaseline()); fail("Expected closed engagement rejection") }
        catch (_: IllegalArgumentException) { }
        assertTrue(store.archive.value.engagements.single().operatorBaselines.isEmpty())
    }

    @Test fun operatorBaselineLimitRejectsFurtherWritesAtomically() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        repeat(20) { store.saveOperatorBaseline(engagement, operatorBaseline().copy(capturedAt = it + 1L)) }
        val before = file.readBytes()
        try { store.saveOperatorBaseline(engagement, operatorBaseline()); fail("Expected baseline limit rejection") }
        catch (_: IllegalArgumentException) { }
        assertArrayEquals(before, file.readBytes())
        assertEquals(20, store.archive.value.engagements.single().operatorBaselines.size)
    }

    private fun referenceReport(exposed: Boolean = true): ServiceInspectionReport {
        val response = "HTTP/1.0 ${if (exposed) "200 OK" else "401 Unauthorized"}\r\n" +
            "X-Fieldwatch-Lab-Product: fieldwatch-reference-camera\r\nX-Fieldwatch-Lab-Protocol: 1\r\n" +
            "X-Fieldwatch-Lab-Build: ${if (exposed) "1.0-exposed" else "1.1-protected"}\r\n" +
            (if (exposed) "X-Fieldwatch-Lab-Canary: ${DeviceValidation.MARKER}\r\n" else "WWW-Authenticate: Basic realm=\"FieldwatchLab\"\r\n") + "\r\n"
        return serviceReport().copy(attemptedRequestHex = ServiceInspection.hex(ServiceInspection.request("192.168.1.1", 80)),
            receivedHex = ServiceInspection.hex(response.toByteArray()))
    }

    @Test fun referenceComparisonIsEncryptedLinkedAndIdempotentWithoutFindings() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Synthetic fixtures")
        store.saveServiceReport(engagement, referenceReport(), 94)
        store.saveServiceReport(engagement, referenceReport(false).copy(port = 8082,
            attemptedRequestHex = ServiceInspection.hex(ServiceInspection.request("192.168.1.1", 8082))), 94)
        val sources = store.archive.value.engagements.single().evidence
        assertTrue(store.saveFixtureComparison(engagement, sources[0].id, sources[1].id, 94))
        val saved = store.archive.value.engagements.single()
        val evidence = saved.evidence.single { it.source == "reference-fixture-comparison" }
        val comparison = kotlinx.serialization.json.Json.decodeFromString<FixtureComparisonReport>(evidence.text)
        assertEquals(FixtureComparisonOutcome.EXPECTED_REFERENCE_PAIR, comparison.outcome)
        assertEquals(sources[0].sha256, comparison.exposed.sourceSha256)
        assertEquals(sources[1].sha256, comparison.protectedControl.sourceSha256)
        assertTrue(saved.findings.isEmpty()); assertTrue(saved.access.isEmpty())
        assertFalse(store.saveFixtureComparison(engagement, sources[0].id, sources[1].id, 94))
        assertEquals(saved, store.archive.value.engagements.single())
        assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("EXPECTED_REFERENCE_PAIR"))
        val reopened = store(file)
        reopened.load()
        assertEquals(store.archive.value, reopened.archive.value)
        assertFalse(reopened.saveFixtureComparison(engagement, sources[0].id, sources[1].id, 94))
        val summary = AssessmentReports.export(saved, false, 2000, "test")
        assertFalse(summary.contains(sources[0].id)); assertFalse(summary.contains("EXPECTED_REFERENCE_PAIR"))
        assertTrue(AssessmentReports.export(saved, true, 2000, "test").contains("EXPECTED_REFERENCE_PAIR"))
    }

    @Test fun closedEngagementAndRepeatedRoleCannotSaveComparison() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Synthetic fixtures")
        store.saveServiceReport(engagement, referenceReport(), 94)
        val source = store.archive.value.engagements.single().evidence.single()
        val before = file.readBytes()
        try { store.saveFixtureComparison(engagement, source.id, source.id, 94); fail("Expected distinct role rejection") }
        catch (_: IllegalArgumentException) { }
        assertArrayEquals(before, file.readBytes())
        store.close(engagement)
        try { store.saveFixtureComparison(engagement, source.id, "other", 94); fail("Expected closed engagement rejection") }
        catch (_: IllegalArgumentException) { }
        assertEquals(1, store.archive.value.engagements.single().evidence.size)
    }

    @Test fun referenceValidationIsEncryptedLinkedAndIdempotentWithoutAccessClaims() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Synthetic reference only")
        store.saveServiceReport(engagement, referenceReport(), 94)
        val source = store.archive.value.engagements.single().evidence.single()
        assertTrue(store.validateDeviceEvidence(engagement, source.id, 94))
        val saved = store.archive.value.engagements.single()
        val reportEvidence = saved.evidence.single { it.source == "device-validation" }
        val report = kotlinx.serialization.json.Json.decodeFromString<DeviceValidationReport>(reportEvidence.text)
        assertEquals(DeviceValidationOutcome.LAB_MARKER_EXPOSED, report.outcome)
        assertEquals(source.sha256, report.sourceSha256)
        assertEquals(listOf(source.id, reportEvidence.id), saved.findings.single().evidenceIds)
        assertTrue(saved.findings.single().title.contains("LAB ONLY"))
        assertTrue(saved.access.isEmpty())
        assertFalse(store.validateDeviceEvidence(engagement, source.id, 94))
        assertEquals(saved, store.archive.value.engagements.single())
        assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("LAB_MARKER_EXPOSED"))
        val reopened = store(file)
        reopened.load()
        assertEquals(store.archive.value, reopened.archive.value)
        assertFalse(reopened.validateDeviceEvidence(engagement, source.id, 94))
        assertFalse(AssessmentReports.export(saved, false, 2000, "test").contains(DeviceValidation.reference.id))
        assertTrue(AssessmentReports.export(saved, true, 2000, "test").contains("LAB_MARKER_EXPOSED"))
    }

    @Test fun protectedAndUnknownReferenceResultsRemainEvidenceOnly() = runBlocking {
        val store = store(File(temp.newFolder(), "vault.bin"))
        store.load()
        val engagement = store.create("Lab", "Synthetic reference only")
        store.saveServiceReport(engagement, referenceReport(false), 94)
        store.saveServiceReport(engagement, serviceReport(), 94)
        val sources = store.archive.value.engagements.single().evidence.toList()
        sources.forEach { assertTrue(store.validateDeviceEvidence(engagement, it.id, 94)) }
        val saved = store.archive.value.engagements.single()
        assertEquals(4, saved.evidence.size)
        assertTrue(saved.findings.isEmpty()); assertTrue(saved.access.isEmpty())
    }

    @Test fun closedEngagementRejectsReferenceValidationWithoutMutation() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Synthetic reference only")
        store.saveServiceReport(engagement, referenceReport(), 94)
        val source = store.archive.value.engagements.single().evidence.single()
        store.close(engagement)
        val before = file.readBytes()
        try { store.validateDeviceEvidence(engagement, source.id, 94); fail("Expected closed engagement rejection") }
        catch (_: IllegalArgumentException) { }
        assertArrayEquals(before, file.readBytes())
        assertTrue(store.archive.value.engagements.single().findings.isEmpty())
    }

    @Test fun versionedEvaluationsAreLinkedEncryptedAndIdempotent() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        store.saveWifiSecurity(engagement, wifiReport(), 94)
        val source = store.archive.value.engagements.single().evidence.single()
        assertEquals(1, store.evaluateEvidence(engagement, source.id, 94))
        val saved = store.archive.value.engagements.single()
        val finding = saved.findings.single()
        val evaluation = saved.evidence.single { it.source == "versioned-check-evaluation" }
        val report = kotlinx.serialization.json.Json.decodeFromString<CheckEvaluation>(evaluation.text)
        assertEquals(source.sha256, report.sourceSha256)
        assertEquals(CheckOutcome.INCONCLUSIVE, report.results.single { it.checkId == "wifi-pmf-optional" }.outcome)
        assertEquals(CheckOutcome.INCONCLUSIVE, report.results.single { it.checkId == "wifi-psk-sae-compatibility" }.outcome)
        assertEquals("wifi-open", finding.checkId)
        assertEquals(1, finding.checkVersion)
        assertEquals(FindingConfidence.SUSPECTED, finding.confidence)
        assertEquals(listOf(source.id, evaluation.id), finding.evidenceIds)
        assertTrue(saved.access.isEmpty())
        assertEquals(0, store.evaluateEvidence(engagement, source.id, 94))
        assertEquals(saved, store.archive.value.engagements.single())
        assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("wifi-open"))
        val reopened = store(file)
        reopened.load()
        assertEquals(store.archive.value, reopened.archive.value)
        val summary = AssessmentReports.export(saved, false, 2000, "test")
        assertFalse(summary.contains("wifi-open")); assertFalse(summary.contains(source.id))
        assertTrue(AssessmentReports.export(saved, true, 2000, "test").contains("wifi-open"))
    }

    @Test fun batchReviewsMixedEvidenceAtomicallyAndSharesSingleReviewDeduplication() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized fixtures")
        val other = store.create("Other lab", "Separate fixtures")
        val http = serviceReport().copy(attemptedRequestHex = ServiceInspection.hex(ServiceInspection.request("192.168.1.1", 80)))
        store.saveServiceReport(engagement, http, 94)
        store.saveWifiSecurity(engagement, wifiReport(), 94)
        val address = "AA:BB:CC:00:00:01"
        store.addAsset(engagement, "Sensor", address, AssessmentTransport.BLE)
        val bluetooth = BluetoothToolState(BluetoothToolTarget(address, AssessmentTransport.BLE))
        store.saveBluetoothSession(engagement, BluetoothToolReports.report(bluetooth, 700), 94)
        store.saveServiceReport(other, http, 94)
        val sources = store.archive.value.engagements.single { it.id == engagement }.evidence
        val foreign = store.archive.value.engagements.single { it.id == other }.evidence.single()
        assertEquals(1, store.evaluateEvidence(engagement, sources.first().id, 94))

        val before = store.archive.value
        rejects { store.evaluateEvidenceBatch(engagement, listOf(sources.last().id, foreign.id), 94) }
        assertEquals(before, store.archive.value)

        val ids = sources.map { it.id }
        assertEquals(EvidenceReviewBatch(2, 1, 1), store.evaluateEvidenceBatch(engagement, ids + ids.last(), 94))
        val reviewed = store.archive.value.engagements.single { it.id == engagement }
        val reports = reviewed.evidence.filter { it.source == "versioned-check-evaluation" }
            .map { Json.decodeFromString<CheckEvaluation>(it.text) }
        assertEquals(sources.associate { it.id to it.sha256 }, reports.associate { it.sourceEvidenceId to it.sourceSha256 })
        assertTrue(reports.any { it.bluetoothAccess is BluetoothAccessObservation.Ble })
        assertTrue(reports.any { it.httpAccess?.status == 200 })
        assertEquals(setOf("http-cleartext", "wifi-open"), reviewed.findings.map { it.checkId }.toSet())
        assertTrue(reviewed.access.isEmpty())

        val reopened = store(file)
        reopened.load()
        assertEquals(EvidenceReviewBatch(0, 3, 0), reopened.evaluateEvidenceBatch(engagement, ids, 94))
        assertEquals(reviewed, reopened.archive.value.engagements.single { it.id == engagement })
    }

    @Test fun cleartextEvaluationConfirmsOnlyTheTransportCondition() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        store.saveServiceReport(engagement, serviceReport().copy(attemptedRequestHex = ServiceInspection.hex(ServiceInspection.request("192.168.1.1", 80))), 94)
        val source = store.archive.value.engagements.single().evidence.single()
        assertEquals(1, store.evaluateEvidence(engagement, source.id, 94))
        val saved = store.archive.value.engagements.single()
        assertEquals("http-cleartext", saved.findings.single().checkId)
        assertEquals(FindingConfidence.CONFIRMED, saved.findings.single().confidence)
        assertTrue(saved.access.isEmpty())

        // Recreate the previous registry's saved evaluation while retaining its finding.
        val currentEvidence = saved.evidence.single { it.source == "versioned-check-evaluation" }
        val current = Json.decodeFromString<CheckEvaluation>(currentEvidence.text)
        val priorBody = Json.encodeToString(current.copy(registryVersion = 1, httpAccess = null,
            results = current.results.filterNot { it.checkId == "https-redirect-to-http" }))
        val priorEvidence = currentEvidence.copy(text = priorBody, sha256 = AssessmentRules.sha256(priorBody.toByteArray()))
        val prior = saved.copy(
            evidence = saved.evidence.map { if (it.id == priorEvidence.id) priorEvidence else it },
            runs = saved.runs.map { if (it.id == priorEvidence.runId) it.copy(checkVersion = 1) else it },
        )
        val priorBytes = Json.encodeToString(store.archive.value.copy(engagements = listOf(prior))).toByteArray()
        file.writeBytes(AesGcmAssessmentCipher { key }.encrypt(priorBytes))
        val reopened = store(file)
        reopened.load()
        assertEquals(0, reopened.evaluateEvidence(engagement, source.id, 94))
        val updated = reopened.archive.value.engagements.single()
        assertEquals(saved.findings, updated.findings)
        assertEquals(listOf(1, AssessmentChecks.VERSION), updated.evidence.filter { it.source == "versioned-check-evaluation" }
            .map { Json.decodeFromString<CheckEvaluation>(it.text).registryVersion })
    }

    @Test fun inconclusiveChecksAreSavedWithoutFindings() = runBlocking {
        val store = store(File(temp.newFolder(), "vault.bin"))
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        store.saveServiceReport(engagement, serviceReport().copy(receivedHex = "", outcome = "timeout"), 94)
        val source = store.archive.value.engagements.single().evidence.single()
        assertEquals(0, store.evaluateEvidence(engagement, source.id, 94))
        val saved = store.archive.value.engagements.single()
        assertEquals(2, saved.evidence.size)
        assertTrue(saved.findings.isEmpty()); assertTrue(saved.access.isEmpty())
    }

    @Test fun closedAndUnsupportedEvidenceCannotCreateEvaluations() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        val asset = store.addAsset(engagement, "Lab", "192.168.1.1", AssessmentTransport.NETWORK)
        val run = store.startObservation(engagement, asset)
        val note = store.addEvidence(engagement, run, "Note", "HTTP/1.1 200 OK", 94)
        store.finishObservation(engagement, run)
        val before = file.readBytes()
        try { store.evaluateEvidence(engagement, note, 94); fail("Expected unsupported source rejection") }
        catch (_: IllegalArgumentException) { }
        assertArrayEquals(before, file.readBytes())
        store.saveWifiSecurity(engagement, wifiReport(), 94)
        val source = store.archive.value.engagements.single().evidence.last()
        store.close(engagement)
        try { store.evaluateEvidence(engagement, source.id, 94); fail("Expected closed engagement rejection") }
        catch (_: IllegalArgumentException) { }
        assertTrue(store.archive.value.engagements.single().findings.isEmpty())
    }

    @Test fun failedEvaluationWriteDoesNotPublishFindingsOrPartialEvidence() = runBlocking {
        var failWrites = false
        val delegate = AesGcmAssessmentCipher { key }
        val cipher = object : AssessmentCipher {
            override fun encrypt(plain: ByteArray): ByteArray { check(!failWrites) { "Injected failure" }; return delegate.encrypt(plain) }
            override fun decrypt(sealed: ByteArray) = delegate.decrypt(sealed)
        }
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file, cipher)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        store.saveWifiSecurity(engagement, wifiReport(), 94)
        val before = store.archive.value
        val bytes = file.readBytes()
        val source = before.engagements.single().evidence.single()
        failWrites = true
        try { store.evaluateEvidence(engagement, source.id, 94); fail("Expected write failure") }
        catch (_: IllegalStateException) { }
        assertEquals(before, store.archive.value)
        assertArrayEquals(bytes, file.readBytes())
    }

    @Test fun serviceAndWifiSnapshotsRemainEncryptedAndReuseMatchingAssets() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        store.saveServiceReport(engagement, serviceReport(), 94)
        store.saveServiceReport(engagement, serviceReport().copy(outcome = "timeout"), 94)
        store.saveWifiSecurity(engagement, wifiReport(), 94)
        val saved = store.archive.value.engagements.single()
        assertEquals(2, saved.assets.size)
        assertEquals(3, saved.runs.size)
        assertEquals(setOf("service-inspection", "wifi-security-advertisement"), saved.evidence.map { it.source }.toSet())
        assertTrue(saved.findings.isEmpty()); assertTrue(saved.access.isEmpty())
        saved.evidence.forEach { assertEquals(AssessmentRules.sha256(it.text.toByteArray()), it.sha256) }
        assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("Private lab"))
        val reopened = store(file)
        reopened.load()
        assertEquals(store.archive.value, reopened.archive.value)
    }

    @Test fun invalidStructuredSnapshotsLeaveVaultUnchanged() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        val before = file.readBytes()
        try { store.saveServiceReport(engagement, serviceReport().copy(port = 0), 94); fail("Expected invalid endpoint rejection") }
        catch (_: IllegalArgumentException) { }
        try { store.saveWifiSecurity(engagement, wifiReport().copy(analysis = "invented"), 94); fail("Expected invalid analysis rejection") }
        catch (_: IllegalArgumentException) { }
        assertArrayEquals(before, file.readBytes())
    }

    @Test fun closedEngagementRejectsBothNewSnapshotTypes() = runBlocking {
        val store = store(File(temp.newFolder(), "vault.bin"))
        store.load()
        val engagement = store.create("Lab", "Authorized lab")
        store.close(engagement)
        try { store.saveServiceReport(engagement, serviceReport(), 94); fail("Expected closed engagement rejection") }
        catch (_: IllegalArgumentException) { }
        try { store.saveWifiSecurity(engagement, wifiReport(), 94); fail("Expected closed engagement rejection") }
        catch (_: IllegalArgumentException) { }
        assertTrue(store.archive.value.engagements.single().assets.isEmpty())
    }

    @Test fun networkEvidenceIsEncryptedGroupedByTargetAndHasNoAccessVerdict() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized subnet")
        store.saveNetworkReport(engagement, networkReport(), 94)
        store.saveNetworkReport(engagement, networkReport().copy(cancelled = true), 94)
        val saved = store.archive.value.engagements.single()
        assertEquals(2, saved.assets.size)
        assertEquals(4, saved.runs.size)
        assertEquals(2, saved.runs.count { it.status == AssessmentRunStatus.CANCELLED })
        assertTrue(saved.findings.isEmpty()); assertTrue(saved.access.isEmpty())
        saved.evidence.forEach { evidence ->
            val body = kotlinx.serialization.json.Json.decodeFromString<NetworkEvidenceReport>(evidence.text)
            body.validate()
            assertEquals(listOf(saved.assets.single { it.id == evidence.assetId }.identifier), body.observations.map { it.address })
        }
        assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("192.168.1.1"))
        val reopened = store(file)
        reopened.load()
        assertEquals(store.archive.value, reopened.archive.value)
    }

    @Test fun invalidNetworkEvidenceCannotMutateTheVault() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val engagement = store.create("Lab", "Authorized subnet")
        val before = file.readBytes()
        try {
            store.saveNetworkReport(engagement, networkReport().copy(observations = listOf(TcpObservation("10.0.0.1", 80, "open", 15))), 94)
            fail("Expected out-of-scope rejection")
        } catch (_: IllegalArgumentException) { }
        assertArrayEquals(before, file.readBytes())
    }

    @Test fun closedEngagementRejectsNetworkEvidence() = runBlocking {
        val store = store(File(temp.newFolder(), "vault.bin"))
        store.load()
        val engagement = store.create("Lab", "Authorized subnet")
        store.close(engagement)
        try { store.saveNetworkReport(engagement, networkReport(), 94); fail("Expected closed engagement rejection") }
        catch (_: IllegalArgumentException) { }
        assertTrue(store.archive.value.engagements.single().assets.isEmpty())
    }

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
        val source = saved.evidence.single()
        assertEquals(0, first.evaluateEvidence(id, source.id, 94))
        val reviewed = first.archive.value.engagements.single()
        val derived = reviewed.evidence.single { it.source == "versioned-check-evaluation" }
        val review = Json.decodeFromString<CheckEvaluation>(derived.text)
        assertEquals(source.id, review.sourceEvidenceId)
        assertEquals(source.sha256, review.sourceSha256)
        assertTrue(review.bluetoothAccess is BluetoothAccessObservation.Ble)
        assertTrue(reviewed.findings.isEmpty() && reviewed.access.isEmpty())
        val second = store(file)
        second.load()
        assertEquals(first.archive.value, second.archive.value)
        assertEquals(0, second.evaluateEvidence(id, source.id, 94))
        assertEquals(reviewed, second.archive.value.engagements.single())
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
