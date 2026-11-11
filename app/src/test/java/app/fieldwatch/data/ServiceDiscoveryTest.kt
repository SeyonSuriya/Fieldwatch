package app.fieldwatch.data

import app.fieldwatch.domain.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.spec.SecretKeySpec

class ServiceDiscoveryTest {
    @get:Rule val temp = TemporaryFolder()
    private val key = SecretKeySpec(ByteArray(32) { 42 }, "AES")
    private fun store(file: File) = AssessmentStore(file, AesGcmAssessmentCipher { key }, "test") { 1000L }
    private fun report(headers: String) = ServiceInspectionReport(address = "192.168.1.1", port = 8123,
        probe = ServiceProbe.HTTP_HEAD, network = "Lab Wi-Fi", startedAt = 10, endedAt = 20, outcome = "observed",
        attemptedRequestHex = ServiceInspection.hex(ServiceInspection.request("192.168.1.1", 8123)),
        receivedHex = ServiceInspection.hex("HTTP/1.1 200 OK\r\n$headers\r\n\r\n".toByteArray()))
    private fun fixture(report: ServiceInspectionReport, test: suspend (AssessmentStore, AssessmentEngagement, String) -> Unit) = runBlocking {
        val store = store(File(temp.newFolder(), "vault.bin"))
        store.load()
        val id = store.create("Lab", "Authorized synthetic fixture")
        store.saveServiceReport(id, report, 1)
        val snapshot = store.archive.value.engagements.single()
        test(store, snapshot, snapshot.evidence.single().id)
    }

    @Test fun exactApacheAffectedVersionsMatchOnlyReviewedAdvisories() {
        mapOf("2.4.49" to listOf("CVE-2021-41773", "CVE-2021-42013"), "2.4.50" to listOf("CVE-2021-42013"),
            "2.4.48" to emptyList(), "2.4.51" to emptyList(), "2.4.490" to emptyList(), "2.4.49-vendor" to emptyList()).forEach { (version, expected) ->
            fixture(report("Server: Apache/$version (Unix)")) { _, snapshot, source ->
                val result = ServiceDiscovery.evaluate(snapshot, source, 2000)
                assertEquals("Apache HTTP Server", result.product)
                assertEquals(version, result.advertisedVersion)
                assertEquals(expected, result.candidates.map { it.cve })
                assertTrue(result.candidates.all { it.confidence == "UNVERIFIED_VERSION_MATCH" })
            }
        }
    }

    @Test fun identifiesCommonHttpSoftwareWithoutInferringDeviceFirmware() {
        mapOf("nginx/1.24.0" to "nginx", "lighttpd/1.4.71" to "lighttpd", "Microsoft-IIS/10.0" to "Microsoft IIS",
            "GoAhead-Webs" to "GoAhead", "Boa/0.94.14rc21" to "boa", "Apache" to "Apache HTTP Server").forEach { (server, expected) ->
            fixture(report("Server: $server")) { _, snapshot, source ->
                val result = ServiceDiscovery.evaluate(snapshot, source, 2000)
                assertEquals(expected, result.product)
                assertTrue(result.candidates.isEmpty())
                assertTrue(result.explanation.contains("vulnerability status is unknown"))
            }
        }
    }

    @Test fun ambiguousMalformedOrMissingServerNeverMatchesCve() {
        listOf("Server: Apache/2.4.49\r\nServer: nginx/1.24.0", "Server: nginx/1.24.0 Apache/2.4.49",
            "X-Server: Apache/2.4.49", "Server: Apache/2.4.49evil", "Server: private-router").forEach { headers ->
            fixture(report(headers)) { _, snapshot, source -> assertTrue(ServiceDiscovery.evaluate(snapshot, source, 2000).candidates.isEmpty()) }
        }
    }

    @Test fun unattemptedTruncatedAndFailedHttpDoNotProduceCandidates() {
        val valid = report("Server: Apache/2.4.49")
        listOf(valid.copy(attemptedRequestHex = ""), valid.copy(receivedHex = valid.receivedHex.dropLast(4)),
            valid.copy(outcome = "connection-or-io-error")).forEach { inspection ->
            fixture(inspection) { _, snapshot, source ->
                val result = ServiceDiscovery.evaluate(snapshot, source, 2000)
                assertNull(result.product)
                assertTrue(result.candidates.isEmpty())
            }
        }
    }

    @Test fun httpsCandidatesRequireVerifiedTlsMetadata() {
        val base = report("Server: Apache/2.4.49").copy(probe = ServiceProbe.HTTPS_HEAD)
        fixture(base) { _, snapshot, source -> assertTrue(ServiceDiscovery.evaluate(snapshot, source, 2000).candidates.isEmpty()) }
        fixture(base.copy(tlsProtocol = "TLSv1.3", tlsCipher = "TLS_AES_128_GCM_SHA256", certificateSha256 = "0".repeat(64))) { _, snapshot, source ->
            assertEquals(2, ServiceDiscovery.evaluate(snapshot, source, 2000).candidates.size)
        }
    }

    @Test fun sshIdentificationRequiresCompleteBannerAndDoesNotInferCvesFromPort() {
        val base = report("Server: Apache/2.4.49").copy(probe = ServiceProbe.BANNER, attemptedRequestHex = "")
        fixture(base.copy(receivedHex = ServiceInspection.hex("SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n".toByteArray()))) { _, snapshot, source ->
            val result = ServiceDiscovery.evaluate(snapshot, source, 2000)
            assertEquals("OpenSSH", result.product)
            assertEquals("9.6p1", result.advertisedVersion)
            assertTrue(result.candidates.isEmpty())
        }
        fixture(base.copy(receivedHex = "")) { _, snapshot, source -> assertNull(ServiceDiscovery.evaluate(snapshot, source, 2000).product) }
    }

    @Test fun sourceTamperingAndTargetMismatchAreRejected() = fixture(report("Server: Apache/2.4.49")) { _, snapshot, source ->
        for (changed in listOf(snapshot.copy(evidence = snapshot.evidence.map { it.copy(text = it.text + " ") }),
            snapshot.copy(assets = snapshot.assets.map { it.copy(identifier = "192.168.1.2") }))) {
            try { ServiceDiscovery.evaluate(changed, source, 2000); fail("Untrusted source was accepted") }
            catch (_: IllegalArgumentException) { }
        }
    }

    @Test fun batchDeduplicatesSingleReviewsAndRejectsInvalidSourcesAtomically() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val id = store.create("Lab", "Authorized synthetic fixtures")
        val otherId = store.create("Other lab", "Separate engagement")
        store.saveServiceReport(id, report("Server: Apache/2.4.49"), 1)
        store.saveServiceReport(id, report("Server: Apache/2.4.50"), 1)
        store.saveServiceReport(otherId, report("Server: Apache/2.4.49"), 1)
        val sources = store.archive.value.engagements.single { it.id == id }.evidence.map { it.id }
        val unrelated = store.archive.value.engagements.single { it.id == otherId }.evidence.single().id
        assertTrue(store.saveServiceDiscovery(id, sources.first()))
        val before = store.archive.value
        try {
            store.saveServiceDiscoveries(id, listOf(sources.last(), unrelated))
            fail("Batch accepted evidence from another engagement")
        } catch (_: IllegalArgumentException) { }
        assertEquals(before, store.archive.value)

        assertEquals(1, store.saveServiceDiscoveries(id, sources + sources.last()))
        val saved = store.archive.value.engagements.single { it.id == id }
        assertEquals(2, saved.evidence.count { it.source == "service-discovery" })
        assertEquals(3, saved.findings.size)
        assertTrue(saved.findings.all { it.confidence == FindingConfidence.SUSPECTED })
        val reopened = store(file)
        reopened.load()
        assertEquals(0, reopened.saveServiceDiscoveries(id, sources))
        assertEquals(saved, reopened.archive.value.engagements.single { it.id == id })
    }

    @Test fun persistsLinkedSuspectedCandidatesDeduplicatesAndExports() = runBlocking {
        val file = File(temp.newFolder(), "vault.bin")
        val store = store(file)
        store.load()
        val id = store.create("Lab", "Authorized synthetic fixture")
        store.saveServiceReport(id, report("Server: Apache/2.4.49"), 1)
        val source = store.archive.value.engagements.single().evidence.single()
        assertTrue(store.saveServiceDiscovery(id, source.id))
        assertFalse(store.saveServiceDiscovery(id, source.id))
        val saved = store.archive.value.engagements.single()
        val derived = saved.evidence.single { it.source == "service-discovery" }
        val result = Json.decodeFromString<ServiceDiscoveryReport>(derived.text)
        assertEquals(source.sha256, result.sourceSha256)
        assertEquals(2, saved.findings.size)
        assertTrue(saved.findings.all { it.confidence == FindingConfidence.SUSPECTED && it.evidenceIds == listOf(source.id, derived.id) })
        assertTrue(saved.access.isEmpty())
        assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("CVE-2021-41773"))
        val reopened = store(file)
        reopened.load()
        assertEquals(saved, reopened.archive.value.engagements.single())
        assertEquals(saved, Json.decodeFromString<AssessmentReport>(AssessmentReports.export(saved, true, 3000, "test")).engagement)
        store.close(id)
        try { store.saveServiceDiscovery(id, source.id); fail("Closed engagement accepted discovery") }
        catch (_: IllegalArgumentException) { }
    }
}
