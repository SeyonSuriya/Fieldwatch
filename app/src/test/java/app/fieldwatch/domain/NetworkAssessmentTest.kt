package app.fieldwatch.domain

import org.junit.Assert.*
import org.junit.Test

class NetworkAssessmentTest {
    private fun rejected(action: () -> Unit) { try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } }
    @Test fun subnetBoundariesExcludeBroadcastAndNetwork() {
        val hosts = NetworkScope.hosts("192.168.1.122/24")
        assertEquals(254, hosts.size)
        assertEquals("192.168.1.1", hosts.first())
        assertEquals("192.168.1.254", hosts.last())
    }
    @Test fun pointToPointAndSingleHostsAreRetained() {
        assertEquals(listOf("192.168.1.0", "192.168.1.1"), NetworkScope.hosts("192.168.1.1/31"))
        assertEquals(listOf("192.168.1.8"), NetworkScope.hosts("192.168.1.8"))
    }
    @Test fun rejectsDnsIpv6AmbiguityAndOversizedRanges() {
        listOf("example.com", "::1", "192.168.01.1", "256.1.2.3", "1.2.3.4/23", "1.2.3.4/33", "1.2.3.4/24/x").forEach { value -> rejected { NetworkScope.hosts(value) } }
    }
    @Test fun rejectsNonUnicastTargets() {
        listOf("0.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255").forEach { value -> rejected { NetworkScope.hosts(value) } }
    }
    @Test fun subnetMembershipUsesFullPrefix() {
        assertTrue(NetworkScope.contains("192.168.0.130", 25, "192.168.0.254"))
        assertFalse(NetworkScope.contains("192.168.0.130", 25, "192.168.0.1"))
        assertFalse(NetworkScope.contains("192.168.0.130", 32, "192.168.0.131"))
    }
    @Test fun validatesAndDeduplicatesPorts() {
        assertEquals(listOf(80, 443), NetworkScope.ports("80, 443,80"))
        listOf("", "0", "65536", "http", "1-50", (1..17).joinToString(",")).forEach { value -> rejected { NetworkScope.ports(value) } }
    }
    private fun report() = NetworkEvidenceReport(scope = "192.168.1.8", ports = listOf(80), network = "Wi-Fi lab", startedAt = 10, endedAt = 20, cancelled = false,
        observations = listOf(TcpObservation("192.168.1.8", 80, "open", 15)))
    @Test fun acceptsCompletedAndPartialReports() { report().validate(); report().copy(cancelled = true).validate() }
    @Test fun rejectsOutOfScopeOrInventedObservations() {
        val row = report().observations.single()
        listOf(row.copy(address = "192.168.1.9"), row.copy(port = 443), row.copy(outcome = "exploited"), row.copy(observedAt = 21)).forEach { value -> rejected { report().copy(observations = listOf(value)).validate() } }
    }
    @Test fun rejectsDuplicateObservationsAndUnboundedPlan() {
        rejected { report().copy(observations = report().observations + report().observations).validate() }
        rejected { report().copy(scope = "192.168.1.0/24", ports = listOf(80,443)).validate() }
    }
    @Test fun missingCapabilitiesAreUnknown() {
        assertTrue(WifiSecurityAnalysis.describe(null).startsWith("Unknown"))
        assertTrue(WifiSecurityAnalysis.describe("[FUTURE][ESS]").startsWith("Unclassified"))
    }
    @Test fun openAndOweAreDistinct() {
        assertTrue(WifiSecurityAnalysis.describe("[ESS]").startsWith("Open"))
        assertTrue(WifiSecurityAnalysis.describe("[RSN-OWE-CCMP][ESS]").contains("enhanced open"))
        assertTrue(WifiSecurityAnalysis.describe("[OWE_TRANSITION][ESS]").contains("compatibility"))
    }
    @Test fun mixedAndLegacyModesArePreserved() {
        val mixed = WifiSecurityAnalysis.describe("[WPA-PSK-TKIP][RSN-PSK+SAE-CCMP][WPS][ESS]")
        assertTrue(mixed.contains("WPA1")); assertTrue(mixed.contains("WPA2")); assertTrue(mixed.contains("WPA3")); assertTrue(mixed.contains("untested"))
        assertTrue(WifiSecurityAnalysis.describe("[WEP][ESS]").contains("obsolete"))
        assertTrue(WifiSecurityAnalysis.describe("[RSN-EAP-CCMP][ESS]").contains("Enterprise"))
    }
}
