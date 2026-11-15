package app.fieldwatch.domain

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class AdvisoryCandidate(
    val cve: String,
    val title: String,
    val affectedVersions: List<String>,
    val vendorFixRelease: String,
    val requirements: String,
    val reference: String,
    val confidence: String = "UNVERIFIED_VERSION_MATCH",
)

@Serializable
data class ServiceDiscoveryReport(
    val format: String = "fieldwatch-service-discovery",
    val version: Int = 1,
    val catalogVersion: Int = 1,
    val catalogReviewedOn: String = "2026-11-04",
    val sourceEvidenceId: String,
    val sourceSha256: String,
    val assetId: String,
    val evaluatedAt: Long,
    val address: String,
    val port: Int,
    val protocol: String,
    val product: String?,
    val advertisedVersion: String?,
    val advertisedIdentity: String?,
    val explanation: String,
    val candidates: List<AdvisoryCandidate>,
    val httpPath: String? = null,
)

/** Offline, deterministic interpretation. No extra requests, credentials or exploit payloads. */
object ServiceDiscovery {
    const val VERSION = 1
    const val CATALOG_VERSION = 1
    private const val APACHE = "https://httpd.apache.org/security/vulnerabilities_24.html"
    val catalog = listOf(
        AdvisoryCandidate("CVE-2021-41773", "Apache HTTP Server path traversal / file disclosure", listOf("2.4.49"), "2.4.50",
            "Requires an affected unpatched build and Alias-like mapping without the usual require all denied protection. CGI adds execution risk. Patch/backport and configuration are unverified. The 2.4.50 fix was incomplete; also review CVE-2021-42013 and upgrade to a currently supported release.", "$APACHE#CVE-2021-41773"),
        AdvisoryCandidate("CVE-2021-42013", "Apache HTTP Server incomplete traversal fix", listOf("2.4.49", "2.4.50"), "2.4.51",
            "Requires an affected unpatched build and Alias-like mapping without the usual require all denied protection. CGI adds execution risk. Patch/backport, mapping and CGI configuration are unverified. Upgrade to a currently supported release.", "$APACHE#CVE-2021-42013"),
    )

    fun evaluate(engagement: AssessmentEngagement, evidenceId: String, now: Long): ServiceDiscoveryReport {
        require(now > 0)
        val source = engagement.evidence.single { it.id == evidenceId }
        require(source.source == "service-inspection") { "Select saved service inspection evidence." }
        require(source.text.toByteArray(Charsets.UTF_8).size <= AssessmentRules.MAX_NOTE_BYTES &&
            AssessmentRules.sha256(source.text.toByteArray(Charsets.UTF_8)) == source.sha256) { "Evidence integrity check failed." }
        val asset = engagement.assets.single { it.id == source.assetId }
        require(engagement.runs.any { it.id == source.runId && it.assetId == asset.id && it.status == AssessmentRunStatus.RECORDED })
        val report = Json.decodeFromString<ServiceInspectionReport>(source.text).also { it.validate() }
        require(asset.transport == AssessmentTransport.NETWORK && asset.identifier == report.address) { "Evidence target mismatch." }
        val identity = identify(report)
        val matches = if (identity.first == "Apache HTTP Server") catalog.filter { identity.second in it.affectedVersions } else emptyList()
        return ServiceDiscoveryReport(sourceEvidenceId = source.id, sourceSha256 = source.sha256, assetId = asset.id,
            evaluatedAt = now, address = report.address, port = report.port, protocol = ServiceInspection.identify(report.receivedHex),
            product = identity.first, advertisedVersion = identity.second, advertisedIdentity = identity.third,
            explanation = "Identity is a server advertisement, not verified firmware. Headers/banners may be hidden, proxied, forged or retain old versions after backports. ${if (matches.isEmpty()) "No match in the two-entry catalog; vulnerability status is unknown." else "Affected-version candidates require independent build and configuration validation."}",
            candidates = matches, httpPath = report.httpPath.takeIf { report.probe == ServiceProbe.HTTP_HEAD || report.probe == ServiceProbe.HTTPS_HEAD })
    }

    private fun identify(report: ServiceInspectionReport): Triple<String?, String?, String?> {
        val http = HttpEvidence.read(report)
        if (http != null) {
            val servers = http.headers.filter { it.first == "server" }.map { it.second }
            if (servers.size != 1) return Triple(null, null, null)
            val server = servers.single()
            val pattern = Regex("^(Apache|nginx|lighttpd|Microsoft-IIS|GoAhead-Webs|Boa)(?:/([0-9][0-9A-Za-z.+_-]{0,63}))?(?:[ \\t]+\\([^\\r\\n]*\\))?$", RegexOption.IGNORE_CASE)
            val match = pattern.matchEntire(server) ?: return Triple(null, null, server.take(200))
            val product = when (match.groupValues[1].lowercase()) {
                "apache" -> "Apache HTTP Server"
                "microsoft-iis" -> "Microsoft IIS"
                "goahead-webs" -> "GoAhead"
                else -> match.groupValues[1].lowercase()
            }
            return Triple(product, match.groupValues[2].ifEmpty { null }, server.take(200))
        }
        if (report.probe == ServiceProbe.BANNER && report.outcome in setOf("observed", "eof")) {
            val text = ServiceInspection.bytes(report.receivedHex).toString(Charsets.US_ASCII)
            val line = text.substringBefore("\r\n")
            if (!text.contains("\r\n")) return Triple(null, null, null)
            val ssh = Regex("SSH-(?:2\\.0|1\\.99)-(OpenSSH|dropbear)_([0-9][0-9A-Za-z.+_-]{0,63})(?: [\\x20-\\x7e]*)?").matchEntire(line)
            if (ssh != null) return Triple(ssh.groupValues[1], ssh.groupValues[2], line.take(200))
        }
        return Triple(null, null, null)
    }
}
