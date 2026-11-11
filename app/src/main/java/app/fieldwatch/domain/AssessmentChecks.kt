package app.fieldwatch.domain

import java.net.URI
import java.net.URISyntaxException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
enum class CheckOutcome { CONDITION_OBSERVED, NOT_OBSERVED, INCONCLUSIVE, NOT_APPLICABLE }

@Serializable
data class CheckResult(val checkId: String, val checkVersion: Int = 1, val outcome: CheckOutcome, val explanation: String)

data class CheckDefinition(val id: String, val title: String, val severity: FindingSeverity, val confidence: FindingConfidence,
    val remediation: String, val references: List<String>, val version: Int = 1)

@Serializable
data class HttpAccessObservation(
    val status: Int,
    val interpretation: String,
)

@Serializable
data class CheckEvaluation(
    val format: String = "fieldwatch-check-evaluation",
    val formatVersion: Int = 1,
    val registryVersion: Int = 1,
    val sourceEvidenceId: String,
    val sourceSha256: String,
    val assetId: String,
    val evaluatedAt: Long,
    val results: List<CheckResult>,
    val httpAccess: HttpAccessObservation? = null,
)

/** Offline interpretation of saved observations. No network or exploitation side effects. */
object AssessmentChecks {
    const val VERSION = 2
    private val json = Json
    private const val TLS_REF = "https://www.rfc-editor.org/rfc/rfc8996"
    private const val WIFI_REF = "https://csrc.nist.gov/pubs/sp/800/153/final"
    val definitions = listOf(
        CheckDefinition("wifi-wep", "WEP protection advertised", FindingSeverity.MEDIUM, FindingConfidence.SUSPECTED,
            "Replace WEP with supported WPA2/WPA3 protection; verify AP configuration and isolate legacy equipment.", listOf(WIFI_REF)),
        CheckDefinition("wifi-wpa1", "Legacy WPA1 protection advertised", FindingSeverity.MEDIUM, FindingConfidence.SUSPECTED,
            "Disable legacy WPA1 compatibility where feasible and verify WPA2/WPA3 configuration.", listOf(WIFI_REF)),
        CheckDefinition("wifi-open", "Open Wi-Fi link advertised", FindingSeverity.LOW, FindingConfidence.SUSPECTED,
            "Confirm intended guest/public use. Use supported link encryption and application TLS; isolate untrusted clients.", listOf(WIFI_REF)),
        CheckDefinition("wifi-wps", "WPS advertisement review", FindingSeverity.INFORMATIONAL, FindingConfidence.SUSPECTED,
            "Review whether WPS is needed. An advertisement does not establish PIN enrollment, missing rate limits or exploitability.", listOf(WIFI_REF)),
        CheckDefinition("http-cleartext", "HTTP response observed over cleartext TCP", FindingSeverity.LOW, FindingConfidence.CONFIRMED,
            "Prefer HTTPS and review whether this cleartext endpoint is needed. No sensitive content or credentials were tested.", listOf("https://www.rfc-editor.org/rfc/rfc9110#section-17.1")),
        CheckDefinition("http-basic-cleartext", "Basic authentication challenge on cleartext HTTP", FindingSeverity.MEDIUM, FindingConfidence.SUSPECTED,
            "Require HTTPS before offering authentication. No credentials were submitted; credential acceptance remains untested.", listOf("https://www.rfc-editor.org/rfc/rfc7617#section-4")),
        CheckDefinition("https-redirect-to-http", "HTTPS response redirects to cleartext HTTP", FindingSeverity.MEDIUM, FindingConfidence.CONFIRMED,
            "Keep redirect destinations on HTTPS and review the intended destination.", listOf("https://www.rfc-editor.org/rfc/rfc9110#section-15.4")),
        CheckDefinition("tls-legacy", "Deprecated TLS version negotiated", FindingSeverity.MEDIUM, FindingConfidence.CONFIRMED,
            "Disable TLS 1.0/1.1 and use supported TLS 1.2/1.3 configurations. This check does not enumerate all supported versions.", listOf(TLS_REF)),
        CheckDefinition("ssh-v1", "SSH version 1 banner advertised", FindingSeverity.MEDIUM, FindingConfidence.SUSPECTED,
            "Verify SSH server settings and require SSH version 2. A banner is a server claim; no SSH login or downgrade was attempted.", listOf("https://www.rfc-editor.org/rfc/rfc4253#section-5")),
    )
    fun definition(id: String) = definitions.single { it.id == id }
    fun supports(source: String) = source in setOf("wifi-security-advertisement", "service-inspection")

    fun evaluate(engagement: AssessmentEngagement, evidenceId: String, now: Long): CheckEvaluation {
        val evidence = engagement.evidence.singleOrNull { it.id == evidenceId } ?: error("Select saved evidence.")
        require(supports(evidence.source)) { "This evidence format has no supported checks yet." }
        require(evidence.text.toByteArray().size <= AssessmentRules.MAX_NOTE_BYTES && AssessmentRules.sha256(evidence.text.toByteArray()) == evidence.sha256)
        val asset = engagement.assets.single { it.id == evidence.assetId }
        require(engagement.runs.any { it.id == evidence.runId && it.assetId == asset.id && it.status == AssessmentRunStatus.RECORDED })
        var httpAccess: HttpAccessObservation? = null
        val results = when (evidence.source) {
            "wifi-security-advertisement" -> {
                val report = json.decodeFromString<WifiSecurityReport>(evidence.text).also { it.validate() }
                require(asset.transport == AssessmentTransport.WIFI && asset.identifier.equals(report.bssid, true)) { "Wi-Fi evidence target mismatch." }
                wifi(report)
            }
            else -> {
                val report = json.decodeFromString<ServiceInspectionReport>(evidence.text).also { it.validate() }
                require(asset.transport == AssessmentTransport.NETWORK && asset.identifier == report.address) { "Service evidence target mismatch." }
                val parsed = HttpEvidence.read(report)
                httpAccess = parsed?.let(::accessObservation)
                service(report, parsed)
            }
        }
        require(now > 0)
        return CheckEvaluation(registryVersion = VERSION, sourceEvidenceId = evidence.id, sourceSha256 = evidence.sha256,
            assetId = asset.id, evaluatedAt = now, results = results, httpAccess = httpAccess)
    }

    private fun result(id: String, outcome: CheckOutcome, text: String) = CheckResult(id, checkVersion = definition(id).version, outcome = outcome, explanation = text)
    private fun wifi(report: WifiSecurityReport): List<CheckResult> {
        val raw = report.capabilities?.uppercase().orEmpty()
        val tokens = Regex("\\[([^\\[\\]]+)\\]").findAll(raw).map { it.groupValues[1] }.toList()
        val wellFormed = tokens.isNotEmpty() && tokens.joinToString("") { "[$it]" } == raw
        fun flag(id: String, observed: Boolean) = result(id, when {
            !wellFormed -> CheckOutcome.INCONCLUSIVE
            observed -> CheckOutcome.CONDITION_OBSERVED
            else -> CheckOutcome.NOT_OBSERVED
        }, if (!wellFormed) "Missing or malformed capability flags; configuration cannot be assessed."
            else if (observed) "Condition advertised at ${report.lastSeen}; advertisement authenticity and AP configuration remain unverified."
            else "Condition absent from this advertisement; this is not a security pass or proof of absence.")
        val open = wellFormed && tokens.toSet() in setOf(setOf("ESS"), setOf("ESS", "WPS"))
        return listOf(flag("wifi-wep", tokens.any { it == "WEP" }), flag("wifi-wpa1", tokens.any { it.startsWith("WPA-") }),
            result("wifi-open", when {
                !wellFormed -> CheckOutcome.INCONCLUSIVE
                open -> CheckOutcome.CONDITION_OBSERVED
                tokens.any { it == "WEP" || it.startsWith("RSN-") || it.startsWith("WPA-") || it.startsWith("WPA2-") } -> CheckOutcome.NOT_OBSERVED
                else -> CheckOutcome.INCONCLUSIVE
            }, if (open) "Minimal ESS advertisement indicates an open link; intended use and actual AP configuration are unverified."
                else "Open-link condition was not established. Unknown and OWE transition flags require review."),
            result("wifi-wps", if (!wellFormed || "WPS" in tokens) CheckOutcome.INCONCLUSIVE else CheckOutcome.NOT_OBSERVED,
                if ("WPS" in tokens) "WPS is advertised. Enrollment method, lockout and exploitability were not tested; no vulnerability is inferred."
                else "No WPS exploitability assessment was performed."))
    }

    private val redirects = setOf(301, 302, 303, 307, 308)

    private fun accessObservation(response: ParsedHttpEvidence): HttpAccessObservation {
        val interpretation = when (response.status) {
            401 -> if (response.headers.any { (name, value) -> name == "www-authenticate" && value.isNotBlank() }) {
                "HEAD / received HTTP 401 with a WWW-Authenticate header."
            } else {
                "HEAD / received HTTP 401 without a nonempty WWW-Authenticate header."
            }
            403 -> "The server refused HEAD /. The reason and policies for other paths are unknown."
            in redirects -> "The server redirected HEAD /. The destination was not visited."
            in 200..299 -> "HEAD / succeeded without credentials. Authorization for content and other paths remains unknown."
            else -> "The server responded to HEAD /. Authorization remains unknown."
        }
        return HttpAccessObservation(response.status, interpretation)
    }

    private fun redirectDowngrade(probe: ServiceProbe, response: ParsedHttpEvidence?): CheckOutcome {
        if (probe != ServiceProbe.HTTPS_HEAD) return CheckOutcome.NOT_APPLICABLE
        if (response == null) return CheckOutcome.INCONCLUSIVE
        if (response.status !in redirects) return CheckOutcome.NOT_OBSERVED
        val location = response.headers.filter { it.first == "location" }.singleOrNull()?.second
        if (location.isNullOrBlank()) return CheckOutcome.INCONCLUSIVE
        val destination = try { URI(location) } catch (_: URISyntaxException) { return CheckOutcome.INCONCLUSIVE }
        return when (destination.scheme?.lowercase()) {
            null -> CheckOutcome.NOT_OBSERVED
            "http" -> if (destination.host != null) CheckOutcome.CONDITION_OBSERVED else CheckOutcome.INCONCLUSIVE
            "https" -> if (destination.host != null) CheckOutcome.NOT_OBSERVED else CheckOutcome.INCONCLUSIVE
            else -> CheckOutcome.INCONCLUSIVE
        }
    }

    private fun service(report: ServiceInspectionReport, parsed: ParsedHttpEvidence?): List<CheckResult> {
        val isHttp = report.probe in setOf(ServiceProbe.HTTP_HEAD, ServiceProbe.HTTPS_HEAD)
        val clear = report.probe == ServiceProbe.HTTP_HEAD
        fun httpOutcome(observed: Boolean) = when {
            !isHttp -> CheckOutcome.NOT_APPLICABLE
            parsed == null -> CheckOutcome.INCONCLUSIVE
            observed -> CheckOutcome.CONDITION_OBSERVED
            else -> CheckOutcome.NOT_OBSERVED
        }
        // Deliberately accepts only Basic as the first challenge in a field. Complex lists stay unclassified.
        val basic = parsed?.status == 401 && parsed.headers.any { (name, value) -> name == "www-authenticate" && Regex("(?i)^Basic[ \\t]+realm=\"[^\"\\\\]*\"(?:[ \\t]*,.*)?$").matches(value) }
        val downgrade = redirectDowngrade(report.probe, parsed)
        val tls = report.probe in setOf(ServiceProbe.TLS, ServiceProbe.HTTPS_HEAD)
        val legacyTls = report.tlsProtocol in setOf("TLSv1", "TLSv1.0", "TLSv1.1")
        val banner = ServiceInspection.bytes(report.receivedHex).toString(Charsets.ISO_8859_1)
        val sshV1 = Regex("^SSH-1\\.(?!99-)[0-9]+-[^\\r\\n]+\\r?\\n$").matches(banner)
        val sshV2 = Regex("^SSH-(?:1\\.99|2\\.0)-[^\\r\\n]+\\r?\\n$").matches(banner)
        return listOf(
            result("http-cleartext", httpOutcome(clear), if (parsed != null && clear) "A complete HTTP ${parsed.status} header response to HEAD / was captured over cleartext TCP. No sensitive data or login was tested."
                else "A complete applicable cleartext HTTP exchange was not established; this does not establish that the endpoint requires HTTPS."),
            result("http-basic-cleartext", httpOutcome(clear && basic), if (clear && basic) "HTTP 401 advertises a Basic realm on cleartext TCP. Credential submission/acceptance was not tested."
                else "No qualifying cleartext Basic challenge was established. Unrecognized or combined challenge syntax may be unclassified."),
            result("https-redirect-to-http", downgrade, when (downgrade) {
                CheckOutcome.CONDITION_OBSERVED -> "The verified HTTPS response advertised a cleartext HTTP redirect. The destination was not visited."
                CheckOutcome.INCONCLUSIVE -> "The response or redirect destination could not be interpreted."
                else -> "No HTTPS-to-HTTP redirect was observed in this capture."
            }),
            result("tls-legacy", when {
                !tls -> CheckOutcome.NOT_APPLICABLE
                report.tlsProtocol == null -> CheckOutcome.INCONCLUSIVE
                legacyTls -> CheckOutcome.CONDITION_OBSERVED
                report.tlsProtocol in setOf("TLSv1.2", "TLSv1.3") -> CheckOutcome.NOT_OBSERVED
                else -> CheckOutcome.INCONCLUSIVE
            }, if (legacyTls) "The verified session negotiated ${report.tlsProtocol}. This does not enumerate all server capabilities."
                else "Only the saved handshake is assessed; a failed handshake is not proof of a certificate flaw or deprecated TLS support."),
            result("ssh-v1", when {
                report.probe != ServiceProbe.BANNER -> CheckOutcome.NOT_APPLICABLE
                report.outcome !in setOf("observed", "eof") -> CheckOutcome.INCONCLUSIVE
                sshV1 -> CheckOutcome.CONDITION_OBSERVED
                sshV2 -> CheckOutcome.NOT_OBSERVED
                else -> CheckOutcome.INCONCLUSIVE
            }, if (sshV1) "A complete SSH version 1 banner was captured. Protocol negotiation and login were not attempted."
                else "No qualifying SSH version 1 banner was established. SSH-1.99 is compatible with SSH version 2 and is not flagged."))
    }
}
