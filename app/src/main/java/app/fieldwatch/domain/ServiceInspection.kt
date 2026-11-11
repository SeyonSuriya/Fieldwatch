package app.fieldwatch.domain

import kotlinx.serialization.Serializable

@Serializable
enum class ServiceProbe { BANNER, HTTP_HEAD, TLS, HTTPS_HEAD }

@Serializable
data class TlsCertificateDetails(
    val issuer: String,
    val notBefore: Long,
    val notAfter: Long,
    val issuerTruncated: Boolean = false,
) {
    fun validate() {
        require(issuer.length <= MAX_ISSUER_CHARS && issuer.none { it.isISOControl() })
        require(notBefore <= notAfter)
    }

    companion object {
        const val MAX_ISSUER_CHARS = 1024
    }
}

@Serializable
data class ServiceInspectionReport(
    val format: String = "fieldwatch-service-inspection",
    val version: Int = 1,
    val address: String,
    val port: Int,
    val probe: ServiceProbe,
    val network: String,
    val startedAt: Long,
    val endedAt: Long,
    val outcome: String,
    val attemptedRequestHex: String = "",
    val receivedHex: String = "",
    val captureLimitReached: Boolean = false,
    val tlsProtocol: String? = null,
    val tlsCipher: String? = null,
    val certificateSha256: String? = null,
    val requestedTlsProtocol: String? = null,
    val certificateDetails: TlsCertificateDetails? = null,
) {
    fun validate() {
        require(NetworkScope.hosts(address) == listOf(address))
        require(port in 1..65535 && network.length in 1..200 && startedAt > 0 && endedAt >= startedAt)
        require(format == "fieldwatch-service-inspection" && version == 1)
        require(outcome in setOf("observed", "eof", "timeout", "tls-validation-or-handshake-failed", "connection-or-io-error") ||
            (outcome == "tls-version-unavailable" && requestedTlsProtocol != null))
        val http = probe == ServiceProbe.HTTP_HEAD || probe == ServiceProbe.HTTPS_HEAD
        require(attemptedRequestHex.isEmpty() || (http && attemptedRequestHex == ServiceInspection.hex(ServiceInspection.request(address, port))))
        require(receivedHex.length <= ServiceInspection.MAX_CAPTURE * 2 && receivedHex.length % 2 == 0 && receivedHex.all { it in "0123456789abcdef" })
        require(!captureLimitReached || receivedHex.length == ServiceInspection.MAX_CAPTURE * 2)
        val tls = probe == ServiceProbe.TLS || probe == ServiceProbe.HTTPS_HEAD
        require(tls || listOf(tlsProtocol, tlsCipher, certificateSha256).all { it == null })
        require(listOf(tlsProtocol, tlsCipher, certificateSha256).let { fields -> fields.all { it == null } || fields.all { it != null } })
        require(probe != ServiceProbe.TLS || outcome != "observed" || tlsProtocol != null)
        require(listOfNotNull(tlsProtocol, tlsCipher).all { it.length in 1..160 })
        require(certificateSha256 == null || certificateSha256.matches(Regex("[0-9a-f]{64}")))
        certificateDetails?.let {
            require(tlsProtocol != null && outcome != "tls-validation-or-handshake-failed")
            it.validate()
        }
        requestedTlsProtocol?.let { requested ->
            require(probe == ServiceProbe.TLS && requested in ServiceInspection.TLS_AUDIT_VERSIONS)
            require(receivedHex.isEmpty())
            require(if (outcome == "observed") tlsProtocol == requested else tlsProtocol == null)
        }
    }
}

object ServiceInspection {
    const val MAX_CAPTURE = 4096
    const val DEADLINE_MS = 5000L
    val TLS_AUDIT_VERSIONS = listOf("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")

    fun validateTlsAudit(attempts: List<ServiceInspectionReport>) {
        require(attempts.map { it.requestedTlsProtocol } == TLS_AUDIT_VERSIONS) { "A TLS audit needs all four version results." }
        val endpoint = attempts.first()
        attempts.forEach {
            it.validate()
            require(it.address == endpoint.address && it.port == endpoint.port && it.network == endpoint.network) {
                "TLS audit results must share one endpoint and Wi-Fi network."
            }
        }
    }

    fun request(address: String, port: Int): ByteArray {
        require(NetworkScope.hosts(address) == listOf(address) && port in 1..65535)
        return "HEAD / HTTP/1.0\r\nHost: $address:$port\r\nConnection: close\r\nUser-Agent: Fieldwatch-Assessment/1\r\n\r\n".toByteArray(Charsets.US_ASCII)
    }
    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    fun bytes(hex: String): ByteArray = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    fun display(hex: String): String = bytes(hex).toString(Charsets.ISO_8859_1).map {
        if (it == '\n' || it == '\r' || it == '\t' || it.code in 32..126) it else '·'
    }.joinToString("")

    fun advertisedLabel(report: ServiceInspectionReport): String? {
        val http = HttpEvidence.read(report)
        val label = if (http != null) {
            http.headers.filter { it.first == "server" }.singleOrNull()?.second
        } else if (report.probe == ServiceProbe.BANNER && report.outcome in setOf("observed", "eof")) {
            val captured = bytes(report.receivedHex).toString(Charsets.ISO_8859_1)
            if ('\n' in captured || report.outcome == "eof") captured.substringBefore('\n').trimEnd('\r') else null
        } else {
            null
        }
        return label?.trim()?.takeIf { it.isNotEmpty() && it.all { char -> char.code in 32..126 } }?.take(120)
    }

    /** Server claims only; never infer an application from the port number. */
    fun identify(hex: String): String {
        val text = display(hex)
        return when {
            Regex("^SSH-[0-9]+\\.[0-9]+-").containsMatchIn(text) -> "SSH banner advertised"
            Regex("^HTTP/1\\.[01] [0-9]{3}( |\\r|\\n)").containsMatchIn(text) -> "HTTP response observed"
            text.startsWith("220 ") && text.lineSequence().first().contains("SMTP", true) -> "SMTP greeting advertised"
            text.startsWith("220 ") && text.lineSequence().first().contains("FTP", true) -> "FTP greeting advertised"
            text.startsWith("+OK") -> "POP-style greeting; protocol unconfirmed"
            text.isEmpty() -> "No application bytes captured"
            else -> "Unclassified response; inspect raw bytes"
        }
    }
}

@Serializable
data class WifiSecurityReport(
    val format: String = "fieldwatch-wifi-security",
    val version: Int = 1,
    val bssid: String,
    val ssid: String,
    val channel: Int,
    val frequencyMhz: Int,
    val firstSeen: Long,
    val lastSeen: Long,
    val capturedAt: Long,
    val capabilities: String?,
    val parsedSecurity: String?,
    val analysis: String,
) {
    fun validate() {
        require(format == "fieldwatch-wifi-security" && version == 1)
        require(bssid.matches(Regex("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")))
        require(ssid.length <= 200 && channel in 0..300 && frequencyMhz in 0..100000)
        require(firstSeen > 0 && lastSeen >= firstSeen && capturedAt > 0)
        require(listOfNotNull(capabilities, parsedSecurity).all { it.length <= 8192 })
        require(analysis == WifiSecurityAnalysis.describe(capabilities))
    }
    companion object {
        fun from(row: Sighting, capturedAt: Long): WifiSecurityReport {
            require(row.kind == RadioKind.WIFI)
            return WifiSecurityReport(bssid = row.mac.uppercase(), ssid = row.name, channel = row.channel,
                frequencyMhz = row.frequencyMhz, firstSeen = row.firstSeen, lastSeen = row.lastSeen, capturedAt = capturedAt,
                capabilities = row.facts.capabilities, parsedSecurity = row.facts.security,
                analysis = WifiSecurityAnalysis.describe(row.facts.capabilities)).also { it.validate() }
        }
    }
}
