package app.fieldwatch.data

import app.fieldwatch.domain.*
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Blocking bounded protocol exchange. Caller owns cancellation by closing the supplied socket. */
object ServiceInspector {
    fun configureTls(socket: SSLSocket) {
        socket.useClientMode = true
        socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
    }

    internal fun pinEnabledTlsProtocol(socket: SSLSocket, protocol: String): Boolean {
        require(protocol in ServiceInspection.TLS_AUDIT_VERSIONS)
        if (protocol !in socket.enabledProtocols) return false
        socket.enabledProtocols = arrayOf(protocol)
        return true
    }

    fun inspect(socket: Socket, address: String, port: Int, probe: ServiceProbe, network: String,
        requestedTlsProtocol: String? = null,
        nanoTime: () -> Long = System::nanoTime): ServiceInspectionReport {
        ServiceInspection.request(address, port) // Validate even modes which do not send HTTP.
        require(requestedTlsProtocol == null || (probe == ServiceProbe.TLS && requestedTlsProtocol in ServiceInspection.TLS_AUDIT_VERSIONS))
        val startedAt = System.currentTimeMillis()
        val deadline = nanoTime() + ServiceInspection.DEADLINE_MS * 1_000_000
        fun remaining(): Int = ((deadline - nanoTime()) / 1_000_000).coerceAtMost(ServiceInspection.DEADLINE_MS).toInt()
            .also { if (it <= 0) throw SocketTimeoutException() }
        var active = socket
        var outcome = "observed"
        var protocol: String? = null
        var cipher: String? = null
        var certificate: String? = null
        var certificateDetails: TlsCertificateDetails? = null
        var attemptedRequest = ""
        val captured = ByteArrayOutputStream()
        try {
            val numeric = InetAddress.getByAddress(address.split('.').map { it.toInt().toByte() }.toByteArray())
            socket.connect(InetSocketAddress(numeric, port), minOf(1500, remaining()))
            socket.soTimeout = remaining()
            if (probe == ServiceProbe.TLS || probe == ServiceProbe.HTTPS_HEAD) {
                // Default platform trust and IP SAN verification. No alternate connection or trust-all fallback.
                val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(socket, address, port, true) as SSLSocket
                active = tls
                configureTls(tls)
                if (requestedTlsProtocol != null && !pinEnabledTlsProtocol(tls, requestedTlsProtocol)) {
                    outcome = "tls-version-unavailable"
                } else {
                    tls.soTimeout = remaining()
                    tls.startHandshake()
                    val session = tls.session
                    if (requestedTlsProtocol != null && session.protocol != requestedTlsProtocol) {
                        throw SSLException("Negotiated protocol differs from the requested version")
                    }
                    val leaf = session.peerCertificates.first()
                    val fingerprint = ServiceInspection.hex(MessageDigest.getInstance("SHA-256").digest(leaf.encoded))
                    certificateDetails = (leaf as? X509Certificate)?.let {
                        val issuer = it.issuerX500Principal.name
                        TlsCertificateDetails(
                            issuer = issuer.take(TlsCertificateDetails.MAX_ISSUER_CHARS).map { char ->
                                if (char.isISOControl()) ' ' else char
                            }.joinToString(""),
                            notBefore = it.notBefore.time,
                            notAfter = it.notAfter.time,
                            issuerTruncated = issuer.length > TlsCertificateDetails.MAX_ISSUER_CHARS,
                        )
                    }
                    protocol = session.protocol
                    cipher = session.cipherSuite
                    certificate = fingerprint
                }
            }
            if (probe == ServiceProbe.HTTP_HEAD || probe == ServiceProbe.HTTPS_HEAD) {
                val request = ServiceInspection.request(address, port)
                attemptedRequest = ServiceInspection.hex(request)
                active.getOutputStream().write(request)
                active.getOutputStream().flush()
            }
            if (probe != ServiceProbe.TLS) {
                val input = active.getInputStream()
                // HTTP stops at the first header boundary, without consuming a body or following Location.
                var tail = 0
                while (captured.size() < ServiceInspection.MAX_CAPTURE) {
                    active.soTimeout = remaining()
                    val value = input.read()
                    if (value < 0) { outcome = "eof"; break }
                    captured.write(value)
                    tail = (tail shl 8) or value
                    if (probe == ServiceProbe.BANNER && value == 10) break
                    if (probe != ServiceProbe.BANNER && tail == 0x0d0a0d0a) break
                }
            }
        } catch (_: SocketTimeoutException) { outcome = "timeout" }
        catch (_: SSLException) { outcome = "tls-validation-or-handshake-failed" }
        catch (_: java.io.IOException) { outcome = "connection-or-io-error" }
        finally { runCatching { active.close() }; runCatching { socket.close() } }
        return ServiceInspectionReport(address = address, port = port, probe = probe, network = network,
            startedAt = startedAt, endedAt = maxOf(startedAt, System.currentTimeMillis()), outcome = outcome,
            attemptedRequestHex = attemptedRequest,
            receivedHex = ServiceInspection.hex(captured.toByteArray()), captureLimitReached = captured.size() == ServiceInspection.MAX_CAPTURE,
            tlsProtocol = protocol, tlsCipher = cipher, certificateSha256 = certificate,
            requestedTlsProtocol = requestedTlsProtocol, certificateDetails = certificateDetails).also { it.validate() }
    }
}
