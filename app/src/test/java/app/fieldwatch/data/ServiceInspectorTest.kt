package app.fieldwatch.data

import app.fieldwatch.domain.*
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class ServiceInspectorTest {
    private class StubSocket(val input: InputStream) : Socket() {
        val output = ByteArrayOutputStream()
        var endpoint: SocketAddress? = null
        var closedByInspector = false
        var timeoutValue = 0
        override fun connect(endpoint: SocketAddress, timeout: Int) { this.endpoint = endpoint; assertTrue(timeout in 1..1500) }
        override fun getInputStream() = input
        override fun getOutputStream() = output
        override fun setSoTimeout(timeout: Int) { timeoutValue = timeout }
        override fun getSoTimeout() = timeoutValue
        override fun close() { closedByInspector = true }
    }
    private fun inspect(socket: StubSocket, mode: ServiceProbe = ServiceProbe.HTTP_HEAD) =
        ServiceInspector.inspect(socket, "192.168.1.2", 8080, mode, "Wi-Fi test")

    @Test fun headRequestIsExactAndDoesNotConsumeBody() {
        val input = ByteArrayInputStream("HTTP/1.1 200 OK\r\nServer: Lab\r\n\r\nSECRET BODY".toByteArray())
        val socket = StubSocket(input)
        val report = inspect(socket)
        assertArrayEquals(ServiceInspection.request("192.168.1.2", 8080), socket.output.toByteArray())
        assertEquals("SECRET BODY".length, input.available())
        assertFalse(ServiceInspection.display(report.receivedHex).contains("SECRET"))
        assertEquals(ServiceInspection.hex(socket.output.toByteArray()), report.attemptedRequestHex)
        assertEquals("observed", report.outcome)
        assertTrue(socket.closedByInspector)
        assertEquals("192.168.1.2", (socket.endpoint as InetSocketAddress).address.hostAddress)
    }
    @Test fun redirectIsRecordedWithoutAnotherConnection() {
        val socket = StubSocket(ByteArrayInputStream("HTTP/1.1 302 Found\r\nLocation: http://203.0.113.8/private\r\n\r\n".toByteArray()))
        val report = inspect(socket)
        assertTrue(ServiceInspection.display(report.receivedHex).contains("Location:"))
        assertEquals("HTTP response observed", ServiceInspection.identify(report.receivedHex))
        assertEquals("192.168.1.2", (socket.endpoint as InetSocketAddress).address.hostAddress)
        assertEquals(1, socket.output.toString().split("HEAD /").size - 1)
    }
    @Test fun bannerSendsNothingAndStopsAtFirstLine() {
        val socket = StubSocket(ByteArrayInputStream("SSH-2.0-Lab\r\nextra".toByteArray()))
        val report = inspect(socket, ServiceProbe.BANNER)
        assertEquals(0, socket.output.size())
        assertEquals("", report.attemptedRequestHex)
        assertEquals("SSH banner advertised", ServiceInspection.identify(report.receivedHex))
        assertEquals(5, socket.input.available())
    }
    @Test fun captureLimitDoesNotReadExtraBytes() {
        val input = ByteArrayInputStream(ByteArray(5000) { 65 })
        val report = inspect(StubSocket(input))
        assertEquals(ServiceInspection.MAX_CAPTURE * 2, report.receivedHex.length)
        assertTrue(report.captureLimitReached)
        assertEquals(5000 - ServiceInspection.MAX_CAPTURE, input.available())
    }
    @Test fun timeoutPreservesPartialBytesAndClosesSocket() {
        var reads = 0
        val socket = StubSocket(object : InputStream() {
            override fun read(): Int = if (reads++ < 3) 65 else throw SocketTimeoutException()
        })
        val report = inspect(socket)
        assertEquals("timeout", report.outcome)
        assertEquals("414141", report.receivedHex)
        assertTrue(socket.closedByInspector)
    }
    @Test fun eofAndIoFailureRemainDistinct() {
        assertEquals("eof", inspect(StubSocket(ByteArrayInputStream(byteArrayOf()))).outcome)
        val socket = StubSocket(object : InputStream() { override fun read(): Int = throw java.io.IOException() })
        assertEquals("connection-or-io-error", inspect(socket).outcome)
        assertTrue(socket.closedByInspector)
    }
    @Test fun slowDripCannotRenewTheTotalReadDeadline() {
        var time = 0L
        val socket = StubSocket(object : InputStream() {
            override fun read(): Int { time += 1_000_000_000L; return 65 }
        })
        val report = ServiceInspector.inspect(socket, "192.168.1.2", 80, ServiceProbe.HTTP_HEAD, "Wi-Fi lab") { time }
        assertEquals("timeout", report.outcome)
        assertEquals(5, ServiceInspection.bytes(report.receivedHex).size)
        assertTrue(socket.closedByInspector)
    }
    @Test fun tlsUsesClientModeAndEndpointIdentification() {
        (SSLSocketFactory.getDefault().createSocket() as SSLSocket).use { socket ->
            ServiceInspector.configureTls(socket)
            assertTrue(socket.useClientMode)
            assertEquals("HTTPS", socket.sslParameters.endpointIdentificationAlgorithm)
        }
    }

    @Test fun tlsAuditPinsOnlyVersionsAlreadyEnabledOnTheSocket() {
        (SSLSocketFactory.getDefault().createSocket() as SSLSocket).use { socket ->
            socket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
            ServiceInspector.configureTls(socket)
            assertFalse(ServiceInspector.pinEnabledTlsProtocol(socket, "TLSv1"))
            assertArrayEquals(arrayOf("TLSv1.2", "TLSv1.3"), socket.enabledProtocols)
            assertTrue(ServiceInspector.pinEnabledTlsProtocol(socket, "TLSv1.2"))
            assertArrayEquals(arrayOf("TLSv1.2"), socket.enabledProtocols)
            assertEquals("HTTPS", socket.sslParameters.endpointIdentificationAlgorithm)
        }
    }
}
