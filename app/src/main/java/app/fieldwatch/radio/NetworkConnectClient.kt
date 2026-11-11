package app.fieldwatch.radio

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import app.fieldwatch.domain.NetworkScope
import app.fieldwatch.domain.TcpObservation
import app.fieldwatch.domain.ServiceProbe
import app.fieldwatch.domain.ServiceInspection
import app.fieldwatch.domain.ServiceInspectionReport
import app.fieldwatch.data.ServiceInspector
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/** Owns only sockets on the selected Wi-Fi network. Never binds the whole process. */
class NetworkConnectClient(context: Context) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val network: Network = connectivity.allNetworks.singleOrNull {
        connectivity.getNetworkCapabilities(it)?.let { caps ->
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } == true
    } ?: error("Connect to exactly one Wi-Fi network before checking targets.")
    val description: String = "Wi-Fi network ${network.networkHandle}"
    private val sockets = mutableSetOf<Socket>()
    private var closed = false

    fun validateTargets(hosts: List<String>): List<String> {
        val caps = connectivity.getNetworkCapabilities(network)
        check(caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) { "Selected Wi-Fi network is unavailable." }
        val links = connectivity.getLinkProperties(network) ?: error("Wi-Fi link information unavailable.")
        val locals = links.linkAddresses.filter { it.address is Inet4Address }
        require(hosts.all { target -> locals.any { NetworkScope.contains(it.address.hostAddress!!, it.prefixLength, target) } }) {
            "Every target must be within a directly connected Wi-Fi IPv4 subnet."
        }
        return hosts.filterNot { target -> locals.any { it.address.hostAddress == target } }.also {
            require(it.isNotEmpty()) { "Scope contains only this handset; choose another target." }
        }
    }

    suspend fun probe(address: String, port: Int): TcpObservation = withContext(Dispatchers.IO) {
        currentCoroutineContext().ensureActive()
        validateTargets(listOf(address))
        val socket = synchronized(sockets) {
            check(!closed) { "Network run stopped." }
            network.socketFactory.createSocket().also { sockets.add(it) }
        }
        val outcome = try {
            val bytes = address.split('.').map { it.toInt().toByte() }.toByteArray()
            socket.connect(InetSocketAddress(InetAddress.getByAddress(bytes), port), 800)
            "open"
        } catch (_: SocketTimeoutException) { "timeout" }
        catch (_: ConnectException) { "connect-rejected-or-error" }
        catch (_: java.io.IOException) { "unreachable-or-error" }
        finally { synchronized(sockets) { sockets.remove(socket) }; runCatching { socket.close() } }
        currentCoroutineContext().ensureActive()
        TcpObservation(address, port, outcome, System.currentTimeMillis())
    }

    suspend fun auditTls(address: String, port: Int): List<ServiceInspectionReport> =
        ServiceInspection.TLS_AUDIT_VERSIONS.map { inspect(address, port, ServiceProbe.TLS, it) }
            .also(ServiceInspection::validateTlsAudit)

    suspend fun inspect(address: String, port: Int, probe: ServiceProbe, requestedTlsProtocol: String? = null): ServiceInspectionReport = coroutineScope {
        ServiceInspection.request(address, port)
        validateTargets(listOf(address))
        val socket = synchronized(sockets) {
            check(!closed) { "Network run stopped." }
            network.socketFactory.createSocket().also { sockets.add(it) }
        }
        val expired = java.util.concurrent.atomic.AtomicBoolean(false)
        val deadline = launch {
            delay(ServiceInspection.DEADLINE_MS)
            expired.set(true)
            runCatching { socket.close() }
        }
        try {
            val report = withContext(Dispatchers.IO) {
                ServiceInspector.inspect(socket, address, port, probe, description, requestedTlsProtocol = requestedTlsProtocol)
            }
            currentCoroutineContext().ensureActive()
            when {
                !expired.get() -> report
                requestedTlsProtocol != null -> report.copy(outcome = "timeout",
                    tlsProtocol = null, tlsCipher = null, certificateSha256 = null)
                else -> report.copy(outcome = "timeout")
            }
        } finally {
            deadline.cancel()
            synchronized(sockets) { sockets.remove(socket) }
            runCatching { socket.close() }
        }
    }

    fun close() = synchronized(sockets) {
        closed = true
        sockets.forEach { runCatching { it.close() } }
        sockets.clear()
    }
}
