package app.fieldwatch.domain

import kotlinx.serialization.Serializable

/** Numeric addresses only: scope expansion never invokes DNS. */
object NetworkScope {
    fun number(address: String): Long {
        val parts = address.split('.')
        require(parts.size == 4 && parts.all { it.matches(Regex("0|[1-9][0-9]{0,2}")) && it.toInt() <= 255 }) { "Enter a numeric IPv4 address." }
        return parts.fold(0L) { value, part -> (value shl 8) or part.toLong() }
    }
    fun address(number: Long): String = (3 downTo 0).joinToString(".") { ((number ushr (it * 8)) and 255).toString() }
    fun contains(local: String, prefix: Int, target: String): Boolean {
        require(prefix in 0..32)
        val mask = (0xffffffffL shl (32 - prefix)) and 0xffffffffL
        return (number(local) and mask) == (number(target) and mask)
    }
    fun hosts(input: String): List<String> {
        val parts = input.trim().split('/')
        require(parts.size in 1..2) { "Enter one IPv4 address or /24–/32 range." }
        val value = number(parts[0])
        val prefix = if (parts.size == 1) 32 else requireNotNull(parts[1].toIntOrNull()) { "Invalid prefix." }
        require(prefix in 24..32) { "A run supports at most a /24 range." }
        val size = 1L shl (32 - prefix)
        val base = value and (0xffffffffL xor (size - 1))
        val range = if (prefix <= 30) (base + 1)..(base + size - 2) else base until (base + size)
        return range.map(::address).also { hosts ->
            require(hosts.all { val first = number(it) ushr 24; first in 1L..223L && first != 127L && !it.startsWith("169.254.") }) {
                "Unicast IPv4 targets only; loopback and link-local targets are unsupported."
            }
        }
    }
    fun ports(input: String): List<Int> {
        val tokens = input.split(',')
        require(tokens.size in 1..16) { "Choose 1–16 comma-separated TCP ports." }
        return tokens.map { it.trim().toIntOrNull()?.also { port -> require(port in 1..65535) { "Ports must be 1–65535." } }
            ?: throw IllegalArgumentException("Enter numeric TCP ports.") }.distinct()
    }
}

@Serializable
data class TcpObservation(val address: String, val port: Int, val outcome: String, val observedAt: Long)

@Serializable
data class NetworkEvidenceReport(
    val format: String = "fieldwatch-network-connect",
    val version: Int = 1,
    val scope: String,
    val ports: List<Int>,
    val network: String,
    val startedAt: Long,
    val endedAt: Long,
    val cancelled: Boolean,
    val observations: List<TcpObservation>,
) {
    fun validate() {
        require(format == "fieldwatch-network-connect" && version == 1)
        val hosts = NetworkScope.hosts(scope)
        require(ports.isNotEmpty() && ports.size <= 16 && ports.distinct() == ports && ports.all { it in 1..65535 })
        require(network.length in 1..200 && startedAt > 0 && endedAt >= startedAt)
        require(observations.size <= hosts.size * ports.size)
        require(hosts.size * ports.size <= 256)
        require(observations.map { it.address to it.port }.distinct().size == observations.size)
        require(observations.all { it.address in hosts && it.port in ports && it.outcome in OUTCOMES && it.observedAt in startedAt..endedAt })
    }
    companion object { val OUTCOMES = setOf("open", "connect-rejected-or-error", "timeout", "unreachable-or-error") }
}

/** Capability flags are advertisement claims, never a successful vulnerability check. */
object WifiSecurityAnalysis {
    fun describe(capabilities: String?): String {
        if (capabilities.isNullOrBlank()) return "Unknown: security capabilities unavailable."
        val flags = capabilities.uppercase()
        val modes = buildList {
            if ("WEP" in flags) add("WEP (obsolete protection)")
            if (Regex("\\[WPA-").containsMatchIn(flags)) add("WPA1 (legacy protection)")
            if ("PSK" in flags && ("RSN" in flags || "WPA2" in flags)) add("WPA2 personal advertised")
            if ("SAE" in flags) add("WPA3 personal advertised")
            if ("EAP" in flags) add("Enterprise authentication advertised")
            if ("OWE_TRANSITION" in flags) add("OWE transition: open compatibility may be offered")
            else if ("OWE" in flags) add("OWE enhanced open advertised")
        }
        val base = if (modes.isNotEmpty()) modes.joinToString("; ")
            else if (flags == "[ESS]" || flags == "[ESS][WPS]" || flags == "[WPS][ESS]") "Open network advertised: no link encryption"
            else "Unclassified capabilities: inspect raw flags"
        return base + if ("WPS" in flags) "; WPS advertised (exploitability untested)" else ""
    }
}
