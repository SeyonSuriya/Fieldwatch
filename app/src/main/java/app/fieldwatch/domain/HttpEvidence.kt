package app.fieldwatch.domain

data class ParsedHttpEvidence(val status: Int, val headers: List<Pair<String, String>>)

/** Strict interpretation of one captured HEAD response; never follows a redirect. */
object HttpEvidence {
    fun read(report: ServiceInspectionReport): ParsedHttpEvidence? {
        if (report.probe !in setOf(ServiceProbe.HTTP_HEAD, ServiceProbe.HTTPS_HEAD) || report.outcome !in setOf("observed", "eof")) return null
        if (report.attemptedRequestHex != ServiceInspection.hex(ServiceInspection.request(report.address, report.port))) return null
        if (report.probe == ServiceProbe.HTTPS_HEAD && report.tlsProtocol == null) return null
        val bytes = ServiceInspection.bytes(report.receivedHex)
        if (bytes.any { (it.toInt() and 255) !in 32..126 && it != 13.toByte() && it != 10.toByte() && it != 9.toByte() }) return null
        val text = bytes.toString(Charsets.US_ASCII)
        if (!text.endsWith("\r\n\r\n")) return null
        val lines = text.dropLast(4).split("\r\n")
        val status = Regex("HTTP/1\\.[01] ([1-5][0-9]{2})(?: [\\x20-\\x7e]*)?").matchEntire(lines.first())?.groupValues?.get(1)?.toInt() ?: return null
        if (status < 200) return null
        val headers = lines.drop(1).map { line ->
            if ('\r' in line || '\n' in line) return null
            val split = line.indexOf(':')
            if (split <= 0 || !line.substring(0, split).matches(Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))) return null
            line.substring(0, split).lowercase() to line.substring(split + 1).trim(' ', '\t')
        }
        return ParsedHttpEvidence(status, headers)
    }
}
