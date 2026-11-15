package app.fieldwatch.domain

import kotlinx.serialization.json.Json

data class CoverageInspection(
    val evidenceId: String,
    val probe: ServiceProbe,
    val outcome: String,
    val endedAt: Long,
    val advertisedLabel: String?,
    val httpPath: String? = null,
)

data class CertificateCapture(
    val evidenceId: String,
    val network: String,
    val probe: ServiceProbe,
    val protocol: String,
    val endedAt: Long,
    val sha256: String,
    val details: TlsCertificateDetails? = null,
)

data class CertificateChange(val previous: CertificateCapture, val current: CertificateCapture)

data class CertificateHistory(
    val latest: CertificateCapture,
    val captureCount: Int,
    val changes: List<CertificateChange>,
)

data class ServiceCapture(
    val evidenceId: String,
    val network: String,
    val probe: ServiceProbe,
    val endedAt: Long,
    val advertisedLabel: String?,
    val httpAccess: HttpAccessSignal?,
    val httpPath: String? = null,
)

enum class HttpAccessSignal(val label: String) {
    SUCCESS("Successful response without credentials"),
    CHALLENGE("HTTP 401 with an authentication header"),
    NO_CHALLENGE("HTTP 401 without an authentication header"),
    FORBIDDEN("HTTP 403 refusal"),
    REDIRECT("HTTP redirect"),
}

data class ServiceChange(val previous: ServiceCapture, val current: ServiceCapture) {
    val advertisedLabelChanged: Boolean
        get() = previous.advertisedLabel != null && current.advertisedLabel != null &&
            previous.advertisedLabel != current.advertisedLabel

    val httpAccessChanged: Boolean
        get() = previous.httpAccess != null && current.httpAccess != null &&
            previous.httpAccess != current.httpAccess
}

data class ServiceCoverage(
    val port: Int,
    val latestTcp: TcpObservation? = null,
    val latestTcpEvidenceId: String? = null,
    val latestInspection: CoverageInspection? = null,
    val capturedResponses: Int = 0,
    val certificateHistories: List<CertificateHistory> = emptyList(),
    val serviceChanges: List<ServiceChange> = emptyList(),
)

data class PendingEvidenceReview(
    val evidenceId: String,
    val title: String,
    val checks: Boolean,
    val discovery: Boolean,
)

data class TargetCoverage(
    val asset: AssessmentAsset,
    val savedEvidenceCount: Int,
    val services: List<ServiceCoverage>,
    val pendingReviews: List<PendingEvidenceReview>,
    val unreadableNetworkRecords: Int,
)

object AssessmentCoverage {
    fun summarize(engagement: AssessmentEngagement): List<TargetCoverage> {
        val byAsset = engagement.evidence.groupBy { it.assetId }
        return engagement.assets.map { asset ->
            val evidence = byAsset[asset.id].orEmpty()
            val checked = evidence.filter { it.source == "versioned-check-evaluation" }.mapNotNull { row ->
                decode<CheckEvaluation>(row)?.takeIf {
                    it.format == "fieldwatch-check-evaluation" && it.formatVersion == 1 &&
                        it.registryVersion == AssessmentChecks.VERSION && it.assetId == asset.id
                }?.let { it.sourceEvidenceId to it.sourceSha256 }
            }.toSet()
            val discovered = evidence.filter { it.source == "service-discovery" }.mapNotNull { row ->
                decode<ServiceDiscoveryReport>(row)?.takeIf {
                    it.format == "fieldwatch-service-discovery" && it.version == ServiceDiscovery.VERSION &&
                        it.catalogVersion == ServiceDiscovery.CATALOG_VERSION && it.assetId == asset.id
                }?.let { it.sourceEvidenceId to it.sourceSha256 }
            }.toSet()
            val services = mutableMapOf<Int, ServiceCoverage>()
            val certificates = mutableMapOf<Int, MutableList<CertificateCapture>>()
            val serviceCaptures = mutableMapOf<Int, MutableList<ServiceCapture>>()
            var unreadable = 0
            for (row in evidence) {
                when (row.source) {
                    "network-tcp-connect" -> {
                        val observations = runCatching {
                            require(asset.transport == AssessmentTransport.NETWORK)
                            Json.decodeFromString<NetworkEvidenceReport>(row.text).also { it.validate() }
                                .observations.filter { it.address == asset.identifier }.also { require(it.isNotEmpty()) }
                        }.getOrNull()
                        if (observations == null) {
                            unreadable++
                            continue
                        }
                        for (observation in observations) {
                            val service = services[observation.port] ?: ServiceCoverage(observation.port)
                            if (service.latestTcp == null || observation.observedAt >= service.latestTcp.observedAt) {
                                services[observation.port] = service.copy(latestTcp = observation, latestTcpEvidenceId = row.id)
                            }
                        }
                    }
                    "service-inspection" -> {
                        val report = runCatching {
                            Json.decodeFromString<ServiceInspectionReport>(row.text).also {
                                it.validate()
                                require(asset.transport == AssessmentTransport.NETWORK && it.address == asset.identifier)
                            }
                        }.getOrNull()
                        if (report == null) {
                            unreadable++
                            continue
                        }
                        val service = services[report.port] ?: ServiceCoverage(report.port)
                        val label = ServiceInspection.advertisedLabel(report)
                        val http = HttpEvidence.read(report)
                        val path = report.httpPath.takeIf { report.probe == ServiceProbe.HTTP_HEAD || report.probe == ServiceProbe.HTTPS_HEAD }
                        if (http != null || label != null) {
                            serviceCaptures.getOrPut(report.port) { mutableListOf() } += ServiceCapture(
                                row.id, report.network, report.probe, report.endedAt, label, http?.accessSignal(), path)
                        }
                        val latest = if (service.latestInspection == null || report.endedAt >= service.latestInspection.endedAt) {
                            CoverageInspection(row.id, report.probe, report.outcome, report.endedAt, label, path)
                        } else service.latestInspection
                        val captured = report.outcome in setOf("observed", "eof") &&
                            (report.receivedHex.isNotEmpty() || report.tlsProtocol != null)
                        services[report.port] = service.copy(latestInspection = latest,
                            capturedResponses = service.capturedResponses + if (captured) 1 else 0)
                        if (report.tlsProtocol != null && report.certificateSha256 != null &&
                            report.outcome != "tls-validation-or-handshake-failed") {
                            certificates.getOrPut(report.port) { mutableListOf() } += CertificateCapture(
                                row.id, report.network, report.probe, report.tlsProtocol, report.endedAt,
                                report.certificateSha256, report.certificateDetails)
                        }
                    }
                }
            }
            val pending = evidence.mapNotNull { row ->
                val identity = row.id to row.sha256
                val checks = AssessmentChecks.supports(row.source) && identity !in checked
                val discovery = row.source == "service-inspection" && identity !in discovered
                if (checks || discovery) PendingEvidenceReview(row.id, row.title, checks, discovery) else null
            }
            val coveredServices = services.values.sortedBy { it.port }.map { service ->
                val histories = certificates[service.port].orEmpty()
                    .groupBy { Triple(it.network, it.probe, it.protocol) }.values.map { captures ->
                        val ordered = captures.sortedBy { it.endedAt }
                        val changes = ordered.zipWithNext { before, after ->
                            CertificateChange(before, after).takeIf { before.sha256 != after.sha256 }
                        }.filterNotNull()
                        CertificateHistory(ordered.last(), ordered.size, changes)
                    }.sortedByDescending { it.latest.endedAt }
                val changes = serviceCaptures[service.port].orEmpty().groupBy { Triple(it.network, it.probe, it.httpPath) }
                    .values.flatMap { captures ->
                        captures.sortedBy { it.endedAt }.zipWithNext(::ServiceChange).filter {
                            it.advertisedLabelChanged || it.httpAccessChanged
                        }
                    }.sortedByDescending { it.current.endedAt }
                service.copy(certificateHistories = histories, serviceChanges = changes)
            }
            TargetCoverage(asset, evidence.size, coveredServices, pending, unreadable)
        }
    }

    private fun ParsedHttpEvidence.accessSignal(): HttpAccessSignal? = when (status) {
        in 200..299 -> HttpAccessSignal.SUCCESS
        401 -> if (headers.any { it.first == "www-authenticate" && it.second.isNotBlank() }) {
            HttpAccessSignal.CHALLENGE
        } else HttpAccessSignal.NO_CHALLENGE
        403 -> HttpAccessSignal.FORBIDDEN
        301, 302, 303, 307, 308 -> HttpAccessSignal.REDIRECT
        else -> null
    }

    private inline fun <reified T> decode(evidence: AssessmentEvidence): T? =
        runCatching { Json.decodeFromString<T>(evidence.text) }.getOrNull()
}
