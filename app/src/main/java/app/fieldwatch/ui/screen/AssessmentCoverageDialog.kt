package app.fieldwatch.ui.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.fieldwatch.domain.AssessmentCoverage
import app.fieldwatch.domain.AssessmentEngagement
import app.fieldwatch.domain.TargetCoverage
import app.fieldwatch.domain.TlsCertificateDetails
import app.fieldwatch.domain.TlsCertificateValidity
import java.time.Instant
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
internal fun AssessmentCoverageDialog(
    engagement: AssessmentEngagement,
    canSave: Boolean,
    onDismiss: () -> Unit,
    onOpenEvidence: (String) -> Unit,
    onSaveChecks: (List<String>) -> Unit,
    onSaveDiscovery: (List<String>) -> Unit,
) {
    val coverage by produceState<List<TargetCoverage>?>(null, engagement) {
        value = null
        value = withContext(Dispatchers.Default) { AssessmentCoverage.summarize(engagement) }
    }
    var targetId by remember(engagement.id) { mutableStateOf<String?>(null) }
    val target = coverage?.firstOrNull { it.asset.id == targetId }
    var certificatePort by remember(targetId) { mutableStateOf<Int?>(null) }
    val certificateService = target?.services?.firstOrNull { it.port == certificatePort }
    var serviceChangePort by remember(targetId) { mutableStateOf<Int?>(null) }
    val changedService = target?.services?.firstOrNull { it.port == serviceChangePort }
    val overviewScroll = rememberLazyListState()
    val detailScroll = key(targetId) { rememberLazyListState() }
    val certificateScroll = key(targetId, certificatePort) { rememberLazyListState() }
    val changesScroll = key(targetId, serviceChangePort) { rememberLazyListState() }
    val validityCheckedAt = remember(targetId, certificatePort) { System.currentTimeMillis() }
    val back = {
        when {
            certificatePort != null -> certificatePort = null
            serviceChangePort != null -> serviceChangePort = null
            targetId != null -> targetId = null
            else -> onDismiss()
        }
    }
    AlertDialog(
        onDismissRequest = back,
        title = {
            Text(certificateService?.let { "Certificate history · TCP ${it.port}" }
                ?: changedService?.let { "Service changes · TCP ${it.port}" }
                ?: target?.asset?.label ?: "Target coverage")
        },
        text = {
            val targets = coverage
            when {
                targets == null -> CircularProgressIndicator()
                targets.isEmpty() -> Text("Add a target or save an observation to see coverage.")
                else -> LazyColumn(Modifier.fillMaxWidth().heightIn(max = 460.dp),
                    state = when {
                        certificateService != null -> certificateScroll
                        changedService != null -> changesScroll
                        target == null -> overviewScroll
                        else -> detailScroll
                    },
                    verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (changedService != null) {
                        item { Text("Changes compare saved responses from the same Wi-Fi network and inspection mode.") }
                        items(changedService.serviceChanges, key = { it.current.evidenceId }) { change ->
                            Column {
                                HorizontalDivider()
                                Text("${change.current.probe.name.replace('_', ' ')} · ${change.current.network}",
                                    style = MaterialTheme.typography.titleSmall)
                                Text("Previous · ${coverageTime(change.previous.endedAt)}")
                                if (change.advertisedLabelChanged) Text("Advertised software or banner: ${change.previous.advertisedLabel}")
                                if (change.httpAccessChanged) Text(change.previous.httpAccess!!.label)
                                TextButton(onClick = { onOpenEvidence(change.previous.evidenceId) }) { Text("Open previous inspection") }
                                Text("New · ${coverageTime(change.current.endedAt)}")
                                if (change.advertisedLabelChanged) Text("Advertised software or banner: ${change.current.advertisedLabel}")
                                if (change.httpAccessChanged) Text(change.current.httpAccess!!.label)
                                TextButton(onClick = { onOpenEvidence(change.current.evidenceId) }) { Text("Open changed inspection") }
                            }
                        }
                    } else if (certificateService != null) {
                        item { Text("Comparisons use the same saved Wi-Fi network, inspection mode and negotiated TLS version.") }
                        for (history in certificateService.certificateHistories) {
                            val latest = history.latest
                            item {
                                Column {
                                    HorizontalDivider()
                                    Text("${latest.protocol} · ${latest.probe.name.replace('_', ' ')}", style = MaterialTheme.typography.titleSmall)
                                    Text(latest.network)
                                    Text("${history.captureCount} captures · ${history.changes.size} fingerprint changes")
                                    Text("Latest capture · ${coverageTime(latest.endedAt)}")
                                    val details = latest.details
                                    if (details == null) {
                                        Text("Validity dates unavailable", style = MaterialTheme.typography.bodySmall)
                                    } else {
                                        Text(when (details.validityAt(validityCheckedAt)) {
                                            TlsCertificateValidity.EXPIRED -> "Saved certificate expired"
                                            TlsCertificateValidity.EXPIRING_SOON -> "Saved certificate expires within ${TlsCertificateDetails.EXPIRY_NOTICE_DAYS} days"
                                            TlsCertificateValidity.NOT_YET_VALID -> "Saved certificate is not yet valid"
                                            TlsCertificateValidity.VALID -> "Saved certificate is within its validity dates"
                                        }, style = MaterialTheme.typography.bodySmall)
                                        Text("Valid until (UTC) ${Instant.ofEpochMilli(details.notAfter)}",
                                            style = MaterialTheme.typography.bodySmall)
                                    }
                                    Text("SHA-256: ${latest.sha256}", style = MaterialTheme.typography.bodySmall)
                                    TextButton(onClick = { onOpenEvidence(latest.evidenceId) }) { Text("Open latest capture") }
                                }
                            }
                            items(history.changes.asReversed(), key = { "certificate-change-${it.current.evidenceId}" }) { change ->
                                Column {
                                    Text("Fingerprint changed", style = MaterialTheme.typography.titleSmall)
                                    Text("Previous · ${coverageTime(change.previous.endedAt)}")
                                    Text(change.previous.sha256, style = MaterialTheme.typography.bodySmall)
                                    TextButton(onClick = { onOpenEvidence(change.previous.evidenceId) }) { Text("Open previous capture") }
                                    Text("New · ${coverageTime(change.current.endedAt)}")
                                    Text(change.current.sha256, style = MaterialTheme.typography.bodySmall)
                                    TextButton(onClick = { onOpenEvidence(change.current.evidenceId) }) { Text("Open changed capture") }
                                }
                            }
                        }
                    } else if (target == null) {
                        item { Text("Based on saved evidence in this engagement.") }
                        items(targets, key = { it.asset.id }) { row ->
                            Column {
                                Text(row.asset.label, style = MaterialTheme.typography.titleSmall)
                                Text(row.asset.identifier)
                                Text("${row.savedEvidenceCount} evidence records · ${row.services.size} TCP endpoints · ${row.pendingReviews.size} records awaiting review")
                                TextButton(onClick = { targetId = row.asset.id }) { Text("View target coverage") }
                            }
                        }
                    } else {
                        val pendingChecks = target.pendingReviews.filter { it.checks }.map { it.evidenceId }
                        val pendingDiscovery = target.pendingReviews.filter { it.discovery }.map { it.evidenceId }
                        item {
                            Text(target.asset.identifier)
                            if (pendingChecks.isNotEmpty()) {
                                OutlinedButton(onClick = { onSaveChecks(pendingChecks) }, enabled = canSave) {
                                    Text("Save pending checks (${pendingChecks.size})")
                                }
                            }
                            if (pendingDiscovery.isNotEmpty()) {
                                OutlinedButton(onClick = { onSaveDiscovery(pendingDiscovery) }, enabled = canSave) {
                                    Text("Save pending discovery (${pendingDiscovery.size})")
                                }
                            }
                            if (target.unreadableNetworkRecords > 0) {
                                Text("${target.unreadableNetworkRecords} network records could not be interpreted.")
                            }
                            if (target.services.isNotEmpty()) Text("TCP endpoints", style = MaterialTheme.typography.titleSmall)
                        }
                        items(target.services, key = { it.port }) { service ->
                            Column {
                                HorizontalDivider()
                                Text(service.latestInspection?.advertisedLabel ?: "TCP port ${service.port}",
                                    style = MaterialTheme.typography.titleSmall)
                                if (service.latestInspection?.advertisedLabel != null) Text("TCP port ${service.port}")
                                service.latestTcp?.let { tcp ->
                                    Text("Latest TCP check: ${tcp.outcome.replace('-', ' ')} · ${coverageTime(tcp.observedAt)}")
                                }
                                val inspection = service.latestInspection
                                if (inspection == null) {
                                    Text("No service inspection saved.")
                                } else {
                                    Text("${service.capturedResponses} saved responses")
                                    Text("Latest inspection: ${inspection.probe.name.replace('_', ' ')} · ${inspection.outcome.replace('-', ' ')} · ${coverageTime(inspection.endedAt)}")
                                    TextButton(onClick = { onOpenEvidence(inspection.evidenceId) }) { Text("Open inspection") }
                                }
                                if (service.certificateHistories.isNotEmpty()) {
                                    val validity = service.certificateHistories.groupingBy {
                                        it.latest.details?.validityAt(validityCheckedAt)
                                    }.eachCount()
                                    val statuses = listOfNotNull(
                                        validity[TlsCertificateValidity.EXPIRED]?.let { "$it expired" },
                                        validity[TlsCertificateValidity.EXPIRING_SOON]?.let { "$it expiring within ${TlsCertificateDetails.EXPIRY_NOTICE_DAYS} days" },
                                        validity[TlsCertificateValidity.NOT_YET_VALID]?.let { "$it not yet valid" },
                                        validity[TlsCertificateValidity.VALID]?.let { "$it within validity dates" },
                                        validity[null]?.let { "$it without validity dates" },
                                    )
                                    val attention = TlsCertificateValidity.EXPIRED in validity ||
                                        TlsCertificateValidity.EXPIRING_SOON in validity ||
                                        TlsCertificateValidity.NOT_YET_VALID in validity
                                    Text("Latest saved certificates by TLS context: ${statuses.joinToString(", ")}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (attention) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                                    val changes = service.certificateHistories.sumOf { it.changes.size }
                                    OutlinedButton(onClick = { certificatePort = service.port }) { Text("Certificate history ($changes changes)") }
                                }
                                if (service.serviceChanges.isNotEmpty()) {
                                    OutlinedButton(onClick = { serviceChangePort = service.port }) {
                                        Text("Service changes (${service.serviceChanges.size})")
                                    }
                                }
                            }
                        }
                        item {
                            Text("Evidence awaiting review", style = MaterialTheme.typography.titleSmall)
                            if (target.pendingReviews.isEmpty()) Text("No saved records awaiting the current checks.")
                        }
                        items(target.pendingReviews, key = { it.evidenceId }) { review ->
                            Column {
                                Text(review.title)
                                Text(when {
                                    review.checks && review.discovery -> "Checks and service discovery pending"
                                    review.checks -> "Checks pending"
                                    else -> "Service discovery pending"
                                })
                                OutlinedButton(onClick = { onOpenEvidence(review.evidenceId) }) { Text("Open source evidence") }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = back) {
            Text(when {
                certificateService != null || changedService != null -> "Back to endpoints"
                target == null -> "Done"
                else -> "Back to targets"
            })
        } },
    )
}

private fun coverageTime(timestamp: Long) = DateFormat.getDateTimeInstance().format(Date(timestamp))
