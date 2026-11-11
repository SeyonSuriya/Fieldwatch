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
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
internal fun AssessmentCoverageDialog(
    engagement: AssessmentEngagement,
    onDismiss: () -> Unit,
    onOpenEvidence: (String) -> Unit,
) {
    val coverage by produceState<List<TargetCoverage>?>(null, engagement) {
        value = null
        value = withContext(Dispatchers.Default) { AssessmentCoverage.summarize(engagement) }
    }
    var targetId by remember(engagement.id) { mutableStateOf<String?>(null) }
    val target = coverage?.firstOrNull { it.asset.id == targetId }
    val overviewScroll = rememberLazyListState()
    val detailScroll = key(targetId) { rememberLazyListState() }
    val back = { if (targetId == null) onDismiss() else targetId = null }
    AlertDialog(
        onDismissRequest = back,
        title = { Text(target?.asset?.label ?: "Target coverage") },
        text = {
            val targets = coverage
            when {
                targets == null -> CircularProgressIndicator()
                targets.isEmpty() -> Text("Add a target or save an observation to see coverage.")
                else -> LazyColumn(Modifier.fillMaxWidth().heightIn(max = 460.dp),
                    state = if (target == null) overviewScroll else detailScroll,
                    verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    if (target == null) {
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
                        item {
                            Text(target.asset.identifier)
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
        confirmButton = { TextButton(onClick = back) { Text(if (target == null) "Done" else "Back to targets") } },
    )
}

private fun coverageTime(timestamp: Long) = DateFormat.getDateTimeInstance().format(Date(timestamp))
