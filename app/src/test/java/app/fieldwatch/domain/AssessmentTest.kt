package app.fieldwatch.domain

import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class AssessmentTest {
    private fun engagement(): AssessmentEngagement {
        val text = "Confidential response with token ABC123"
        return AssessmentEngagement("eng-1", "Secret customer", "Private scope", 1,
            assets = listOf(AssessmentAsset("asset-1", "Private camera", "192.0.2.10", AssessmentTransport.NETWORK, 1)),
            runs = listOf(AssessmentRun("run-1", "asset-1", 2, status = AssessmentRunStatus.RECORDED, endedAt = 3)),
            evidence = listOf(AssessmentEvidence("e-1", "asset-1", "run-1", "Private evidence", text,
                AssessmentRules.sha256(text.toByteArray()), 2, appVersion = "test", catalogVersion = 94)),
            findings = listOf(AssessmentFinding("f-1", "asset-1", "Private finding", "Confidential details",
                FindingSeverity.HIGH, evidenceIds = listOf("e-1"), createdAt = 3)),
        )
    }

    @Test fun summaryOmitsAllOperatorTextIdentifiersAndEvidenceHashes() {
        val engagement = engagement()
        val exported = AssessmentReports.export(engagement, false, 5, "test")
        listOf(engagement.name, engagement.scope, engagement.assets.single().label,
            engagement.assets.single().identifier, engagement.evidence.single().title,
            engagement.evidence.single().text, engagement.evidence.single().sha256,
            engagement.findings.single().title, engagement.findings.single().description).forEach { assertFalse(exported.contains(it)) }
        val parsed = Json.decodeFromString<AssessmentReport>(exported)
        assertNull(parsed.engagement)
        assertEquals(1, parsed.summary!!.assetCount)
        assertEquals(1, parsed.summary!!.findingConfidences[FindingConfidence.SUSPECTED])
    }

    @Test fun fullReportPreservesEvidenceAndProvenance() {
        val engagement = engagement()
        val parsed = Json.decodeFromString<AssessmentReport>(AssessmentReports.export(engagement, true, 5, "test"))
        assertEquals(engagement, parsed.engagement)
        assertNull(parsed.summary)
        assertTrue(parsed.disclosure.contains("unencrypted"))
    }

    @Test fun textReportLinksFindingsToOneSourceEntryAndOmitsRawEvidence() {
        val base = engagement()
        val first = base.findings.single()
        val lowerPriority = first.copy(id = "f-2", severity = FindingSeverity.LOW, confidence = FindingConfidence.CONFIRMED,
            title = "Other finding", description = "Operator detail\r\nSecond line\u001b")
        val report = AssessmentReports.exportFindingsText(base.copy(findings = listOf(lowerPriority, first)), 5, "test")
        assertTrue(report.contains("F1  HIGH / SUSPECTED"))
        assertTrue(report.contains("F2  LOW / CONFIRMED"))
        assertEquals(2, report.lines().count { it == "  E1" })
        assertEquals(1, report.lines().count { it == "E1" })
        assertTrue(report.contains("Evidence ID\n  e-1"))
        assertTrue(report.contains(base.evidence.single().sha256))
        assertTrue(report.contains("  Operator detail\n  Second line "))
        assertFalse(report.contains(base.evidence.single().text))
        assertFalse(report.contains('\u001b'))
    }

    @Test fun textReportHandlesEngagementsWithoutFindings() {
        val original = engagement()
        val report = AssessmentReports.exportFindingsText(original.copy(findings = emptyList()), 5, "test")
        assertTrue(report.contains("No findings recorded."))
        assertFalse(report.contains(original.evidence.single().sha256))
    }

    @Test fun findingEvidenceCannotReferToAnotherAsset() {
        val original = engagement()
        val invalid = original.copy(findings = original.findings.map { it.copy(assetId = "missing") })
        assertThrows(IllegalArgumentException::class.java) { AssessmentRules.validate(AssessmentArchive(engagements = listOf(invalid))) }
    }

    @Test fun changedEvidenceContentIsRejectedEvenWithValidRelationships() {
        val original = engagement()
        val invalid = original.copy(evidence = original.evidence.map { it.copy(text = "Altered") })
        assertThrows(IllegalArgumentException::class.java) { AssessmentRules.validate(AssessmentArchive(engagements = listOf(invalid))) }
    }

    @Test fun unsupportedVersionAndDuplicateIdsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { AssessmentRules.validate(AssessmentArchive(formatVersion = 2)) }
        assertThrows(IllegalArgumentException::class.java) {
            AssessmentRules.validate(AssessmentArchive(engagements = listOf(engagement(), engagement())))
        }
    }

    @Test fun fabricatedAccessWithUnrelatedRunEvidenceIsRejected() {
        val original = engagement()
        val invalid = original.copy(access = listOf(AssessmentAccess("access-1", "asset-1", "nonexistent-run", "test service",
            listOf("read"), listOf("e-1"), 4)))
        assertThrows(IllegalArgumentException::class.java) { AssessmentRules.validate(AssessmentArchive(engagements = listOf(invalid))) }
    }
}
