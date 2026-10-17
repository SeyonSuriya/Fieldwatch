# Reference fixture comparison

This M6 verification-workflow step links exposed and protected synthetic reference observations into one report. It does not add a commercial-device module, send new traffic, certify a physical handset or complete M6 product validation.

## Workflow

1. Collect and save plain HTTP HEAD / evidence from the [reference lab](device-validation.md)'s exposed and protected fixtures on different ports or hosts. Collect both within 15 minutes on the same Wi-Fi network.
2. Open their engagement in Assessments and select **Compare reference lab fixtures**.
3. Explicitly select the exposed observation and protected control. The picker shows endpoint, save time and an evidence-ID prefix, with up to the newest 100 service observations. It does not guess roles from port numbers or auto-select matching-looking products.
4. Select **Review comparison**. Cancel saves nothing. Review both outcomes and any mismatch reasons, then **Save encrypted comparison** if wanted.
5. The report appears under the exposed fixture's asset. It links both original evidence IDs and SHA-256 hashes, including the protected control when that belongs to another asset. The friendly view shows both endpoints and results; raw JSON/hashes remain available through **Show raw comparison and hashes** and full engagement export.

Validation independently rechecks each source's digest, recorded run, exact request, supported mode, target binding, response syntax and reference identity/build/marker rules. A single evidence record cannot fill both roles. The expected pair additionally requires:

- Distinct numeric address/port endpoints.
- Matching recorded Android Wi-Fi network handles.
- Earliest recorded request start to latest recorded request end spanning no more than 15 minutes.
- Matching module ID/version and fixture revision.
- `LAB_MARKER_EXPOSED` in the exposed slot and `LAB_PROTECTION_OBSERVED` in the protected slot.

The resulting outcome is `EXPECTED_REFERENCE_PAIR` or `INCONCLUSIVE`. Reversed roles, unsupported targets, failed/partial controls, inconsistent modes, timing/network mismatch and same-endpoint captures do not produce a successful pair. Source integrity/target errors reject review/save. Unknown or failed observations never become real-product vulnerability claims.

This is a comparison of recorded data. Matching network handles and timestamps are not hardware attestation or trusted clock evidence. Old captures close in time may form a historical pair; comparing them now does not rerun requests or establish current target behavior. Identity/build fields remain unauthenticated server claims. A pair report confirms neither a manufacturer vulnerability nor access to device files/media.

## Storage and compatibility

Comparison reports are bounded encrypted assessment evidence using the existing schema, with their own recorded run, app/catalog versions and SHA-256 hash. Both per-source lab evaluations and their module/fixture versions are embedded. The run is attributed to the exposed asset; the embedded control source link preserves its separate attribution. No new findings or access records are created. Individual lab evaluations remain available separately.

Save recomputes the comparison from the immutable stored sources instead of trusting UI-supplied outcomes. Repeating the same source pair/hash, comparison/module versions and fixture revision adds no duplicate, including after restarting. Inconclusive comparisons can be retained with their reasons. Closed engagements and vault limits reject writes through the existing atomic persistence path. Full exports include the complete comparison and original evidence; structural summaries expose only the usual aggregate run/evidence counts.

## Verification checklist

Software validation: development APK assembled; all 706 JVM tests across 55 suites passed with zero failures, errors or skipped tests. Physical handset comparison checks remain pending.

- Review the expected pair from ports 8081/8082, then cancel and confirm no new records. Review/save again and verify original IDs/hashes and both endpoints.
- Reverse the roles, select two observations of the same endpoint, change Wi-Fi network between captures, or exceed the 15-minute window. Verify inconclusive reasons and that no finding/access is created.
- Try a timeout/partial control or a non-reference service. Verify it cannot pass as a protected fixture.
- Save/repeat, restart/repeat, then export full/summary reports. Check duplicate prevention, friendly/raw views and summary omission.
- Close the engagement and verify further saves are blocked. Compare target logs before/after review/save: no additional requests should occur.

JVM fixtures cover expected/reversed pairs, repeated-role rejection, network/endpoint/time boundaries, incomplete controls, corrupted hashes, historical-result wording, encrypted persistence, source links, restart deduplication, export boundaries and closure. Real handset verification remains with the user. Product-specific M6 work still needs an identified target role, exact firmware and reproducible affected/unaffected product behavior.
