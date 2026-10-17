# M5: versioned observation checks

The built-in registry v1 evaluates saved M4 service and Wi-Fi security evidence offline. It does not open a socket, reconnect Bluetooth, send credentials, exploit a target or create access records. These initial checks address observable configuration concerns that phone evidence can support; they are not a measured ranking of exploited devices or a CVE database.

## Use

1. Save a service inspection or Wi-Fi security snapshot to an open engagement.
2. Open that engagement in Assessments. On the saved evidence, select **Review versioned checks**.
3. Review each condition, outcome, limitation and recommended action. Cancel leaves the vault untouched.
4. **Save check results** records every result as encrypted evaluation evidence. Only observed conditions create findings. Repeat evaluation of the same source evidence/hash with the same registry version adds no duplicate records.

Closed engagements cannot be changed. Existing operator findings remain suspected and retain their original workflow. Unsupported collector formats and manual notes cannot be passed off as supported service/Wi-Fi evidence. Malformed reports, digest mismatches and report/asset target mismatches reject evaluation. New collection is required to retest a target: evaluation of an old snapshot is not a fresh assessment.

## Outcomes and confidence

- CONDITION_OBSERVED: the supported condition is present in the recorded observation. A finding is created with the check's defined severity/confidence.
- NOT_OBSERVED: the qualifying condition was not found in this observation. This is not a security pass, proof of absence, or an assessment of other endpoints/configurations.
- INCONCLUSIVE: missing, incomplete, failed, ambiguous or unsupported observation. No finding is created.
- NOT_APPLICABLE: this check does not apply to the selected inspection mode. No finding is created.

CONFIRMED findings apply only to a directly observed, narrowly worded transport/session condition. They do not confirm sensitive-data exposure, missing authorization, a CVE, exploitation or device access. Advertised Wi-Fi and SSH configurations remain SUSPECTED because advertisements can be spoofed, stale or inconsistent with actual configuration. Impact and severity are initial review priorities; deployment context still matters.

## Registry v1

All individual checks are version 1. Registry version must change when behavior, coverage or check metadata changes, and affected check versions must also be incremented. Existing historical evaluations/findings are retained rather than rewritten.

| Check ID | Evidence and qualifying condition | Finding |
| --- | --- | --- |
| wifi-wep | Well-formed capability tokens contain exact WEP | Medium, suspected |
| wifi-wpa1 | A capability token starts WPA-; WPA2/RSN alone do not qualify | Medium, suspected |
| wifi-open | Minimal ESS-only or ESS+WPS advertisement | Low, suspected; intended guest/public use needs review |
| wifi-wps | WPS advertisement | Inconclusive; no automatic finding; PIN method, lockout and exploitability untested |
| http-cleartext | Complete valid final HTTP/1.0 or 1.1 headers in a plain HTTP HEAD inspection with a recorded request attempt | Low, confirmed cleartext response only |
| http-basic-cleartext | That HTTP exchange returns 401 and an actual WWW-Authenticate field starts with Basic and a quoted realm | Medium, suspected; credential acceptance untested |
| tls-legacy | A verified saved TLS session negotiated TLS 1.0/1.1 | Medium, confirmed negotiated version only |
| ssh-v1 | Banner-mode capture contains a complete SSH-1.x greeting, excluding SSH-1.99 compatibility | Medium, suspected server claim |

Unknown Wi-Fi flags and OWE transition advertisements are not classified as open links. WPS advertisement never proves a vulnerability. HTTP parsing rejects incomplete headers, folded fields, invalid field names, binary/control bytes and interim responses. Basic is recognized conservatively as the first challenge in a header field; complex combined challenges may be unclassified. Header presence or an HTTP 200 response never establishes that protected content is accessible without authorization. Server product/version strings are not mapped to CVEs.

TLS handshake failures are inconclusive, not certificate-vulnerability findings. A single modern TLS session does not rule out legacy protocol support; this registry performs no downgrade enumeration. Android's default TLS policy may prevent negotiating legacy versions, so the positive legacy-TLS fixture exercises the offline evaluator, not a claim of handset capability. SSH-1.99 is compatible with SSH version 2 and is explicitly excluded from SSH-v1 findings. Unknown/partial banners do not imply a protocol or product vulnerability.

## Evidence, storage and exports

An evaluation stores registry version, every check ID/version/outcome/explanation, evaluation time, source evidence ID/hash and asset ID. It receives its own assessment run (`observation-checks`), encrypted evidence and SHA-256 digest. Each generated finding links both the original evidence and evaluation evidence, records its individual check ID/version, and includes recommended action, references and an explicit limit on the conclusion. Inconclusive/non-applicable/not-observed results remain visible in the saved evaluation JSON even when no finding is generated.

Evaluation, evidence and findings are written atomically under the existing vault lock and bounds. Storage/encryption failures do not publish partially generated findings. Same-source/version deduplication applies across restarts. Distinct snapshots may create historical findings even when their conditions are similar. No network or radio work is launched by review/save. Original finding JSON without check metadata remains readable; metadata fields have defaults. Full exports include evaluations, raw evidence and linked findings in plaintext; structural summary exports omit all raw contents/identifiers/check text and include finding counts.

## Validation and handset checklist

Software validation: the development APK assembled successfully; all 669 JVM tests across 52 suites passed with zero failures, errors or skipped tests. Handset verification has not been performed here.

JVM fixtures cover positive/negative Wi-Fi flags, legacy/modern/failed TLS metadata, cleartext/HTTPS, Basic versus other headers, malformed/partial HTTP, SSH v1/v2/1.99, unknown banners, target/digest rejection, legacy finding decoding, encrypted persistence, source links, idempotence and closed/unsupported-source rejection. These are synthetic observation fixtures and controlled protocol streams; they are not vulnerable/fixed product certifications.

On the handset:

1. Save known lab Wi-Fi and HTTP/TLS/banner observations, review results and compare them to the original raw evidence and actual lab configuration.
2. Cancel a preview and verify no records are added. Save it, then repeat and verify no duplicates. Restart and repeat again.
3. Confirm unknown flags, WPS and failed TLS do not create confirmed vulnerabilities. Confirm plain HTTP only confirms a cleartext response, never login success or device access.
4. Export full/summary reports and check version/provenance, evidence links and summary omission. Close the engagement and verify checks cannot save.
5. Upgrade over an M4 development install without uninstalling. Verify existing encrypted records and operator findings still open; confirm the new source labels show the actual collector instead of calling every record an operator note.

## Primary references

- [NIST SP 800-153: WLAN configuration and monitoring](https://csrc.nist.gov/pubs/sp/800/153/final).
- [RFC 7617: Basic authentication security considerations](https://www.rfc-editor.org/rfc/rfc7617#section-4).
- [RFC 8996: deprecation of TLS 1.0/1.1](https://www.rfc-editor.org/rfc/rfc8996).
- [RFC 4253: SSH compatibility, including SSH-1.99](https://www.rfc-editor.org/rfc/rfc4253#section-5).
- [RFC 9110: HTTP security considerations](https://www.rfc-editor.org/rfc/rfc9110#section-17.1).

M6 depends on reproducible device-specific affected/unaffected lab targets before a module can claim product vulnerability validation. M5 does not relax that requirement.
