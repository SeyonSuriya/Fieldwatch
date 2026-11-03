# Service identification and advisory candidates

Fieldwatch 1.1.27 adds an offline discovery review to saved service inspections.
This is a functional feature: it identifies advertised software, matches a small
reviewed advisory catalog, and saves linked suspected findings in an engagement.
It does not execute an exploit or infer access from a version string.

## Use it

1. In Network assessment, select an open authorized engagement and inspect a
   service with HTTP HEAD, HTTPS HEAD or a passive banner capture.
2. Save inspection evidence, then open that engagement in Assessments.
3. On the saved service inspection, choose **Discover software and advisory candidates**.
4. Review the advertised identity and any candidate prerequisites. Choose
   **Save discovery review** to save the derived evidence and suspected findings.
5. Full exports include the source, source hash, identity, advisory references,
   catalog version/review date and findings. Summaries retain aggregate counts.

The review reuses existing captured bytes; it starts no new connection. HTTP
recognition requires a completed, recorded HEAD exchange parsed as a single strict
response. Duplicate Server fields and ambiguous/malformed identities do not match.
HTTPS identification requires a verified TLS session in the source. OpenSSH and
Dropbear identification requires a complete SSH banner. Ports and MAC vendors do
not establish a product, firmware version or CVE.

Recognized HTTP identities: Apache HTTP Server, nginx, lighttpd, Microsoft IIS,
GoAhead-Webs and Boa. Versionless or unknown identities remain usable evidence,
without inventing a software version. Raw source bytes remain authoritative.

## Initial catalog

Catalog v1, reviewed 4 November 2026, contains two vendor-sourced advisories:

| Advisory | Advertised Apache versions that become candidates | Vendor fix release |
| --- | --- | --- |
| CVE-2021-41773 | 2.4.49 | 2.4.50; incomplete fix, also review the next advisory |
| CVE-2021-42013 | 2.4.49, 2.4.50 | 2.4.51 |

Source: [Apache HTTP Server security notices](https://httpd.apache.org/security/vulnerabilities_24.html).
Both depend on affected code and configuration. Headers cannot establish whether a
vendor backported a patch or whether vulnerable mappings/CGI are configured. Follow
vendor upgrade guidance for a currently supported release, rather than treating
these historical fix releases as current upgrade recommendations.

Exact advertised version matches are labeled UNVERIFIED_VERSION_MATCH and saved
as HIGH / SUSPECTED candidate findings linked to both the source and derived report.
This priority is for investigation, not a confirmed target severity or compromise.
No access result is generated. Saving the same source/hash with the same parser
and catalog versions is deduplicated; closed engagements remain read-only.

A missing match means vulnerability status is unknown. This initial two-entry
catalog does not cover all flaws in the recognized software, device firmware,
wireless protocol vulnerabilities or other services. It is bundled and versioned,
not a live advisory feed. Stored results retain their catalog version.

## Next functional step

Add a target-specific validation module with reproducible vulnerable and protected
fixtures, explicit prerequisites and bounded evidence. A candidate must not be
promoted to confirmed or access-proven merely because its banner matches.


## Build validation (4 November 2026)

`testDevelopmentUnitTest assembleDevelopment` passed. All 714 JVM tests passed,
including eight new discovery tests, with zero failures/errors/skips. Coverage
includes exact affected/fixed/version-suffix boundaries, common software identities,
ambiguous headers, incomplete/failed exchanges, verified-TLS prerequisites, SSH
banners, tamper/target rejection, encrypted persistence/reload, deduplication,
closed-engagement rejection and full-report preservation.

Development APK: `app/build/outputs/apk/development/app-development.apk`,
application ID `app.fieldwatch.dev`, version `1.1.27-dev`, version code 37.
SHA-256: `4d297870fdc68540965770a50c7845c55103c1e4a056f485ac32311f0ed623eb`.
Build log: `.gradle/service-discovery-build.log`.
Result record: `.gradle/service-discovery-result.json`.

The new UI compiled but was not exercised on the emulator or Samsung handset in
this phase. The earlier eleven-check emulator result describes the earlier APKs;
it is not relabeled as validation of this new build. No exploit was executed or
real-device vulnerability confirmed. Physical verification remains with the operator.
