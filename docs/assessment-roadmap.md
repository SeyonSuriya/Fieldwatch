# Assessment development decisions

Confirmed with the user on 17 October 2026. Follow the milestone order; this document does not claim the assessment features are implemented.

## Platform and capability policy

- Assessment support targets Android 13 and newer, including verification against the latest stable Android release at implementation time. Do not raise the existing reconnaissance minimum SDK until the compatibility impact is reviewed.
- Core operation is phone-only. Detect available capabilities and enable optional privileged features when root and the required interfaces actually work. Root presence alone is not proof of radio capability.
- Optional external-radio features remain in scope. Report compatible interface requirements and connected-hardware status instead of silently removing those features.
- Broad compatibility with current Wi-Fi, network, BLE, Classic, and IoT products is the goal, not a guarantee of access to every product. Active assessments operate within an explicitly selected authorized scope. Public reachability is not authorization.
- Initial modules should be prioritized using current exploitation evidence, prevalence, phone feasibility, and access to reproducible vulnerable/fixed lab targets. No device-specific module is supported without those validation fixtures.
- Potentially disruptive modules need explicit operator initiation, side-effect reporting, cancellation where possible, and recovery instructions. Do not silently downgrade results or label unsuccessful/inconclusive actions as exploitation.
- Evidence must be protected locally and conveniently reviewable. Provide deliberate, redacted or full exports as appropriate; reports should link findings to their evidence. Design encryption, key handling, retention, and export boundaries before adding sensitive artifact collection.

## Milestones

1. M0: reproducible baseline build/tests, then physical-device verification and capability matrix.
2. M1: engagements, assets, assessment runs, protected evidence, findings and access-result schemas.
3. M2: Classic discovery and unified inventory, preserving existing reconnaissance behavior.
4. M3: BLE GATT inspection and Classic service/serial tools.
5. M4: scoped connected-network service assessment and Wi-Fi security analysis.
6. M5: versioned vulnerability checks with evidence and explicit confidence.
7. M6: initial device-specific validation modules tested on affected and unaffected targets.
8. M7: protocol-specific service/data/media clients for demonstrated access paths.
9. M8: optional privileged/external-radio features that pass feasibility gates.
10. M9: integrated reporting, recovery, performance, and release hardening.

Evidence capture, regressions, and capability checks accompany each milestone. Existing-stream interception is a separate feasibility investigation, not an assumed consequence of pairing or service access. Universal takeover is not a deliverable.

## Development progress

The user authorized development after the baseline and will perform physical-device verification. No APK installation, rooting, target exploitation, or external-hardware purchase has been performed here. Physical handset results and lab fixtures remain necessary before dependent validation.

M0 software baseline: all 538 original JVM tests passed and the original debug APK assembled successfully. See [build-baseline.md](build-baseline.md). An isolated `app.fieldwatch.dev` development variant is now implemented and verified by APK inspection. The capability screen reports hardware presence and explicitly leaves root/external-radio capabilities unverified. Physical-device checks remain with the user.

M1 first slice: engagement/asset/run/evidence/finding/access schemas; encrypted bounded persistence; manual observations and suspected findings; explicit summary/full JSON export; read-only closure and explicit deletion; interruption recovery. The development APK builds and all 556 tests pass. See [assessment-workspace.md](assessment-workspace.md) for implementation, security boundaries, and handset verification steps.

Still pending in the foundation: validation of Keystore/document-provider/UI behavior on handsets. No automatic asset correlation, active vulnerability validation, confirmed-access modules, or portable encrypted backup is implied.

M2 software slice: single-cycle Bluetooth Classic inquiry; explicitly distinct paired history; a unified Wi-Fi/BLE/Classic inventory; search/filters; bounded Bluetooth session state and loss counters; encrypted engagement snapshot imports. The development APK builds and all 585 tests pass. See [classic-inventory.md](classic-inventory.md) for behavior, boundaries, and handset checks. No service connections, pairing operations, or exploitation are implemented in M2.

M3 software slice: scoped BLE connections and GATT inventory; characteristic/descriptor reads; confirmed characteristic writes and notifications/indications; MTU limits; explicit cached/SDP UUID discovery; secure/insecure RFCOMM connection choices and hex/UTF-8 serial I/O; bounded transcripts and encrypted protocol-evidence snapshots. All 612 tests pass and the development APK builds. See [bluetooth-tools.md](bluetooth-tools.md) for security semantics, limitations, and handset checks. No device-specific vulnerability or access verdict is fabricated by these service tools.

M4a software slice: explicitly confirmed connected-Wi-Fi IPv4 scopes; bounded TCP connection observations; network-bound sockets, lifecycle cancellation and encrypted per-target evidence; Wi-Fi security advertisement analysis preserving raw flags and timestamps. The development APK builds and all 627 tests pass. See [network-assessment.md](network-assessment.md). Physical verification remains with the user and is not represented as complete.

M4b software slice: explicit single-endpoint banner/HTTP HEAD/TLS/HTTPS HEAD inspection; bounded response captures and conservative protocol labels; numeric-IP TLS endpoint verification with no insecure fallback; frozen Wi-Fi security snapshots; encrypted per-asset evidence for both report types. The development APK builds and all 645 tests across 51 suites pass. See [network-assessment.md](network-assessment.md) for protocol, deadline, certificate and handset limits. M4 software implementation is complete for the documented connected-Wi-Fi IPv4/TCP scope; physical verification remains pending.

Next implementation milestone: M5 versioned vulnerability checks with evidence and explicit confidence. Start with observable configuration/service checks and reproducible fixtures; a banner or certificate failure alone must not establish a CVE or device-access claim.

## Required phase completion report

For every development phase completion, show:

1. What was built and its material boundaries.
2. Build/test results and outstanding handset verification.
3. A suggested Git commit message for the build (do not claim a commit exists unless actually created).
4. The next development phase or step.

M1 suggested message: `feat: add isolated development build and encrypted assessment workspace`.

M2 suggested message: `feat: add Classic Bluetooth discovery and unified radio inventory`.

M3 suggested message: `feat: add scoped BLE GATT inspection and Classic RFCOMM tools`.

M4a suggested message: `feat: add scoped Wi-Fi network checks and security observations`.

M4b suggested message: `feat: add scoped service inspection and Wi-Fi security evidence`.

## Initial check selection method

Use [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) as evidence of observed exploitation, not as a product-prevalence ranking or proof that a target is affected. Use the [OWASP IoT Security Testing Guide](https://owasp.org/owasp-istg/01_introduction/index.html) to organize test coverage.

The initial candidate areas are exposed management interfaces, missing service authorization, sensitive-data disclosure, insecure transport, and identifiable outdated router/camera/IoT services. BLE/Classic checks should focus first on observable service permissions and supported application protocols. Select individual CVEs only after confirming phone feasibility, affected-version identification, and vulnerable/fixed fixtures. Do not describe this candidate list as a measured ranking of the most exploited vulnerabilities.
