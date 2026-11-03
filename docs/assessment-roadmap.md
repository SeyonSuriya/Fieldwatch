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

M5 software slice: built-in versioned offline check registry with eight Wi-Fi/service configuration checks; condition/not-observed/inconclusive/not-applicable outcomes; review-before-save; confidence-limited findings with check versions and original/evaluation evidence links; encrypted atomic persistence and same-source/version deduplication. The development APK builds and all 669 tests across 52 suites pass. See [versioned-checks.md](versioned-checks.md). These are synthetic observation fixtures, not affected/fixed product certifications; handset verification remains pending. No CVE matching, credential attempts, exploitation or access records were added.

M6a software slice: module contract with explicit identity/build prerequisites, support level, fixture revision, side effects and recovery; one LAB ONLY reference module; paired synthetic exposed/protected HTTP target modes using a shared fixture manifest; reviewable outcomes, encrypted reports, provenance-linked synthetic findings and restart-safe deduplication. The development APK builds; all 685 Android/JVM tests across 53 suites and 4 actual loopback HTTP fixture tests pass. See [device-validation.md](device-validation.md). No manufacturer device, CVE exploit or access record is supported by this reference module.

M6b prerequisite slice: reviewable operator-handset baseline capture from public local Android APIs, encrypted engagement storage, bounded history, summary/full export separation and legacy-schema compatibility. The development APK builds and all 696 JVM tests across 54 suites pass. It keeps operator-phone metadata separate from target records and makes no vulnerability/capability verdict. See [handset-baseline.md](handset-baseline.md) for Android 16 packaging review and physical checks.

M6 verification-workflow slice: explicit exposed/protected source selection; offline pair comparison with independent integrity/target checks, network/endpoint/time/version prerequisites and inconclusive reasons; linked encrypted reports, readable/raw views and restart-safe deduplication. The development APK builds and all 706 JVM tests across 55 suites pass. See [fixture-comparison.md](fixture-comparison.md). Comparisons create no new findings or access records and do not certify physical devices.

Simulation setup, 3 November 2026: the user authorized Android Studio/emulator-based testing. Added isolated `app.fieldwatch.simulation` app/test builds, four Android instrumentation tests, loopback exposed/protected/slow/invalid-TLS services and a serial-pinned PowerShell runner. Both APKs compile; 706 existing JVM tests and 7 desktop fixture tests pass. The available API 37 virtual device stayed ADB-offline during headless/cold-boot attempts; instrumentation has not run. See [emulator-testing.md](emulator-testing.md). This simulation work is independent of manufacturer vulnerability certification.

Existing-device runtime verification, 3 November 2026: the existing Pixel_10 AVD booted Android 17/API 37. After diagnosing an initial startup ANR and updating incompatible AndroidX test tooling to the public InputManager API, the four instrumentation tests passed with zero failures/skips. The helper now records current run status/runtime/APK hashes and quotes the Kotlin compiler property correctly for PowerShell. See [emulator-testing.md](emulator-testing.md) and the ignored local `.gradle/emulator-result.json` report. Android 16, physical radios, SAF picker UI and cold-start performance remain separate verification items.

Next implementation step: extend simulation coverage to the remaining planned protocol and lifecycle cases before claiming broader compatibility; retain the real-product fixture gate for manufacturer modules. The SM-A56B/DS is the phone running Fieldwatch. The owned router export showed TCP 80/443/8080 open, 22 rejected-or-error, WPA2/WPS advertised. Its advertised MF922/7520V3WLAN strings are not verified firmware; service-inspection/firmware evidence and affected/unaffected manufacturer fixtures remain unavailable. M6 product support is incomplete; successful reference simulation does not establish commercial-device vulnerability support.

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

M5 suggested message: `feat: add versioned evidence checks and linked configuration findings`.

M6a suggested message: `feat: add reference device validation and paired lab fixtures`.

M6b prerequisite suggested message: `feat: add encrypted operator handset baselines and compatibility reporting`.

M6 comparison suggested message: `feat: add evidence-linked reference fixture comparisons`.

Simulation setup suggested message: `test: add isolated Android emulator assessment suite and local lab services`.

Existing-device verification suggested message: `test: fix API 37 instrumentation compatibility and record emulator results`.

## Initial check selection method

Use [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) as evidence of observed exploitation, not as a product-prevalence ranking or proof that a target is affected. Use the [OWASP IoT Security Testing Guide](https://owasp.org/owasp-istg/01_introduction/index.html) to organize test coverage.

The initial candidate areas are exposed management interfaces, missing service authorization, sensitive-data disclosure, insecure transport, and identifiable outdated router/camera/IoT services. BLE/Classic checks should focus first on observable service permissions and supported application protocols. Select individual CVEs only after confirming phone feasibility, affected-version identification, and vulnerable/fixed fixtures. Do not describe this candidate list as a measured ranking of the most exploited vulnerabilities.

Extended emulator coverage suggested message: `test: verify lifecycle cancellation and simulated Bluetooth sessions on Android`. Six runtime tests and seven host fixture tests pass; system document-picker coverage is next.

Document-picker phase suggested message: `test: verify Android document-picker exports and cancellation`. Eight runtime tests pass, including real local Downloads summary/full export, cancellation/retry, frozen-selection behavior and synthetic-file cleanup. Next: interrupted-session recovery and app-restart validation.

Process-restart phase suggested message: `test: verify interrupted assessment recovery across app restarts`. Eleven emulator checks pass (eight standard plus three restart phases); completed records and evidence remain intact, interrupted state is durable, and synthetic fixtures are cleaned up. Next: isolated encrypted-vault failure handling tests.
