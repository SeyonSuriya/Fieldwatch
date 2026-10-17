# Operator handset baseline and Android 16 verification

This M6 prerequisite step records the phone running Fieldwatch without treating it as a remote assessment target. It does not add a Samsung-specific vulnerability module or complete real-product M6 validation.

## Use

Open an authorized engagement in Assessments and select **Review this phone's baseline**. The preview reads public local Android APIs and freezes the result. Cancel saves nothing; **Save encrypted baseline** adds it to the engagement's operator-phone records. Saved snapshots remain visible after restarting. Closed engagements are read-only. Each engagement supports at most 20 snapshots; use another engagement if more are needed. Existing baselines are not silently replaced.

The snapshot contains manufacturer/model, Android release/SDK, reported patch date, display/incremental build labels, app version/target SDK, four hardware-feature reports and six permission states. Missing/unknown metadata remains unavailable. Fields are bounded and validated, including calendar-valid patch dates and SDK-specific permission applicability. The field set is explicitly limited; there is no generic diagnostic dump.

No IMEI, serial number, Android ID, fingerprint, MAC/IP address, location, account, contacts or target data is requested. Capture does not ask for permissions, scan radios, open sockets, invoke a shell or request root. Build labels are Android-reported firmware metadata and may differ from Samsung's Settings presentation; they do not identify a verified vulnerable product version.

Hardware presence and granted permissions do not prove operational scan/connection support. Snapshot capture does not check whether Bluetooth/Wi-Fi/location is enabled, bypass OEM policy, prove monitor mode/injection, verify root, detect an external radio or certify an OS version. Android build/patch strings are local reports, not remote attestation or vulnerability verdicts. Permissions can change after the timestamp.

Baselines are operator metadata, separate from target assets, assessment runs, evidence and findings. Saving one does not create a target, finding or access record. Persistence uses the existing bounded authenticated encrypted vault and atomic write path. Full engagement JSON exports include the snapshots in plaintext; summary exports contain only `operatorBaselineCount`, without device/build/permission metadata. Existing engagement JSON without this optional field still loads. Upgrades preserve prior records; downgrading to older app code is not promised.

## User-reported handset details

The user supplied model **SM-A56B/DS**, Android **16**, security patch **2026-09-05**, correcting the earlier A51 label. Its role (operator phone or target) and exact firmware/build remain unconfirmed. These values are not prefilled as verified local data or used to select a vulnerability module. The capture feature will report whichever phone actually runs Fieldwatch.

## Compatibility review

The APK still compiles/targets SDK 35 with minimum SDK 29; assessment screens require Android 13+. An Android 16 runtime is a separate test environment, not a statement that the app targets SDK 36 or passed handset verification. No SDK/toolchain migration was bundled into this metadata feature.

The compatibility review checked Google's [Android 16 changes for all apps](https://developer.android.com/about/versions/16/behavior-changes-all). In particular:

- Android 16 can retain a local bond record after remote bond loss while disconnecting the link and showing system recovery UI. Verify that paired history is not confused with a live connection and that the user can recover through system settings; Fieldwatch does not force pairing or remove bonds.
- Runtime changes can affect code using non-SDK internals. The reviewed Fieldwatch source contains no reflection into ART, job scheduling APIs or broadcast receiver priority dependency; this source review does not certify all transitive libraries or OEM behavior.
- APK inspection found the bundled `libandroidx.graphics.path.so` in arm64-v8a, armeabi-v7a, x86 and x86_64. Each inspected ELF PT_LOAD segment has 16 KiB alignment, and the development APK passes `zipalign -c -P 16 4`. This is a packaging check, not a 16 KiB-device runtime test.

The baseline uses [Build.VERSION](https://developer.android.com/reference/android/os/Build.VERSION), including the reported security patch and runtime SDK. Firmware strings alone cannot establish which vendor fixes are present.

## Handset checks

1. Upgrade the development APK without uninstalling. Verify old engagements, evidence, findings and reference-module results still open.
2. Review the baseline. Compare model, Android release, patch and build labels with Settings; record differences instead of inferring a firmware match.
3. Cancel and verify no snapshot was saved. Review/save a new snapshot, restart and check its original timestamp and contents.
4. Deny/grant one of the normal app permissions through system settings, return, and capture a new baseline. Confirm the new state is reported and earlier snapshots remain unchanged. No permission prompt should be launched by capture.
5. Export full and summary JSON. Check that full includes the baseline and summary contains only the baseline count. Close the engagement and verify new saves are blocked.
6. On Android 16, verify Wi-Fi scan visibility, Classic inquiry, BLE GATT, RFCOMM, network binding, timeout/cancellation, secure-screen handling and SAF export using the earlier phase checklists. Exercise bond loss on an owned lab peripheral and confirm the app reports disconnection without automatic re-pairing.

JVM tests cover schema compatibility, field/permission/date validation, privacy boundaries, encrypted persistence, closure and limits. Actual local Android API values, system/OEM behavior and radio operation require the user's physical handset checks.

Software validation: development APK assembled; all 696 JVM tests across 54 suites passed, with zero failures, errors or skipped tests. APK identity remains `app.fieldwatch.dev` with target SDK 35. Physical Android 16 verification remains pending.
