# Assessment workspace: first development slice

This document describes the M1 engagement/evidence foundation and isolated development variant from M0. M2 subsequently adds [Classic discovery and unified inventory](classic-inventory.md). Active vulnerability checks, exploitation, and service/media access remain later roadmap milestones.

## Install and entry point

Build with `./scripts/check-baseline.ps1` (default variant: Development). For the original build tasks use `-Variant Debug`.

- Development APK: `app/build/outputs/apk/development/app-development.apk`.
- App label: **Fieldwatch Dev**.
- Application ID: `app.fieldwatch.dev`.
- The original `app.fieldwatch` app and its data remain separate.
- Development builds are debuggable and unshrunk; they are for lab verification, not distribution as hardened public builds.

After the existing disclaimer/permission flow, use the report-shaped **Open assessments** action in the top bar. The assessment workspace requires Android 13+. Existing reconnaissance retains Android 10+ support.

From the workspace, **Open radio inventory** opens the M2 collector view. See [classic-inventory.md](classic-inventory.md) for discovery behavior, snapshot import and handset checks.

## Implemented workflow

1. Create an engagement with a name and authorized scope.
2. Add a target record: label, identifier, and transport (Wi-Fi, BLE, Classic, or network).
3. Start a manual observation for that target. This records a run; it does not initiate a connection or execute a scan.
4. Add titled evidence notes with capture time, source, app/catalog versions, and a SHA-256 digest of the note's UTF-8 content.
5. Finish the observation once evidence exists, or cancel it without evidence.
6. Record a suspected finding linked to an evidence note, with severity and explanation.
7. Export a summary or explicitly choose a full report.
8. Close an engagement to make it read-only, or explicitly delete it once no observations are running.

No note or suspected finding creates a confirmed vulnerability or access result. Access-result schemas exist for later module integration, with evidence/run/target consistency checks.

## Storage and export boundaries

- The entire assessment archive (including target identifiers and scope) is encrypted using AES-256-GCM with a fresh provider-generated IV per write. Its key is generated and retained by Android Keystore. No hardcoded key or plaintext fallback is used.
- The versioned envelope is authenticated. Ciphertext modification, an unavailable/wrong key, unsupported schema, and inconsistent records fail closed. Existing vault files are not replaced with an empty archive after load failure.
- The file lives under app-private `noBackupFilesDir/assessments/vault.bin`, outside the app's FileProvider paths. Existing scan logs, sessions, and exports do not acquire this protection automatically.
- Writes use encrypted temporary files, file synchronization, and atomic replacement where available; published UI state changes only after successful persistence. Unsupported atomic-move filesystems use replacement-move fallback. This is not a claim of forensic secure deletion or full power-loss guarantees on every filesystem.
- Runs left active after a process restart become **interrupted**, not successful or silently resumed.
- Limits: 100 engagements; per engagement, 500 assets, 2,000 runs, 2,000 evidence notes, and 1,000 findings. Notes are limited to 64 KiB in UTF-8; the serialized archive is limited to 8 MiB. Nothing is silently evicted. Export/delete controls provide manual retention.
- Assessment screens request Android screenshot/recording protection. This must be checked on a handset.
- The vault opens with the app; there is no separate biometric/PIN lock in this slice. Key hardware backing is not assumed, and encryption does not protect an unlocked app or a compromised operating system.
- Uninstalling/clearing app data loses the vault and its key. A missing key cannot be regenerated to decrypt old evidence. Export important records before uninstalling.

The **summary JSON** includes counts by run status, finding severity/confidence, and access-result count. It excludes all operator-supplied text, names, scope, target identifiers, evidence content, and evidence hashes. It is structural omission, not heuristic replacement of sensitive words.

The **full JSON** includes the selected engagement and its evidence. An explicit confirmation explains disclosure, then Android's document picker selects the destination. No decrypted export is staged in app cache or sent to a backend. Both report types are unencrypted at the chosen destination; full exports require appropriate handling. Cancelling the picker discards the pending export. There is no report re-import or encrypted portable-backup function yet.

SHA-256 checks detect changes to note content; they do not establish that an operator observation is true.

Android security references: [Keystore](https://developer.android.com/privacy-and-security/keystore), [key generation](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec), [cryptography](https://developer.android.com/privacy-and-security/cryptography).

## Handset verification checklist

The user is handling physical-device verification. No device installation or active target testing was performed during implementation.

- Install Fieldwatch Dev alongside the original app; confirm their icons/data are separate.
- Confirm original live scanning, filters, alerts, reports, and FileProvider sharing still work in the development installation.
- Open Assessments, create an engagement/target, record a note, finish the observation, and create a suspected finding.
- Restart the app and confirm records survive with the same evidence digest.
- Leave a manual observation running, terminate the app process, reopen Assessments, and confirm **interrupted** status. Simply changing screens should not interrupt a run.
- Confirm finishing without evidence and closing/deleting with a running observation show a useful error without losing data.
- Confirm a closed engagement is read-only and remains exportable.
- Export summary/full JSON, inspect disclosure/content, and cancel an export to confirm no extra export is created.
- Verify screenshot/recording protection while the workspace and its dialogs are visible, and that normal capture behavior returns after leaving it.
- Confirm reconnecting/navigating away during export does not export a different engagement.
- Confirm Android 13 and later behavior, particularly Keystore writes, file replacement, process restart, and document-provider access. Hardware-presence labels are not assertions of operational radio support.

## Verification status

On 17 October 2026, `testDevelopmentUnitTest assembleDevelopment` succeeded. All **556 tests across 44 suites passed** (0 failures, errors or skipped tests), including 18 new assessment tests. A final incremental verification against the saved source also passed (23 seconds; 8 tasks executed, 35 up-to-date). `git diff --check` and the helper's PowerShell syntax check passed.

APK inspection confirmed `app.fieldwatch.dev`, label `Fieldwatch Dev`, version `1.1.26-dev`, and debuggability enabled. Reconnaissance minimum SDK remains 29; target SDK remains 35.

JVM tests cover the domain, real JCA encryption, persistence, and reports. They do not exercise Android Keystore, Compose interaction, document providers, or physical radio behavior. Existing serialization/deprecation/native-symbol warnings remain. The new CI development-build step is configured but has not been run on GitHub during this work.
