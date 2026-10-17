# M2: Classic Bluetooth discovery and unified inventory

M3 subsequently adds [scoped Bluetooth service tools](bluetooth-tools.md) to BLE/Classic inventory rows. The M2-only boundaries below describe that phase's discovery behavior.

## Built

- Assessments → **Open radio inventory** combines existing Wi-Fi/BLE sightings, Classic inquiry results, and Android pairing-history records.
- Classic inquiry is explicitly started, single-cycle, bounded to 30 seconds, cancellable, and cancelled when the screen stops or is left. It does not pair, connect, enumerate services, or retry automatically.
- Permission, Bluetooth-off, Location-off, refused-start, existing-inquiry, completion, timeout, and cancellation-failure states are visible.
- An already-running inquiry is not adopted. Cancellation is attempted only after Fieldwatch's own successful start request. The adapter is still a shared Android resource; this is not a controller-level isolation guarantee.
- Paired records have no invented last-seen time or RSSI. Paired BLE devices remain BLE records. Unknown transport is explicitly marked as unconfirmed. Devices Android identifies as LE-only are not turned into Classic inquiry results.
- Optional device class, dual-mode status, observation timestamps, reported RSSI, and existing vendor lookup metadata are displayed. Android's device-class bits are not represented as a full CoD service bitmap.
- Inventory search and transport/observed/paired filters are available. Observed means reported at the displayed time, not currently connected or guaranteed present.
- Exact address+transport deduplication is used. A matching address across Wi-Fi, BLE, and Classic remains separate; no physical-device identity or MAC de-randomization is inferred.
- The Bluetooth session cache is capped at 500 records. Oldest unpaired rows are evicted first; new rows are omitted if the cache contains only paired records. Omitted/evicted events and rejected observations are counted. These counters do not measure every packet lost by Android or the original Wi-Fi/BLE collectors.
- Clear-history removes only the Bluetooth session cache/counters and then refreshes pairing history. Existing scan state and saved engagement evidence are unaffected.
- Operators can save a frozen row into a selected open engagement. The store atomically creates/reuses the target, adds a completed `inventory-snapshot` record, and attaches encrypted source-labelled evidence. The capture time and original observation time are separate. Pairing-history imports retain null observation timestamps.
- Repeated imports reuse the same target within the same transport but retain separate evidence snapshots. No import creates a finding or access claim.
- Screen capture protection is shared and reference counted across assessment/inventory navigation transitions.

The original `RadioKind { WIFI, BLE }` and existing scan service were deliberately left unchanged. Classic data is not silently routed through BLE decoders, legacy radio-count logic, log formats, or TAK output.

## Operational boundaries

Android Classic inquiry is active discovery and generally finds discoverable devices. It can interfere with Bluetooth audio or BLE collection on the shared adapter. No Classic scanning runs automatically in the background. There is no claim that every Bluetooth device will appear.

Inventory is an in-memory session view. Results disappear when its ViewModel/process is discarded unless explicitly saved to an engagement. Recorded snapshots are normalized metadata, not full RF captures; names/optional fields are bounded. Existing Wi-Fi/BLE freshness and retention semantics are preserved.

Receiver registration uses Android's exported-receiver mode for privileged Bluetooth broadcasts, with a Bluetooth sender permission and a fixed system-action allowlist. Results are still treated as untrusted metadata. No incoming name or address is interpreted as a command.

Pairing history is read on entering the screen, on request, and on relevant system broadcasts. A paired flag is a cached Android observation, not an ongoing assertion of connection state. Collector status is independent of encrypted-store readiness: a vault failure prevents saving without disabling discovery or replacing existing evidence.

## Handset verification

The user is responsible for physical-device verification. JVM tests do not verify Android broadcasts, actual inquiries, BLE coexistence, or the radio cancellation API.

1. Install the latest **Fieldwatch Dev** APK alongside the original app.
2. Open Assessments → Open radio inventory. Confirm existing Wi-Fi/BLE records appear without starting a new Classic inquiry.
3. Refresh paired records. Confirm unobserved paired devices have no RSSI or observed timestamp; paired BLE devices retain the BLE label.
4. Make a lab Classic device discoverable, start one inquiry, and verify its address/name, optional class/RSSI, and source. Confirm the cycle finishes without restarting.
5. Stop a running inquiry, leave the screen, rotate the phone, and background the app. Confirm Fieldwatch cancels its own cycle and does not silently restart. Check both Bluetooth audio and BLE collection during/after inquiry.
6. Test Bluetooth off, Location off, revoked Nearby devices/precise-location permissions, and an inquiry started elsewhere. Confirm useful blocked states and recovery after restoring settings.
7. Search/filter inventory; verify paired-only records are excluded by the observed-only filter.
8. Save a selected snapshot into an open engagement, inspect its source/timestamps, repeat the import, and confirm one target with two evidence records. Verify full export preserves the snapshot and summary export omits the identifiers/text.
9. Close the engagement and confirm it cannot receive new snapshots. Clear session history and confirm saved evidence remains.
10. Verify screenshot/recording protection throughout transitions between Assessments and Inventory and their dialogs, then confirm normal behavior resumes after leaving both.

## Verification results

On 17 October 2026, `testDevelopmentUnitTest assembleDevelopment` completed successfully in 1 minute 48 seconds. All **585 tests across 46 suites passed**, with 0 failures, errors or skipped tests. This includes 29 new tests for inquiry ownership, lifecycle cancellation, monotonic timeouts, rejected/limited records, source/transport separation, pairing semantics, and atomic engagement imports.

APK inspection confirms `app.fieldwatch.dev`, label `Fieldwatch Dev`, version `1.1.26-dev`, and debuggability enabled. `git diff --check` passed. Existing build warnings remain; CI execution and handset checks were not performed here.

Development APK: `app/build/outputs/apk/development/app-development.apk`.

Local build log: `.gradle/m2-development-build.log`; unit-test report: `app/build/reports/tests/testDevelopmentUnitTest/index.html`.

## Phase completion format

At each development milestone completion, report the implemented behavior, validation and physical-test limits, a suggested Git commit message, and the next phase. A suggested message does not mean a commit was created.

Suggested M2 commit message: `feat: add Classic Bluetooth discovery and unified radio inventory`

Next: **M3 — BLE GATT service/characteristic inspection and Bluetooth Classic service discovery / serial tools**, with explicit connection actions and evidence capture. Vulnerability modules remain later milestones.

Primary platform references: [device discovery](https://developer.android.com/develop/connectivity/bluetooth/find-bluetooth-devices), [BluetoothDevice API](https://developer.android.com/reference/android/bluetooth/BluetoothDevice), [privileged Bluetooth broadcasts and receiver export rules](https://developer.android.com/develop/background-work/background-tasks/broadcasts).
