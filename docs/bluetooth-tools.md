# M3: Bluetooth service inspection and serial tools

## Built and entry point

From Assessments → Radio inventory, choose **Open Bluetooth service tools** on a BLE or Classic row. Select an open engagement and confirm that the displayed target belongs to its authorized scope. Choosing scope adds/reuses its target record but does not connect.

Wi-Fi rows do not offer Bluetooth operations. The assessment tools require Android 13+. The original reconnaissance minimum SDK and production app identity are unchanged.

### BLE

- Explicit LE connection with `autoConnect=false`; no automatic reconnection or automatic reads.
- Explicit GATT service discovery, characteristic properties, and descriptor UUID inventory.
- Attribute keys distinguish repeated service/characteristic UUIDs; callbacks resolve the selected Android attribute object rather than guessing by UUID alone.
- Explicit characteristic/descriptor reads, last successful values, timestamps, hexadecimal output, and raw Android result codes with common access-control explanations.
- Confirmed characteristic writes in hex or UTF-8, selecting response/no-response where the characteristic declares support. The review dialog freezes target, attribute and payload. No automatic splitting, command replay, or protocol guessing.
- A larger-MTU request once per connection; use the callback's actual negotiated MTU. Initial write limit is 20 bytes (MTU 23 minus ATT overhead); maximum single write is 512 bytes.
- Explicit notifications/indications through the client configuration descriptor. Confirmation requires a descriptor-write result; ambiguous/missing CCCDs and repeated enable requests are refused. Failed changes restore local subscription registration when possible; disconnect is not a guarantee of remote rollback.
- A remote service-database change closes the session so stale handles are not reused.

### Bluetooth Classic

- Read Android's cached UUIDs without initiating SDP.
- Explicit SDP UUID request, with address-filtered results and a bounded wait. Android may return cached UUIDs even following an SDP request; an empty list is not proof of absent services. This is UUID enumeration, not a complete SDP attribute-record browser.
- Explicit RFCOMM connection to a selected 16-bit alias or full 128-bit service UUID. `1101` is a Serial Port example, not a promise that the target offers it. Many other Bluetooth profiles do not expose an RFCOMM serial stream.
- Authenticated/encrypted sockets by default; an explicit insecure-socket option with no automatic fallback. Android still controls pairing. No pairing bypass, reflection, or fixed-channel guessing is implemented.
- A serial terminal with hex/UTF-8 input, optional explicit CRLF for text, exact-byte review, incoming data and outgoing-operation results.

## Operation and resource behavior

One command is in flight at a time. Every asynchronous command has a 20-second monotonic timeout. Timeout or cancellation closes the session and invalidates its callbacks before another operation is accepted; late results cannot be attached to a newer request. A rejected command is not automatically retried.

Leaving/backgrounding the tools screen closes only its owned GATT/socket resources and unregisters its SDP receiver. Cancelling an SDP wait stops this app's listener; it does not claim to cancel every Android-internal queued discovery. A Classic inquiry already running on the shared adapter blocks service requests/connections instead of being silently cancelled. The inventory screen first attempts to stop its own inquiry before opening tools.

Socket connect/read/write work runs off the UI thread. Closing the socket aborts blocked socket operations. Serial reads await the main consumer rather than building an unbounded message queue. GATT notifications use a 32-entry queue with visible overflow counts. No Bluetooth bytes, credentials, or payloads are printed to application logs by these tools.

## Evidence semantics and limits

- Connection success is a transport result, not a vulnerability or unrestricted-access finding.
- Characteristic properties are advertised capabilities, not evidence of authentication policy. Reads may cause Android pairing; a successful read does not establish that it was unauthenticated.
- A no-response write does not prove a remote write acknowledgement. A write response does not prove application-level effects. Serial stream writes do not prove peer processing; failed sends may be partial.
- Write intent and exact requested bytes are recorded before transmission. Outcomes, timeouts and failures are separate events.
- The target-scoped transcript is kept in memory until explicitly saved. It retains 64 events, with at most 512 preview bytes per event, original byte counts, truncation flags and omitted-history counts. Payload-received counters count reported application bytes; they are not RF/link-layer capture counts.
- GATT inventory is bounded to 32 services, 128 characteristics and 128 descriptors with omitted-attribute counts. Classic UUIDs are capped at 128. Data already omitted from these views is not recoverable from an export.
- UUIDs, instance keys, result statuses, source labels, event timestamps and session identifiers are included in protocol snapshots. Snapshot capture time is distinct from operation time.
- A report is fitted to the existing 64-KiB evidence-note limit, omitting older events first, then excess inventory if necessary, with explicit additional omission counts. Hex is canonical; per-event UTF-8 previews may split multibyte characters and replace control bytes for display.
- Saving a snapshot requires the matching target/transport in an open engagement. It creates an evidence-linked `bluetooth-tools` record, without fabricating a finding or access result.
- Saved protocol evidence uses the existing encrypted vault and is included in explicit full engagement exports. Summary exports omit evidence content. There is no automatic plaintext transcript file, audio interception, or media playback added in M3.
- Clear history is explicit and available only while disconnected. It removes unsaved transcript/values/inventory, not previously saved evidence. Save or clear a transcript before switching its engagement context.

Existing screenshot-protection and vault limitations apply; see [assessment-workspace.md](assessment-workspace.md). In particular, the development APK is debuggable, captured data is visible in an unlocked app, and there is no separate biometric/PIN lock. Root/OS compromise is outside the vault's protection boundary.

## Handset verification checklist

The user is performing physical-device verification. Desktop tests do not establish actual Bluetooth stack compatibility.

1. Open tools for an authorized BLE device. Confirm no connection is attempted until scope and **Connect BLE** are selected. Confirm pairing dialogs remain Android-controlled.
2. Discover GATT services. Check a lab device with repeated UUIDs and verify that distinct instance keys operate on the intended characteristic/descriptor.
3. Read a known public value and a protected value; compare returned bytes and Android status with the lab target's expected security policy. Do not infer unauthenticated access merely from success.
4. Test confirmed writes only on reversible lab characteristics. Inspect the exact hex/UTF-8/CRLF review, negotiated write limits, with-response/no-response behavior, remote effects, and failed/partial outcomes.
5. Request larger MTU once and verify the actual negotiated value. Confirm oversized writes are rejected locally rather than split.
6. Enable and disable notifications/indications; verify descriptor acknowledgement, displayed data, permission errors, disconnect behavior and loss/truncation counters under load.
7. Turn Bluetooth off, revoke permissions, move a device out of range, and cancel pending operations. Confirm bounded timeouts, cleanup, no automatic retry, and ignored late callbacks.
8. For a Classic lab device, compare cached UUIDs with an SDP response. Test both a real service and an absent service; an empty/failed response must not become a vulnerability finding.
9. Connect to an actual RFCOMM service. Test hex and UTF-8 serial RX/TX, explicit CRLF, default secure pairing, and explicitly selected insecure mode where supported. Verify that unsupported UUIDs fail without channel guessing/fallback.
10. Leave/background the screen while connecting, reading, writing and receiving. Confirm resources close. Check pairing-screen interruptions on the particular OEM; a cancelled connection may need a new explicit attempt after pairing.
11. Save a protocol snapshot, restart the app, inspect evidence source/session/result metadata, and compare summary/full engagement exports. Confirm raw payloads remain absent from summary exports.
12. Verify scope switching restrictions, read-only closed engagements, explicit transcript clearing, and screenshot protection across navigation/dialog transitions.

## Verification and phase completion

On 17 October 2026, the final `testDevelopmentUnitTest assembleDevelopment` check passed in 21 seconds. All **612 tests across 48 suites passed**, with 0 failures, errors or skipped tests. This includes 27 new tests for strict payload/UUID parsing, operation serialization, repeated UUID instance keys, timeouts and stale callbacks, MTU/write limits, subscription acknowledgement/ambiguity, cache-vs-SDP provenance, bounded reports, and encrypted protocol-evidence imports.

APK inspection confirms `app.fieldwatch.dev`, label `Fieldwatch Dev`, version `1.1.26-dev`, debuggability enabled, and the existing SDK configuration. `git diff --check` passed (Git reports line-ending normalization notices on some edited Windows files). Existing warnings remain. No handset, pairing, real GATT/SDP/socket, or GitHub CI run was performed here; those are not established by JVM tests.

APK: `app/build/outputs/apk/development/app-development.apk`. Final log: `.gradle/m3-final-check.log`. Unit-test report: `app/build/reports/tests/testDevelopmentUnitTest/index.html`.

Suggested commit message: `feat: add scoped BLE GATT inspection and Classic RFCOMM tools`

Next: **M4 — scoped connected-network discovery/service assessment and Wi-Fi security inventory**. Device-specific vulnerability confirmation and exploitation remain M5/M6; media/service clients beyond these Bluetooth tools remain later milestones.

Platform references: [GATT API](https://developer.android.com/reference/android/bluetooth/BluetoothGatt), [memory-safe callback APIs](https://developer.android.com/reference/android/bluetooth/BluetoothGattCallback), [Classic UUID discovery](https://developer.android.com/reference/android/bluetooth/BluetoothDevice#fetchUuidsWithSdp()), [RFCOMM connections](https://developer.android.com/develop/connectivity/bluetooth/connect-bluetooth-devices).
