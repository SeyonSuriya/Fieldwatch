# M4a: connected-network and Wi-Fi observations

This is the first M4 implementation step. Service fingerprinting, HTTP/TLS inspection and dedicated Wi-Fi security evidence snapshots remain M4b work. Device-specific vulnerability checks remain later milestones.

## Operation

On Android 13+, open Assessments → Network and Wi-Fi assessment. Choose an open engagement, review its scope, enter one numeric IPv4 address or a /24–/32 range, and choose up to 16 comma-separated TCP ports. The final confirmation lists the scope and ports. A run permits at most 256 address/port pairs. Narrow the range when using multiple ports.

Checks use four simultaneous TCP connections, each with an 800 ms connection timeout. No application payloads are sent. A TCP handshake can still be logged or affect a fragile target. The handset's own addresses are omitted. /24–/30 expansion excludes the network and broadcast address; /31 retains both endpoints. Loopback, multicast, unspecified and link-local targets are unsupported. No DNS, IPv6, UDP, raw packet, ICMP, ARP enumeration or port-range syntax is implemented in this step.

The tool requires exactly one visible Wi-Fi network and binds every socket to that Android Network. Every target must fall within an IPv4 prefix assigned to that network. Link state and prefix membership are rechecked before each probe; failed sockets never fall back to cellular or the process default network. No VPN transport is selected. This does not enumerate routed subnets, bypass a VPN policy, or prove physical target identity. DHCP addresses can be reassigned.

Stop, leaving the screen, backgrounding the app or clearing its ViewModel cancels the run and closes its owned sockets. A batch of at most four observations is published only after that batch completes; cancellation can discard an in-flight batch. Unfinished endpoints have no result. Process death loses unsaved results. There are no automatic retries or background scans.

## Results and evidence

- `open`: TCP connection accepted; does not identify the service or establish authenticated access.
- `connect-rejected-or-error`: Android raised a connection exception; does not reliably distinguish refusal from other connection errors.
- `timeout`: connection deadline expired; does not establish that a device is absent.
- `unreachable-or-error`: another socket I/O failure; no service or vulnerability verdict.

Save encrypted evidence explicitly after a run. Reports preserve the submitted scope/ports, selected Android network handle, start/end times, partial/completed state and timestamped observations. The handle is a session identifier, not an SSID, BSSID or durable device identity. Results are grouped by IP asset, reuse matching network assets, and create recorded/cancelled assessment runs with SHA-256 evidence hashes. No findings or access records are created. Closed engagements, invalid scopes, forged out-of-scope observations and storage limits reject the write atomically. Existing summary/full exports apply; full exports are plaintext.

Wi-Fi security inventory reads up to 100 existing scan records without starting another scan. It preserves the raw capability flags, parsed security description, BSSID, channel and last-seen time. Recognized flags describe WEP, WPA1, WPA2 personal, SAE, enterprise authentication, OWE/transition and WPS advertisements. Missing/unsupported flags remain unknown/unclassified. A minimal ESS-only advertisement is described as open. Advertisements can be incomplete, spoofed, stale or retained by the collector; no authentication, downgrade, WPS attack or exploitability has been tested. Dedicated security snapshot export follows in M4b; the existing radio inventory can save radio metadata today.

## Handset verification

1. Install the development APK separately from the original app. Open a lab engagement on Android 13 and a current Android handset.
2. Connect to a controlled Wi-Fi network. Check a known listening service, a deliberately closed port and a filtered endpoint. Compare target logs with the displayed numeric endpoints and outcomes.
3. Confirm invalid addresses, nonlocal scopes, too many ports and plans exceeding 256 endpoints fail before traffic starts. A /24 run with one port must omit the handset itself.
4. Stop during a filtered run, background the app and navigate away. Verify sockets stop and partial reports contain only completed batches. Repeat on rotation and after returning to the screen.
5. Disable Wi-Fi or change access points while checking. Verify the run stops/fails without cellular fallback. Test a Wi-Fi network without internet and a handset with a VPN; record OEM restrictions and failures.
6. Save a partial and a complete report. Reopen the engagement, export summary/full JSON and verify per-target attribution, timestamps and omission of raw evidence in the summary. Close the engagement and verify further saves fail.
7. Compare flags on known open, WPA2, SAE transition, enterprise and OWE lab APs. Verify missing security data stays unknown. Confirm security observations are never labeled confirmed vulnerabilities.

## Implementation references

Software validation: development APK assembled; 627 JVM tests across 49 suites passed with no failures, errors or skipped tests. Scope/port boundaries, report integrity, Wi-Fi flag distinctions, encrypted persistence, per-target attribution and closed-engagement rejection are covered. JVM tests do not verify Android routing, socket cancellation or OEM behavior; use the handset checklist above.

Network-specific socket behavior: [Android Network](https://developer.android.com/reference/android/net/Network). Connected-prefix information: [Android LinkProperties](https://developer.android.com/reference/android/net/LinkProperties). Actual handset behavior remains unverified here.
