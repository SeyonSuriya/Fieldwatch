# M4: connected-network, service and Wi-Fi observations

M4a introduced connected-network observations. M4b adds explicit service inspection and dedicated Wi-Fi security evidence snapshots. Device-specific vulnerability checks remain later milestones. Scope is numeric IPv4 on connected Wi-Fi; no universal service inventory or vulnerability coverage is implied.

M5 now provides [versioned offline checks](versioned-checks.md) on these saved snapshots, with explicit outcomes, confidence and source links. Collecting or saving M4 evidence alone still creates no findings or access records.

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

Wi-Fi security inventory reads up to 100 existing scan records without starting another scan. It preserves the raw capability flags, parsed security description, BSSID, channel and last-seen time. Recognized flags describe WEP, WPA1, WPA2 personal, SAE, enterprise authentication, OWE/transition and WPS advertisements. Missing/unsupported flags remain unknown/unclassified. A minimal ESS-only advertisement is described as open. Advertisements can be incomplete, spoofed, stale or retained by the collector; no authentication, downgrade, WPS attack or exploitability has been tested.

M4b adds Review security snapshot on each Wi-Fi row. Selecting it freezes that record and capture time; the confirmation binds the snapshot to the selected engagement. Saving preserves SSID/BSSID, channel/frequency, first/last observation times, raw flags, parsed security, analysis text and capture time in encrypted evidence. It reuses the Wi-Fi asset by BSSID. No finding/access verdict is generated. The current format is version 1; its analysis text must match the recorded flags. Oversized or malformed metadata is rejected rather than silently truncated. Full engagement export includes the snapshot; summary export omits it. A BSSID advertisement does not establish physical identity or permission to connect to an AP.

## M4b service inspection

Choose an open engagement and enter one numeric target/port under Inspect one service. Selecting an open TCP result only fills these fields; it does not launch a probe. A separate confirmation displays the destination, target and protocol choice before opening a new socket on the connected Wi-Fi network. The same local-prefix checks and handset-address exclusion apply. This inspection is independent of prior TCP results, since services can change between observations.

Four modes are implemented:

- Banner: connect and read at most the first newline-terminated line or 4 KiB. No application bytes are sent.
- HTTP HEAD: connect and send exactly `HEAD / HTTP/1.0`, numeric `Host: address:port`, `Connection: close`, and `User-Agent: Fieldwatch-Assessment/1`. Read only through the first CRLF/CRLF boundary or 4 KiB. No body is consumed, redirects are not followed, and no DNS, credentials, cookies, authentication retry or path discovery is used.
- TLS: perform one handshake using the platform default trust configuration with HTTPS endpoint identification for the numeric IP. Record negotiated protocol/cipher and the SHA-256 digest of the validated leaf certificate. No application bytes are sent.
- HTTPS HEAD: perform that verified TLS handshake, then the same HEAD exchange. No HTTP is attempted after a failed handshake.

Each inspection has a five-second total deadline, including connection/handshake, and a 1.5-second TCP connect timeout. Reads recompute their remaining deadline, and an independent deadline task closes the owned underlying socket, including during a slow handshake or write. Stop/background/navigation cancellation closes the same socket and discards an unfinished inspection. A completed response can still be partial: EOF, timeout, I/O error, TLS validation/handshake failure and capture-limit state remain explicit. The TLS error category does not claim every handshake failure is a certificate vulnerability. Default TLS negotiation does not enumerate all supported protocols/ciphers or test downgrade behavior.

TLS currently supports numeric IP identities only. Most self-signed IoT certificates and certificates valid only for a hostname will fail. There is no trust-all fallback, hostname override, SNI/virtual-host selection, certificate download on failed validation, or automatic plaintext retry. These limits are reported as inspection failures, not confirmed vulnerabilities. IPv6, UDP/mDNS/SSDP, STARTTLS and protocol logins remain outside this M4 implementation.

Service labels are derived from captured SSH/HTTP/SMTP/FTP or POP-style greetings, never from the port alone. These are server claims, not reliable product/version or vulnerability identification. Unknown replies remain unclassified. Raw received hex is authoritative; the readable preview replaces nonprinting bytes. HTTP evidence records the intended bytes when a write was attempted; it does not claim the whole request was received by the server. Captured headers can contain sensitive server-issued cookies even though Fieldwatch sends none.

Save inspection evidence explicitly. The result retains its original target and engagement even if the screen's input fields change afterward. Completed attempts, including failures, become recorded runs, not successful-access records. The report stores mode, selected network handle, timestamps, outcome, attempted request, raw response, capture limit and any verified TLS metadata. Existing size limits, encrypted storage, closed-engagement rejection and summary/full export rules apply.

## Handset verification

1. Install the development APK separately from the original app. Open a lab engagement on Android 13 and a current Android handset.
2. Connect to a controlled Wi-Fi network. Check a known listening service, a deliberately closed port and a filtered endpoint. Compare target logs with the displayed numeric endpoints and outcomes.
3. Confirm invalid addresses, nonlocal scopes, too many ports and plans exceeding 256 endpoints fail before traffic starts. A /24 run with one port must omit the handset itself.
4. Stop during a filtered run, background the app and navigate away. Verify sockets stop and partial reports contain only completed batches. Repeat on rotation and after returning to the screen.
5. Disable Wi-Fi or change access points while checking. Verify the run stops/fails without cellular fallback. Test a Wi-Fi network without internet and a handset with a VPN; record OEM restrictions and failures.
6. Save a partial and a complete report. Reopen the engagement, export summary/full JSON and verify per-target attribution, timestamps and omission of raw evidence in the summary. Close the engagement and verify further saves fail.
7. Compare flags on known open, WPA2, SAE transition, enterprise and OWE lab APs. Verify missing security data stays unknown. Confirm security observations are never labeled confirmed vulnerabilities.
8. On controlled SSH/SMTP/FTP/banner fixtures, compare captured bytes and protocol labels with server logs. Unknown banners and empty responses must remain inconclusive. Cancel a slow banner and verify there is no lingering socket.
9. Inspect HTTP fixtures with a normal HEAD response, redirect to an out-of-scope address, misleading port number, oversized headers, early EOF and a slow drip. Confirm only one numeric endpoint is contacted, only HEAD / is sent, no redirect/body is consumed and deadline/limit states are accurate. A capture reaching exactly 4 KiB conservatively reports the limit even if the response ends there.
10. Test TLS/HTTPS against trusted IP-SAN certificates and self-signed, expired and wrong-identity certificates. Confirm failed verification sends no HEAD request, has no insecure fallback, and creates no finding/access claim. Compare successful session protocol/cipher and leaf digest with the lab server. These TLS trust and Android networking checks require a handset.
11. Save service reports and Wi-Fi snapshots, then edit the selected engagement/target fields. Verify existing results still save to their original destination. Check per-asset attribution, hashes and full/summary exports. Freeze a Wi-Fi snapshot, receive a newer scan record before saving, and verify the frozen flags/timestamp remain intact.

## Implementation references

M4b validation: the development APK assembled successfully and all 645 JVM tests across 51 suites passed, with zero failures, errors or skipped tests. Coverage includes protocol exchanges, redirect/body boundaries, capture limits, partial/error outcomes, slow-drip deadlines, TLS endpoint-identification configuration, report integrity and encrypted snapshot persistence. JVM tests use controlled socket streams; they do not verify Android routing, actual TLS trust negotiation, socket cancellation on handsets or OEM behavior. Use the handset checklist above. The earlier M4a baseline was 627 tests.

Network-specific socket behavior: [Android Network](https://developer.android.com/reference/android/net/Network). Connected-prefix information: [Android LinkProperties](https://developer.android.com/reference/android/net/LinkProperties). Actual handset behavior remains unverified here.

TLS endpoint verification: [Android SSLParameters](https://developer.android.com/reference/javax/net/ssl/SSLParameters#setEndpointIdentificationAlgorithm(java.lang.String)).
