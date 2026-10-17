# M6a: reference-device validation foundation

M6a introduces an explicit module contract, synthetic exposed/protected reference device, and reviewable validation reports. It does not certify any manufacturer device or implement a CVE exploit. M6 remains incomplete until affected/unaffected product fixtures and handset results are available.

## Module contract and support

The built-in catalog currently has one module: `fieldwatch-reference-authz` version 1, fixture revision 1, support `LAB_ONLY`. It declares an exact product, affected/protected build sets, prerequisites, side effects and recovery. Future product modules require verified identity/version prerequisites, actual positive and negative product fixtures, a documented supported operation and an honest outcome. Broad marketing model names and server banners alone are insufficient.

The reference product is `fieldwatch-reference-camera`. Build `1.0-exposed` returns the synthetic `FW-LAB-CANARY-1` header to an unauthenticated HEAD request. Build `1.1-protected` returns a specific HTTP 401 challenge without that header. These are deliberately named synthetic fixture modes, not camera firmware or manufacturer releases. The protected fixture never accepts credentials, including made-up credentials used by the local regression test. Neither mode serves files, bodies, media or device data.

The module evaluates a saved M4 plain HTTP HEAD / inspection. It sends no new traffic. It requires the original digest, matching network asset, recorded run, completed exact request attempt, valid complete HTTP headers and unambiguous identity/build/protocol/canary fields. The shared strict HTTP parser is also used by M5; the refactor does not change M5 check behavior or versions.

Outcomes:

| Outcome | Meaning |
| --- | --- |
| LAB_MARKER_EXPOSED | Exact synthetic exposed-build response, HTTP 200 and exact marker captured without an Authorization request field. Creates one low-severity confirmed finding explicitly marked LAB ONLY. |
| LAB_PROTECTION_OBSERVED | Exact protected-build control, HTTP 401, expected challenge and no marker field. No finding; only this HEAD operation was blocked. |
| NOT_APPLICABLE | The complete response does not claim the exact reference product. No supported commercial product or CVE is inferred. |
| INCONCLUSIVE | Unknown build/protocol, inconsistent build/behavior, duplicate fields, partial/failed capture, missing request, wrong marker or unsupported inspection mode. No finding. |

Server identity and build headers are unauthenticated claims and can be imitated. The positive result confirms only that a synthetic header was returned in that saved observation. It does not authenticate hardware identity, confirm protected file/media access, demonstrate arbitrary authentication bypass or establish a real-product vulnerability. A negative control is not a complete security assessment.

## Run the reference target

The fixture requires Python 3 and only its standard library. It can run on a controlled lab host or a separate lab phone with a Python environment. Fieldwatch itself stays phone-only and requires no root or additional radio. Two fixtures may run on different ports of the same authorized host.

Loopback smoke testing (not reachable by Fieldwatch's local-network scope):

```text
python scripts/lab/reference_device.py --mode exposed --port 8081
python scripts/lab/reference_device.py --mode protected --port 8082
```

For handset verification, bind each server to the lab host's actual private Wi-Fi interface, for example:

```text
python scripts/lab/reference_device.py --mode exposed --bind 192.168.1.10 --port 8081
python scripts/lab/reference_device.py --mode protected --bind 192.168.1.10 --port 8082
```

Replace the example with the authorized host's real interface. The script defaults to loopback and rejects public/wildcard binds. It does not change firewall rules or run itself in the background. Allowing handset connections through the lab host's firewall is a separate operator configuration. Stop each server with Ctrl+C. Only HEAD / serves the fixture; other paths return 404 and GET returns 405. No files are read from request paths.

The canonical identity/build/status/marker manifest is `app/src/test/resources/device-validation/reference-fixtures.json`. Both Python target tests and JVM module tests consume it, and the JVM tests assert module/fixture version and build agreement. The server reads this repository-relative resource; keep the repository layout when running it.

## App workflow

1. Create/select an authorized lab engagement in Fieldwatch Dev. Connect the handset to the same Wi-Fi subnet as the fixture.
2. Open Network and Wi-Fi assessment. Enter the host's numeric IPv4 address and port 8081 in Inspect one service. Select HTTP HEAD /, review the exact target and collect the response. Save inspection evidence.
3. Repeat for protected port 8082. The app does not pair or compare different targets automatically.
4. Open the engagement. On each service evidence record, choose **Review reference lab module**. Review prerequisites, claimed product/build, outcome, side effects and recovery.
5. Cancel leaves records untouched. **Save lab validation** saves the report and links original/evaluation evidence. The exposed response creates only a LAB ONLY finding; the protected control saves a result without a finding. No access record is created.

Collection continues to use M4 scope validation, network-bound sockets, deadlines, capture bounds and lifecycle cancellation. Validation itself is offline. Re-running a module/version/fixture revision on the same source/hash does not add duplicates, including after a restart. New observations are independent historical evidence. Closed engagements cannot receive results. Writes obey the existing atomic encrypted-vault and size-limit controls. Full exports include raw source evidence and provenance; summaries omit them.

## Verification

Software validation: development APK assembled successfully; all 685 Android/JVM tests across 53 suites passed with zero failures, errors or skipped tests. The 4 Python loopback HTTP fixture tests also passed. No physical handset or manufacturer product verification was performed here.

Local Python tests exercise actual loopback HTTP exchanges for exposed/protected modes, rejection of credentials, method/path behavior and bind restrictions:

```text
python -m unittest discover -s scripts/lab -p test_reference_device.py
```

CI now includes that fixture test step. Remote CI has not been run from this workspace. Android JVM tests cover shared-fixture positives/negative controls, unknown identities/builds/protocols, inconsistent responses, duplicate headers, wrong/missing markers, redirects, partial/error outcomes, unsupported modes, evidence integrity/target binding, encryption, source links, idempotence, closure and export boundaries. These are software-fixture checks, not physical-product certifications.

Handset checks remain with the user:

- Verify exposed and protected targets produce their distinct outcomes using fresh M4 captures. Compare target logs with one HEAD request per collection.
- Test cancellation/backgrounding during collection. Confirm module review sends no additional requests.
- Cancel a preview, save/repeat, restart/repeat and verify no unintended records or duplicates.
- Check LAB ONLY labeling, evidence hashes/links, closed-engagement rejection, and full versus summary exports.
- Change fixture mode and recollect. Confirm old evidence retains its original result and the new response is assessed independently.

## Product onboarding for M6b

For an actual device module, record manufacturer/model variant, firmware/build and security patch, supported protocol/service, authoritative advisory where applicable, target ownership/scope, expected side effects and recovery. Supply reproducible affected and unaffected target behavior before marking it supported. The Samsung A51 has been proposed as a candidate; its role, exact variant and software details remain to be confirmed. No Samsung-specific vulnerability or compatibility is asserted by M6a.
