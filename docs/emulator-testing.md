# Android Studio simulation tests

This setup runs Fieldwatch's assessment code on an Android virtual device against synthetic loopback services. It is separate from the installed phone build and does not establish commercial-device vulnerability support or physical-radio compatibility.

## Builds and isolation

- `development`: existing `app.fieldwatch.dev`, Fieldwatch Dev.
- `simulation`: new `app.fieldwatch.simulation`, Fieldwatch Simulation. It has independent app storage and the same assessment implementation and network scope restrictions.
- Simulation instrumentation: `app.fieldwatch.simulation.test`, AndroidJUnitRunner. Tests are restricted to the simulation build on an emulator API 33+.

No emulator host exception was added to production network validation. The suite uses numeric `10.0.2.2`, the emulator's host-access address, only when it is within the selected simulated Wi-Fi subnet. If Wi-Fi capabilities/routing are unavailable, tests fail instead of relaxing scope or switching to a real target. The desktop services bind only to `127.0.0.1` and serve synthetic reference data.

## Android Studio

1. Open this repository and let Gradle sync. The project needs JDK 17, Android SDK platform 35 and its build tools. Studio's project `local.properties` SDK setting takes precedence over environment variables; install missing project SDK packages if prompted.
2. In Device Manager, start an API 33+ virtual phone and wait for the home screen. An Android 16/API 36 image matches the reported handset OS; another API is a separate compatibility test, not Android 16 certification.
3. Select the `simulation` build variant to run the isolated app. Existing Wi-Fi/BLE/Classic screens depend on the emulator's simulated capabilities and do not represent physical radio coverage.
4. For automated testing, use the PowerShell helper below. It starts and stops the loopback services and invokes only the explicitly selected emulator.

To run directly inside Studio instead, select the simulation variant and emulator, start `python scripts/lab/emulator_lab.py` in a terminal, then run `SimulationAssessmentTest` from `app/src/androidTest/java/app/fieldwatch/`. Stop that terminal's server with Ctrl+C afterward. The helper performs the same fixture lifecycle automatically and pins every ADB action to one emulator.

Do not uninstall or clear the phone's Fieldwatch Dev to run these tests. This suite uses a different package and does not send commands to physical devices.

During this session, Android Studio also generated Gradle daemon criteria selecting JetBrains JDK 21, a Foojay resolver entry in settings, and a tooling parallel-sync property. Those IDE-generated changes were preserved, not authored or reverted as part of the simulation feature. The helper's Java 17 selection is its launcher environment; Gradle daemon criteria can select a different runtime. Compilation bytecode remains Java 17. Review the IDE-generated Gradle changes separately when committing.

## Automated run

From the repository directory:

```powershell
.\scripts\test-emulator.ps1 -EmulatorSerial emulator-5554
```

Use the actual emulator serial shown by Android Studio/ADB. The helper rejects non-emulator serials, requires a booted `ranchu`/`goldfish` emulator and API 33+, installs only the simulation/test APKs, and checks that all four instrumentation tests passed without skipped/crashed tests. Python 3 is required for the host fixtures. Override `-EmulatorSdk` if Studio uses another SDK location; `-JavaHome` selects a Java 17 installation.

To reuse already-built simulation APKs:

```powershell
.\scripts\test-emulator.ps1 -EmulatorSerial emulator-5580 -SkipBuild
```

Build output paths:

```text
app/build/outputs/apk/simulation/app-simulation.apk
app/build/outputs/apk/androidTest/simulation/app-simulation-androidTest.apk
```

The helper uses bounded build workers and in-process Kotlin compilation to reduce concurrent JVM pressure. On a memory-constrained desktop, build first and boot the emulator afterward, then run with `-SkipBuild`. The existing API 37.0 Play Store virtual phone expanded its initial RAM allocation during startup in this workspace; a cold boot can be resource intensive. The installed Android Studio application is not closed or reconfigured by the helper.

## Test services and coverage

`scripts/lab/emulator_lab.py` starts four loopback services:

| Host port | Service |
| --- | --- |
| 18081 | Exposed reference fixture: synthetic marker in HEAD response |
| 18082 | Protected reference fixture: HTTP 401 without marker |
| 18083 | Delayed HEAD response for cancellation |
| 18084 | Intentionally invalid TLS response for handshake-error handling |

The instrumentation suite checks:

1. Real Android Wi-Fi-bound TCP/HEAD connections to both reference fixtures; distinct module outcomes; linked pair report; local handset baseline; real Android Keystore AES-GCM persistence; durable store reload; full/summary report generation and app-private file round-trip; closed-engagement rejection.
2. The cancellation pattern used by the ViewModel: cancel the operation and close its owned socket. No completed cancelled report is accepted.
3. Invalid TLS handshake handling, without sending an HTTP request or retrying plaintext. This is not a trusted/self-signed/expired certificate test matrix.
4. Compose interaction with the actual assessment screen: creating an engagement, reviewing the local baseline and saving it. The test removes only its uniquely named simulation engagement afterward.

The storage test uses a unique simulation-only directory and Keystore alias, which it cleans up after itself. UI testing uses only the simulation package's engagement store. No unique phone identifiers, real device credentials or router data are used.

Report generation/app-private file testing does not exercise the system document picker/SAF provider UI. Permission prompts, real process death, OEM behavior, physical Wi-Fi/Bluetooth discovery, pairing, radio coexistence, root/external-radio capabilities and manufacturer-specific vulnerability fixtures remain separate tests. Emulator Bluetooth functionality varies by runtime/image; this initial suite makes no Bluetooth interoperability claim.

## Outputs and troubleshooting

Validation, 3 November 2026: both simulation APKs compiled; the existing baseline has 706 passing JVM tests and 7 passing desktop HTTP/fixture tests. The user requested continuation with an existing virtual device. The existing `Pixel_10` profile successfully booted Android 17/API 37 on emulator 37.2.13.0 with WHPX, a cold boot, 4 GB guest RAM, four virtual cores and software graphics. No AVD data wipe, new system image, protection override or network-scope exception was used.

The first instrumentation attempt ended in a bind-application startup ANR. A normal app launch then completed. The next run reached all four tests and exposed an older Espresso dependency's reflective `InputManager.getInstance` call, unavailable on this runtime. Test-only dependencies were updated to AndroidX runner 1.7.0, JUnit extension 1.3.0 and Espresso 3.7.0; the [AndroidX test release notes](https://developer.android.com/jetpack/androidx/releases/test) document the public-API replacement. The test APK rebuilt successfully under Studio's selected JDK 21 daemon; the helper's dotted Kotlin compiler property was quoted for PowerShell compatibility.

The final run on `emulator-5580` passed **all four instrumentation tests, zero failed/skipped**, in 41.743 seconds of runner time. The simulation app SHA-256 was `4f657787e3d282c2a791d356198e42277e9ded92c21425d5466c11433def45f1`; the updated test APK SHA-256 was `61fef13109e9bda2f07492520a45d19cc6d6c01d9f02eb87bef04f08b6637ef7`. This is a functional test result, not a cold-start performance pass, Android 16 certification, physical-radio validation, SAF picker UI test or commercial-device vulnerability result. Earlier startup failures remain recorded; they are not relabeled as passing.

- `.gradle/emulator-instrumentation.log`: raw instrumentation result and assertion failures.
- `.gradle/emulator-result.json`: current run status, runtime version and tested APK hashes; a started/failed run replaces the previous status so it cannot silently reuse an older pass.
- `.gradle/emulator-instrumentation-inputmanager-failure.log`: retained pre-fix test-library failure.
- `.gradle/emulator-lab.log` and `.gradle/emulator-lab-error.log`: host fixture startup/errors.
- `.gradle/simulation-build.log`: build log from this development session.
- `.gradle/simulation-compatibility-build.log`: updated AndroidX test APK build.

An occupied fixture port fails startup rather than stopping another process. An offline emulator requires finishing its boot in Device Manager before retrying. No phone commands, firewall changes, security-protection overrides, scope bypasses or app-data resets are performed by this helper. Simulation APKs remain on the selected emulator for inspection; host fixture processes started by the helper are stopped in its cleanup path.

Keep only one AVD running on this 16 GB desktop and finish memory-heavy builds before starting tests where possible. The emulator may appear offline while Android's first boot and system package initialization are still in progress. Kernel diagnostics are more informative than repeated blind restarts. The passing run used the existing Pixel_10 profile alone after duplicate task-owned emulator instances were stopped. The final helper invocation was `./scripts/test-emulator.ps1 -EmulatorSerial emulator-5580 -SkipBuild`. Each test has a 120-second runner limit; limits/failures are not treated as passes.

Primary references: [Android instrumented tests](https://developer.android.com/training/testing/instrumented-tests) and [Android Emulator networking](https://developer.android.com/studio/run/emulator-networking).


## Extended lifecycle and Bluetooth controller coverage

The suite now declares six tests. The two added scenarios exercise the actual network
screen ON_STOP observer while a synthetic HEAD response is pending, and a fake
Bluetooth transport on the Android runtime. Bluetooth assertions cover rejection of
a write to a read-only characteristic, authentication-error handling, stale BLE
callbacks after disconnect, and Classic RFCOMM sent-byte accounting and stale input.
No Bluetooth radio, pairing, GATT platform implementation or RFCOMM socket is exercised
by the fake transport. The lifecycle test checks that stopping the screen produces no
completed service report or persisted evidence.

The runner requires exactly six passing tests and rejects failures/skips. The earlier
four-test result above describes the earlier APKs only. Extended-suite execution is
recorded separately below after validation. System document-picker UI coverage remains
pending; app-private export generation is already covered.


Extended-suite validation, 3 November 2026: test APK compilation passed (1m 27s),
all seven desktop fixture tests passed, and all six Android instrumentation tests
passed with zero skipped on `emulator-5580`, API 37, in 58.518 seconds.
The helper exited successfully and recorded `PASSED` at `2026-11-03T18:27:28.9525271+00:00`.
Test APK SHA-256: `eb2e302d41dcc3230df85f32ca2c6014f5c99b30c42a4238a7d7a3f85c69913a`.

The first six-test run passed inside Android but the helper falsely rejected its
output because an unanchored `FAILURES` pattern matched a test method name.
Failure detection now matches instrumentation failure lines; checks verified crash,
failure, ignored and assumption-failure markers still reject the run, while that
test name does not. The full suite was rerun successfully after this correction.
Production app behavior and physical-radio verification are unchanged. Next step:
system document-picker export and cancellation tests using synthetic reports.
