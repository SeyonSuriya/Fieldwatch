# Build and regression baseline

Date: 17 October 2026 (Asia/Colombo).

Source revision: `844ace8c5c787695977b2c4857e06533603aba95`.

No application source or build configuration changes were made for this baseline. New documentation and a helper script were added separately.

## Environment

- Windows, Eclipse Temurin JDK 17.0.20.1+1.
- Project Gradle wrapper 8.11.1; existing AGP 8.7.3 and Kotlin 2.0.21.
- Android SDK platform 35, build-tools 35.0.0, and platform-tools downloaded locally. AGP also installed its selected build-tools 34.0.0 automatically.
- Toolchains, SDK, Gradle downloads, and build logs live under the ignored `.gradle/` directory. Machine-wide Java settings were not changed.

## Checks

Invocation: `gradlew.bat testDebugUnitTest assembleDebug --console=plain --stacktrace`, with process-local Java/SDK/Gradle-home settings.

- Unit tests: **538 passed, 0 failures, 0 errors, 0 skipped, across 41 suites**.
- APK assembly: **passed**. Gradle completed successfully in 15 minutes 15 seconds, with 57 tasks executed. The baseline APK is 9,413,724 bytes.
- Helper script: PowerShell syntax parsed without errors.

Local outputs:

- Unit-test HTML report: `app/build/reports/tests/testDebugUnitTest/index.html`.
- Unit-test XML results: `app/build/test-results/testDebugUnitTest/`.
- Build log: `.gradle/baseline-build.log`.
- APK output: `app/build/outputs/apk/debug/app-debug.apk`.

## Reproduce

From PowerShell, run `./scripts/check-baseline.ps1 -Variant Debug` to reproduce the original variant's tasks. The helper now defaults to `Development` for the isolated development installation. It discovers the downloaded project-local toolchain, or accepts `-JavaHome` and `-AndroidSdk`, and restores the caller's environment afterwards. Dependency downloads require network access. See [assessment-workspace.md](assessment-workspace.md) for subsequent development results; the 538-test result above is the original, unchanged baseline.

## Existing warnings observed

- The older Android build plugin reports SDK XML metadata newer than it understands.
- Serialization `EncodeDefault` usages need experimental-API opt-in annotations.
- Deprecated Android Wi-Fi/GNSS API usages and always-true/false instance checks are reported.
- A native AndroidX graphics library could not have debug symbols stripped and is packaged as supplied.

These warnings were recorded without altering the original baseline configuration.

## Remaining verification

- Physical-device startup, permissions, background scanning, radio coexistence, GNSS, battery, and exports have not been verified.
- Android 13 through the latest stable release have not been tested as a device matrix. Building against SDK 35 does not establish that coverage.
- Rooted and external-radio capabilities have not been probed.
- The existing debug variant retains the production application ID and enables shrinking while disabling debuggability. Do not treat the original baseline APK as an isolated development installation. A separate `development` variant was added subsequently; see [assessment-workspace.md](assessment-workspace.md).
- No APK was installed, no target devices were assessed, and no exploitation modules were implemented.
