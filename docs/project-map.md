# Fieldwatch project map

Source review: 17 October 2026. This is a development orientation, not a security audit or a claim that every execution path has been verified. Runtime radio behavior still needs a physical Android device.

## Current application

Fieldwatch is a single-module Android application for nearby Wi-Fi access-point and Bluetooth LE advertisement reconnaissance. It works locally without an account or application backend. The checked-in build configuration is version 1.1.26, version code 36, application ID `app.fieldwatch`.

It uses Kotlin 2.0.21, Jetpack Compose / Material 3, coroutines, StateFlow, and kotlinx.serialization. Android minimum API is 29 (Android 10); compile and target API are 35. Gradle is 8.11.1 and Android Gradle Plugin is 8.7.3. The source targets Java 17.

There is no Room database, dependency-injection framework, or separate server module. Application objects are wired manually through `FieldwatchApp`.

## Runtime flow

```text
MainActivity -> FieldwatchViewModel -> FieldwatchApp.startScanning()
                                         |
                                    ScanService
                                         |
                  WifiRadio / BleRadio -> Observation
                                         |
                    bounded channel -> batched ingestion
                                         |
                         DeviceStore -> Sighting
                           |                 |
                    SignatureEngine    payload decoding
                           |                 |
                           +-----------------+
                                         |
           StateFlow -> ViewModel -> Compose screens
                                         |
                 SitStore / LogStore / Alerter / TakPublisher
```

GNSS monitoring is a parallel path: Android location and raw GNSS measurements feed calibration and interference analysis, then live notices, saved session marks, reports, and optional TAK output.

`MainActivity` owns permission requests and Compose startup. `FieldwatchApp` owns shared stores, alerts, radio flood detectors, GPS path, arrival baseline, GNSS objects, and TAK publisher. `ScanService` is a foreground LifecycleService, with staggered radio startup, recovery, a processing loop, and periodic publication.

## Source map

All Kotlin paths below are relative to `app/src/main/java/app/fieldwatch/`.

| Area | Files | Responsibility |
| --- | --- | --- |
| App lifecycle | `MainActivity.kt`, `FieldwatchApp.kt` | Startup, permissions, shared object wiring, location, scanning |
| Collection | `radio/ScanService.kt`, `WifiRadio.kt`, `BleRadio.kt`, `Permissions.kt` | Android scanners, quotas, retries, ingestion, foreground notification |
| Parsing | `radio/WifiIeParser.kt`, `BleAdParser.kt`, `domain/RadioFacts.kt` | Wi-Fi information elements, BLE advertising structures, normalized facts |
| Shared schema | `domain/Models.kt` | Observation, Sighting, Fleet, rules, decode maps, filters, settings, persisted config |
| Live device state | `data/DeviceStore.kt` | Address-keyed aggregation, freshness, history, relabeling, eviction |
| Identification | `domain/SignatureEngine.kt`, `DefaultCatalog.kt`, `ApVendorOuis.kt` | Indexed rules, built-in signatures, product-specific ambiguity handling |
| Lookup data | `domain/RadioDb.kt`, `OuiLookup.kt`, `FastPairModels.kt` | Offline vendor / assigned-number / model lookups |
| Payload interpretation | `domain/AdvPayloadDecoder.kt`, `SignatureFieldDecoder.kt`, `CatalogDecodes.kt`, `OpenDroneId.kt`, `Cta2063.kt`, `PayloadLocation.kt` | Standard and catalog-defined decoding, Remote ID, advertised positions |
| Signature discovery | `domain/SignatureCandidates.kt` | Candidate families and rules suggested from observations and logs |
| Detection | `domain/PairingFlood.kt`, `WifiBeaconFlood.kt` | Burst heuristics and display suppression |
| GNSS | `radio/GnssMonitor.kt`, `domain/GnssInterference.kt`, `GnssCalibration.kt`, `data/GnssProfileStore.kt` | Device calibration, receiver monitoring, confidence and notices |
| Filtering and field views | `domain/FilterEngine.kt`, `Geo.kt`, `Hunt.kt`, `RadarPlot.kt`, `ClassOutline.kt` | View gates, co-travel, RSSI cues, display geometry |
| Settings and migrations | `data/ConfigStore.kt`, `domain/SettingsExchange.kt`, `SignatureExchange.kt` | Local config, stock migrations, import/export and overlay behavior |
| Sessions | `data/SitStore.kt`, `domain/Sit.kt` | Start/end saved surveys, paths, radio summaries, flood/GNSS marks |
| Logs | `data/LogStore.kt`, `domain/LogReplay.kt` | Rotating JSONL, legacy CSV reading, unique-radio reconstruction |
| Reports | `domain/DebriefReport.kt`, `DebriefPrompt.kt`, `SitDiff.kt`, `SitDiffPrompt.kt`, `data/DebriefPdf.kt` | Debrief, session comparisons, PDF, copyable AI context |
| Exports | `domain/SitExport.kt`, `GeoExport.kt`, `CsvCells.kt`, `DeviceDetailText.kt`, `DeviceDetailPrompt.kt` | CSV/JSON, GPX/KML/WiGLE, device text and prompt exports |
| Maps | `data/PathTiles.kt`, `PlaceLookup.kt`, `domain/SitPathPlot.kt` | Optional online tiles/geocoding and path plot models |
| TAK | `radio/TakPublisher.kt`, `domain/TakPublish.kt` | CoT formatting, rate/hold behavior, UDP multicast/unicast output |
| Alerts | `alert/Alerter.kt`, `domain/RadioBookmarks.kt` | Watch targets, sound, speech, notifications, Mine suppression |
| Presentation | `ui/FieldwatchViewModel.kt`, `FieldwatchAppUi.kt`, `screen/`, `component/`, `theme/` | Reactive UI state, actions, navigation, screens and widgets |

## Existing operator features

- Live list, radar, timeline, hybrid sparklines, and class outline.
- Wi-Fi AP and BLE details with raw/decoded advertisement information.
- Custom signatures, matching rules, decode fields, candidate suggestions, and signature packs.
- Filters and saved presets, arrival baseline, co-travel filtering, named radios, observer notes, watchlists, and Mine markers.
- RSSI-based Hunt cues. Radar and Hunt do not establish measured bearing or reliable range.
- Saved survey sessions, radio/path history, session comparisons, debrief text/PDF, geographic exports, and copyable AI prompts.
- BLE pairing/name flood and Wi-Fi beacon-flood heuristics.
- Calibrated GNSS interference checks and optional spoofing indicators.
- Optional TAK/CoT publication.

## Important data semantics

1. `Observation` is a scan input. `Sighting` is accumulated state, not a packet. Its key is radio kind plus normalized MAC address. A rotating address can therefore become a new radio record.
2. `Fleet` is the historical internal name for a signature definition. It is not an engagement or a device fleet inventory. Rules can use OR or AND behavior; multiple signatures may match one radio.
3. Matching uses OUI indexes and cached compiled plans. Some product ambiguity is resolved by explicit code (for example, Tesla/iBeacon, Polar/GoPro, DJI variants, and Apple/Find My). Generic rule edits can interact with these exceptions.
4. Cached Wi-Fi results are treated differently from fresh observations. Preserve this distinction when changing discovery, hit counts, age, or arrival behavior.
5. GPS tags normally identify where the handset heard a radio. Advertised Remote ID / custom decoded coordinates have separate payload fields. Keep handset, aircraft, and operator positions distinct.
6. Ingestion has a 512-observation channel with DROP_OLDEST overflow and batches of up to 80. Logging selects first sightings or every 25th hit, with at most 16 selected rows per batch. This is intentionally lossy and unsuitable as a complete capture record.
7. DeviceStore has a soft live target of 400, a hard ceiling of 900, 40 RSSI samples, and age-based eviction. Raw/manufacturer hex is truncated in the live state.
8. Saved sessions are also bounded: 6,000 radios, 2,000 operator path points, 40 trail points, and 10 closed sessions. Open-session flushing runs every 10 seconds.
9. Logs are stored as JSONL even though legacy settings retain a log-format field. Export conversions and replay are separate concerns.
10. Replay reconstructs unique radios and can re-match against the current catalog. Later interpretation can differ from the label originally seen; future evidence exports should record catalog and detector versions explicitly.
11. Hiding a device from Live is not deletion from a saved session or log. Flood suppression and report exclusions have their own rules.
12. Privacy/demo mode masks selected presentation output and disables TAK. Raw logs and several structured exports retain sensitive fields. Treat each export path separately when changing privacy behavior.

## Persistence and network boundaries

Application-private storage holds `config.json`, rotating logs, saved session JSON, and GNSS calibration data. FileProvider shares specific log/cache directories; Android backup is disabled. These are ordinary app-private files, not an encrypted evidence vault.

Normal collection needs no backend. Optional network paths include GitHub stock signature updates, OpenStreetMap tiles, system geocoding, and configured TAK UDP publication. AI export generates text for the user to share; it is not an embedded model API integration.

## Development and verification

There are 41 JVM test source files covering parsers, decoding, store behavior, catalog migrations, filters, sessions, comparisons, exports, GNSS logic, flood heuristics, TAK formatting, and other domain behavior. There is no checked-in `androidTest` suite in this inventory.

The GitHub workflow runs `testDebugUnitTest` on Java 17 with Android SDK 35, then `assembleDebug`. Equivalent Windows commands are:

```powershell
.\gradlew.bat testDebugUnitTest
.\gradlew.bat assembleDebug
```

During the initial orientation, the available `java` reported version 23, neither Android SDK environment variable was set, and `local.properties` was absent. A subsequent project-local Java 17 / Android SDK setup passed all 538 unit tests and assembled the original debug APK. See [build-baseline.md](build-baseline.md) for results, reproduction steps, warnings, and outstanding handset checks.

The debug build is unusual: it uses the production application ID, disables debuggability, and enables minification/resource shrinking. Review build variants before installing a development build alongside an existing installation. Release signing optionally reads local properties; publisher signing material is not part of the normal checkout.

Supporting scripts build offline lookup assets and documentation. `dist/` contains prebuilt deliverables and stock catalog JSON; their presence does not establish that they were generated from this exact source revision.

## Extension approach for red-team work

The present foundation supports RF reconnaissance and assessment reporting. It has no implemented monitor-mode capture, Wi-Fi client/probe capture, packet injection, BLE GATT assessment, Bluetooth Classic inquiry, cellular collection, or external-radio adapter layer. Wi-Fi collection requests Android scans, so “passive” here describes the application workflow rather than a guarantee that the handset emits no RF.

Useful development directions, in dependency order:

1. **Reproducible development baseline:** configure Java 17/SDK 35, run existing tests/build, and verify startup, permissions, background behavior, and exports on a physical handset.
2. **Engagement context:** add project/session scope, target inventory, assessment notes, and findings tied to observations. Keep these concepts separate from `Fleet` signatures.
3. **Evidence fidelity:** retain immutable observation/event records where needed; record source, timestamps, catalog version, detector reason, and dropped-event counters. Preserve existing lightweight live state as a derived view.
4. **Explainable findings:** expose matched rules and confidence, separate advertisement claims from conclusions, and link findings to supporting observations.
5. **Repeatable analysis:** extend replay with deterministic fixtures and regression cases for new detectors. Existing log replay is aggregation, not full-fidelity radio replay.
6. **Collector boundaries:** introduce a collector interface if additional hardware or assessment transports are needed. Carry source capabilities into the model so unsupported measurements are not implied.

For a new feature, first identify its layer: collection -> schema -> interpretation -> persistence -> presentation/export. Add schema defaults and migration/import behavior when persisting new fields. Verify both live and saved-session paths; changing only a screen often leaves reports and exports inconsistent.

Avoid an application-wide rewrite before feature work. Extract focused responsibilities from the ViewModel as features touch them. `FieldwatchViewModel.kt`, `ConfigStore.kt`, `DefaultCatalog.kt`, and the reporting/UI files already concentrate substantial responsibility.

## Items to investigate before relying on stronger guarantees

- Buffer overflow, sampling, truncation, and retention need visibility if the app becomes an evidence-oriented tool.
- Config loading falls back to seeded defaults after decode failure; recovery/backup behavior deserves attention before storing engagement-critical metadata there.
- Import/download paths use whole-file reads in places; review size and nesting bounds as part of any import-hardening work.
- In `SignatureEngine.match`, the detection-policy argument is accepted but is not visibly used in that method body. Trace intended settings behavior before adding policy controls.
- Location lifecycle, scanner retries, battery behavior, and OEM compatibility need physical-device validation; JVM tests cannot establish radio behavior.
- Localization documents describe future requirements, not implemented language-pack support.

No application behavior was changed in this review.
