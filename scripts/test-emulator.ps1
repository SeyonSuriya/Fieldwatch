param(
    [string]$EmulatorSerial = 'emulator-5580',
    [string]$EmulatorSdk = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$JavaHome,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
if ($EmulatorSerial -notmatch '^emulator-[0-9]+$') { throw 'An Android emulator serial is required; physical devices are not supported by this test script.' }
$taskAdb = Join-Path $EmulatorSdk 'platform-tools/adb.exe'
if (-not (Test-Path -LiteralPath $taskAdb)) { throw 'Supply -EmulatorSdk with Android Studio SDK location.' }
if (-not $JavaHome) {
    $taskLocalJdk = Get-ChildItem -LiteralPath (Join-Path $taskRoot '.gradle/toolchains/java17') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'bin/java.exe') } | Select-Object -First 1
    $JavaHome = if ($taskLocalJdk) { $taskLocalJdk.FullName } else { $env:JAVA_HOME }
}
if (-not $SkipBuild -and -not $JavaHome) { throw 'Supply a Java 17 JDK with -JavaHome.' }
$taskPrevious = @{}
foreach ($taskName in @('JAVA_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','ANDROID_USER_HOME','GRADLE_USER_HOME')) {
    $taskPrevious[$taskName] = [Environment]::GetEnvironmentVariable($taskName, 'Process')
}
$taskServer = $null
$taskRestartPending = $false
$taskRestartToken = [Guid]::NewGuid().ToString('N')
$taskStartedAt = [DateTimeOffset]::UtcNow.ToString('o')
$taskResultPath = Join-Path $taskRoot '.gradle/emulator-result.json'
Push-Location -LiteralPath $taskRoot
try {
    New-Item -ItemType Directory -Force -Path (Join-Path $taskRoot '.gradle') | Out-Null
    [ordered]@{status='STARTED';startedAtUtc=$taskStartedAt;emulator=$EmulatorSerial} | ConvertTo-Json | Set-Content -LiteralPath $taskResultPath
    $env:JAVA_HOME = $JavaHome
    $taskBuildSdk = Join-Path $taskRoot '.gradle/android-sdk'
    $env:ANDROID_HOME = if (Test-Path -LiteralPath (Join-Path $taskBuildSdk 'platforms/android-35/android.jar')) { $taskBuildSdk } else { $EmulatorSdk }
    $env:ANDROID_SDK_ROOT = $env:ANDROID_HOME
    $env:GRADLE_USER_HOME = Join-Path $taskRoot '.gradle/user-home'
    $env:ANDROID_USER_HOME = if ($taskPrevious['ANDROID_USER_HOME']) { $taskPrevious['ANDROID_USER_HOME'] } else { Join-Path $env:USERPROFILE '.android' }
    New-Item -ItemType Directory -Force -Path $env:ANDROID_USER_HOME | Out-Null
    if (-not $SkipBuild) {
        & ./gradlew.bat assembleSimulation assembleSimulationAndroidTest --console=plain --max-workers=2 '-Pkotlin.compiler.execution.strategy=in-process'
        if ($LASTEXITCODE -ne 0) { throw 'Simulation build failed.' }
    }
    $taskState = & $taskAdb -s $EmulatorSerial get-state 2>&1
    if ($LASTEXITCODE -ne 0 -or "$taskState".Trim() -ne 'device') { throw 'Start the emulator in Android Studio and wait for the home screen, then retry.' }
    $taskHardware = (& $taskAdb -s $EmulatorSerial shell getprop ro.hardware).Trim()
    $taskBoot = (& $taskAdb -s $EmulatorSerial shell getprop sys.boot_completed).Trim()
    if ($taskHardware -notin @('ranchu','goldfish') -or $taskBoot -ne '1') { throw 'A fully booted Android emulator is required.' }
    $taskApi = (& $taskAdb -s $EmulatorSerial shell getprop ro.build.version.sdk).Trim()
    if ([int]$taskApi -lt 33) { throw 'Assessment simulation requires emulator API 33+.' }
    foreach ($taskPort in 18081..18084) {
        $taskListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $taskPort)
        try { $taskListener.Start() } finally { $taskListener.Stop() }
    }
    $taskPython = (Get-Command python -ErrorAction Stop).Source
    $taskServer = Start-Process -FilePath $taskPython -ArgumentList @('-u','scripts/lab/emulator_lab.py') -WorkingDirectory $taskRoot -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $taskRoot '.gradle/emulator-lab.log') -RedirectStandardError (Join-Path $taskRoot '.gradle/emulator-lab-error.log') -PassThru
    $taskReady = $false
    for ($taskAttempt = 0; $taskAttempt -lt 40; $taskAttempt++) {
        if ($taskServer.HasExited) { throw 'Loopback fixture server failed; check .gradle/emulator-lab-error.log.' }
        if ((Get-Content -LiteralPath .gradle/emulator-lab.log -Raw -ErrorAction SilentlyContinue) -match 'READY loopback lab') { $taskReady = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $taskReady) { throw 'Loopback fixture server did not become ready.' }
    & $taskAdb -s $EmulatorSerial install -r -t app/build/outputs/apk/simulation/app-simulation.apk
    if ($LASTEXITCODE -ne 0) { throw 'Simulation APK installation failed.' }
    & $taskAdb -s $EmulatorSerial install -r -t app/build/outputs/apk/androidTest/simulation/app-simulation-androidTest.apk
    if ($LASTEXITCODE -ne 0) { throw 'Instrumentation APK installation failed.' }
    function Invoke-FieldwatchSimulationTest([string]$TestClass, [int]$ExpectedCount, [string]$LogName, [switch]$Restart) {
        $taskArguments = @('-s', $EmulatorSerial, 'shell', 'am', 'instrument', '-w', '-r', '-e', 'timeout_msec', '120000', '-e', 'class', $TestClass)
        if ($Restart) { $taskArguments += @('-e', 'restartToken', $taskRestartToken) }
        $taskArguments += 'app.fieldwatch.simulation.test/androidx.test.runner.AndroidJUnitRunner'
        $taskOutput = & $taskAdb @taskArguments 2>&1
        $taskExit = $LASTEXITCODE
        $taskOutput | Set-Content -LiteralPath (Join-Path '.gradle' $LogName)
        $taskOutput | Write-Output
        $taskText = $taskOutput -join "`n"
        $taskExpected = 'OK \(' + $ExpectedCount + ' tests?\)'
        if ($taskExit -ne 0 -or $taskText -notmatch $taskExpected -or $taskText -match '(?m)^(FAILURES!|INSTRUMENTATION_FAILED|INSTRUMENTATION_RESULT: shortMsg=|INSTRUMENTATION_STATUS_CODE: -[234](?:\s|$))') {
            throw "Emulator tests failed, crashed or were skipped. Inspect .gradle/$LogName."
        }
    }
    function Stop-FieldwatchSimulation {
        # Fixed simulation package only; never force-stop the user's development app or phone.
        & $taskAdb -s $EmulatorSerial shell am force-stop app.fieldwatch.simulation
        if ($LASTEXITCODE -ne 0) { throw 'Could not stop the simulation app for the restart check.' }
    }
    Invoke-FieldwatchSimulationTest 'app.fieldwatch.SimulationAssessmentTest' 8 'emulator-instrumentation.log'
    Stop-FieldwatchSimulation
    $taskRestartPending = $true
    Invoke-FieldwatchSimulationTest 'app.fieldwatch.SimulationRestartTest#seedInterruptedEngagement' 1 'emulator-restart-seed.log' -Restart
    Stop-FieldwatchSimulation
    Invoke-FieldwatchSimulationTest 'app.fieldwatch.SimulationRestartTest#verifyRecoveredEngagement' 1 'emulator-restart-recovery.log' -Restart
    Stop-FieldwatchSimulation
    Invoke-FieldwatchSimulationTest 'app.fieldwatch.SimulationRestartTest#verifyRecoveryIsDurableAndCleanup' 1 'emulator-restart-durable.log' -Restart
    $taskRestartPending = $false
    $taskRelease = (& $taskAdb -s $EmulatorSerial shell getprop ro.build.version.release).Trim()
    [ordered]@{
        format='fieldwatch-emulator-run';version=1;status='PASSED';startedAtUtc=$taskStartedAt;finishedAtUtc=[DateTimeOffset]::UtcNow.ToString('o')
        emulator=$EmulatorSerial;api=[int]$taskApi;androidRelease=$taskRelease;testsPassed=11;testsSkipped=0;standardTestsPassed=8;restartTestsPassed=3
        simulationApkSha256=(Get-FileHash -Algorithm SHA256 app/build/outputs/apk/simulation/app-simulation.apk).Hash.ToLowerInvariant()
        testApkSha256=(Get-FileHash -Algorithm SHA256 app/build/outputs/apk/androidTest/simulation/app-simulation-androidTest.apk).Hash.ToLowerInvariant()
        limitations=@('Emulator only','Synthetic local services','No physical radio or manufacturer-device certification','SAF coverage limited to local Downloads in the emulator','Process restart only; no mid-write power-loss or OS-reboot testing')
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $taskResultPath
    Write-Output "PASS: 11 simulation tests (8 standard + 3 restart phases) on $EmulatorSerial (API $taskApi). No physical-device or radio certification."
} catch {
    [ordered]@{status='FAILED';startedAtUtc=$taskStartedAt;finishedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');emulator=$EmulatorSerial;details='See emulator-instrumentation.log and runner output.'} |
        ConvertTo-Json | Set-Content -LiteralPath $taskResultPath
    throw
} finally {
    if ($taskRestartPending) {
        try {
            Stop-FieldwatchSimulation
            Invoke-FieldwatchSimulationTest 'app.fieldwatch.SimulationRestartTest#cleanupRestartFixture' 1 'emulator-restart-cleanup.log' -Restart
        } catch { Write-Warning "Synthetic restart fixture cleanup failed. Preserve the emulator data and inspect .gradle/emulator-restart-cleanup.log." }
    }
    if ($taskServer -and -not $taskServer.HasExited) { Stop-Process -Id $taskServer.Id -Force }
    foreach ($taskName in $taskPrevious.Keys) { [Environment]::SetEnvironmentVariable($taskName, $taskPrevious[$taskName], 'Process') }
    Pop-Location
}
