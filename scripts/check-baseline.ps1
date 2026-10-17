param(
    [string]$JavaHome,
    [string]$AndroidSdk,
    [ValidateSet('Debug', 'Development')]
    [string]$Variant = 'Development'
)

$ErrorActionPreference = 'Stop'
$baselineRoot = Split-Path -Parent $PSScriptRoot
if (-not $JavaHome) {
    $localJdk = Get-ChildItem -LiteralPath (Join-Path $baselineRoot '.gradle/toolchains/java17') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'bin/java.exe') } |
        Select-Object -First 1
    $JavaHome = if ($localJdk) { $localJdk.FullName } else { $env:JAVA_HOME }
}
if (-not $AndroidSdk) {
    $localSdk = Join-Path $baselineRoot '.gradle/android-sdk'
    $AndroidSdk = if (Test-Path -LiteralPath $localSdk) { $localSdk } else { $env:ANDROID_HOME }
    if (-not $AndroidSdk) { $AndroidSdk = $env:ANDROID_SDK_ROOT }
}
if (-not $JavaHome -or -not (Test-Path -LiteralPath (Join-Path $JavaHome 'bin/java.exe'))) {
    throw 'Supply -JavaHome with a Java 17 JDK directory, or set JAVA_HOME.'
}
if (-not $AndroidSdk -or -not (Test-Path -LiteralPath (Join-Path $AndroidSdk 'platforms/android-35/android.jar'))) {
    throw 'Supply -AndroidSdk with an SDK containing Android platform 35.'
}

# Keep environment changes local to this invocation and preserve the caller's directory.
$previousJava = $env:JAVA_HOME
$previousSdk = $env:ANDROID_HOME
$previousSdkRoot = $env:ANDROID_SDK_ROOT
$previousGradle = $env:GRADLE_USER_HOME
Push-Location -LiteralPath $baselineRoot
try {
    $env:JAVA_HOME = $JavaHome
    $env:ANDROID_HOME = $AndroidSdk
    $env:ANDROID_SDK_ROOT = $AndroidSdk
    $env:GRADLE_USER_HOME = Join-Path $baselineRoot '.gradle/user-home'
    & (Join-Path $JavaHome 'bin/java.exe') -version
    & .\gradlew.bat "test${Variant}UnitTest" "assemble${Variant}" --console=plain --stacktrace
    if ($LASTEXITCODE -ne 0) { throw "Baseline checks failed (exit $LASTEXITCODE)." }
} finally {
    $env:JAVA_HOME = $previousJava
    $env:ANDROID_HOME = $previousSdk
    $env:ANDROID_SDK_ROOT = $previousSdkRoot
    $env:GRADLE_USER_HOME = $previousGradle
    Pop-Location
}
