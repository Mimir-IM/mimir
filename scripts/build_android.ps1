# build_android.ps1 — Build mimir as an Android shared library for all ABIs
# and generate UniFFI Kotlin bindings.
#
# Prerequisites (run once):
#   rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
#   cargo install cargo-ndk
#   Install Android NDK via Android Studio → SDK Manager → NDK (Side by side)
#
# Usage:
#   .\scripts\build_android.ps1
#
# Outputs:
#   jniLibs/arm64-v8a/libmimir.so
#   jniLibs/armeabi-v7a/libmimir.so
#   jniLibs/x86/libmimir.so
#   jniLibs/x86_64/libmimir.so
#   kotlin-bindings/uniffi/mimir/mimir.kt

param(
    [string]$NdkVersion = "",          # Override NDK version (auto-detected if empty)
    [string]$ApiLevel = "23",          # Minimum Android API level
    [switch]$Debug = $false            # Build debug instead of release
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot | Split-Path    # workspace root (parent of scripts/)

# ── Auto-detect NDK ──────────────────────────────────────────────────────────

$SdkRoot = $env:ANDROID_HOME
if (-not $SdkRoot) {
    $SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
}

$NdkRoot = $env:ANDROID_NDK_HOME
if (-not $NdkRoot) {
    $NdkDir = Join-Path $SdkRoot "ndk"
    if ($NdkVersion) {
        $NdkRoot = Join-Path $NdkDir $NdkVersion
    } else {
        # Pick the highest installed NDK version
        $installed = Get-ChildItem $NdkDir -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($installed) {
            $NdkRoot = $installed.FullName
        }
    }
}

if (-not $NdkRoot -or -not (Test-Path $NdkRoot)) {
    Write-Error "Android NDK not found. Set ANDROID_NDK_HOME or install via Android Studio SDK Manager."
}
Write-Host "Using NDK: $NdkRoot"
$env:ANDROID_NDK_HOME = $NdkRoot

# ── Targets ──────────────────────────────────────────────────────────────────

$Targets = @(
    @{ Triple = "aarch64-linux-android";   Abi = "arm64-v8a"    },
    @{ Triple = "armv7-linux-androideabi"; Abi = "armeabi-v7a"  },
    @{ Triple = "i686-linux-android";     Abi = "x86"          },
    @{ Triple = "x86_64-linux-android";   Abi = "x86_64"       }
)

$BuildMode = if ($Debug) { "" } else { "--release" }
$ProfileDir = if ($Debug) { "debug" } else { "release" }
$OutRoot = Join-Path $Root "jniLibs"

# ── Build all ABIs ────────────────────────────────────────────────────────────

foreach ($t in $Targets) {
    Write-Host ""
    Write-Host "=== Building for $($t.Triple) ===" -ForegroundColor Cyan

    $jniDir = Join-Path $OutRoot $t.Abi
    New-Item -ItemType Directory -Force $jniDir | Out-Null

    $args = @(
        "ndk",
        "--target", $t.Triple,
        "--platform", $ApiLevel,
        "-o", $OutRoot,
        "build",
        "--package", "mimir"
    )
    if (-not $Debug) { $args += "--release" }

    & cargo @args
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed for $($t.Triple)"
    }

    Write-Host "Built: $jniDir\libmimir.so" -ForegroundColor Green
}

# ── Generate Kotlin bindings ──────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Generating UniFFI Kotlin bindings ===" -ForegroundColor Cyan

# Build the native Windows DLL first so uniffi-bindgen can read its metadata.
# (uniffi-bindgen cannot parse cross-compiled ELF binaries on Windows.)
Write-Host "Building native Windows DLL for binding generation..."
Push-Location $Root
try {
    & cargo build -p mimir --lib
    if ($LASTEXITCODE -ne 0) { Write-Error "Native lib build failed" }
} finally {
    Pop-Location
}

$RefLib = Join-Path $Root "target\debug\mimir.dll"
if (-not (Test-Path $RefLib)) {
    Write-Error "Native DLL not found: $RefLib"
}

$BindingsDir = Join-Path $Root "kotlin-bindings"
New-Item -ItemType Directory -Force $BindingsDir | Out-Null

Push-Location $Root
try {
    & cargo run --bin uniffi-bindgen -- generate `
        --library $RefLib `
        --language kotlin `
        --out-dir $BindingsDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "uniffi-bindgen failed"
    }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "=== Build complete ===" -ForegroundColor Green
Write-Host "JNI libraries:"
foreach ($t in $Targets) {
    $so = Join-Path $OutRoot "$($t.Abi)\libmimir.so"
    if (Test-Path $so) {
        $size = (Get-Item $so).Length / 1MB
        Write-Host "  $so  ($([math]::Round($size, 1)) MB)"
    }
}
Write-Host ""
Write-Host "Kotlin bindings:"
Get-ChildItem $BindingsDir -Recurse -Filter "*.kt" | ForEach-Object {
    Write-Host "  $($_.FullName)"
}
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Copy jniLibs/ to Android-ng/app/src/main/jniLibs/ in the Android project"
Write-Host "  2. Copy kotlin-bindings/uniffi/mimir/mimir.kt to Android-ng/app/src/main/java/uniffi/mimir/"
Write-Host "  3. Ensure 'implementation `"net.java.dev.jna:jna:5.18.1@aar`"' is in app/build.gradle"
