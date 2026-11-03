<#
.SYNOPSIS
  Builds the engine for Windows ARM64 and proves the result is an ARM64 PE,
  without claiming anything about running it.

.DESCRIPTION
  The ARM64 leg is D-003 and this script is its engine half: `cargo build --release
  --target aarch64-pc-windows-msvc` (and, with -WithTests, the test binaries too),
  then `verify-hardening.ps1 -Arch arm64` reads the PE back and refuses anything
  that is not a CFG-instrumented, ASLR/DEP-marked, stripped ARM64 image.

  **No ARM64 machine exists here, so nothing this produces has ever been run.**
  The evidence is compile-time and static: cargo finished, the PE machine field is
  `0xAA64`, and the hardening bits are present. Not one runtime behaviour is
  claimed, and no probe result is copied over from the x64 run.

  Three toolchain pieces are needed, and this machine has them in unusual places
  (measured 2026-11-03), so the script resolves each one and says where it found
  it instead of depending on a developer's PATH:

    * the **MSVC ARM64 build tools** (cl.exe/link.exe for the target and the ARM64
      CRT) - from the newest Visual Studio that has them, located by vswhere. The
      Build Tools 2022 on this machine do *not* have them; Visual Studio 18 does;
    * a **C compiler for the target** - `ring` assembles code with clang, and no
      standalone clang is installed. Any clang on PATH wins; otherwise the LLVM
      inside the Android NDK is used (clang 19, full AArch64 backend, `llvm-lib`
      for the archive step), which is a build-time tool only - none of its code is
      in the output;
    * the **Windows SDK's ARM64 import libraries** (kernel32, ucrt), which the
      default SDK install already carries.

  Overrides, if a machine has the better pieces: `CC_aarch64_pc_windows_msvc`,
  `AR_aarch64_pc_windows_msvc`, `CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER`.
  `INCLUDE`/`LIB` are set here from the toolset that was found, because clang in
  MSVC mode reads them the way cl.exe does.

  This script does not package anything. `scripts\make-release.ps1 -Arch arm64`
  does that, and it refuses on this machine because the Flutter half has no
  Windows ARM64 output here (no cross-compile flag, and the SDK's cache holds
  only `windows-x64*`) - so a *portable package* for ARM64 still needs an ARM64
  host, while its engine can be built and checked anywhere this script succeeds.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build-engine-arm64.ps1
  powershell -ExecutionPolicy Bypass -File scripts\build-engine-arm64.ps1 -WithTests

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9).
#>
param(
  # Also compile the test binaries (`cargo test --no-run`) - more of the tree is
  # type-checked and linked, still nothing is executed.
  [switch]$WithTests,
  # Where cargo writes. The x64 default (`engine\target`) is shared with the
  # normal build, so a cross build gets its own directory.
  [string]$CargoTargetDir = "",
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$triple = "aarch64-pc-windows-msvc"
if (-not $CargoTargetDir) { $CargoTargetDir = Join-Path $env:TEMP "mics-target-arm64" }

$failures = New-Object System.Collections.Generic.List[string]

# 1) The MSVC toolset for the target. Newest install that has it wins; an
#    installation without the ARM64 component is skipped rather than guessed at.
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found - Visual Studio (or its Build Tools) is required" }
$installations = @(& $vswhere -all -products * -property installationPath 2>$null |
  Where-Object { $_ } | ForEach-Object { $_.Trim() })
$toolset = $null
$install = $null
foreach ($path in $installations) {
  foreach ($candidate in @(Get-ChildItem (Join-Path $path "VC\Tools\MSVC") -Directory -ErrorAction SilentlyContinue |
      Sort-Object Name -Descending)) {
    if (Test-Path (Join-Path $candidate.FullName "bin\Hostx64\arm64\cl.exe")) {
      $toolset = $candidate.FullName
      $install = $path
      break
    }
  }
  if ($toolset) { break }
}
if (-not $toolset) {
  throw "no Visual Studio installation has the MSVC ARM64 build tools ('MSVC v143 - VS 2022 C++ ARM64 build tools' component)"
}
Write-Output "toolset : $toolset"

# 2) A C compiler for the target: ring's assembly needs clang.
$cc = [Environment]::GetEnvironmentVariable("CC_aarch64_pc_windows_msvc")
if (-not $cc) { $cc = (Get-Command clang.exe -ErrorAction SilentlyContinue).Source }
if (-not $cc) {
  # The Android NDK ships a full LLVM; it is a build-time tool, not a dependency.
  $ndkRoot = Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk"
  $ndk = @(Get-ChildItem $ndkRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending) | Select-Object -First 1
  if ($ndk) {
    $candidate = Join-Path $ndk.FullName "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
    if (Test-Path $candidate) { $cc = $candidate }
  }
}
if (-not $cc -or -not (Test-Path $cc)) {
  throw "no clang for $triple - install the LLVM component in Visual Studio, install LLVM, or set CC_aarch64_pc_windows_msvc"
}
Write-Output "clang   : $cc"
$ar = [Environment]::GetEnvironmentVariable("AR_aarch64_pc_windows_msvc")
if (-not $ar) {
  $sibling = Join-Path (Split-Path $cc -Parent) "llvm-lib.exe"
  if (Test-Path $sibling) { $ar = $sibling } else { $ar = Join-Path $toolset "bin\Hostx64\arm64\lib.exe" }
}
Write-Output "archiver: $ar"

$linker = [Environment]::GetEnvironmentVariable("CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER")
if (-not $linker) { $linker = Join-Path $toolset "bin\Hostx64\arm64\link.exe" }
if (-not (Test-Path $linker)) { throw "the ARM64 linker is missing from the toolset: $linker" }
Write-Output "linker  : $linker"

# 3) The Windows SDK's ARM64 libs. INCLUDE/LIB are what clang in MSVC mode and
#    link.exe read; cc-rs does not set them for an explicitly named compiler.
$sdkRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
$sdkVer = @(Get-ChildItem (Join-Path $sdkRoot "Lib") -Directory -ErrorAction SilentlyContinue |
  Where-Object { Test-Path (Join-Path $_.FullName "um\arm64\kernel32.lib") } |
  Sort-Object Name -Descending) | Select-Object -First 1
if (-not $sdkVer) { throw "no Windows SDK version has arm64 import libraries under $sdkRoot\Lib" }
Write-Output "sdk     : $($sdkVer.Name)"
# Include and Lib are two trees side by side (`<root>\Include\<version>` and
# `<root>\Lib\<version>`), so the version folder is not a prefix for both.
$sdkInclude = Join-Path $sdkRoot "Include\$($sdkVer.Name)"
$sdkLib = Join-Path $sdkRoot "Lib\$($sdkVer.Name)"

$env:CC_aarch64_pc_windows_msvc = $cc
$env:AR_aarch64_pc_windows_msvc = $ar
$env:CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER = $linker
$env:INCLUDE = @(
  (Join-Path $toolset "include"),
  (Join-Path $sdkInclude "ucrt"),
  (Join-Path $sdkInclude "shared"),
  (Join-Path $sdkInclude "um"),
  (Join-Path $sdkInclude "winrt")
) -join ";"
$env:LIB = @(
  (Join-Path $toolset "lib\arm64"),
  (Join-Path $sdkLib "ucrt\arm64"),
  (Join-Path $sdkLib "um\arm64")
) -join ";"
$env:YRX_REGENERATE_MODULES_RS = "false"
$env:CARGO_TARGET_DIR = $CargoTargetDir

$engine = Join-Path $CargoTargetDir "$triple\release\mics-engine.exe"

if (-not $SkipBuild) {
  Push-Location (Join-Path $repo "engine")
  try {
    . (Join-Path $PSScriptRoot "engine-rustflags.ps1")
    $env:CARGO_ENCODED_RUSTFLAGS = Get-EngineRustFlags -Repo $repo -Target $triple
    # The same flags the shipped x64 engine carries: CFG (D-021) and the path
    # remap that keeps the build account out of the binary (ط1).
    Write-Output "building: cargo build --release --target $triple"
    & cargo build --release --target $triple
    $buildExit = $LASTEXITCODE
    if ($buildExit -eq 0 -and $WithTests) {
      Write-Output "compiling: cargo test --release --no-run --target $triple (built, never run)"
      & cargo test --release --no-run --target $triple
      $testExit = $LASTEXITCODE
    } else { $testExit = $buildExit }
  } finally { Pop-Location }
  if ($buildExit -ne 0) {
    Write-Output "RESULT: FAIL - the ARM64 engine did not build (cargo exit $buildExit)"
    exit 1
  }
  if ($testExit -ne 0) {
    Write-Output "RESULT: FAIL - the ARM64 test binaries did not compile (cargo exit $testExit)"
    exit 1
  }
}

if (-not (Test-Path $engine)) {
  Write-Output "RESULT: FAIL - no ARM64 engine at $engine"
  exit 1
}
$info = Get-Item $engine
Write-Output ("engine  : {0} ({1:N0} bytes)" -f $engine, $info.Length)
Write-Output ("sha256  : {0}" -f (Get-FileHash $engine -Algorithm SHA256).Hash.ToLower())

# The fact that matters: an ARM64 image with the hardening bits, read out of the
# file. A compile that linked an x64 binary by mistake fails here.
$checkOut = Join-Path $env:TEMP "mics-arm64-hardening.out"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-hardening.ps1") `
  -Path $engine -Arch arm64 > $checkOut 2>&1
$checkExit = $LASTEXITCODE
Get-Content $checkOut | Where-Object { $_ -match "machine|DllCharacteristics|GuardFlags|RESULT|^  - " } |
  ForEach-Object { "  $_" }
Remove-Item $checkOut -ErrorAction SilentlyContinue
if ($checkExit -ne 0) {
  Write-Output "RESULT: FAIL - the ARM64 binary is not the hardened ARM64 image the release claims"
  exit 1
}

Write-Output "RESULT: PASS - the engine compiled and linked for $triple as a stripped, CFG-instrumented ARM64 PE"
Write-Output "note   : no ARM64 hardware here - this binary was never executed; the claim is build-time only"
exit 0