<#
.SYNOPSIS
  Assembles the portable release folder, zips it and writes SHA256SUMS.

.DESCRIPTION
  `dist\MICS-portable` is what users copy and run, so it has to be built from the
  current binaries in one step instead of being patched by hand. This script:

    1. checks that the committed third-party inventory (`sbom.cdx.json` and
       `THIRD-PARTY-NOTICES`) still describes the lockfiles, and ships both;
    2. copies the Flutter release output (`build\windows\x64\runner\Release`) into
       `dist\MICS-portable`;
    3. copies `engine\rules` next to the binaries - the guard and YARA packs are
       hot-reloaded from there, and a package without them silently falls back to
       the compiled-in starter pack;
    4. refuses to continue if any required file is missing, so a half-built folder
       is never published - and refuses an app that was not built obfuscated or
       binaries whose PE is not hardened (`verify-hardening.ps1`, g1/D-021);
    5. signs the staged binaries when asked - the engine last, because its
       signature has to cover the package manifest - builds that manifest from the
       final bytes, injects it into `mics-engine.exe` as the `MICS_MANIFEST`
       resource, signs the engine, and proves the staged package is the one its
       manifest describes (`verify-manifest.ps1`, c2/D-025). It then proves the same
       gate refuses a tampered copy and that the engine reports the tamper
       (`verify-tamper.ps1`, t2): a flipped byte per shipped binary, a same-size
       swapped DLL, an edited manifest, the manifest in an unsigned engine;
    6. writes `VERSION` (version, build time, engine hash, rule count, what was
       hardened);
    7. zips the folder to `dist\MICS-portable-<version>-<arch>.zip`;
    8. writes `dist\SHA256SUMS` for the zip, the engine, the app, the rules and the
       inventory.

  `-Arch x64` (the default) is the leg that ships today. `-Arch arm64` is wired
  end to end - the engine is built with `--target aarch64-pc-windows-msvc`, the
  Flutter output is read from `build\windows\arm64\runner\<Configuration>`, and the
  zip, `VERSION` and `SHA256SUMS` carry the arch - but it needs a toolchain this
  machine does not have, so it checks first and refuses with the list instead of
  failing somewhere inside cargo (`-CheckToolchain` prints that list and stops
  there). There is no ARM64 hardware here, so nothing it would produce is runnable
  here even after a successful build: the claim is "built", never "verified on
  ARM64" (D-003).

  The Dart symbol table produced by `--obfuscate` goes to
  `dist\symbols\<version>\` and is never part of the package: it maps `app.so`
  back to the source. `dist\MICS-portable` is swapped in after the zip is written,
  by renaming the old folder aside rather than deleting it in place, so a copy
  someone is running is left whole instead of half-deleted.

  Nothing here needs elevation.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1
  powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1 -Version 0.1.0 -SkipBuild
  powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1 -Arch arm64 -CheckToolchain

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9).
#>
param(
  [string]$Version = "",
  [string]$Configuration = "Release",
  [string]$EnginePath = "",
  [switch]$SkipBuild,
  # Sign the staged binaries before they are hashed and zipped. Without -PfxPath
  # this uses a self-signed certificate trusted on this machine (fine for local
  # testing, no reputation for downloads); with -PfxPath it uses a real one.
  [switch]$Sign,
  [string]$PfxPath = "",
  [string]$PfxPassword = "",
  # Which architecture to package (D-003). The default is the leg that ships.
  [ValidateSet("x64", "arm64")]
  [string]$Arch = "x64",
  # Report what the ARM64 leg needs and stop, instead of trying to build it.
  [switch]$CheckToolchain
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
# The target triple and the folder Flutter uses are two different names for the
# same choice: cargo calls it x86_64/aarch64, Flutter names its build folder after
# the host architecture.
$triple = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
$buildDir = Join-Path $root "build\windows\$Arch\runner\$Configuration"
$portable = Join-Path $root "dist\MICS-portable"
$rulesSrc = Join-Path $root "engine\rules"
$flutterArchDir = Join-Path $root "build\windows\$Arch"

# What an ARM64 build needs, read off the disk instead of assumed. `ring` compiles
# assembly with clang for `aarch64-pc-windows-msvc`, and the MSVC ARM64 toolset
# provides the CRT and the linker: without both, cargo stops inside a build script
# with a message about a missing tool, which says nothing about what to install.
# Checking first turns that into a list. Measured on this machine 2026-11-03: the
# first three rows are missing, the SDK libs and the Rust target are present, and
# the Flutter SDK has no windows-arm64 artifacts at all (only windows-x64*), so an
# ARM64 app also needs an ARM64 host and its own SDK download.
function Test-Arm64Prerequisites {
  $rows = New-Object System.Collections.Generic.List[object]

  $rustlib = (& rustc --print sysroot 2>$null)
  $targetStd = if ($rustlib) { Join-Path $rustlib "lib\rustlib\$triple\lib" } else { "" }
  $rows.Add([pscustomobject]@{
    Name = "rust target $triple"
    Ok = [bool]($targetStd -and (Test-Path $targetStd))
    Detail = if ($targetStd -and (Test-Path $targetStd)) { $targetStd } else { "run: rustup target add $triple" }
  })

  # vswhere knows where the C++ tools are even when `cl.exe` is not on PATH.
  $vs = ""
  $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path $vswhere) {
    $found = & $vswhere -latest -products * -property installationPath 2>$null
    if ($found) { $vs = ($found | Select-Object -First 1).Trim() }
  }
  $toolsets = if ($vs) { @(Get-ChildItem (Join-Path $vs "VC\Tools\MSVC") -Directory -ErrorAction SilentlyContinue) } else { @() }
  $toolset = $toolsets | Select-Object -Last 1

  $arm64Cl = if ($toolset) { Join-Path $toolset.FullName "bin\Hostx64\arm64\cl.exe" } else { "" }
  $rows.Add([pscustomobject]@{
    Name = "MSVC ARM64 build tools"
    Ok = [bool]($arm64Cl -and (Test-Path $arm64Cl))
    Detail = if ($arm64Cl -and (Test-Path $arm64Cl)) { $arm64Cl }
             else { "install the 'MSVC v143 - VS 2022 C++ ARM64 build tools' component" }
  })

  $arm64Crt = if ($toolset) { Join-Path $toolset.FullName "lib\arm64\libcmt.lib" } else { "" }
  $rows.Add([pscustomobject]@{
    Name = "MSVC ARM64 CRT libs"
    Ok = [bool]($arm64Crt -and (Test-Path $arm64Crt))
    Detail = if ($arm64Crt -and (Test-Path $arm64Crt)) { Split-Path $arm64Crt -Parent } else { "comes with the same component" }
  })

  # clang: ring's assembly, or an explicit CC for the target. Same order as
  # `build-engine-arm64.ps1`, so this check and that build agree on what they find.
  $ccOverride = [Environment]::GetEnvironmentVariable("CC_aarch64_pc_windows_msvc")
  $clang = (Get-Command clang.exe -ErrorAction SilentlyContinue).Source
  if (-not $clang) {
    # The Android NDK ships a full LLVM (clang 19, AArch64 backend, llvm-lib). It
    # is a build-time tool: none of its code is in the output.
    $ndk = @(Get-ChildItem (Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk") -Directory -ErrorAction SilentlyContinue |
      Sort-Object Name -Descending) | Select-Object -First 1
    if ($ndk) {
      $candidate = Join-Path $ndk.FullName "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
      if (Test-Path $candidate) { $clang = $candidate }
    }
  }
  if (-not $clang -and $vs) {
    foreach ($p in @("VC\Tools\Llvm\x64\bin\clang.exe", "VC\Tools\Llvm\bin\clang.exe")) {
      $candidate = Join-Path $vs $p
      if (Test-Path $candidate) { $clang = $candidate; break }
    }
  }
  if (-not $clang -and (Test-Path "${env:ProgramFiles}\LLVM\bin\clang.exe")) { $clang = "${env:ProgramFiles}\LLVM\bin\clang.exe" }
  $rows.Add([pscustomobject]@{
    Name = "clang (ring's assembly)"
    Ok = [bool]($ccOverride -or $clang)
    Detail = if ($ccOverride) { "CC_aarch64_pc_windows_msvc=$ccOverride" }
             elseif ($clang) { $clang }
             else { "install the LLVM/clang component, or set CC_aarch64_pc_windows_msvc" }
  })

  $sdkLib = ""
  foreach ($kits in @("${env:ProgramFiles(x86)}\Windows Kits\10\Lib")) {
    $ver = Get-ChildItem $kits -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if ($ver -and (Test-Path (Join-Path $ver.FullName "um\arm64\kernel32.lib"))) { $sdkLib = (Join-Path $ver.FullName "um\arm64") }
  }
  $rows.Add([pscustomobject]@{
    Name = "Windows SDK arm64 libs"
    Ok = [bool]$sdkLib
    Detail = if ($sdkLib) { $sdkLib } else { "add the SDK's ARM64 libraries" }
  })

  $flutterRoot = ""
  $flutterCmd = Get-Command flutter.bat -ErrorAction SilentlyContinue
  if ($flutterCmd) { $flutterRoot = Split-Path (Split-Path $flutterCmd.Source -Parent) -Parent }
  $flutterArm = if ($flutterRoot) { Join-Path $flutterRoot "bin\cache\artifacts\engine\windows-arm64" } else { "" }
  $rows.Add([pscustomobject]@{
    Name = "Flutter windows-arm64 engine"
    Ok = [bool]($flutterArm -and (Test-Path $flutterArm))
    Detail = if ($flutterArm -and (Test-Path $flutterArm)) { $flutterArm } else { "downloaded on an ARM64 host; this SDK has windows-x64* only" }
  })

  $rows.Add([pscustomobject]@{
    Name = "ARM64 host"
    Ok = ([Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") -eq "ARM64")
    Detail = "this host is $([Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")); Flutter has no Windows cross-compile flag"
  })

  return $rows
}

function Show-Toolchain([object[]]$rows, [ref]$Code) {
  Write-Output "ARM64 build prerequisites ($triple)"
  $width = ($rows | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
  foreach ($row in $rows) {
    $state = if ($row.Ok) { "present" } else { "MISSING" }
    Write-Output ("  {0,-12} {1}  {2}" -f $state, $row.Name.PadRight($width), $row.Detail)
  }
  $missing = @($rows | Where-Object { -not $_.Ok })
  if ($missing.Count -eq 0) {
    $Code.Value = 0
    Write-Output "RESULT: READY - this machine can produce and package the ARM64 leg"
    return
  }
  $Code.Value = 1
  Write-Output ("RESULT: NOT READY - {0} of {1} prerequisite(s) missing: {2}" -f `
    $missing.Count, $rows.Count, (($missing | ForEach-Object { $_.Name }) -join ", "))
}

# The exit code travels through a [ref]: this file's output stream is its report,
# so returning the code from a function that also writes the report would capture
# the report instead.
if ($CheckToolchain) {
  $toolchainCode = 1
  Show-Toolchain (Test-Arm64Prerequisites) ([ref]$toolchainCode)
  exit $toolchainCode
}
if ($Arch -eq "arm64") {
  $arm64Rows = Test-Arm64Prerequisites
  if (@($arm64Rows | Where-Object { -not $_.Ok }).Count -gt 0) {
    $toolchainCode = 1
    Show-Toolchain $arm64Rows ([ref]$toolchainCode)
    Write-Output "RESULT: FAIL - the ARM64 leg is wired but this machine cannot build it; nothing was packaged (use -CheckToolchain for the list alone)"
    exit 1
  }
}

if (-not $Version) {
  $cargo = Get-Content (Join-Path $root "engine\Cargo.toml") -Raw
  if ($cargo -match '(?m)^version\s*=\s*"([^"]+)"') { $Version = $Matches[1] }
  else { throw "cannot read the version from engine\Cargo.toml - pass -Version" }
}

# Where the Dart symbol table for this version lives - outside the package, see
# the obfuscation note where the app is built.
$symbolsDir = Join-Path $root "dist\symbols\$Version"

# The third-party inventory (sbom.cdx.json, THIRD-PARTY-NOTICES) is generated from
# the lockfiles and committed with them, so the package can never describe a
# dependency set that is no longer the one in the tree. Checked before building: a
# stale inventory should not cost a full build to discover. The tool's own
# `RESULT:` line is read as well as its exit code, because a `dart run` wrapper can
# swallow the code (`main` returning a number does not set it - the tool sets
# `exitCode` explicitly, and this check does not depend on that alone).
Write-Host "checking the third-party inventory..."
$sbomOut = Join-Path $env:TEMP "mics-sbom-check.out"
$stopPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
Push-Location $root
try {
  & dart run tool\sbom.dart --check > $sbomOut 2>&1
  $sbomExit = $LASTEXITCODE
} finally {
  Pop-Location
  $ErrorActionPreference = $stopPreference
}
# The tool's own words, including the first line that differs: `--check` prints
# "components differs at line N" with the committed and generated text, and dropping
# that line is what left "stale" as the only clue for two release runs.
Get-Content $sbomOut |
  Where-Object { $_ -match "RESULT|sbom:|stale|differs at line|committed:|generated:" } |
  ForEach-Object { "  $_" }
$sbomRaw = Get-Content $sbomOut -Raw
$sbomPassed = ($sbomExit -eq 0) -and ($sbomRaw -match "RESULT: PASS")
if (-not $sbomPassed) {
  # Two different failures wore one message: the files really are stale, and the check
  # never ran. On the runner the tool printed nothing at all (measured 2026-11-05, run
  # 41972021335: no `sbom:` line, no difference line, only this FAIL), and calling that
  # "stale" sends the reader to regenerate files that were already right.
  if ($sbomRaw -notmatch "RESULT:") {
    Write-Output "  the check did not report a result (exit $sbomExit); its output was:"
    Get-Content $sbomOut -ErrorAction SilentlyContinue | Select-Object -Last 25 | ForEach-Object { "  | $_" }
    Remove-Item $sbomOut -ErrorAction SilentlyContinue
    Write-Output "RESULT: FAIL - the third-party inventory check did not run on this machine (exit $sbomExit); nothing was packaged"
  } else {
    Write-Output "RESULT: FAIL - sbom.cdx.json or THIRD-PARTY-NOTICES is stale; run 'dart run tool\sbom.dart' and commit both"
  }
  exit 1
}
Remove-Item $sbomOut -ErrorAction SilentlyContinue

# The engine is built by cargo, not by Flutter, and it may live outside the repo
# (CARGO_TARGET_DIR). Find it explicitly so the package never ships a stale one.
# A cross build puts its output under the triple, so the subfolder follows -Arch.
$releaseSub = if ($Arch -eq "arm64") { "$triple\release" } else { "release" }
$EnginePathWasGiven = [bool]$EnginePath
if (-not $EnginePath) {
  $candidates = @(
    (Join-Path $root "engine\target\$releaseSub\mics-engine.exe"),
    (Join-Path $buildDir "mics-engine.exe")
  )
  if ($env:CARGO_TARGET_DIR) { $candidates = @((Join-Path $env:CARGO_TARGET_DIR "$releaseSub\mics-engine.exe")) + $candidates }
  foreach ($c in $candidates) { if (Test-Path $c) { $EnginePath = $c; break } }
}
if ($EnginePath -and -not (Test-Path $EnginePath)) {
  Write-Output "RESULT: FAIL - the engine build at $EnginePath does not exist"
  exit 1
}
# A build is not required up front: step 4 below runs `cargo build --release` itself and
# then prefers the binary it just built. Demanding one here is what made this script
# unable to cut a release from a clean checkout - the exact thing the Release workflow
# does (measured 2026-11-05, run 41976679343: "no engine build found for x64" on a
# runner that had just fetched the crates and had not built anything yet).
if (-not $EnginePath -and $SkipBuild) {
  Write-Output "RESULT: FAIL - no engine build found for $Arch and -SkipBuild was given; run 'cargo build --release' in engine\ or pass -EnginePath"
  exit 1
}
if ($EnginePath) { $EnginePath = (Resolve-Path $EnginePath).Path }

if (-not $SkipBuild) {
  # Native builds write progress to stderr, and with ErrorActionPreference=Stop
  # PowerShell 5.1 turns a single stderr line into a terminating error. Let them
  # write freely and judge them by their exit code instead.
  $stopPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"

  # The Windows build needs nuget.exe: Flutter's plugins fetch NuGet packages at
  # configure time (audioplayers_windows needs Microsoft.Windows.ImplementationLibrary)
  # and CMake looks for the tool on PATH. A machine without it - or a tree that was
  # cleaned, so the plugin has to configure again - fails there with "Failed to
  # install nuget package", so make one available before asking for the build.
  if (-not (Get-Command nuget.exe -ErrorAction SilentlyContinue)) {
    $toolDir = Join-Path $env:TEMP "mics-tools"
    $nugetPath = Join-Path $toolDir "nuget.exe"
    if (-not (Test-Path $nugetPath)) {
      New-Item -ItemType Directory -Force -Path $toolDir | Out-Null
      Write-Host "fetching nuget.exe (the Windows build needs it)..."
      try {
        Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" `
          -OutFile $nugetPath -UseBasicParsing -TimeoutSec 120
      } catch {
        throw "nuget.exe is needed for the Windows build and could not be fetched: $($_.Exception.Message)"
      }
    }
    $env:PATH = "$toolDir;$env:PATH"
  }

  Write-Host "building the app ($Configuration) for $Arch..."
  # Flutter has no Windows cross-compile flag: the folder it writes is named after
  # the host architecture, so an ARM64 app is produced on an ARM64 host, and
  # `-Arch arm64` on an x64 one is refused earlier by the prerequisite check
  # rather than failing here.
  if (-not (Test-Path $flutterArchDir) -and $Arch -ne "x64") {
    throw "no Flutter output for $Arch at $flutterArchDir - build the app on an ARM64 host first"
  }
  # Dart obfuscation (g1, D-021): the Release AOT snapshot ships with its symbol
  # names replaced, and the symbol table that makes a stack trace readable is
  # written *outside* the package (`dist\symbols\<version>`), because it maps the
  # binary back to the source and is the one artifact that must never be
  # published. The engine is Rust and is stripped by its own release profile.
  New-Item -ItemType Directory -Force -Path $symbolsDir | Out-Null
  Push-Location $root
  try {
    & flutter build windows --release --obfuscate "--split-debug-info=$symbolsDir"
    if ($LASTEXITCODE -ne 0) { throw "flutter build windows failed ($LASTEXITCODE)" }
  } finally { Pop-Location }

  # The engine is cargo's, not Flutter's - build it here so "make a release" is one
  # command. It must carry its Windows version resource: that is what Task Manager
  # shows instead of the file name, so a package without it ships an engine that
  # appears as "mics-engine.exe".
  Write-Host "building the engine..."
  Push-Location (Join-Path $root "engine")
  try {
    $env:MICS_REQUIRE_VERSION_RESOURCE = "1"
    $env:YRX_REGENERATE_MODULES_RS = "false"
    # The shipped engine must not name this machine's user (docs/TODO.md, the
    # fingerprint slice): rustc records the source directory of every dependency,
    # which by default is `%USERPROFILE%\.cargo\registry\src\...`, so the release
    # binary carried the account name 1238 times. The remap rewrites that prefix
    # while compiling. It has to be *appended* to the crate's own flags, because
    # `CARGO_ENCODED_RUSTFLAGS` overrides `.cargo\config.toml` instead of adding
    # to it - setting the remap alone cost the engine its CFG table, which the
    # hardening gate below refused on 2026-11-02 (`engine-rustflags.ps1` reads the
    # config, so it stays the one place the flags are written down).
    . (Join-Path $PSScriptRoot "engine-rustflags.ps1")
    $env:CARGO_ENCODED_RUSTFLAGS = Get-EngineRustFlags -Repo $root -Target $triple
    if ($Arch -eq "arm64") { & cargo build --release --target $triple } else { & cargo build --release }
    $cargoExit = $LASTEXITCODE
  } finally {
    Pop-Location
    $ErrorActionPreference = $stopPreference
  }
  if ($cargoExit -ne 0) { throw "cargo build --release failed ($cargoExit)" }

  # Prefer the binary we just built over whatever the earlier lookup found.
  if (-not $EnginePathWasGiven) {
    $fresh = @()
    if ($env:CARGO_TARGET_DIR) { $fresh += (Join-Path $env:CARGO_TARGET_DIR "$releaseSub\mics-engine.exe") }
    $fresh += (Join-Path $root "engine\target\$releaseSub\mics-engine.exe")
    foreach ($c in $fresh) { if (Test-Path $c) { $EnginePath = (Resolve-Path $c).Path; break } }
    if (-not $EnginePath -or -not (Test-Path $EnginePath)) {
      Write-Output "RESULT: FAIL - cargo reported success but no mics-engine.exe is under engine\target\$releaseSub (set CARGO_TARGET_DIR or pass -EnginePath)"
      exit 1
    }
  }
}

if (-not (Test-Path $buildDir)) { throw "no build output at $buildDir - build first or drop -SkipBuild" }

# Required in the package: the app, the engine, Flutter's runtime, the asset
# bundle, both rule packs (missing rules = silently fewer detections) and the
# third-party inventory the SBOM/notices pair makes up.
$required = @(
  "mics_app.exe",
  "mics-engine.exe",
  "flutter_windows.dll",
  "data\app.so",
  "data\icudtl.dat",
  "data\flutter_assets\AssetManifest.bin",
  "rules\yara\starter.yar",
  "rules\guard\starter.json",
  "sbom.cdx.json",
  "THIRD-PARTY-NOTICES"
)

# Assemble into a staging folder first. The live `dist\MICS-portable` may be the
# copy someone is running right now: deleting it in place is how the first version
# of this script left a half-empty folder behind (the cleanup died on a DLL that
# the running app had loaded). Build, check and zip from staging, then swap.
$staging = Join-Path $root "dist\MICS-portable.staging"
Write-Host "assembling $staging ..."
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item (Join-Path $buildDir "*") $staging -Recurse -Force
Copy-Item $rulesSrc (Join-Path $staging "rules") -Recurse -Force
# The one file that comes from cargo rather than from the Flutter build.
Copy-Item $EnginePath (Join-Path $staging "mics-engine.exe") -Force
Copy-Item $EnginePath (Join-Path $buildDir "mics-engine.exe") -Force
# What is inside the package, in machine-readable and human-readable form. These
# are the committed copies, which --check above just proved describe this tree.
Copy-Item (Join-Path $root "sbom.cdx.json") $staging -Force
Copy-Item (Join-Path $root "THIRD-PARTY-NOTICES") $staging -Force
Write-Host ("engine   : {0}" -f $EnginePath)

$missing = @()
foreach ($rel in $required) {
  if (-not (Test-Path (Join-Path $staging $rel))) { $missing += $rel }
}
if ($missing.Count -gt 0) {
  Write-Output "RESULT: FAIL - the package is incomplete:"
  foreach ($m in $missing) { Write-Output "  missing: $m" }
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  exit 1
}

# The app has to be obfuscated, and Flutter writes that symbol table only for the
# build it just made. A `-SkipBuild` run with no symbols for this version is a
# package assembled from some other build, and shipping it would mean publishing a
# readable app.so as a release.
$symbols = @(Get-ChildItem $symbolsDir -Filter "*.symbols" -ErrorAction SilentlyContinue)
if ($symbols.Count -eq 0) {
  Write-Output "RESULT: FAIL - no Dart symbol table under $symbolsDir"
  Write-Output "  the app was not built with --obfuscate; run this script without -SkipBuild"
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  exit 1
}

# The build flags are a claim; the PE is the fact. An unhardened binary is not
# packaged at all, the same way an incomplete one is not.
Write-Host "checking the staged binaries are hardened..."
$stopPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-hardening.ps1") -Path $staging -Arch $Arch
  $hardeningExit = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $stopPreference
}
if ($hardeningExit -ne 0) {
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  Write-Output "RESULT: FAIL - the staged binaries are not hardened; nothing was published"
  exit 1
}

# The build flags are one claim and the remap is another: this reads the staged
# bytes and fails if they name the account that built them, or if a counted
# fingerprint grew past `qa\opsec-baseline.json`.
Write-Host "checking the staged binaries carry no build fingerprint..."
$stopPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-opsec.ps1") -Path $staging
  $opsecExit = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $stopPreference
}
if ($opsecExit -ne 0) {
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  Write-Output "RESULT: FAIL - the staged files carry a build fingerprint; nothing was published"
  exit 1
}

$signArgs = @()
if ($Sign -or $PfxPath) {
  # The engine is left out of this pass on purpose: its signature has to cover the
  # manifest resource, and Windows' resource API cannot rewrite an already-signed
  # PE - the file keeps a certificate table that no longer matches its layout, and
  # signtool then refuses it (0x800700C1, measured 2026-11-03). So the engine is
  # signed once, after the injection below.
  Write-Host "signing the staged binaries (the engine waits for its manifest)..."
  if ($PfxPath) { $signArgs = @("-PfxPath", (Resolve-Path $PfxPath).Path, "-PfxPassword", $PfxPassword) }
  else { $signArgs = @("-SelfSigned") }
  $stopPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "sign.ps1") `
      @signArgs -BuildDir $staging -Except "mics-engine.exe"
    $signExit = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $stopPreference
  }
  if ($signExit -ne 0) {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "RESULT: FAIL - signing failed; nothing was published"
    exit 1
  }
}

# ------------------------------------------------- the package's own manifest
# Every shipped file, described by the package itself (c2, D-025). The document is
# built from the bytes as they are now - after signing, so the hashes cover the
# signatures - and injected into the staged engine as the MICS_MANIFEST resource.
# The engine is not in its own manifest: its integrity is its signature, which
# `platform\windows\signature.rs` pins to the release certificate's common name.
# Writing a resource rewrites the PE, so the engine is signed right after; then the
# resource is read back out of the staged package and every file it lists is
# re-hashed, so a package that does not describe itself never leaves here.
. (Join-Path $PSScriptRoot "manifest-resource.ps1")
Write-Host "building the package manifest..."
$manifestFiles = Get-MicsManifestFiles -Path $staging
$manifestJson = New-MicsManifestJson -Files $manifestFiles -Version $Version
Write-MicsManifestResource -Exe (Join-Path $staging "mics-engine.exe") -Json $manifestJson
Write-Host ("  manifest : format 1, {0} file(s), {1} byte(s), in mics-engine.exe as MICS_MANIFEST" -f $manifestFiles.Count, $manifestJson.Length)

if ($Sign -or $PfxPath) {
  Write-Host "signing the engine (its signature covers the injected manifest)..."
  $stopPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "sign.ps1") `
      @signArgs -BuildDir $staging -Only "mics-engine.exe"
    $resignExit = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $stopPreference
  }
  if ($resignExit -ne 0) {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "RESULT: FAIL - signing the engine after the manifest injection failed; nothing was published"
    exit 1
  }
}

# The manifest names `data\flutter_assets\...` and `dartjni.dll`, so the engine's
# counted strings rise by exactly those names. The probe above ran where D-025
# records the order (before signing); this second call reads the bytes the
# manifest just changed, so a package the release tier would refuse cannot be
# staged here either. `qa\opsec-baseline.json` carries the written reason.
Write-Host "re-checking the staged binaries after the manifest injection..."
$stopPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-opsec.ps1") -Path $staging
  $opsecFinalExit = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $stopPreference
}
if ($opsecFinalExit -ne 0) {
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  Write-Output "RESULT: FAIL - the manifest changed the staged fingerprints and the baseline does not allow it"
  exit 1
}

Write-Host "verifying the package's manifest describes the package..."
$stopPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-manifest.ps1") -Path $staging
  $manifestExit = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $stopPreference
}
if ($manifestExit -ne 0) {
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  Write-Output "RESULT: FAIL - the staged package does not match its own manifest; nothing was published"
  exit 1
}

# The gate above proves the package is the published one; this proves it *refuses*
# a package that is not, and that the engine says so too (t2). It works on copies
# under %TEMP%, so the staging folder is untouched.
Write-Host "verifying that a tampered copy is refused and reported..."
$stopPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-tamper.ps1") -Path $staging
  $tamperExit = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $stopPreference
}
if ($tamperExit -ne 0) {
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
  Write-Output "RESULT: FAIL - a tampered copy was not refused or not reported; nothing was published"
  exit 1
}

$engine = Join-Path $staging "mics-engine.exe"
$app = Join-Path $staging "mics_app.exe"
$engineHash = (Get-FileHash $engine -Algorithm SHA256).Hash
$appHash = (Get-FileHash $app -Algorithm SHA256).Hash
$ruleCount = (Get-ChildItem (Join-Path $staging "rules") -Recurse -File).Count
# Say it out loud rather than let the first launch surprise anyone: an unsigned exe
# makes Windows show "Unknown publisher", and SmartScreen cannot vouch for a
# brand-new binary. Signing is the real fix (see docs/TODO.md, P4); the hashes above
# are taken after signing, so the zip and SHA256SUMS describe the signed files.
$signature = (Get-AuthenticodeSignature $app).Status
$signer = (Get-AuthenticodeSignature $app).SignerCertificate.Subject
# What Task Manager calls the engine. Empty means the version resource did not get
# embedded, and the engine will appear under its file name instead.
$engineName = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(
  (Join-Path $staging "mics-engine.exe")).FileDescription
if (-not $engineName) { $engineName = "(none - Task Manager will show mics-engine.exe)" }
$built = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")

$versionFile = Join-Path $staging "VERSION"
@(
  "MI CS $Version (portable, $Arch)",
  "built   $built",
  "engine  $engineHash",
  "app     $appHash",
  "rules   $ruleCount file(s) hot-reloaded from rules\",
  "hardened CFG + ASLR/DEP, engine LTO and stripped, app obfuscated (symbols not shipped)"
) | Set-Content -Path $versionFile -Encoding ASCII

$zip = Join-Path $root ("dist\MICS-portable-$Version-$Arch.zip")
if (Test-Path $zip) { Remove-Item $zip -Force }
Write-Host "zipping $zip ..."
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zip -CompressionLevel Optimal

$sums = Join-Path $root "dist\SHA256SUMS"
$lines = @()
# Every path is relative to this file (dist\), so `sha256sum -c SHA256SUMS` or a
# loop over Get-FileHash works without guessing where a file lives.
$lines += "$((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower())  MICS-portable-$Version-$Arch.zip"
$lines += "$($engineHash.ToLower())  MICS-portable/mics-engine.exe"
$lines += "$($appHash.ToLower())  MICS-portable/mics_app.exe"
$lines += "$((Get-FileHash (Join-Path $staging "rules\yara\starter.yar") -Algorithm SHA256).Hash.ToLower())  MICS-portable/rules/yara/starter.yar"
$lines += "$((Get-FileHash (Join-Path $staging "rules\guard\starter.json") -Algorithm SHA256).Hash.ToLower())  MICS-portable/rules/guard/starter.json"
$lines += "$((Get-FileHash (Join-Path $staging "sbom.cdx.json") -Algorithm SHA256).Hash.ToLower())  MICS-portable/sbom.cdx.json"
$lines += "$((Get-FileHash (Join-Path $staging "THIRD-PARTY-NOTICES") -Algorithm SHA256).Hash.ToLower())  MICS-portable/THIRD-PARTY-NOTICES"
$lines | Set-Content -Path $sums -Encoding ASCII

# Swap the staging build into place. Never delete the live folder in place: a DLL
# that a running MI CS has mapped makes Remove-Item fail *halfway* - it deletes
# what is not loaded and refuses what is - which is how a release once left a
# gutted folder behind. Move the old folder aside first, put the new one in place,
# and only then try to delete the leftover, so a locked folder is left whole.
$prefix = $portable.TrimEnd('\') + '\'
$users = @(Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -and $_.Path.StartsWith($prefix, 'OrdinalIgnoreCase') } |
  ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
$aside = $null
$asideProblem = $null
$swapped = $true
if (Test-Path $portable) {
  $aside = Join-Path $root ("dist\MICS-portable.old-" + (Get-Date).ToString("yyyyMMdd-HHmmss"))
  try {
    Rename-Item $portable $aside -ErrorAction Stop
  } catch {
    $swapped = $false
    $aside = $null
    $asideProblem = $_.Exception.Message
  }
}
if ($swapped) {
  Rename-Item $staging $portable
  $sizeMb = (Get-ChildItem $portable -Recurse -File | Measure-Object Length -Sum).Sum / 1MB
  $fileCount = (Get-ChildItem $portable -Recurse -File).Count
  Write-Output ("  folder : {0}  (refreshed, {1:N1} MB, {2} file(s))" -f $portable, $sizeMb, $fileCount)
  if ($aside -and (Test-Path $aside)) {
    try { Remove-Item $aside -Recurse -Force -ErrorAction Stop }
    catch {
      Write-Output ("           whatever is left of the previous copy stays at {0}" -f $aside)
    }
  }
} else {
  Write-Output ("  folder : left as it is - the previous copy could not be moved aside: {0}" -f $asideProblem)
  if ($users.Count -gt 0) { Write-Output ("           running from it: {0}" -f ($users -join ", ")) }
  Write-Output "           close MI CS (and anything else using that folder) and run this again"
  Write-Output "           the zip above is complete either way and is what gets published"
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "MI CS $Version portable release"
Write-Output ("  zip    : {0}  ({1:N1} MB)" -f $zip, ((Get-Item $zip).Length / 1MB))
Write-Output ("  sums   : {0}" -f $sums)
Write-Output ("  engine : {0}" -f $engineHash)
Write-Output "  rules  : $ruleCount file(s)"
Write-Output "  hardened: CFG + ASLR/DEP + stripped (checked from the PE, not the flags)"
Write-Output ("  symbols: {0}  (kept out of the package on purpose)" -f $symbolsDir)
Write-Output ("  engine name: {0}" -f $engineName)
Write-Output ("  manifest: {0} file(s) described by the MICS_MANIFEST resource in the engine" -f $manifestFiles.Count)
if ($signature -eq "Valid") {
  Write-Output "  signed : $signature - $signer"
} else {
  Write-Output "  signed : $signature - Windows will show 'Unknown publisher' and SmartScreen"
  Write-Output "           may ask before the first run; see the SmartScreen row in the README troubleshooting table"
  Write-Output "           (re-run with -Sign to sign it with a certificate trusted on this machine)"
}
Write-Output "verify with: powershell -ExecutionPolicy Bypass -File scripts\verify-release.ps1"
Write-Output "             powershell -ExecutionPolicy Bypass -File scripts\verify-manifest.ps1"
Write-Output "             powershell -ExecutionPolicy Bypass -File scripts\verify-tamper.ps1"
Write-Output "RESULT: PASS"
