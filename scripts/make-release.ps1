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
    5. writes `VERSION` (version, build time, engine hash, rule count, what was
       hardened);
    6. zips the folder to `dist\MICS-portable-<version>-x64.zip`;
    7. writes `dist\SHA256SUMS` for the zip, the engine, the app, the rules and the
       inventory.

  The Dart symbol table produced by `--obfuscate` goes to
  `dist\symbols\<version>\` and is never part of the package: it maps `app.so`
  back to the source. `dist\MICS-portable` is swapped in after the zip is written,
  by renaming the old folder aside rather than deleting it in place, so a copy
  someone is running is left whole instead of half-deleted.

  Nothing here needs elevation.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1
  powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1 -Version 0.1.0 -SkipBuild

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
  [string]$PfxPassword = ""
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$buildDir = Join-Path $root "build\windows\x64\runner\$Configuration"
$portable = Join-Path $root "dist\MICS-portable"
$rulesSrc = Join-Path $root "engine\rules"

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
Get-Content $sbomOut | Where-Object { $_ -match "RESULT|sbom:|stale" } | ForEach-Object { "  $_" }
$sbomPassed = ($sbomExit -eq 0) -and ((Get-Content $sbomOut -Raw) -match "RESULT: PASS")
Remove-Item $sbomOut -ErrorAction SilentlyContinue
if (-not $sbomPassed) {
  Write-Output "RESULT: FAIL - sbom.cdx.json or THIRD-PARTY-NOTICES is stale; run 'dart run tool\sbom.dart' and commit both"
  exit 1
}

# The engine is built by cargo, not by Flutter, and it may live outside the repo
# (CARGO_TARGET_DIR). Find it explicitly so the package never ships a stale one.
$EnginePathWasGiven = [bool]$EnginePath
if (-not $EnginePath) {
  $candidates = @(
    (Join-Path $root "engine\target\release\mics-engine.exe"),
    (Join-Path $buildDir "mics-engine.exe")
  )
  if ($env:CARGO_TARGET_DIR) { $candidates = @((Join-Path $env:CARGO_TARGET_DIR "release\mics-engine.exe")) + $candidates }
  foreach ($c in $candidates) { if (Test-Path $c) { $EnginePath = $c; break } }
}
if (-not $EnginePath -or -not (Test-Path $EnginePath)) {
  Write-Output "RESULT: FAIL - no engine build found; run 'cargo build --release' in engine\ or pass -EnginePath"
  exit 1
}
$EnginePath = (Resolve-Path $EnginePath).Path

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

  Write-Host "building the app ($Configuration)..."
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
    $env:CARGO_ENCODED_RUSTFLAGS = Get-EngineRustFlags -Repo $root
    & cargo build --release
    $cargoExit = $LASTEXITCODE
  } finally {
    Pop-Location
    $ErrorActionPreference = $stopPreference
  }
  if ($cargoExit -ne 0) { throw "cargo build --release failed ($cargoExit)" }

  # Prefer the binary we just built over whatever the earlier lookup found.
  if (-not $EnginePathWasGiven) {
    $fresh = @()
    if ($env:CARGO_TARGET_DIR) { $fresh += (Join-Path $env:CARGO_TARGET_DIR "release\mics-engine.exe") }
    $fresh += (Join-Path $root "engine\target\release\mics-engine.exe")
    foreach ($c in $fresh) { if (Test-Path $c) { $EnginePath = (Resolve-Path $c).Path; break } }
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
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-hardening.ps1") -Path $staging
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

if ($Sign -or $PfxPath) {
  Write-Host "signing the staged binaries..."
  $signArgs = @()
  if ($PfxPath) { $signArgs = @("-PfxPath", (Resolve-Path $PfxPath).Path, "-PfxPassword", $PfxPassword) }
  else { $signArgs = @("-SelfSigned") }
  $stopPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "sign.ps1") `
      @signArgs -BuildDir $staging
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
  "MI CS $Version (portable, x64)",
  "built   $built",
  "engine  $engineHash",
  "app     $appHash",
  "rules   $ruleCount file(s) hot-reloaded from rules\",
  "hardened CFG + ASLR/DEP, engine LTO and stripped, app obfuscated (symbols not shipped)"
) | Set-Content -Path $versionFile -Encoding ASCII

$zip = Join-Path $root ("dist\MICS-portable-$Version-x64.zip")
if (Test-Path $zip) { Remove-Item $zip -Force }
Write-Host "zipping $zip ..."
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zip -CompressionLevel Optimal

$sums = Join-Path $root "dist\SHA256SUMS"
$lines = @()
# Every path is relative to this file (dist\), so `sha256sum -c SHA256SUMS` or a
# loop over Get-FileHash works without guessing where a file lives.
$lines += "$((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower())  MICS-portable-$Version-x64.zip"
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
Write-Output "  engine name: $engineName"
if ($signature -eq "Valid") {
  Write-Output "  signed : $signature - $signer"
} else {
  Write-Output "  signed : $signature - Windows will show 'Unknown publisher' and SmartScreen"
  Write-Output "           may ask before the first run; see the SmartScreen row in the README troubleshooting table"
  Write-Output "           (re-run with -Sign to sign it with a certificate trusted on this machine)"
}
Write-Output "verify with: powershell -ExecutionPolicy Bypass -File scripts\verify-release.ps1"
Write-Output "RESULT: PASS"
