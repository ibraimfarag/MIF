<#
.SYNOPSIS
  Assembles the portable release folder, zips it and writes SHA256SUMS.

.DESCRIPTION
  `dist\MICS-portable` is what users copy and run, so it has to be built from the
  current binaries in one step instead of being patched by hand. This script:

    1. copies the Flutter release output (`build\windows\x64\runner\Release`) into
       `dist\MICS-portable`;
    2. copies `engine\rules` next to the binaries - the guard and YARA packs are
       hot-reloaded from there, and a package without them silently falls back to
       the compiled-in starter pack;
    3. refuses to continue if any required file is missing, so a half-built folder
       is never published;
    4. writes `VERSION` (version, build time, engine hash, rule count);
    5. zips the folder to `dist\MICS-portable-<version>-x64.zip`;
    6. writes `dist\SHA256SUMS` for the zip, the engine, the app and the rules.

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
  [switch]$SkipBuild
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

# The engine is built by cargo, not by Flutter, and it may live outside the repo
# (CARGO_TARGET_DIR). Find it explicitly so the package never ships a stale one.
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
  Write-Host "building the app ($Configuration)..."
  Push-Location $root
  try {
    & flutter build windows --release
    if ($LASTEXITCODE -ne 0) { throw "flutter build windows failed ($LASTEXITCODE)" }
  } finally { Pop-Location }
}

if (-not (Test-Path $buildDir)) { throw "no build output at $buildDir - build first or drop -SkipBuild" }

# Required in the package: the app, the engine, Flutter's runtime, the asset
# bundle, and both rule packs (missing rules = silently fewer detections).
$required = @(
  "mics_app.exe",
  "mics-engine.exe",
  "flutter_windows.dll",
  "data\app.so",
  "data\icudtl.dat",
  "data\flutter_assets\AssetManifest.bin",
  "rules\yara\starter.yar",
  "rules\guard\starter.json"
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

$engine = Join-Path $staging "mics-engine.exe"
$app = Join-Path $staging "mics_app.exe"
$engineHash = (Get-FileHash $engine -Algorithm SHA256).Hash
$appHash = (Get-FileHash $app -Algorithm SHA256).Hash
$ruleCount = (Get-ChildItem (Join-Path $staging "rules") -Recurse -File).Count
$built = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")

$versionFile = Join-Path $staging "VERSION"
@(
  "MI CS $Version (portable, x64)",
  "built   $built",
  "engine  $engineHash",
  "app     $appHash",
  "rules   $ruleCount file(s) hot-reloaded from rules\"
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
$lines | Set-Content -Path $sums -Encoding ASCII

# Swap the staging build into place - unless someone is running MI CS from that
# folder right now, in which case leave their copy exactly as it is. The zip is
# already complete either way.
$prefix = $portable.TrimEnd('\') + '\'
$users = @(Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -and $_.Path.StartsWith($prefix, 'OrdinalIgnoreCase') } |
  ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
if ($users.Count -eq 0) {
  if (Test-Path $portable) { Remove-Item $portable -Recurse -Force }
  Rename-Item $staging $portable
  Write-Output "  folder : $portable  (refreshed, $((Get-ChildItem $portable -Recurse -File | Measure-Object Length -Sum).Sum / 1MB) MB, $((Get-ChildItem $portable -Recurse -File).Count) file(s))"
} else {
  Write-Output ("  folder : left as it is - {0} is running from it" -f ($users -join ", "))
  Write-Output "           close MI CS and run this again to refresh the unpacked folder"
  Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "MI CS $Version portable release"
Write-Output ("  zip    : {0}  ({1:N1} MB)" -f $zip, ((Get-Item $zip).Length / 1MB))
Write-Output ("  sums   : {0}" -f $sums)
Write-Output ("  engine : {0}" -f $engineHash)
Write-Output "  rules  : $ruleCount file(s)"
Write-Output "verify with: powershell -ExecutionPolicy Bypass -File scripts\verify-release.ps1"
Write-Output "RESULT: PASS"
