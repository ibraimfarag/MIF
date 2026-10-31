<#
.SYNOPSIS
  Proves the published portable release: hashes, completeness and that the
  extracted copy actually runs (privileged helper, desktop card, rule loading).

.DESCRIPTION
  `scripts\make-release.ps1` produces `dist\MICS-portable-<version>-x64.zip` and
  `dist\SHA256SUMS`. This probe checks that artifact the way a user would:

    1. every SHA256SUMS line matches the file it names;
    2. the zip extracts to a clean folder with the required files, including both
       rule packs and the third-party inventory, which is then read back and
       checked;
    3. the extracted engine serves the privileged helper protocol
       (`verify-helper.ps1`);
    4. the extracted engine puts a real card on the desktop (`verify-toast.ps1`);
    5. the extracted engine loads its rules **from the package**, not from the
       compiled-in fallback - the engine logs which file it used, and a package
       that falls back is an incomplete package.

  Everything runs from a temp folder, so this also exercises the release copy from
  a normal-integrity location. No elevation anywhere.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-release.ps1

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9). Native stderr is redirected to files, never to a PowerShell
  stream, because 5.1 can deadlock on that (docs/TODO.md 8.13).
#>
param(
  [string]$DistDir = "",
  [switch]$SkipToast
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $DistDir) { $DistDir = Join-Path $root "dist" }

function Fail([string]$message) {
  $failures.Add($message)
  Write-Output "  [FAIL] $message"
}

function Pass([string]$message) {
  Write-Output "  [PASS] $message"
}

# Two engine processes share this data folder, and the log falls back to a
# per-process file if the main one is busy, so read every log line there is.
function Read-EngineLog([string]$dataDir) {
  $logs = Join-Path $dataDir "logs"
  if (-not (Test-Path $logs)) { return "" }
  $text = ""
  foreach ($f in Get-ChildItem $logs -Filter "*.log" -ErrorAction SilentlyContinue) {
    $text += (Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue)
  }
  return $text
}

$sums = Join-Path $DistDir "SHA256SUMS"
if (-not (Test-Path $sums)) {
  Write-Output "RESULT: FAIL - no $sums; run scripts\make-release.ps1 first"
  exit 1
}

Write-Output "1) checksums in $sums"
# The zip is the artifact and is hashed where it sits. The `MICS-portable/...`
# lines describe the *contents* of that zip, so they are checked against the
# extracted copy further down - not against `dist\MICS-portable`, which is a
# working folder that may be an older build (or the copy someone is running).
$zipLine = $null
$contents = @()
foreach ($line in Get-Content $sums) {
  if (-not $line.Trim()) { continue }
  $parts = $line -split "\s+", 2
  $expected = $parts[0].ToLower()
  $name = $parts[1].Trim()
  if ($name -like "*.zip") {
    # Paths in SHA256SUMS are relative to dist\ (see make-release.ps1).
    $path = Join-Path $DistDir ($name -replace "/", "\")
    $zipLine = $path
    if (-not (Test-Path $path)) { Fail "listed but missing: $name"; continue }
    $actual = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
    if ($actual -eq $expected) { Pass "$name" } else { Fail "$name hash mismatch`n         listed   $expected`n         actual   $actual" }
  } else {
    $contents += , @{ Expected = $expected; Name = $name }
  }
}

if (-not $zipLine -or -not (Test-Path $zipLine)) {
  Write-Output "RESULT: FAIL - SHA256SUMS does not name an existing zip"
  exit 1
}

Write-Output "2) extracting $(Split-Path $zipLine -Leaf)"
$work = Join-Path $env:TEMP ("mics-release-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
  Expand-Archive -Path $zipLine -DestinationPath $work -Force
  $required = @(
    "mics_app.exe", "mics-engine.exe", "flutter_windows.dll", "VERSION",
    "data\app.so", "data\icudtl.dat",
    "rules\yara\starter.yar", "rules\guard\starter.json",
    "sbom.cdx.json", "THIRD-PARTY-NOTICES"
  )
  $missing = @($required | Where-Object { -not (Test-Path (Join-Path $work $_)) })
  if ($missing.Count -eq 0) { Pass "every required file is in the zip" }
  else { Fail ("missing from the zip: " + ($missing -join ", ")) }

  # The inventory a user can read without us: it has to parse, describe every
  # component it lists, and carry the audit verdict the generator produced.
  $bomPath = Join-Path $work "sbom.cdx.json"
  if (Test-Path $bomPath) {
    $bom = Get-Content $bomPath -Raw | ConvertFrom-Json
    if ($bom.bomFormat -eq "CycloneDX" -and $bom.specVersion -eq "1.6") {
      Pass "inventory: CycloneDX $($bom.specVersion), $($bom.components.Count) component(s)"
    } else {
      Fail "the inventory is not a CycloneDX 1.6 document ($($bom.bomFormat) $($bom.specVersion))"
    }
    $unlicensed = @($bom.components | Where-Object { -not $_.licenses })
    if ($unlicensed.Count -eq 0) { Pass "inventory: every component names a license" }
    else { Fail "inventory: $($unlicensed.Count) component(s) name no license, first: $($unlicensed[0].name)" }
    if ($bom.metadata.component.name -ne "MI CS") {
      Fail "the inventory is about '$($bom.metadata.component.name)', not MI CS"
    }
  }
  $noticesPath = Join-Path $work "THIRD-PARTY-NOTICES"
  if (Test-Path $noticesPath) {
    $notices = Get-Content $noticesPath -Raw
    if ($notices -match "License texts missing: 0" -and $notices -match "Copyleft: 0") {
      Pass "notices: no copyleft and every license text present"
    } else {
      Fail "the notices do not report a clean license audit"
    }
  }
  # A nested `rules\rules` is what a second packaging run used to produce when the
  # destination already existed, so check the layout, not just the file names.
  $ruleFiles = @(Get-ChildItem (Join-Path $work "rules") -Recurse -File -ErrorAction SilentlyContinue)
  if ($ruleFiles.Count -eq 2 -and -not (Test-Path (Join-Path $work "rules\rules"))) {
    Pass "rules layout: $($ruleFiles.Count) pack(s), no nested copies"
  } else {
    Fail "rules folder holds $($ruleFiles.Count) file(s): $(($ruleFiles | ForEach-Object { $_.FullName.Substring($work.Length + 1) }) -join ', ')"
  }
  $engine = Join-Path $work "mics-engine.exe"

  # The name a person reads in Task Manager's Processes tab comes from the
  # executable's version resource, not from its file name.
  $engineName = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($engine).FileDescription
  if ($engineName -eq "MiShild Background") {
    Pass "the engine presents itself as '$engineName' (Task Manager, Properties)"
  } else {
    Fail "engine FileDescription is '$engineName', expected 'MiShild Background'"
  }
  $appName = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(
    (Join-Path $work "mics_app.exe")).FileDescription
  if ($appName -eq "MI Cyber Security") {
    Pass "the app presents itself as '$appName' (Task Manager, Properties)"
  } else {
    Fail "app FileDescription is '$appName', expected 'MI Cyber Security'"
  }

  # The published hashes for what is inside the zip: an extracted file can be
  # compared with SHA256SUMS without knowing which build the working folder holds.
  foreach ($entry in $contents) {
    $rel = $entry.Name -replace "^MICS-portable/", "" -replace "/", "\"
    $extracted = Join-Path $work $rel
    if (-not (Test-Path $extracted)) { Fail "listed in SHA256SUMS but not in the zip: $($entry.Name)"; continue }
    $actual = (Get-FileHash $extracted -Algorithm SHA256).Hash.ToLower()
    if ($actual -eq $entry.Expected) { Pass "$($entry.Name) (inside the zip)" }
    else { Fail "$($entry.Name) hash mismatch`n         listed   $($entry.Expected)`n         actual   $actual" }
  }

  Write-Output "3) privileged helper protocol (from the package)"
  $helperOut = Join-Path $env:TEMP "rel-helper.out"
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-helper.ps1") `
    -EnginePath $engine > $helperOut 2>&1
  $helperExit = $LASTEXITCODE
  Get-Content $helperOut | Where-Object { $_ -match "RESULT|\[FAIL\]" } | ForEach-Object { "  $_" }
  Remove-Item $helperOut -ErrorAction SilentlyContinue
  if ($helperExit -eq 0) { Pass "the packaged engine serves the helper protocol" }
  else { Fail "verify-helper.ps1 failed against the packaged engine (exit $helperExit)" }

  if (-not $SkipToast) {
    Write-Output "4) desktop card (from the package)"
    $toastOut = Join-Path $env:TEMP "rel-toast.out"
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-toast.ps1") `
      -EnginePath $engine > $toastOut 2>&1
    $toastExit = $LASTEXITCODE
    Get-Content $toastOut | Where-Object { $_ -match "CARD|RESULT|\[FAIL\]" } | ForEach-Object { "  $_" }
    Remove-Item $toastOut -ErrorAction SilentlyContinue
    if ($toastExit -eq 0) { Pass "a card from the packaged engine reached the desktop" }
    else { Fail "verify-toast.ps1 failed against the packaged engine (exit $toastExit)" }
  }

  Write-Output "5) the package's own rules are the ones loaded"
  $dataDir = Join-Path $work "probe-data"
  $pipeName = "mics_release_probe"
  $env:MICS_DATA_DIR = $dataDir
  $env:MICS_PIPE_NAME = "\\.\pipe\$pipeName"
  $env:MICS_NO_SINGLETON = "1"
  Remove-Item Env:\MICS_NO_GUARD -ErrorAction SilentlyContinue
  Remove-Item Env:\MICS_RULES_DIR -ErrorAction SilentlyContinue

  $serveOut = Join-Path $work "serve.out"
  $serveErr = Join-Path $work "serve.err"
  $payload = Join-Path $work "sample"
  New-Item -ItemType Directory -Force -Path $payload | Out-Null
  Set-Content -Path (Join-Path $payload "note.txt") -Value "nothing to see here" -Encoding ASCII

  # `--service` is the mode that arms the guard on its own (the UI's `guard.start`
  # does the same on demand), and it speaks the named pipe instead of stdin, which
  # a script can drive.
  $engineProc = Start-Process -FilePath $engine -ArgumentList "service" -PassThru -NoNewWindow `
    -RedirectStandardOutput $serveOut -RedirectStandardError $serveErr
  $logPath = Join-Path $dataDir "logs\engine.log"
  $guardLine = $null
  for ($i = 0; $i -lt 40 -and -not $guardLine; $i++) {
    Start-Sleep -Milliseconds 500
    if (Read-EngineLog $dataDir -match "guard: \d+ rule\(s\) from") {
      $guardLine = ([regex]::Match((Read-EngineLog $dataDir), "guard: \d+ rule\(s\) from.*")).Value
    }
  }

  Start-Process -FilePath $engine -ArgumentList "scan", "--path", $payload -Wait -NoNewWindow `
    -RedirectStandardOutput (Join-Path $work "scan.out") -RedirectStandardError (Join-Path $work "scan.err")
  $yaraLine = $null
  $logText = Read-EngineLog $dataDir
  if ($logText -match "YARA rules from") {
    $yaraLine = ([regex]::Match($logText, "YARA rules from.*")).Value
  }
  if (-not $engineProc.HasExited) { $engineProc.Kill() }

  $expectedGuard = Join-Path $work "rules\guard"
  if ($guardLine -and $guardLine -like "*$expectedGuard*") { Pass "guard rules: $guardLine" }
  elseif ($guardLine) { Fail "the guard did not use the packaged rules: $guardLine" }
  else { Fail "the engine never said which guard rules it loaded (looked in $logPath)" }

  if ($yaraLine -and $yaraLine -like "*$work*rules\yara\starter.yar*") { Pass "YARA rules: $yaraLine" }
  else { Fail "the scan did not use the packaged YARA rules (log line: $yaraLine)" }

  $versionFile = Join-Path $work "VERSION"
  if (Test-Path $versionFile) { Pass "VERSION: $((Get-Content $versionFile -TotalCount 1))" }
  else { Fail "the zip has no VERSION file" }
} finally {
  Get-Process mics-engine -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "$work*" } | Stop-Process -Force -ErrorAction SilentlyContinue
  Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -eq 0) {
  Write-Output "RESULT: PASS - the published release matches its hashes, is complete, runs, and loads its own rules"
  exit 0
}
Write-Output "failures:"
foreach ($f in $failures) { Write-Output "  - $f" }
Write-Output "RESULT: FAIL - the release artifact is not what it claims to be"
exit 1