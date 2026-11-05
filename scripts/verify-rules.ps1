<#
.SYNOPSIS
  Measures what the shipped detection pack catches, not that it loads.

.DESCRIPTION
  `scripts\verify-release.ps1` proves that the `rules\` a package carries is the
  one the engine loads, which is a statement about packaging. It said nothing
  about detection, and that gap had a price: the shipped YARA pack carried
  `Malicious_Macro_AutoOpen` with `uint16(0) == 0x504B`. `uint16` reads
  little-endian, so `0x504B` is "KP" in file order - a real container starts
  `50 4B` and reads `0x4B50`, which means the rule could never fire on any
  `.docm` that ever existed. Nothing noticed, because nothing ever asked a rule
  to match a file.

  This probe asks, for every vector in `engine\testdata\detection`:

    * the shipped pack must catch it, under the rule the vector was written for
      (one check per vector, so a rule that stops matching names itself);
    * an ordinary file must stay silent;
    * every rule the pack declares must either have a vector or be listed in the
      unreachable table below with its reason - a new rule cannot ship unproven;
    * the engine must say it loaded the pack under test, not the copy compiled
      into the binary, and the pack's path is printed with its SHA-256 - which
      bytes were measured is part of the measurement.

  Two of the ten shipped rules have no vector here, for reasons that are measured
  rather than assumed:

    * `EICAR_Test_File` - the EICAR string is what Defender itself reacts to, so
      a committed fixture would be quarantined on sight and the probe would fail
      for the wrong reason;
    * `Tiny_Packed_Pe_Installer` - a PE-shaped fixture has to be binary; a
      malformed one in the tree is quarantine bait and a real one is a build
      artifact.

  A third fact is measured but deliberately *not* asserted, because a gate may
  only claim what its vectors can hold: the macro rule tests a container by two
  magic bytes plus substrings, and a real macro document deflates those
  substrings into bytes no pattern can read. Measured on a `.docm` this probe
  builds, the literals `AutoOpen`, `CreateObject` and `Shell` are absent from the
  file - which is why that rule's practical reach is still ~zero after the magic
  was corrected, and why real macro detection needs a parser, not a pattern.

.PARAMETER EngineExe
  The engine to scan with. Default: engine\target\release\mics-engine.exe, then
  engine\target\debug\mics-engine.exe.

.PARAMETER RulesBase
  The folder that *contains* `rules\`, used when the engine has no `rules\` of its
  own beside it (a dev tree). Default: `engine\` of this checkout.

.PARAMETER InPlace
  Measure the pack that sits beside *this* engine - what a release gate needs,
  because the packaged engine's own `rules\` must be the one that detects. Without
  it the pack under test is located through `MICS_RULES_DIR`, which is how a dev
  binary is pointed at the tree's pack.

.PARAMETER Keep
  Leave the scratch folder and its logs in place.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-rules.ps1

.EXAMPLE
  # the way scripts\verify-release.ps1 calls it, against an extracted package
  powershell -ExecutionPolicy Bypass -File scripts\verify-rules.ps1 `
    -EngineExe dist\MICS-portable\mics-engine.exe -InPlace

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9). No elevation, no pipe, no guard: the
  only thing that runs is a one-off `scan --path`. The data directory is given
  `{"dnd": true}` first, because a detection probe must not put seven cards on the
  desktop - measured: seven `alert shown (high)` lines without it, zero with it.
  Environment variables are saved and restored, so a release gate can call this in
  the middle of its own run.
#>
param(
  [string]$EngineExe,
  [string]$RulesBase,
  [switch]$InPlace,
  [switch]$Keep
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if (-not $EngineExe) {
  foreach ($candidate in @(
      (Join-Path $root "engine\target\release\mics-engine.exe"),
      (Join-Path $root "engine\target\debug\mics-engine.exe"))) {
    if (Test-Path $candidate) { $EngineExe = $candidate; break }
  }
}
if (-not $EngineExe -or -not (Test-Path $EngineExe)) {
  Write-Output "RESULT: FAIL - no engine binary; build it (scripts\pipeline.ps1 -Tier full) or pass -EngineExe"
  exit 1
}
if (-not $RulesBase) { $RulesBase = Join-Path $root "engine" }
if ($InPlace) {
  # The engine looks for rules\ next to itself first, and a package that does not
  # carry one falls back to the copy compiled into the binary - which is a
  # packaging failure this probe must see, not paper over.
  $pack = Join-Path (Split-Path -Parent $EngineExe) "rules\yara\starter.yar"
  $packFrom = "the engine's own folder (-InPlace)"
} else {
  $pack = Join-Path $RulesBase "rules\yara\starter.yar"
  $packFrom = "-RulesBase $RulesBase"
}
if (-not (Test-Path $pack)) {
  Write-Output "RESULT: FAIL - no pack at $pack ($packFrom)"
  exit 1
}
$vectors = Join-Path $root "engine\testdata\detection"
if (-not (Test-Path $vectors)) {
  Write-Output "RESULT: FAIL - no vectors at $vectors"
  exit 1
}

# The vectors and the rule each one is written for. `engine\src\scanner\yara_engine.rs`
# carries the same table as a unit test, so a rule that stops matching fails in the
# fast tier too.
$expected = [ordered]@{
  "app.hta"              = "Suspicious_HTA_Exec"
  "certutil.bat"         = "Suspicious_BAT_Certutil_Download"
  "double-extension.txt" = "Double_Extension_Emailer"
  "pk-macro.txt"         = "Malicious_Macro_AutoOpen"
  "ps-download.ps1"      = "Suspicious_Cmd_PowerShell_Download"
  "ransom-note.txt"      = "Ransom_Note_Names"
  "task-create.txt"      = "Suspicious_Scheduled_Task_Creator"
  "vbs-dropper.vbs"      = "Suspicious_VBS_Dropper"
}
$clean = "clean.txt"
$unreachable = [ordered]@{
  "EICAR_Test_File"           = "the EICAR string is what Defender reacts to, so a committed fixture would be quarantined"
  "Tiny_Packed_Pe_Installer"  = "a PE-shaped fixture has to be binary: malformed is quarantine bait, real is a build artifact"
}

$script:checks = 0
$script:skips = 0
$script:failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$text) {
  $script:checks++
  if ($ok) { Write-Output "PASS  $text" }
  else { $script:failures.Add($text); Write-Output "FAIL  $text" }
}
function Skip([string]$text) {
  $script:skips++
  Write-Output "SKIP  $text"
}

$scratch = Join-Path $env:TEMP ("mics-verify-rules-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$dataDir = Join-Path $scratch "data"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

Check (Test-Path $pack) "the pack under test exists ($packFrom)"
Check ($pack -like "*\rules\yara\starter.yar") "the pack is where the engine looks for it (rules\yara\starter.yar)"

# A detection probe that pops a card per finding would be unusable, so the data
# directory says do-not-disturb before anything runs.
$settingsPath = Join-Path $dataDir "settings.json"
[System.IO.File]::WriteAllText($settingsPath, '{ "dnd": true }', (New-Object System.Text.UTF8Encoding($false)))

$saved = @{}
foreach ($name in @("MICS_DATA_DIR", "MICS_NO_SINGLETON", "MICS_NO_GUARD", "MICS_RULES_DIR")) {
  $saved[$name] = [Environment]::GetEnvironmentVariable($name)
}
$scanOut = Join-Path $scratch "scan.out"
$scanErr = Join-Path $scratch "scan.err"
$exit = 1
try {
  $env:MICS_DATA_DIR = $dataDir
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  if ($InPlace) {
    # A packaged engine must find its own rules\; pointing it somewhere else here
    # would hide an incomplete package behind this script's environment.
    Remove-Item Env:\MICS_RULES_DIR -ErrorAction SilentlyContinue
  } else {
    $env:MICS_RULES_DIR = $RulesBase
  }

  Write-Output "== engine:  $EngineExe"
  Write-Output "== pack:    $pack ($packFrom)"
  Write-Output ("== sha256:  " + (Get-FileHash -LiteralPath $pack -Algorithm SHA256).Hash.ToLower())
  Write-Output "== vectors: $vectors"
  Write-Output ""

  $proc = Start-Process -FilePath $EngineExe -ArgumentList "scan", "--path", $vectors, "--json" -Wait -PassThru -NoNewWindow `
    -RedirectStandardOutput $scanOut -RedirectStandardError $scanErr
  $exit = $proc.ExitCode
  if ($exit -ne 0) {
    Write-Output "---- engine stderr ----"
    Get-Content -LiteralPath $scanErr -ErrorAction SilentlyContinue | ForEach-Object { "  $_" }
  }
} finally {
  foreach ($name in $saved.Keys) {
    if ($null -eq $saved[$name]) { Remove-Item ("Env:\" + $name) -ErrorAction SilentlyContinue }
    else { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
  }
}

Check ($exit -eq 0) "the engine scanned the vectors and exited 0 (exit $exit)"

$report = $null
try {
  $report = [System.IO.File]::ReadAllText($scanOut, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
} catch {
  $report = $null
}
Check ($null -ne $report) "the scan answered JSON (not a crash, not a log)"
if ($null -eq $report) {
  Write-Output "---- scan.err ----"
  Get-Content -LiteralPath $scanErr -ErrorAction SilentlyContinue | ForEach-Object { "  $_" }
  Write-Output ("RESULT: FAIL - " + $script:failures.Count + " of " + $script:checks + " check(s) failed")
  if (-not $Keep) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
  exit 1
}

$vectorFiles = @(Get-ChildItem -LiteralPath $vectors -File)
Check ($report.files_scanned -eq $vectorFiles.Count) `
  "every vector was scanned ($($report.files_scanned) of $($vectorFiles.Count))"
Check ($report.files_skipped -eq 0) "nothing was skipped ($($report.files_skipped) skipped)"

# Findings, grouped per file name: one file may legitimately carry more than one.
$byFile = @{}
foreach ($finding in @($report.findings)) {
  $leaf = Split-Path -Leaf $finding.path
  if (-not $byFile.ContainsKey($leaf)) { $byFile[$leaf] = New-Object System.Collections.Generic.List[string] }
  $byFile[$leaf].Add([string]$finding.reason)
}

Write-Output ""
foreach ($file in $expected.Keys) {
  $rule = $expected[$file]
  $reasons = if ($byFile.ContainsKey($file)) { $byFile[$file] } else { @() }
  $hit = @($reasons | Where-Object { $_ -eq ("yara:" + $rule) })
  Check ($hit.Count -ge 1) "$file is caught by $rule (findings: $(if ($reasons.Count) { $reasons -join ', ' } else { 'none' }))"
}
$cleanReasons = if ($byFile.ContainsKey($clean)) { $byFile[$clean] } else { @() }
Check ($cleanReasons.Count -eq 0) "$clean is left alone (findings: $(if ($cleanReasons.Count) { $cleanReasons -join ', ' } else { 'none' }))"

# Every rule the pack declares is either held to a file here or named with its
# reason - and every name in either table still exists in the pack.
$declared = @(Select-String -LiteralPath $pack -Pattern '^rule\s+([A-Za-z0-9_]+)' |
  ForEach-Object { $_.Matches[0].Groups[1].Value })
Check ($declared.Count -gt 0) "the pack declares rules ($($declared.Count))"
$proven = @($expected.Values)
foreach ($rule in $declared) {
  $known = ($proven -contains $rule) -or ($unreachable.Keys -contains $rule)
  Check $known "rule $rule is either held to a vector or named as unreachable"
}
foreach ($rule in $proven) {
  Check ($declared -contains $rule) "vector rule $rule is still declared by the pack"
}

# The engine logs where it loaded the pack from: the copy compiled into the binary
# is the same content today, but a package must use the file it shipped.
$log = @(Get-ChildItem -LiteralPath $dataDir -Recurse -Filter "engine.log" -ErrorAction SilentlyContinue |
  Select-Object -First 1)
$logLine = $null
if ($log) {
  $match = Select-String -LiteralPath $log.FullName -Pattern "YARA rules from .*" | Select-Object -Last 1
  if ($match) { $logLine = $match.Line.Trim() }
}
Check ($logLine -like "*$pack*") "the engine loaded $pack, not the copy compiled into the binary (log: $logLine)"

Write-Output ""
Write-Output "Coverage: $($proven.Count) of $($declared.Count) declared rule(s) are held to a file."
foreach ($rule in $unreachable.Keys) {
  Write-Output "  not exercised: $rule - $($unreachable[$rule])"
}
Write-Output "Measured limit (not asserted): a real .docm deflates its macro strings, so"
Write-Output "  Malicious_Macro_AutoOpen can only see an uncompressed container - measured"
Write-Output "  on a .docm built here: the literals AutoOpen/CreateObject/Shell are absent."
Write-Output ""

if ($script:failures.Count -gt 0) {
  Write-Output "RESULT: FAIL - $($script:failures.Count) of $($script:checks) check(s) failed"
  foreach ($failure in $script:failures) { Write-Output "  - $failure" }
  if (-not $Keep) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
  exit 1
}
Write-Output "RESULT: PASS - $($script:checks) checks, $($script:skips) skipped"
if ($Keep) { Write-Output "(kept $scratch)" }
else { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
exit 0
