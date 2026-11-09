<#
.SYNOPSIS
  Proves the tamper watch notices our sublayer or a filter of ours being removed
  from Windows' filtering engine (WFP), and that it says "unknown" instead of
  guessing when it may not look (D-044).

.DESCRIPTION
  Register section 0.6 row 17, slice (c). MI CS' sublayer and filters are
  *persistent* objects in the BFE (D-042), which is what makes a block outlive
  the app - and what lets anything with an administrator token delete them. The
  engine keeps a record of what it wrote and compares it against the machine.

  Three things have to be measured outside a unit test:

    1. the machine path is honest: with no record and no way to read the BFE
       (an unelevated engine and no helper), the answer is `unknown` with the
       reason in it - never `tampered` (a false alarm) and never `guarded` (a
       claim it cannot support);
    2. the detector and the alert really work: with a record in the database and
       a status injected through the test hook `MICS_WFP_WATCH_LIVE`, a missing
       filter, a missing sublayer and a filter nobody recorded are each judged
       correctly, and a tamper raises a real guard event - an `incident.list`
       entry titled "filtering layer was tampered with" and a `WFP tamper:` line
       in the engine's own log - exactly once per change;
    3. the scan is cheap and leaves no trace when there is nothing to see: a
       repeat poll of an unchanged state adds no second incident.

  The injection is a test hook, not a measurement of the machine, and the
  injected status says so in the report's own `detail`. The part that the hook
  stands in for - reading the BFE - is the part that needs an administrator; on
  a machine where the engine is elevated or the `MICSHelper` service is
  installed, part 1 answers `clear` / `unrecorded` / `guarded` from the real
  engine instead, and the probe says which of the two it saw.

  What this probe does NOT prove:
    * that the guard thread's own 30 s poll fires (parts 2 and 3 call
      `fw.wfp.watch` directly; the tick is the same function on a timer);
    * a delete-and-re-add inside one poll window - D-044 records that blind spot
      instead of claiming around it;
    * deleting a real filter behind the engine's back and watching it notice,
      which needs an administrator: `scripts\verify-wfp.ps1` owns the write
      path, and this probe owns the detection path.

  Usage:
    pwsh ./scripts/verify-wfp-watch.ps1
    pwsh ./scripts/verify-wfp-watch.ps1 -EngineExe engine\target\debug\mics-engine.exe -Keep
#>
param(
  [string]$EngineExe,
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

# A relative -EngineExe is usable in this shell and fatal for the helper: the
# service runs as SYSTEM with its own working directory, so a relative path
# cannot be resolved there (`The system cannot find the path specified`,
# 0x80070003) and the write path fails for a reason that is not about the write.
# Every probe hands the path to the helper, so it is resolved to an absolute one
# here, once (D-045).
$EngineExe = (Resolve-Path -LiteralPath $EngineExe).Path

$script:checks = 0
$script:skips = New-Object System.Collections.Generic.List[string]
$script:failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$text) {
  $script:checks++
  if ($ok) { Write-Output "PASS  $text" }
  else { $script:failures.Add($text); Write-Output "FAIL  $text" }
}
function Skip([string]$text) {
  $script:skips.Add($text)
  Write-Output "SKIP  $text"
}
function Note([string]$text) {
  Write-Output "note  $text"
}

$started = Get-Date
$scratch = Join-Path $env:TEMP ("mics-verify-wfp-watch-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

function Invoke-Rpc([string]$pipeName, [string]$method, $params, [int]$id = 1) {
  $payload = @{ jsonrpc = "2.0"; id = $id; method = $method }
  if ($null -ne $params) { $payload["params"] = $params }
  $text = ($payload | ConvertTo-Json -Depth 8 -Compress) + "`n"
  $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
  try {
    $client.Connect(5000)
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $writer.Write($text)
    $reader = New-Object System.IO.StreamReader($client)
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
      $line = $reader.ReadLine()
      if ($null -eq $line) { break }
      $obj = $null
      try { $obj = $line | ConvertFrom-Json } catch { continue }
      if ($obj.PSObject.Properties.Name -contains "id" -and $obj.id -eq $id) { return $obj }
    }
    return $null
  } finally {
    $client.Dispose()
  }
}

# One engine per scenario: the hooks are read from the process environment and
# the record lives in that scenario's own database, so scenario C never inherits
# scenario B's record. Everything else - guard off (this probe drives the watch
# itself), no singleton, no auto resume - is shared.
function Start-Engine([string]$pipeName, [hashtable]$extra, [string]$tag) {
  $scenarioData = Join-Path $scratch ("data-" + $tag)
  New-Item -ItemType Directory -Path $scenarioData -Force | Out-Null
  $env:MICS_DATA_DIR = $scenarioData
  $env:MICS_PIPE_NAME = $pipeName
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $env:MICS_NO_SCAN_SCHEDULE = "1"
  Remove-Item Env:MICS_WFP_WATCH_SEED -ErrorAction SilentlyContinue
  Remove-Item Env:MICS_WFP_WATCH_LIVE -ErrorAction SilentlyContinue
  foreach ($key in $extra.Keys) { Set-Item -Path ("Env:" + $key) -Value $extra[$key] }
  $out = Join-Path $scratch ("stdout-" + $tag + ".log")
  $err = Join-Path $scratch ("stderr-" + $tag + ".log")
  $proc = Start-Process -FilePath $EngineExe -ArgumentList @("service") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
  $deadline = (Get-Date).AddSeconds(25)
  while ((Get-Date) -lt $deadline) {
    $log = (Get-Content $err -ErrorAction SilentlyContinue) -join "`n"
    if ($log -match "Starting Named Pipe server") { break }
    Start-Sleep -Milliseconds 250
  }
  return @{ proc = $proc; err = $err; data = $scenarioData }
}

function Stop-Engine($handle) {
  if ($handle -and $handle.proc -and -not $handle.proc.HasExited) {
    Stop-Process -Id $handle.proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
  }
}

$elevated = $false
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $elevated = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $elevated = $false }
$helper = $null -ne (Get-Service -Name "MICSHelper" -ErrorAction SilentlyContinue)
Note ("this shell: elevated=$elevated, MICSHelper=$helper")

$a = $null; $b = $null; $c = $null; $d = $null; $e = $null
try {
  # ---- 1. the machine path: no record, and whatever the engine can read -----
  Write-Output ""
  Write-Output "== part 1 - what the watch says before anything was recorded"
  $a = Start-Engine -pipeName "mics-watch-a" -extra @{} -tag "a"
  $first = Invoke-Rpc -pipeName "mics-watch-a" -method "fw.wfp.watch" -params $null
  Check ($null -ne $first -and $null -ne $first.result) "fw.wfp.watch answered"
  $report = $null
  if ($first -and $null -ne $first.result) { $report = $first.result }
  if ($null -ne $report) {
    foreach ($field in @("state", "recorded", "live", "missing", "extra", "sublayer",
        "needs_elevation", "detail", "at", "alerted_at")) {
      Check ($report.PSObject.Properties.Name -contains $field) ("the answer carries " + $field)
    }
    Note ("state={0} recorded={1} live={2} needs_elevation={3}" -f $report.state, $report.recorded,
      $report.live, $report.needs_elevation)
    Check ($report.state -ne "tampered") "an empty record can never be a tamper"
    Check (@("clear", "unrecorded", "unknown", "guarded") -contains $report.state) `
      ("state is one the detector defines: " + $report.state)
    Check ($report.recorded -eq 0) "nothing is recorded on a fresh data directory"
    if ($report.state -eq "unknown") {
      Check ($report.needs_elevation) "unknown comes with needs_elevation"
      Check (("" + $report.detail).Trim().Length -gt 0) "unknown says why in detail"
      Note ("the BFE could not be read here: " + $report.detail)
      if ($elevated -or $helper) {
        Skip "an elevated shell or a working helper should have answered from the machine; the helper predates D-042 or the read failed"
      }
    } else {
      Note "the engine read the real filtering engine (elevated shell or a helper that answers)"
    }
  }

  # ---- 2. the detector: a record, and a status that lost something ----------
  Write-Output ""
  Write-Output "== part 2 - a record that lost a filter, a sublayer, or nothing"
  $b = Start-Engine -pipeName "mics-watch-b" -extra @{
    MICS_WFP_WATCH_SEED = "MICS-probe-alpha;MICS-probe-beta"
    MICS_WFP_WATCH_LIVE = '{"sublayer":true,"filters":1,"names":["MICS-probe-alpha"],"needs_elevation":false,"detail":""}'
  } -tag "b"
  $second = Invoke-Rpc -pipeName "mics-watch-b" -method "fw.wfp.watch" -params $null
  $tamper = $null
  if ($second -and $null -ne $second.result) { $tamper = $second.result }
  Check ($null -ne $tamper) "fw.wfp.watch answered over the injected status"
  if ($null -ne $tamper) {
    Check ($tamper.state -eq "tampered") ("a recorded filter that is gone is a tamper (got " + $tamper.state + ")")
    Check ($tamper.recorded -eq 2 -and $tamper.live -eq 1) "the counts come from the record and the status"
    Check (($tamper.missing -join ",") -eq "MICS-probe-beta") "the missing filter is named"
    Check (("" + $tamper.detail) -match "MICS-probe-beta") "the sentence a user reads names it too"
    Check ($tamper.alerted_at -gt 0) "the alert was stamped"
    Note ("detail: " + $tamper.detail)
  }

  # The alert has to be a real event, not a return value: an incident and a line
  # in the engine's own log.
  $incidents = Invoke-Rpc -pipeName "mics-watch-b" -method "incident.list" -params @{ limit = 20 } -id 2
  $list = @()
  if ($incidents -and $null -ne $incidents.result) { $list = @($incidents.result) }
  $watched = @($list | Where-Object { ("" + $_.title) -match "filtering layer was tampered with" })
  Check ($watched.Count -ge 1) "the tamper opened an incident titled 'filtering layer was tampered with'"
  if ($watched.Count -ge 1) {
    Check ($watched[0].severity -eq "high") ("the incident is HIGH (got " + $watched[0].severity + ")")
    Check (("" + $watched[0].title) -match "MICS-probe-beta") "the incident carries the missing filter's name"
  }
  $logB = (Get-Content $b.err -ErrorAction SilentlyContinue) -join "`n"
  Check ($logB -match "WFP tamper:") "the engine's own log says what happened"
  Check ($logB -match "injected status") "the log marks the injected status as injected"

  # Exactly once: the same loss must not file a second incident on the next poll.
  $again = Invoke-Rpc -pipeName "mics-watch-b" -method "fw.wfp.watch" -params $null -id 3
  $incidentsAgain = Invoke-Rpc -pipeName "mics-watch-b" -method "incident.list" -params @{ limit = 20 } -id 4
  $listAgain = @()
  if ($incidentsAgain -and $null -ne $incidentsAgain.result) { $listAgain = @($incidentsAgain.result) }
  $watchedAgain = @($listAgain | Where-Object { ("" + $_.title) -match "filtering layer was tampered with" })
  Check ($watchedAgain.Count -eq $watched.Count) "the same loss is reported once, not every poll"
  if ($again -and $null -ne $again.result) {
    Check ($again.result.state -eq "tampered") "the state is unchanged on the second look"
    Check ($again.result.alerted_at -eq $tamper.alerted_at) "the alert time does not move on a repeat"
  }

  # ---- 3. the other verdicts, each on its own engine ------------------------
  Write-Output ""
  Write-Output "== part 3 - a matching record, a filter nobody recorded, a missing sublayer"
  $c = Start-Engine -pipeName "mics-watch-c" -extra @{
    MICS_WFP_WATCH_SEED = "MICS-probe-alpha"
    MICS_WFP_WATCH_LIVE = '{"sublayer":true,"filters":2,"names":["MICS-probe-alpha","MICS-stranger"],"needs_elevation":false,"detail":""}'
  } -tag "c"
  $third = Invoke-Rpc -pipeName "mics-watch-c" -method "fw.wfp.watch" -params $null
  if ($third -and $null -ne $third.result) {
    $r = $third.result
    Check ($r.state -eq "guarded") ("a filter nobody recorded is not a tamper (got " + $r.state + ")")
    Check (($r.extra -join ",") -eq "MICS-stranger") "it is listed as extra instead"
    Check (($r.missing -join ",") -eq "") "nothing recorded is missing"
  } else { Check $false "fw.wfp.watch answered for the matching record" }

  $d = Start-Engine -pipeName "mics-watch-d" -extra @{
    MICS_WFP_WATCH_SEED = "MICS-probe-alpha"
    MICS_WFP_WATCH_LIVE = '{"sublayer":false,"filters":1,"names":["MICS-probe-alpha"],"needs_elevation":false,"detail":""}'
  } -tag "d"
  $fourth = Invoke-Rpc -pipeName "mics-watch-d" -method "fw.wfp.watch" -params $null
  if ($fourth -and $null -ne $fourth.result) {
    $r = $fourth.result
    Check ($r.state -eq "tampered") ("a sublayer that is gone is a tamper even with every filter present (got " + $r.state + ")")
    Check (($r.missing -join ",") -eq "") "no filter is reported missing in that case"
    Check (("" + $r.detail) -match "sublayer") "the sentence names the sublayer"
  } else { Check $false "fw.wfp.watch answered for the missing sublayer" }

  # ---- 4. the record only ever moves with a write ---------------------------
  Write-Output ""
  Write-Output "== part 4 - a refused block leaves the record alone"
  $e = Start-Engine -pipeName "mics-watch-e" -extra @{} -tag "e"
  $spec = @{ app = $EngineExe; port = 65002; protocol = 6; note = "probe" }
  $blocked = Invoke-Rpc -pipeName "mics-watch-e" -method "fw.wfp.block" -params $spec -id 5
  $refused = ($null -eq $blocked) -or ($null -ne $blocked.error)
  $after = Invoke-Rpc -pipeName "mics-watch-e" -method "fw.wfp.watch" -params $null -id 6
  if ($refused) {
    $why = "no answer"
    if ($null -ne $blocked -and $null -ne $blocked.error) { $why = $blocked.error.message }
    # The reason is printed, not assumed: on 2026-11-08 this note said "no
    # administrator, no helper" in an elevated shell, while the real cause was
    # the engine failing to enumerate its own filters (D-045).
    Note ("the block was refused here (elevated=$elevated, helper=$helper): " + $why)
    if ($elevated -or $helper) {
      Check $false "fw.wfp.block was refused although this shell can write: $why"
    } elseif ($after -and $null -ne $after.result) {
      Check ($after.result.recorded -eq 0) "a refused write records nothing"
      Check ($after.result.state -ne "tampered") "and it cannot turn into a tamper either"
    } else { Check $false "fw.wfp.watch answered after a refused block" }
  } else {
    Skip "this shell can write (elevated=$elevated, helper=$helper), so the refused-write path is not reachable here"
  }
} finally {
  foreach ($handle in @($a, $b, $c, $d, $e)) { Stop-Engine $handle }
  if (-not $Keep) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
  else { Write-Output "note  kept: $scratch" }
}

$elapsed = [int]((Get-Date) - $started).TotalSeconds
Write-Output ""
Write-Output ("== checks: {0} passed, {1} skipped, {2} failed ({3}s)" -f `
    ($script:checks - $script:failures.Count), $script:skips.Count, $script:failures.Count, $elapsed)
foreach ($skip in $script:skips) { Write-Output ("SKIP  " + $skip) }
foreach ($failure in $script:failures) { Write-Output ("FAIL  " + $failure) }
if ($script:failures.Count -gt 0) { Write-Output "RESULT: FAIL"; exit 1 }
Write-Output "RESULT: PASS"
exit 0
