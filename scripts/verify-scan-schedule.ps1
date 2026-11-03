<#
.SYNOPSIS
  Proves the scan schedule (D-027) runs a scan on its own, reports instead of
  quarantining, and stays quiet when it is off.

.DESCRIPTION
  The schedule is a timer inside the engine: a setting (`scan_interval_hours`,
  0 = off), a target (`scan_target`, empty = the profile folder) and the last
  start it records in the state database. None of that can be asserted from a
  unit test alone - the whole point is that it happens with nobody watching - so
  this probe starts a real engine with an isolated data directory and a folder of
  its own, and measures three claims:

    1. off means off: with `scan_interval_hours = 0` the engine starts, answers
       `scan.schedule`, and starts no scan at all;
    2. due means due: with an interval set and no recorded start, the first tick
       starts a scan over the configured folder without anyone asking - the job
       appears in `job.list` with that root, and it finds the planted file;
    3. report-only: the planted file is **still there** afterwards. A scheduled
       run never quarantines, because nobody chose a file while it was running.

  The planted file is a ransom-note-shaped text file that the bundled starter
  pack's `Ransom_Note_Names` rule matches. It is deliberately *not* an EICAR
  sample: Windows Defender quarantines that the moment it is written, which made
  the first version of this probe measure Defender instead of MI CS (the engine
  saw the file, the read failed, and the job recorded a skip).

  It never touches this machine's real data directory, the real service, or
  `dist\`: everything happens under %TEMP%\mics-verify-scan-schedule-<guid8>,
  which is removed unless -Keep is passed.

.PARAMETER EngineExe
  The engine to drive. Default: engine\target\release\mics-engine.exe, then
  engine\target\debug\mics-engine.exe.

.PARAMETER WaitMs
  How long to wait for the scheduled scan to finish (default 40000).

.PARAMETER Keep
  Leave the scratch folder and its logs in place.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-scan-schedule.ps1

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9). No elevation: the engine runs as the
  current user against a private data directory and a private pipe.
#>
param(
  [string]$EngineExe,
  [int]$WaitMs = 40000,
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

$script:checks = 0
$script:failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$text) {
  $script:checks++
  if ($ok) { Write-Output "PASS  $text" }
  else { $script:failures.Add($text); Write-Output "FAIL  $text" }
}

$started = Get-Date
$scratch = Join-Path $env:TEMP ("mics-verify-scan-schedule-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$dataA = Join-Path $scratch "data-off"
$dataB = Join-Path $scratch "data-on"
$target = Join-Path $scratch "target"
New-Item -ItemType Directory -Path $dataA, $dataB, $target -Force | Out-Null

# Matches the bundled `Ransom_Note_Names` rule; harmless to every real scanner.
$sample = Join-Path $target "README_DECRYPT.txt"
Set-Content -LiteralPath $sample -Value "your files have been encrypted - this is a probe fixture, not malware" -Encoding ascii
Check (Test-Path $sample) "planted the scan fixture (a ransom-note string the starter pack detects)"

function Write-Settings([string]$dir, [int]$hours, [string]$scanTarget) {
  $settings = [ordered]@{
    scan_interval_hours = $hours
    scan_target         = $scanTarget
  }
  $json = $settings | ConvertTo-Json
  $path = Join-Path $dir "settings.json"
  [System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
  return $path
}

# One JSON-RPC request / response pair over the engine's pipe. Notifications
# (progress, job_finished, alerts) arrive first, so the answer is the object
# carrying this request's id.
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
    $deadline = (Get-Date).AddSeconds(15)
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

# Drives one engine session over its own pipe and returns whatever the script
# block returned (plus the engine's own log lines, for a failure message).
function Invoke-Engine([string]$dataDir, [string]$pipeName, [string[]]$argv, [scriptblock]$body) {
  $env:MICS_DATA_DIR = $dataDir
  $env:MICS_PIPE_NAME = $pipeName
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $out = Join-Path $dataDir "stdout.log"
  $err = Join-Path $dataDir "stderr.log"
  $proc = Start-Process -FilePath $EngineExe -ArgumentList $argv -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
  try {
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
      if (Test-Path "\\.\pipe\$pipeName") { break }
      Start-Sleep -Milliseconds 200
    }
    $value = & $body $pipeName
    return @{ Value = $value; Err = (Get-Content $err -ErrorAction SilentlyContinue) }
  } finally {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
  }
}

Write-Output ""
Write-Output "== engine: $EngineExe"
Write-Output "== scratch: $scratch"

# ---- 1. off means off -----------------------------------------------------
Write-Output ""
Write-Output "== part 1 - scan_interval_hours = 0 starts nothing"
Write-Settings -dir $dataA -hours 0 -scanTarget $target | Out-Null
$off = Invoke-Engine -dataDir $dataA -pipeName ("mics-sched-off-" + [guid]::NewGuid().ToString("N").Substring(0, 6)) -argv @("service") -body {
  param($pipe)
  $state = Invoke-Rpc -pipeName $pipe -method "scan.schedule" -params $null
  Start-Sleep -Seconds 4
  $jobs = Invoke-Rpc -pipeName $pipe -method "job.list" -params $null -id 2
  return [pscustomobject]@{ state = $state; jobs = $jobs }
}
Check ($null -ne $off.Value.state) "the engine answered scan.schedule"
Check ($null -ne $off.Value.state -and $off.Value.state.result.enabled -eq $false) "it reports the schedule as off"
Check ($null -ne $off.Value.state -and $off.Value.state.result.interval_hours -eq 0) "interval_hours is 0"
Check ($null -ne $off.Value.jobs -and @($off.Value.jobs.result).Count -eq 0) "no job was started while the schedule was off"

# ---- 2. due means due -----------------------------------------------------
Write-Output ""
Write-Output "== part 2 - an interval set starts a scan by itself, over the configured folder"
Write-Settings -dir $dataB -hours 1 -scanTarget $target | Out-Null
$on = Invoke-Engine -dataDir $dataB -pipeName ("mics-sched-on-" + [guid]::NewGuid().ToString("N").Substring(0, 6)) -argv @("service") -body {
  param($pipe)
  $state = Invoke-Rpc -pipeName $pipe -method "scan.schedule" -params $null
  $jobId = $null
  $jobs = $null
  $one = $null
  $deadline = (Get-Date).AddMilliseconds($WaitMs)
  while ((Get-Date) -lt $deadline -and -not $jobId) {
    Start-Sleep -Milliseconds 500
    $jobs = Invoke-Rpc -pipeName $pipe -method "job.list" -params $null -id 2
    if ($jobs -and $jobs.result -and @($jobs.result).Count -gt 0) { $jobId = $jobs.result[0].job_id }
  }
  if ($jobId) {
    $deadline = (Get-Date).AddMilliseconds($WaitMs)
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Milliseconds 500
      $one = Invoke-Rpc -pipeName $pipe -method "job.get" -params @{ job_id = $jobId } -id 3
      if ($one -and $one.result.job -and $one.result.job.state -ne "running") { break }
    }
  }
  return [pscustomobject]@{ state = $state; jobs = $jobs; job = $one }
}
$stateValue = $on.Value.state
$jobsValue = $on.Value.jobs
$oneValue = $on.Value.job
Check ($null -ne $stateValue -and $stateValue.result.enabled -eq $true) "it reports the schedule as on"
Check ($null -ne $stateValue -and $stateValue.result.interval_hours -eq 1) "interval_hours is the one that was set"
Check ($null -ne $stateValue -and $stateValue.result.target -eq $target) "the target is the folder that was configured"
Check ($null -ne $jobsValue -and @($jobsValue.result).Count -ge 1) "a scan job started without anyone asking"
if ($jobsValue -and @($jobsValue.result).Count -ge 1) {
  Check ($jobsValue.result[0].root -eq $target) "the job's root is the configured folder"
}
Check ($null -ne $oneValue -and $oneValue.result.job.state -eq "done") "the job finished"
if ($null -ne $oneValue) {
  Check ($oneValue.result.job.scanned -ge 1) "it examined the planted file (scanned = $($oneValue.result.job.scanned))"
  Check (@($oneValue.result.findings).Count -ge 1) "it recorded the finding the starter pack detects"
  if (@($oneValue.result.findings).Count -ge 1) {
    Check ($oneValue.result.findings[0].reason -eq "yara:Ransom_Note_Names") "the finding is the YARA rule, not something else"
  }
}
Check (Test-Path $sample) "report-only: the planted file is still where it was"

# ---- 3. the record --------------------------------------------------------
Write-Output ""
Write-Output "== part 3 - the start is recorded, so a restart does not scan again"
$again = Invoke-Engine -dataDir $dataB -pipeName ("mics-sched-again-" + [guid]::NewGuid().ToString("N").Substring(0, 6)) -argv @("service") -body {
  param($pipe)
  Start-Sleep -Seconds 4
  $state = Invoke-Rpc -pipeName $pipe -method "scan.schedule" -params $null
  $jobs = Invoke-Rpc -pipeName $pipe -method "job.list" -params $null -id 2
  return [pscustomobject]@{ state = $state; jobs = $jobs }
}
$restartState = $again.Value.state
Check ($null -ne $restartState -and $null -ne $restartState.result.last_started) "the last start is remembered across a restart"
if ($null -ne $restartState -and $null -ne $restartState.result.last_started) {
  $when = [DateTimeOffset]::FromUnixTimeSeconds([int64]$restartState.result.last_started).LocalDateTime
  $ageMinutes = [Math]::Round(((Get-Date) - $when).TotalMinutes, 1)
  Check ($ageMinutes -ge 0 -and $ageMinutes -lt 15) "it was recorded minutes ago ($ageMinutes), not on this restart"
}
Check (@($again.Value.jobs.result).Count -eq 1) "the restart did not start a second scan (jobs = $(@($again.Value.jobs.result).Count))"

$seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
if (-not $Keep) {
  Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item Env:MICS_DATA_DIR, Env:MICS_PIPE_NAME, Env:MICS_NO_SINGLETON, Env:MICS_NO_GUARD, Env:MICS_NO_AUTO_RESUME -ErrorAction SilentlyContinue
} else {
  Write-Output ""
  Write-Output "kept: $scratch"
}
Write-Output ""
Write-Output ("{0} check(s), {1} failure(s), {2} s" -f $script:checks, $script:failures.Count, $seconds)
if ($script:failures.Count -eq 0) {
  Write-Output "RESULT: PASS - the schedule starts a scan on its own, reports and does not quarantine"
  exit 0
}
Write-Output "RESULT: FAIL"
foreach ($f in $script:failures) { Write-Output "  - $f" }
Write-Output "--- engine stderr (part 2):"
$on.Err | Select-Object -Last 25
exit 1