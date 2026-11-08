<#
.SYNOPSIS
  Proves the engine's life is tied to the app that started it, in both
  directions: it stops when that app stops, and it stops when it is asked to.

.DESCRIPTION
  Until D-039 the engine was started detached and never stopped: closing MI CS
  left `mics-engine.exe` running, and nothing but Task Manager could change
  that. The engine now has two deliberate ways to end, and this probe measures
  both against this machine, with a private data directory, a private pipe and
  a stand-in "app" process under %TEMP%\mics-verify-lifecycle-<guid8>:

    1. the app's process is the engine's lifetime: the engine is started with
       `--parent <pid of a stand-in app>`, is still serving while that process
       lives, and exits within seconds of it being killed - with the reason in
       its log, and without filing a crash report (a killed app is not an
       engine crash);
    2. `shutdown` stops an engine that no app owns, and *answers first*: the
       reply says `stopping` and arrives before the process ends, which is what
       lets the UI tell "my engine is stopping" from "I lost the engine";
    3. a parent that is already gone is not a race: an engine started with a
       dead `--parent` ends by itself instead of serving a machine whose owner
       is missing - and an engine nobody owns keeps running, which is what the
       autostart entry and a verifier rely on;
    4. the flag really is on the command line (`service --help`), so a caller
       cannot pass a parent the engine silently ignores.

  Not measured here: the UI's own half (it asks for a shutdown only when it
  started the engine, decided by comparing `status.pid` with the pid it spawned).
  That needs the window, and it is the client's two-line policy; the engine's
  half - the part that cannot be worked around - is what runs below.

.PARAMETER EngineExe
  The engine to drive. Default: the *newest* of
  engine\target\release\mics-engine.exe and engine\target\debug\mics-engine.exe.

.PARAMETER Keep
  Leave the scratch folder and its logs in place.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-lifecycle.ps1
  powershell -ExecutionPolicy Bypass -File scripts\verify-lifecycle.ps1 -EngineExe engine\target\debug\mics-engine.exe

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9).
#>
param(
  [string]$EngineExe,
  [switch]$Keep
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if (-not $EngineExe) {
  # Newest, not first-found: a stale release build next to a fresh debug one
  # would otherwise be probed as if it were the current code.
  $candidates = @(
    (Join-Path $root "engine\target\release\mics-engine.exe"),
    (Join-Path $root "engine\target\debug\mics-engine.exe")
  ) | Where-Object { Test-Path $_ } | Sort-Object { (Get-Item $_).LastWriteTime } -Descending
  if ($candidates.Count -gt 0) { $EngineExe = $candidates[0] }
}
if (-not $EngineExe -or -not (Test-Path $EngineExe)) {
  Write-Output "RESULT: FAIL - no engine binary; build it (scripts\pipeline.ps1 -Tier full) or pass -EngineExe"
  exit 1
}
$EngineExe = (Resolve-Path $EngineExe).Path

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

$started = Get-Date
$scratch = Join-Path $env:TEMP ("mics-verify-lifecycle-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
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
    $deadline = (Get-Date).AddSeconds(20)
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

# A stand-in "app": a process whose lifetime this script controls. `ping -n 600`
# keeps cmd alive for about ten minutes unless it is killed first. Its output
# goes to a file on purpose: a child that inherited the caller's stdout would
# keep that pipe open, and a probe that hangs its own caller proves nothing.
function Start-StandInApp {
  $out = Join-Path $scratch "standin.stdout.log"
  $err = Join-Path $scratch "standin.stderr.log"
  Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "ping -n 600 127.0.0.1 >NUL") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
}

# `ping` is cmd's child, so killing cmd alone would leave it behind for ten
# minutes; `/T` takes the tree. A process that is already gone is not an error
# here - this runs from `finally` too, where the point is to leave nothing.
function Stop-Tree([int]$processId) {
  if ($processId -le 0) { return }
  $previous = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try { & taskkill.exe /PID $processId /T /F 2>&1 | Out-Null } catch { }
  $ErrorActionPreference = $previous
}

function Start-IsolatedEngine([string]$pipeName, [string]$dataDir, [int]$parentPid, [string]$tag) {
  New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
  $env:MICS_DATA_DIR = $dataDir
  $env:MICS_PIPE_NAME = "\\.\pipe\$pipeName"
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $env:MICS_NO_SCAN_SCHEDULE = "1"
  $arguments = @("service")
  if ($parentPid -gt 0) { $arguments += @("--parent", "$parentPid") }
  $out = Join-Path $scratch "$tag.stdout.log"
  $err = Join-Path $scratch "$tag.stderr.log"
  $proc = Start-Process -FilePath $EngineExe -ArgumentList $arguments -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
  [pscustomobject]@{ Proc = $proc; Out = $out; Err = $err; Pipe = $pipeName; Data = $dataDir }
}

function Wait-Exit($proc, [int]$seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $true }
    Start-Sleep -Milliseconds 200
  }
  return $proc.HasExited
}

function Wait-Log($path, [string]$pattern, [int]$seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    $text = (Get-Content $path -ErrorAction SilentlyContinue) -join "`n"
    if ($text -match $pattern) { return $true }
    Start-Sleep -Milliseconds 200
  }
  return $false
}

function Get-Log($path) { ((Get-Content $path -ErrorAction SilentlyContinue) -join "`n") }

# A crash report (or the session marker's "never said goodbye") landing in the
# sandbox is how an unclean end is proved, so the assertion is "nothing at all".
function Get-CrashReports([string]$dataDir) {
  $dir = Join-Path $dataDir "crash"
  if (-not (Test-Path $dir)) { return @() }
  @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)
}

$engineItem = Get-Item $EngineExe
Write-Output ""
Write-Output "== engine: $EngineExe"
Write-Output "== built:  $($engineItem.LastWriteTime)"
Write-Output "== scratch: $scratch"

$standIn = $null
$engineOne = $null
$engineTwo = $null
try {
  # ---- 1. the app's process is the engine's lifetime ------------------------
  Write-Output ""
  Write-Output "== part 1 - a killed app takes its engine with it"
  $standIn = Start-StandInApp
  Start-Sleep -Milliseconds 500
  Check (-not $standIn.HasExited) "a stand-in app is running (pid $($standIn.Id))"

  $engineOne = Start-IsolatedEngine -pipeName "mics-lifecycle-a" -dataDir (Join-Path $scratch "data-a") -parentPid $standIn.Id -tag "a"
  $watched = Wait-Log $engineOne.Err "watching the app that started this engine \(pid $($standIn.Id)\)" 25
  Check $watched "the engine took the app as its parent (--parent was parsed and honoured)"
  $served = Wait-Log $engineOne.Err "Starting Named Pipe server" 25
  Check $served "the engine came up and served while its app was alive"
  Start-Sleep -Seconds 2
  Check (-not $engineOne.Proc.HasExited) "the engine stayed up for as long as the app did"

  Stop-Tree $standIn.Id
  $exited = Wait-Exit $engineOne.Proc 20
  Check $exited "the engine exited when the app was killed"
  $logOne = Get-Log $engineOne.Err
  Check ($logOne -match "shutdown requested: the app that started this engine \(pid $($standIn.Id)\) exited") `
    "the engine's log names the app as the reason it stopped"
  Check ($logOne -match "engine stopping: ") "the engine logged its own end"
  Check ((Get-CrashReports $engineOne.Data).Count -eq 0) `
    "no crash report was filed for it (a killed app is not an engine crash)"

  # ---- 2. shutdown answers first, then stops a parentless engine ----------
  Write-Output ""
  Write-Output "== part 2 - shutdown stops an engine that no app owns, and answers first"
  $engineTwo = Start-IsolatedEngine -pipeName "mics-lifecycle-b" -dataDir (Join-Path $scratch "data-b") -parentPid 0 -tag "b"
  $served = Wait-Log $engineTwo.Err "Starting Named Pipe server" 25
  Check $served "an engine started without --parent came up"
  Start-Sleep -Seconds 2
  Check (-not $engineTwo.Proc.HasExited) "nothing stops an engine that no app owns"
  $status = Invoke-Rpc -pipeName $engineTwo.Pipe -method "status" -params $null -id 1
  Check ($status -and $null -ne $status.result -and $null -ne $status.result.pid) "it answered status with its pid"

  $reply = Invoke-Rpc -pipeName $engineTwo.Pipe -method "shutdown" -params $null -id 2
  $stopping = $false
  if ($reply -and $null -ne $reply.result) { $stopping = ("$($reply.result.status)" -eq "stopping") }
  Check $stopping "the shutdown reply said `stopping` before the process ended"
  $exited = Wait-Exit $engineTwo.Proc 15
  Check $exited "the process ended after that reply"
  $logTwo = Get-Log $engineTwo.Err
  Check ($logTwo -match "shutdown requested: the app asked the engine to stop \(shutdown\)") `
    "its log says the shutdown method was the reason"
  Check ((Get-CrashReports $engineTwo.Data).Count -eq 0) "it ended cleanly, with no crash report"

  # ---- 3. a parent that was already gone ----------------------------------
  Write-Output ""
  Write-Output "== part 3 - a --parent that is already gone ends the engine"
  # Far above any real pid, so Windows has no such process to wait on.
  $deadPid = 4294967280
  New-Item -ItemType Directory -Path (Join-Path $scratch "data-c") -Force | Out-Null
  $env:MICS_DATA_DIR = Join-Path $scratch "data-c"
  $env:MICS_PIPE_NAME = "\\.\pipe\mics-lifecycle-c"
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $env:MICS_NO_SCAN_SCHEDULE = "1"
  $outC = Join-Path $scratch "c.stdout.log"
  $errC = Join-Path $scratch "c.stderr.log"
  $procC = Start-Process -FilePath $EngineExe -ArgumentList @("service", "--parent", "$deadPid") -PassThru -NoNewWindow `
    -RedirectStandardOutput $outC -RedirectStandardError $errC
  $exited = Wait-Exit $procC 20
  Check $exited "an engine whose app is already gone ends by itself"
  $logC = Get-Log $errC
  Check ($logC -match "was already gone") "its log says the app was already gone, not that it crashed"
  Check ((Get-CrashReports (Join-Path $scratch "data-c")).Count -eq 0) "and it filed no crash report"

  # ---- 4. the flag is part of the command line ----------------------------
  Write-Output ""
  Write-Output "== part 4 - the parent is a documented argument of service"
  $help = (& $EngineExe service --help 2>&1) -join "`n"
  Check ($help -match "--parent") "service --help lists --parent"

  # Cleanup of the two engines this part started is in `finally`.
} finally {
  if ($standIn -and -not $standIn.HasExited) { Stop-Tree $standIn.Id }
  foreach ($engine in @($engineOne, $engineTwo)) {
    if ($engine -and -not $engine.Proc.HasExited) {
      Stop-Process -Id $engine.Proc.Id -Force -ErrorAction SilentlyContinue
    }
  }
  if ($procC -and -not $procC.HasExited) { Stop-Process -Id $procC.Id -Force -ErrorAction SilentlyContinue }
  # A stand-in that was killed mid-run leaves no tree behind either.
  Stop-Tree $standIn.Id
  Start-Sleep -Milliseconds 400
  Remove-Item Env:MICS_DATA_DIR, Env:MICS_PIPE_NAME, Env:MICS_NO_SINGLETON, Env:MICS_NO_GUARD, Env:MICS_NO_AUTO_RESUME, Env:MICS_NO_SCAN_SCHEDULE -ErrorAction SilentlyContinue
  $left = @(Get-Process -Name "mics-engine" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $EngineExe })
  if ($left.Count -gt 0) {
    Write-Output "WARN  an engine this probe started is still running (pid $($left.Id -join ', '))"
  }
  if (-not $Keep) {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
  } else {
    Write-Output ""
    Write-Output "kept: $scratch"
  }
}

$seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
Write-Output ""
foreach ($s in $script:skips) { Write-Output "not measured: $s" }
Write-Output ("{0} check(s), {1} skipped section(s), {2} failure(s), {3} s" -f $script:checks, $script:skips.Count, $script:failures.Count, $seconds)
if ($script:failures.Count -eq 0) {
  Write-Output "RESULT: PASS - the engine ends with the app that started it, and answers a shutdown before it does"
  exit 0
}
Write-Output "RESULT: FAIL"
foreach ($f in $script:failures) { Write-Output "  - $f" }
foreach ($log in @((Join-Path $scratch "a.stderr.log"), (Join-Path $scratch "b.stderr.log"), (Join-Path $scratch "c.stderr.log"))) {
  if (Test-Path $log) {
    Write-Output "--- $log"
    Get-Content $log | Select-Object -Last 15
  }
}
exit 1
