<#
.SYNOPSIS
  Proves the single-instance handoff (D-041) with two real clients on one pipe:
  the activation a second launch sends reaches the client that is already
  attached, carries Explorer's `--scan` path, and answers "nobody is here" when
  the window has closed.

.DESCRIPTION
  Explorer's "Scan with MI CS" verb starts a new MI CS process with
  `--scan "<path>"` (installer/mics.nsi), and so does every later launch of the
  app. A second window with its own engine would be two apps showing one machine,
  so the newcomer asks the engine - the only thing both processes share - whether
  another transport is attached, and ends when one is.

  This script measures the engine's half of that against this machine, with a
  private data directory and a private pipe, using two
  NamedPipeClientStream connections the way the two app windows use two pipe
  handles:

    1. `app.activate` reaches the connection that is already attached, as an
       `event` notification (a notification, not a reply: nothing to answer);
    2. the path survives the trip unchanged, spaces and all;
    3. a plain second launch (no `--scan`) is the same handover with a null path,
       so the window comes forward and scans nothing;
    4. alone, the caller is told `delivered: false` - it is the window - and
       nothing is raised that only the caller could read back.

  Not measured here: the window's own half (raise it, show the scanner, start
  the scan). That needs the app; it is covered by test/handoff_test.dart. The
  verb's registry keys belong to the installer and are checked by
  scripts\verify-installer.ps1.

.PARAMETER EngineExe
  The engine to drive. Default: the *newest* of
  engine\target\release\mics-engine.exe and engine\target\debug\mics-engine.exe.

.PARAMETER Keep
  Leave the scratch folder and its logs in place.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-handoff.ps1
  powershell -ExecutionPolicy Bypass -File scripts\verify-handoff.ps1 -EngineExe engine\target\debug\mics-engine.exe

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
$script:failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$text) {
  $script:checks++
  if ($ok) { Write-Output "PASS  $text" }
  else { $script:failures.Add($text); Write-Output "FAIL  $text" }
}

$started = Get-Date
$scratch = Join-Path $env:TEMP ("mics-verify-handoff-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$pipeName = "mics-handoff-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$dataDir = Join-Path $scratch "data"

# The two connections are the two windows. `Asynchronous` is what makes a read
# with a deadline possible at all: without it ReadLineAsync would run on this
# thread and a missing message would hang the probe instead of failing it.
function Open-Pipe([string]$name) {
  $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $name,
    [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
  try { $client.Connect(5000) } catch { $client.Dispose(); throw }
  $writer = New-Object System.IO.StreamWriter($client)
  $writer.AutoFlush = $true
  [pscustomobject]@{
    Client = $client
    Writer = $writer
    Reader = (New-Object System.IO.StreamReader($client))
    Id     = 0
    Skipped = (New-Object System.Collections.Generic.List[string])
  }
}

function Close-Pipe($conn) {
  if ($null -eq $conn) { return }
  try { $conn.Client.Dispose() } catch { }
}

# One line, or $null when nothing arrived inside the deadline. A timed-out read
# is still pending on that stream, so the caller must not read from it again.
function Read-Line($conn, [int]$timeoutMs) {
  $task = $conn.Reader.ReadLineAsync()
  if (-not $task.Wait($timeoutMs)) { return $null }
  return $task.Result
}

# Sends one request and returns the reply with the matching id. A notification
# that arrives first (the activation itself, when the caller is a client too) is
# set aside rather than answered.
#
# A read that runs out of time leaves that read pending on the stream, so this
# returns instead of reading again: the caller decides whether that connection is
# still usable, and a $null reply means it is not.
function Send-Rpc($conn, [string]$method, $params) {
  $conn.Id++
  $payload = @{ jsonrpc = "2.0"; id = $conn.Id; method = $method }
  if ($null -ne $params) { $payload["params"] = $params }
  $conn.Writer.Write((($payload | ConvertTo-Json -Depth 8 -Compress) + "`n"))
  $line = Read-Line $conn 20000
  while ($null -ne $line) {
    $obj = $null
    try { $obj = $line | ConvertFrom-Json } catch { $obj = $null }
    if ($null -ne $obj -and $obj.PSObject.Properties.Name -contains "id" -and $obj.id -eq $conn.Id) { return $obj }
    $conn.Skipped.Add($line)
    $line = Read-Line $conn 20000
  }
  return $null
}

function Convert-Line([string]$line) {
  if ($null -eq $line) { return $null }
  try { return ($line | ConvertFrom-Json) } catch { return $null }
}

# A stand-in "app": the process whose lifetime the engine is tied to, so the
# probe leaves no engine behind even if it fails half way.
function Start-StandInApp {
  $out = Join-Path $scratch "standin.stdout.log"
  $err = Join-Path $scratch "standin.stderr.log"
  Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "ping -n 600 127.0.0.1 >NUL") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
}

# `ping` is cmd's child, so killing cmd alone would leave it behind for ten
# minutes; `/T` takes the tree.
function Stop-Tree([int]$processId) {
  if ($processId -le 0) { return }
  $previous = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try { & taskkill.exe /PID $processId /T /F 2>&1 | Out-Null } catch { }
  $ErrorActionPreference = $previous
}

function Start-IsolatedEngine([string]$name, [string]$dir, [int]$parentPid) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  # Private pipe + private data: this probe must not see, or be seen by, the
  # engine the user is actually running.
  $env:MICS_DATA_DIR = $dir
  $env:MICS_PIPE_NAME = "\\.\pipe\$name"
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $env:MICS_NO_SCAN_SCHEDULE = "1"
  $arguments = @("service")
  if ($parentPid -gt 0) { $arguments += @("--parent", "$parentPid") }
  $out = Join-Path $scratch "engine.stdout.log"
  $err = Join-Path $scratch "engine.stderr.log"
  Start-Process -FilePath $EngineExe -ArgumentList $arguments -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
}

$engineItem = Get-Item $EngineExe
Write-Output ""
Write-Output "== engine: $EngineExe"
Write-Output "== built:  $($engineItem.LastWriteTime)"
Write-Output "== scratch: $scratch"

$standIn = $null
$engine = $null
$caller = $null
$listener = $null
try {
  Write-Output ""
  Write-Output "== part 1 - a second launch reaches the window that is already open"
  $standIn = Start-StandInApp
  Start-Sleep -Milliseconds 500
  $engine = Start-IsolatedEngine -name $pipeName -dir $dataDir -parentPid $standIn.Id

  for ($i = 0; $i -lt 40 -and $null -eq $caller; $i++) {
    try { $caller = Open-Pipe $pipeName } catch { Start-Sleep -Milliseconds 250 }
  }
  Check ($null -ne $caller) "the engine is listening on its private pipe ($pipeName)"
  if ($null -eq $caller) { throw "no pipe to probe" }

  $pong = Send-Rpc $caller "ping" $null
  Check ($null -ne $pong -and $pong.result -eq "pong") "the caller connection speaks JSON-RPC (ping -> pong)"

  # The window: attached, idle, and waiting for whatever the engine pushes.
  $listener = Open-Pipe $pipeName
  Start-Sleep -Milliseconds 300

  $path = "C:\Users\probe\Downloads\report final.pdf"
  $reply = Send-Rpc $caller "app.activate" @{ path = $path }
  Check ($null -ne $reply -and $reply.result.delivered -eq $true) `
    "with a window attached, the launch is handed over (delivered: true)"

  $note = Convert-Line (Read-Line $listener 5000)
  Check ($null -ne $note -and $note.method -eq "event" -and $note.params.type -eq "activate") `
    "the attached window is told about the activation (event / activate)"
  Check ($null -ne $note -and $note.params.data.path -eq $path) `
    "and the path survives the trip unchanged, spaces included"
  Check ($null -ne $note -and -not ($note.PSObject.Properties.Name -contains "id")) `
    "the activation is a notification, so the window has nothing to answer"

  Write-Output ""
  Write-Output "== part 2 - a plain second launch only comes forward"
  # A fresh window: the one above was read once, and a connection whose read ran
  # out of time cannot be read again.
  Close-Pipe $listener
  $listener = Open-Pipe $pipeName
  Start-Sleep -Milliseconds 300
  $reply2 = Send-Rpc $caller "app.activate" $null
  Check ($null -ne $reply2 -and $reply2.result.delivered -eq $true) `
    "a second launch with no --scan is handed over too"
  $note2 = Convert-Line (Read-Line $listener 5000)
  Check ($null -ne $note2 -and $note2.params.type -eq "activate" -and $null -eq $note2.params.data.path) `
    "it carries a null path, so the window comes forward and scans nothing"

  Write-Output ""
  Write-Output "== part 3 - alone, the launch is the window"
  # The window closes; the engine notices when its transport ends. How long that
  # takes is a scheduling detail, so the answer is polled rather than assumed.
  Close-Pipe $listener
  $listener = $null
  $delivered = $null
  for ($i = 0; $i -lt 24; $i++) {
    Start-Sleep -Milliseconds 250
    $reply3 = Send-Rpc $caller "app.activate" @{ path = $path }
    if ($null -eq $reply3) { break }
    $delivered = $reply3.result.delivered
    if ($delivered -eq $false) { break }
  }
  Check ($delivered -eq $false) "with no window attached, the caller is told it is the window (delivered: false)"

  # The caller's own notifications arrive before its replies on its own pipe, so
  # by now anything that was raised for it has been read: a message nobody else
  # can hear must not be raised at all. This is the last read on that connection.
  if ($delivered -eq $false) {
    $stray = Read-Line $caller 1500
    Check ($null -eq $stray) "and nothing was raised for a caller that has nobody to hand over to"
  }
} finally {
  Close-Pipe $listener
  Close-Pipe $caller
  if ($engine -and -not $engine.HasExited) { Stop-Process -Id $engine.Id -Force -ErrorAction SilentlyContinue }
  if ($standIn -and -not $standIn.HasExited) { Stop-Tree $standIn.Id }
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
Write-Output ("{0} check(s), {1} failure(s), {2} s" -f $script:checks, $script:failures.Count, $seconds)
if ($script:failures.Count -eq 0) {
  Write-Output "RESULT: PASS - a second launch hands over to the window that is open, and knows when there is none"
  exit 0
}
Write-Output "RESULT: FAIL"
foreach ($f in $script:failures) { Write-Output "  - $f" }
foreach ($log in @((Join-Path $scratch "engine.stderr.log"), (Join-Path $scratch "engine.stdout.log"))) {
  if (Test-Path $log) {
    Write-Output "--- $log"
    Get-Content $log | Select-Object -Last 15
  }
}
exit 1
