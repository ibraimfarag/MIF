<#
.SYNOPSIS
  Proves a decoy *read* is detected, that the watcher cannot trip its own trap,
  and that the volume's read coverage is measured rather than assumed.

.DESCRIPTION
  A write, rename or delete on a decoy moves mtime or size and was always caught.
  A read-only open moves neither, which is why it used to be invisible; it does
  move the file's last-access time, and the guard's snapshot carries that time
  now. None of this can be asserted from a unit test, because the whole question
  is a property of the filesystem and of this machine's policy, so this probe
  starts a real engine with a private data directory, a private pipe and a
  private USERPROFILE, and measures five claims:

    1. a decoy MI CS has just written is left quiet: MI CS creates one of the two
       decoys during `canary.configure`, and reading it right afterwards raises
       nothing - the engine's own log says it settled the read instead;
    2. a decoy MI CS did *not* write is read-sensitive at once: opening it
       read-only raises a HIGH `canary_read` event, and its mtime, size and hash
       are unchanged afterwards, so the event cannot be a disguised write;
    3. a write still wins: appending one byte to that same decoy raises the
       CRITICAL `canary_triggered` event, on its own rule id;
    4. the watcher cannot trip its own trap: fifty metadata queries in a row move
       no last-access time and raise no event - that is exactly what the guard's
       poll does on every tick;
    5. the coverage verdict is a measurement, not a constant: `canary.status`
       reports whether this volume keeps a last-access time, and that answer is
       compared with the same measurement taken independently in PowerShell. If
       the engine says reads cannot be seen here, part 2 is reported as SKIP with
       the reason instead of a pass - the way `verify-firewall.ps1` treats a write
       it cannot perform - because this probe never claims what it did not
       measure.

  Everything happens under %TEMP%\mics-verify-canary-<guid8>, which is removed
  unless -Keep is passed. USERPROFILE is pointed into that folder for the engine
  process alone, so the default decoy paths can never create a file in the real
  Documents folder. This machine's real data directory, the real `MICSHelper`
  service and `dist\` are never touched, and no elevation is needed: the read has
  to be visible on the unelevated poll path, without ETW.

.PARAMETER EngineExe
  The engine to drive. Default: engine\target\release\mics-engine.exe, then
  engine\target\debug\mics-engine.exe.

.PARAMETER WaitMs
  How long to wait for a guard event before calling it a miss (default 20000).

.PARAMETER Keep
  Leave the scratch folder and its logs in place.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-canary.ps1

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9). Guard on, singleton off, auto-resume
  off, and `guard_autostart` written to false so the decoys are configured before
  anything arms over them.
#>
param(
  [string]$EngineExe,
  [int]$WaitMs = 20000,
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

# One JSON-RPC request / response pair over the engine's pipe. Notifications
# (progress, alerts, guard events) arrive first, so the answer is the object
# carrying this request's id.
function Invoke-Rpc([string]$pipeName, [string]$method, $params, [int]$id = 1) {
  $payload = @{ jsonrpc = "2.0"; id = $id; method = $method }
  if ($null -ne $params) { $payload["params"] = $params }
  $text = ($payload | ConvertTo-Json -Depth 8 -Compress) + "`n"
  $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
  try {
    $client.Connect(5000)
  } catch {
    # No server (yet). The caller retries; this is not an error on its own.
    $client.Dispose()
    return $null
  }
  try {
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

# Readiness is a real request, not a path probe: `Test-Path \\.\pipe\x` opens a
# connection of its own, so asking it twice in a row races the server's accept
# loop and the second answer is a false negative.
function Wait-Ready([string]$pipeName, [int]$seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    $pong = Invoke-Rpc -pipeName $pipeName -method "ping" -params $null -id 1
    if ($null -ne $pong -and $null -ne $pong.result) { return $true }
    Start-Sleep -Milliseconds 400
  }
  return $false
}

# Every guard event becomes an incident, so this is the product's own record of
# what the guard saw. Counted by guard event type, never by log text.
function Get-GuardEvents([string]$pipeName) {
  $res = Invoke-Rpc -pipeName $pipeName -method "incident.list" -params @{ limit = 50 } -id 70
  if ($null -eq $res -or $null -eq $res.result) { return @() }
  $out = New-Object System.Collections.Generic.List[object]
  foreach ($inc in @($res.result)) {
    foreach ($ev in @($inc.timeline)) { $out.Add($ev) }
  }
  return $out
}
function Count-Events([string]$pipeName, [string]$type) {
  return @(Get-GuardEvents -pipeName $pipeName | Where-Object { $_.type -eq $type }).Count
}
function Wait-Event([string]$pipeName, [string]$type, [int]$seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    $hit = Get-GuardEvents -pipeName $pipeName | Where-Object { $_.type -eq $type } | Select-Object -First 1
    if ($null -ne $hit) { return $hit }
    Start-Sleep -Milliseconds 700
  }
  return $null
}
# Waits until an event count has stopped moving, so the next measurement starts
# from a quiet baseline instead of from a deferred last-access update.
function Wait-Quiet([string]$pipeName, [int]$seconds = 6) {
  $last = -1
  $stable = 0
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    $n = (Get-GuardEvents -pipeName $pipeName).Count
    if ($n -eq $last) { $stable++ } else { $stable = 0; $last = $n }
    if ($stable -ge 3) { return $last }
    Start-Sleep -Milliseconds 700
  }
  return $last
}

# The same measurement the engine makes at arm time, taken independently here:
# write a scratch file, read it, and see whether the last-access time moved.
function Measure-AtimeKept([string]$dir) {
  $p = Join-Path $dir ("pwsh-atime-probe-" + [guid]::NewGuid().ToString("N").Substring(0, 6))
  [System.IO.File]::WriteAllText($p, "probe")
  $before = (Get-Item -LiteralPath $p).LastAccessTime
  $null = [System.IO.File]::ReadAllText($p)
  Start-Sleep -Milliseconds 1300
  $after = (Get-Item -LiteralPath $p).LastAccessTime
  Remove-Item -LiteralPath $p -Force
  return ($after -gt $before)
}

$scratch = Join-Path $env:TEMP ("mics-verify-canary-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$dataDir = Join-Path $scratch "data"
$fakeProfile = Join-Path $scratch "profile"
$decoys = Join-Path $scratch "decoys"
$pipeName = "mics-canary-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$existing = Join-Path $decoys "existing-decoy.xlsx.canary"
$fresh = Join-Path $decoys "mics-created-decoy.txt.canary"
New-Item -ItemType Directory -Path $dataDir, $fakeProfile, (Join-Path $fakeProfile "Documents"), (Join-Path $fakeProfile "Desktop"), $decoys -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $dataDir "decoy-state") -Force | Out-Null

# A partial settings.json is merged onto the defaults; `guard_autostart = false`
# is what keeps the engine from arming the watchers before the decoys below are
# configured, which is the only way part 1 can measure the settle window.
$settingsPath = Join-Path $dataDir "settings.json"
[System.IO.File]::WriteAllText($settingsPath, (@{ guard_autostart = $false } | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))

# The decoy MI CS must NOT create. Same idea as the default decoys, written here
# so that "a decoy that was already on disk" is a real case and not a claim.
[System.IO.File]::WriteAllText($existing, "MI CS canary decoy file. If any program reads this file, something is wrong.`n")
$hashBefore = (Get-FileHash -LiteralPath $existing -Algorithm SHA256).Hash
$statBefore = Get-Item -LiteralPath $existing

Write-Output ""
Write-Output "== engine: $EngineExe"
Write-Output "== scratch: $scratch"
Write-Output "== pipe:    $pipeName"

$savedUserProfile = $env:USERPROFILE
$env:MICS_DATA_DIR = $dataDir
$env:MICS_PIPE_NAME = $pipeName
$env:MICS_NO_SINGLETON = "1"
$env:MICS_NO_AUTO_RESUME = "1"
$env:USERPROFILE = $fakeProfile
# MICS_NO_GUARD is deliberately NOT set: an unelevated guard on a poll is the
# path that has to see a read.
$out = Join-Path $scratch "stdout.log"
$err = Join-Path $scratch "stderr.log"
$proc = Start-Process -FilePath $EngineExe -ArgumentList @("service") -PassThru -NoNewWindow `
  -RedirectStandardOutput $out -RedirectStandardError $err
try {
  if (-not (Wait-Ready -pipeName $pipeName -seconds 30)) {
    throw "the engine never answered ping on \\.\pipe\$pipeName"
  }

  # ---- 0. the guard is armed over the decoys MI CS is told about ------------
  Write-Output ""
  Write-Output "== part 0 - configure the decoys, then start the guard"
  $start = Invoke-Rpc -pipeName $pipeName -method "guard.start" -params $null -id 10
  Check ($null -ne $start -and $start.result.status -eq "running") "guard.start answered running"
  $cfg = Invoke-Rpc -pipeName $pipeName -method "canary.configure" -params @{ paths = @($existing, $fresh) } -id 11
  Check ($null -ne $cfg -and $cfg.result.status -eq "saved") "canary.configure saved two decoy paths"
  Start-Sleep -Milliseconds 1500
  Check (Test-Path $fresh) "MI CS created the decoy it was pointed at (the settle-window case)"
  Check (Test-Path $existing) "the decoy that was already on disk is still the probe's own file"

  # ---- 1. a decoy MI CS just wrote is settled, not reported -----------------
  Write-Output ""
  Write-Output "== part 1 - a decoy MI CS just created is quiet inside its settle window"
  $readsBefore = Count-Events -pipeName $pipeName -type "canary_read"
  $null = [System.IO.File]::ReadAllText($fresh)
  Start-Sleep -Seconds 4
  $readsAfterFresh = Count-Events -pipeName $pipeName -type "canary_read"
  Check ($readsAfterFresh -eq $readsBefore) "reading a decoy MI CS had just created raised no canary_read event"
  $settledLine = @(Select-String -Path $err -Pattern "canary settling" -SimpleMatch -ErrorAction SilentlyContinue).Count
  Check ($settledLine -ge 1) "the engine's own log says it settled a read instead (it was seen, and deliberately not reported)"

  # ---- 5a. is a read even visible on this volume? --------------------------
  Write-Output ""
  Write-Output "== part 5 - the coverage verdict is a measurement"
  $status = Invoke-Rpc -pipeName $pipeName -method "canary.status" -params $null -id 12
  $verdict = $null
  if ($null -ne $status -and $null -ne $status.result.read_detection) {
    $verdict = [bool]$status.result.read_detection.available
  }
  $independent = Measure-AtimeKept -dir $decoys
  Check ($null -ne $verdict) "canary.status carries a read_detection verdict (not a constant, not absent)"
  Check ($verdict -eq $independent) "the engine's verdict matches the same measurement taken here independently (engine=$verdict, pwsh=$independent)"
  if ($null -ne $verdict) {
    Write-Output ("      read_detection.available = {0}; probed on {1}" -f $verdict, $status.result.read_detection.probed_on)
    Check ($status.result.read_detection.probed_on -eq $decoys) "the verdict names the folder the decoys are actually in, not the one they used to be in"
  }

  # ---- 2. a decoy that was already on disk is read-sensitive ---------------
  Write-Output ""
  Write-Output "== part 2 - a read-only open of a pre-existing decoy is detected"
  if ($verdict -ne $true) {
    Skip "part 2: this volume keeps no last-access time, so a read-only open cannot be seen here (the engine says so too, in canary.status)"
  } else {
    $null = [System.IO.File]::ReadAllBytes($existing)
    $ev = Wait-Event -pipeName $pipeName -type "canary_read" -seconds ($WaitMs / 1000)
    Check ($null -ne $ev) "opening the decoy read-only raised a canary_read event"
    if ($null -ne $ev) {
      Check ($ev.severity -eq "high") ("the read event is HIGH, not CRITICAL (severity=" + $ev.severity + ")")
      Check ($ev.rule_id -eq "CANARY_READ") ("the read event has its own rule id, so reads can be quieted alone (rule_id=" + $ev.rule_id + ")")
    }
    $statAfter = Get-Item -LiteralPath $existing
    $hashAfter = (Get-FileHash -LiteralPath $existing -Algorithm SHA256).Hash
    Check ($statAfter.Length -eq $statBefore.Length) "the decoy's size is unchanged: nothing was written"
    Check ($hashAfter -eq $hashBefore) "the decoy's SHA-256 is unchanged: the event is a read, not a disguised write"
  }

  # ---- 3. a write still wins ----------------------------------------------
  Write-Output ""
  Write-Output "== part 3 - a write is still CRITICAL, on its own rule id"
  Add-Content -LiteralPath $existing -Value "x" -NoNewline
  $wev = Wait-Event -pipeName $pipeName -type "canary_triggered" -seconds ($WaitMs / 1000)
  Check ($null -ne $wev) "appending one byte to the decoy raised a canary_triggered event"
  if ($null -ne $wev) {
    Check ($wev.severity -eq "critical") ("the write event is CRITICAL (severity=" + $wev.severity + ")")
    Check ($wev.rule_id -eq "CANARY") ("the write event kept the original rule id (rule_id=" + $wev.rule_id + ")")
  }

  # ---- 4. the watcher cannot trip its own trap ----------------------------
  Write-Output ""
  Write-Output "== part 4 - fifty metadata queries move nothing and raise nothing"
  $null = Wait-Quiet -pipeName $pipeName -seconds 8
  $atimeBefore = (Get-Item -LiteralPath $existing).LastAccessTime
  $readsBefore = Count-Events -pipeName $pipeName -type "canary_read"
  $writesBefore = Count-Events -pipeName $pipeName -type "canary_triggered"
  1..50 | ForEach-Object { $null = [System.IO.File]::GetAttributes($existing) }
  Start-Sleep -Milliseconds 2000
  $atimeAfter = (Get-Item -LiteralPath $existing).LastAccessTime
  Check ($atimeAfter -eq $atimeBefore) "fifty metadata queries did not move the last-access time (the guard's poll cannot self-trigger)"
  Check ((Count-Events -pipeName $pipeName -type "canary_read") -eq $readsBefore) "no new read event came from the metadata queries"
  Check ((Count-Events -pipeName $pipeName -type "canary_triggered") -eq $writesBefore) "no new write event came from the metadata queries"
}
catch {
  Check $false ("the run itself completed: " + $_.Exception.Message)
}
finally {
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500
  $env:USERPROFILE = $savedUserProfile
  Remove-Item Env:\MICS_DATA_DIR, Env:\MICS_PIPE_NAME, Env:\MICS_NO_SINGLETON, Env:\MICS_NO_AUTO_RESUME -ErrorAction SilentlyContinue
}

Write-Output ""
Write-Output "== engine log (last 12 lines)"
Get-Content $err -Tail 12 -ErrorAction SilentlyContinue | ForEach-Object { "      $_" }

Write-Output ""
if ($script:failures.Count -eq 0) {
  Write-Output ("RESULT: PASS - {0} check(s), {1} skipped" -f $script:checks, $script:skips)
  if (-not $Keep) { Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue }
  exit 0
}
Write-Output ("RESULT: FAIL - " + ($script:failures -join "; "))
Write-Output ("      scratch kept for inspection: " + $scratch)
exit 1
