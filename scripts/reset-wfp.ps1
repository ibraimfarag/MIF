<#
.SYNOPSIS
  Removes every filtering-engine object MI CS wrote - its filters, its sublayer
  and its provider - and proves the machine is clean afterwards.

.DESCRIPTION
  MI CS' blocks are *persistent* objects in the BFE (D-042), so they outlive the
  engine and the app. That is the point of them, and it is also why a run that
  dies between "add the filter" and "clean it up" leaves a real, blocking filter
  behind. It happened on 2026-11-08: `fw.wfp.block` added its filter and then
  failed while reading the list back (D-045, a zeroed `layerKey` in the
  enumeration template), so the probes saw an error and never ran their own
  teardown.

  `fw.wfp.reset` is the undo, and it is safe to run any time: it names no filter,
  so it can only remove objects carrying MI CS' own provider key. It also clears
  the tamper watch's record (D-044) - without that, the watch would keep calling
  the missing filters a tamper after the cleanup that removed them.

  The engine is started with the *app's* data directory, not a scratch one, so
  the record that is cleared is the one the installed app reads. Nothing outside
  MI CS' own objects is touched.

  Usage (an elevated shell is needed; or the MICSHelper service must be running):
    pwsh ./scripts/reset-wfp.ps1 -EngineExe engine\target\debug\mics-engine.exe
    pwsh ./scripts/reset-wfp.ps1            # uses the built binary it finds
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
function Note([string]$text) {
  Write-Output "note  $text"
}

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

$started = Get-Date
$scratch = Join-Path $env:TEMP ("mics-reset-wfp-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

$elevated = $false
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $elevated = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $elevated = $false }
$helper = $null -ne (Get-Service -Name "MICSHelper" -ErrorAction SilentlyContinue)

Write-Output "== engine: $EngineExe"
Write-Output ("== this shell: elevated={0}, MICSHelper={1}" -f $elevated, $helper)

$proc = $null
try {
  # No MICS_DATA_DIR: the app's own directory, so the record this clears is the
  # one the app's engine reads. No singleton, so a running app engine does not
  # make this one refuse to start; the reset itself is machine-wide.
  Remove-Item Env:MICS_DATA_DIR -ErrorAction SilentlyContinue
  $env:MICS_PIPE_NAME = "mics-reset-wfp"
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $env:MICS_NO_SCAN_SCHEDULE = "1"
  $out = Join-Path $scratch "stdout.log"
  $err = Join-Path $scratch "stderr.log"
  $proc = Start-Process -FilePath $EngineExe -ArgumentList @("service") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
  $deadline = (Get-Date).AddSeconds(25)
  while ((Get-Date) -lt $deadline) {
    $log = (Get-Content $err -ErrorAction SilentlyContinue) -join "`n"
    if ($log -match "Starting Named Pipe server") { break }
    Start-Sleep -Milliseconds 250
  }
  Check ($log -match "Starting Named Pipe server") "the engine started"

  Write-Output ""
  Write-Output "== part 1 - what the machine holds before"
  $before = Invoke-Rpc -pipeName "mics-reset-wfp" -method "fw.wfp.status" -params $null -id 1
  Check ($null -ne $before -and $null -ne $before.result) "fw.wfp.status answered"
  if ($null -ne $before -and $null -ne $before.error) {
    Note ("status failed: " + $before.error.message)
  }
  if ($before -and $null -ne $before.result) {
    Note ("before: sublayer={0} filters={1} needs_elevation={2}" -f `
        $before.result.sublayer, $before.result.filters, $before.result.needs_elevation)
    if ($before.result.PSObject.Properties.Name -contains "detail" -and $before.result.detail) {
      Note ("detail: " + $before.result.detail)
    }
    foreach ($name in @($before.result.names)) { Note ("filter: " + $name) }
    if ($before.result.needs_elevation) {
      Skip "the BFE cannot be read here, so nothing was removed (needs an administrator or MICSHelper)"
    }
    if (@($before.result.names).Count -gt 0) {
      Note "these are the filters the reset is about to remove; they are MI CS' own by provider key"
    }
  }

  Write-Output ""
  Write-Output "== part 2 - the reset"
  $reset = Invoke-Rpc -pipeName "mics-reset-wfp" -method "fw.wfp.reset" -params $null -id 2
  if ($null -eq $reset) {
    Check $false "fw.wfp.reset answered"
  } elseif ($null -ne $reset.error) {
    Check $false ("fw.wfp.reset was refused: " + $reset.error.message)
  } else {
    Check ($null -ne $reset.result) "fw.wfp.reset answered"
    Note ("removed: " + $reset.result.removed)
  }

  Write-Output ""
  Write-Output "== part 3 - what the machine holds after"
  $after = Invoke-Rpc -pipeName "mics-reset-wfp" -method "fw.wfp.status" -params $null -id 3
  Check ($null -ne $after -and $null -ne $after.result) "fw.wfp.status answered afterwards"
  if ($after -and $null -ne $after.result) {
    Note ("after: sublayer={0} filters={1} needs_elevation={2}" -f `
        $after.result.sublayer, $after.result.filters, $after.result.needs_elevation)
    if ($after.result.needs_elevation) {
      # Zero filters from a machine nobody could read is not a clean machine: it
      # is the same "unknown" answer with the same zeros (measured 2026-11-08).
      Skip "the machine cannot be read back here, so 'nothing is left' is unmeasured"
    } else {
      Check ($after.result.filters -eq 0) "no filter of ours is left on the machine"
      Check ($after.result.sublayer -eq $false) "and our sublayer is gone too"

      # The watch must not read its own cleanup as a tamper (D-044): the record
      # went with the filters.
      $watch = Invoke-Rpc -pipeName "mics-reset-wfp" -method "fw.wfp.watch" -params $null -id 4
      if ($watch -and $null -ne $watch.result) {
        Check ($watch.result.state -ne "tampered") "the cleanup did not leave a tamper behind"
        Note ("watch: state={0} recorded={1}" -f $watch.result.state, $watch.result.recorded)
      } else { Skip "fw.wfp.watch did not answer, so the record could not be read back" }
    }
  }
} finally {
  if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
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
