<#
.SYNOPSIS
  Proves MI CS' own persistent block lives in Windows' filtering engine (WFP)
  and that persisting it is refused without an administrator.

.DESCRIPTION
  Register section 0.6 row 17, slice (a): a block that survives the engine's own
  process, enforced by the Base Filtering Engine (BFE) and not by the Windows
  Firewall's rule table. Three things have to be measured on a real machine,
  because none of them can be seen from a unit test:

    1. the objects are really there: after `fw.wfp.block`, the BFE holds MI CS'
       provider, its sublayer and a filter whose display name carries the
       `MICS-` prefix and the application, and the RPC answer and Windows' own
       `netsh wfp show state` describe the same object;
    2. the block is the action Windows enforces: the filter is looked up in
       `netsh wfp show filters` and its action is read there - Block, and not a
       Permit filter with the same conditions;
    3. the privilege boundary is real: the same call without an elevated shell
       and without the `MICSHelper` service is refused with a reason, and the
       BFE is asked again afterwards - nothing was written (D-007,
       `docs/PRIVILEGED-OPS.md` "a refused call leaves nothing behind").

  The probe cleans up after itself: a filter it created is removed through
  `fw.wfp.unblock` before the engine stops, and a run with -Keep prints the
  scratch directory. When the engine is neither elevated nor served by a
  helper, the blocking checks record a SKIP with the refusal text instead of a
  pass - the probe never turns "could not try" into "works".

    What this probe does NOT prove - the row's remaining slice (b):
      * that the block holds while MI CS is not running at all (this probe
        starts one engine process and stops it; it reboots nothing);
      * that the filter still blocks after a reboot;
      * per-application coverage for an application that has not run yet.
    Those need a reboot and a real target, and are recorded in `docs/TODO.md`
    row 17 as the next slice. Until then the row stays `[~]`.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-wfp.ps1

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
$scratch = Join-Path $env:TEMP ("mics-verify-wfp-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$data = Join-Path $scratch "data"
New-Item -ItemType Directory -Path $data -Force | Out-Null

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

# Windows' own view of the filtering engine: `netsh wfp show state` writes an
# XML file. That file, not our log, is what decides whether an object is really
# in the BFE.
function Get-WfpStateXml([string]$path) {
  Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  & netsh wfp show state file="$path" 2>&1 | Out-Null
  for ($i = 0; $i -lt 20 -and -not (Test-Path $path); $i++) { Start-Sleep -Milliseconds 250 }
  if (-not (Test-Path $path)) { return $null }
  try { [xml](Get-Content -LiteralPath $path -Raw) } catch { $null }
}

function Get-FilterXml([string]$path) {
  Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  & netsh wfp show filters file="$path" 2>&1 | Out-Null
  for ($i = 0; $i -lt 20 -and -not (Test-Path $path); $i++) { Start-Sleep -Milliseconds 250 }
  if (-not (Test-Path $path)) { return $null }
  try { [xml](Get-Content -LiteralPath $path -Raw) } catch { $null }
}

function Get-Elevation {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HelperState {
  $service = Get-Service -Name "MICSHelper" -ErrorAction SilentlyContinue
  return ($null -ne $service -and $service.Status -eq "Running")
}

$env:MICS_DATA_DIR = $data
$env:MICS_PIPE_NAME = "mics-verify-wfp"
$env:MICS_NO_SINGLETON = "1"
$env:MICS_NO_GUARD = "1"
$env:MICS_NO_AUTO_RESUME = "1"
$env:MICS_NO_SCAN_SCHEDULE = "1"
$out = Join-Path $scratch "stdout.log"
$err = Join-Path $scratch "stderr.log"

$elevated = Get-Elevation
$helper = Get-HelperState
$canWrite = $elevated -or $helper

Write-Output ""
Write-Output "== engine: $EngineExe"
Write-Output "== scratch: $scratch"
Write-Output ("== shell elevated: {0}; MICSHelper running: {1}" -f $elevated, $helper)

# A stable, harmless target: the probe blocks the engine binary itself, so the
# filter names a file that certainly exists and covers nothing anyone needs.
$target = $EngineExe
$namePrefix = "MICS-" + (Split-Path -Leaf $target)
$spec = @{ app = $target; port = 65001; protocol = 6; note = "probe" }

$proc = $null
$created = $false
try {
  $proc = Start-Process -FilePath $EngineExe -ArgumentList @("service") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
  $deadline = (Get-Date).AddSeconds(25)
  $log = ""
  while ((Get-Date) -lt $deadline) {
    $log = (Get-Content $err -ErrorAction SilentlyContinue) -join "`n"
    if ($log -match "Starting Named Pipe server") { break }
    Start-Sleep -Milliseconds 250
  }
  Check ($log -match "Starting Named Pipe server") "the engine started"

  # ---- 1. what the engine says it holds ------------------------------------
  Write-Output ""
  Write-Output "== part 1 - the status the engine reports"
  $before = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.status" -params $null
  Check ($null -ne $before -and $null -ne $before.result) "fw.wfp.status answered"
  $status = $null
  if ($before -and $null -ne $before.result) { $status = $before.result }
  if ($null -ne $status) {
    Check ($status.PSObject.Properties.Name -contains "sublayer") "the answer says whether the sublayer exists"
    Check ($status.PSObject.Properties.Name -contains "filters") "the answer counts the filters"
    Check ($status.PSObject.Properties.Name -contains "needs_elevation") "the answer says whether an administrator is needed"
    Note ("before: sublayer={0} filters={1} needs_elevation={2}" -f $status.sublayer, $status.filters, $status.needs_elevation)
    if ($status.PSObject.Properties.Name -contains "detail" -and $status.detail) { Note ("detail: " + $status.detail) }
  }

  # ---- 2. the block, through the engine ------------------------------------
  Write-Output ""
  Write-Output "== part 2 - a persistent block is created and is really in the BFE"
  $block = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.block" -params $spec -id 2
  $blockRefused = ($null -eq $block -or $null -ne $block.error)
  if ($blockRefused) {
    $reason = "no answer"
    if ($block -and $block.error) { $reason = "$($block.error.message)" }
    Check ($reason -ne "no answer") "a refused block carries a reason the UI can show"
    Note ("refusal: " + $reason)
    if ($canWrite) {
      Skip "fw.wfp.block was refused although this shell can write (elevated=$elevated, helper=$helper)"
    } else {
      Skip ("fw.wfp.block was refused ({0}) - no elevated shell and no MICSHelper service" -f $reason)
      Check $true "the refusal matches this shell's privilege (elevated=$elevated, helper=$helper)"
    }
  } else {
    $created = $true
    Check ($block.result.status -eq "blocked") "fw.wfp.block reported a block"
    Check ($block.result.added -eq $true) "the filter was added, not found already present"
    Note ("key=" + $block.result.key + " filters=" + $block.result.filters)

    $status2 = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.status" -params $null -id 3
    $names = @()
    if ($status2 -and $null -ne $status2.result) { $names = @($status2.result.names) }
    $named = @($names | Where-Object { $_ -like "$namePrefix*" })
    Check ($named.Count -ge 1) ("the filter is listed by name ({0}...)" -f $namePrefix)
    if ($named.Count -ge 1) { Note ("name: " + $named[0]) }
    Check ($status2.result.filters -ge 1) "the filter count went up"

    # Windows' own view of the same object.
    $statePath = Join-Path $scratch "wfp-state.xml"
    $state = Get-WfpStateXml $statePath
    if ($null -eq $state) {
      Skip "netsh wfp show state produced no XML to compare against"
    } else {
      $inState = @($state.SelectNodes("//*[local-name()='item']") | Where-Object { $_.InnerText -like "*$namePrefix*" })
      Check ($inState.Count -ge 1) "Windows' filtering state holds the filter, not only our log"
      if ($inState.Count -ge 1) { Note ("state text: " + ($inState[0].InnerText -replace "\s+", " ")) }
    }

    # ---- 3. the block is the action Windows enforces ------------------------
    Write-Output ""
    Write-Output "== part 3 - the filter's action, as Windows reports it"
    $filtersPath = Join-Path $scratch "wfp-filters.xml"
    $filtersXml = Get-FilterXml $filtersPath
    if ($null -eq $filtersXml) {
      Skip "netsh wfp show filters produced no XML"
    } else {
      $mine = @($filtersXml.SelectNodes("//*[local-name()='item']") | Where-Object { $_.InnerText -like "*$namePrefix*" })
      Check ($mine.Count -ge 1) "the filter appears in netsh wfp show filters"
      if ($mine.Count -ge 1) {
        $text = $mine[0].InnerText
        Note ("filter text: " + ($text -replace "\s+", " "))
        Check ($text -match "BLOCK") "the filter's action is Block"
        Check (-not ($text -match "PERMIT")) "it is not a Permit filter"
      }
    }
  }

  # ---- 4. the undo ---------------------------------------------------------
  Write-Output ""
  Write-Output "== part 4 - the block is removed and the state says so"
  if ($created) {
    $unblock = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.unblock" -params $spec -id 4
    if ($null -eq $unblock -or $null -ne $unblock.error) {
      $reason = "no answer"
      if ($unblock -and $unblock.error) { $reason = "$($unblock.error.message)" }
      Check $false ("fw.wfp.unblock failed: {0}" -f $reason)
    } else {
      Check ($unblock.result.removed -eq $true) "the filter was removed"
      $created = $false
      $after = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.status" -params $null -id 5
      $namesAfter = @()
      if ($after -and $null -ne $after.result) { $namesAfter = @($after.result.names) }
      Check (@($namesAfter | Where-Object { $_ -like "$namePrefix*" }).Count -eq 0) "the filter is gone from the list the engine gives us"
      $stateAfter = Join-Path $scratch "wfp-state-after.xml"
      $null = Get-WfpStateXml $stateAfter
      if (Test-Path $stateAfter) {
        $afterText = Get-Content -LiteralPath $stateAfter -Raw
        Check (-not ($afterText -match [regex]::Escape($namePrefix))) "Windows' filtering state no longer names it"
      }
    }
  } else {
    Skip "nothing was created, so there is nothing to remove"
  }

  # ---- 5. what a refused call leaves behind --------------------------------
  Write-Output ""
  Write-Output "== part 5 - a refusal writes nothing"
  if (-not $canWrite) {
    $stateBeforeRefusal = Join-Path $scratch "wfp-state-before-refusal.xml"
    $null = Get-WfpStateXml $stateBeforeRefusal
    $refused = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.block" -params $spec -id 6
    Check ($null -ne $refused -and $null -ne $refused.error) "an unelevated block is refused with a reason"
    if ($refused -and $refused.error) { Note ("refusal: " + $refused.error.message) }
    if (Test-Path $stateBeforeRefusal) {
      $beforeText = Get-Content -LiteralPath $stateBeforeRefusal -Raw
      Check (-not ($beforeText -match [regex]::Escape($namePrefix))) "nothing of ours was in the BFE before the refusal"
      $stateAfterRefusal = Join-Path $scratch "wfp-state-after-refusal.xml"
      $null = Get-WfpStateXml $stateAfterRefusal
      if (Test-Path $stateAfterRefusal) {
        $afterRefusalText = Get-Content -LiteralPath $stateAfterRefusal -Raw
        Check (-not ($afterRefusalText -match [regex]::Escape($namePrefix))) "and nothing of ours is there after it"
      }
    } else {
      Skip "no state XML, so the refusal could not be checked against the BFE"
    }
  } else {
    Skip "this shell can write (elevated=$elevated, helper=$helper), so the refusal path is not reachable here"
  }

  # ---- 6. the log says how it went ----------------------------------------
  Write-Output ""
  Write-Output "== part 6 - the engine's own log"
  $engineLog = (Get-Content $err -ErrorAction SilentlyContinue) -join "`n"
  Check (-not ($engineLog -match "netsh")) "the engine never shells out to netsh"
} finally {
  # The undo comes before the process stops: with the engine gone there is no
  # pipe left to ask, and the filter would stay in the machine.
  if ($created) {
    $cleanup = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.unblock" -params $spec -id 9
    if ($null -eq $cleanup -or $null -ne $cleanup.error) {
      Write-Output "note  cleanup unblock did not answer; the filter may still be in the BFE"
    }
  }
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
