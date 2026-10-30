# Measures what the guard loop costs, as a differential between two real runs.
#
#   guard-on  : the engine with `MICS_NO_GUARD` unset
#   guard-off : the same engine with `MICS_NO_GUARD=1`
#
# Both runs are isolated (own pipe names, own data dir, own rules dir) so a real
# MI CS on the machine is untouched, and the rules dir holds one *inert* rule so the
# guard neither falls back to the bundled starter pack nor raises anything: the
# starter pack kills script hosts whose command line contains \temp\ - which would
# kill this script - and its alerts pop a real Windows toast at the user. Pass
# -RealRules to measure the shipped configuration anyway and accept both.
#
# `guard::rules_dir()` takes `MICS_RULES_DIR` and appends `rules\guard`, so the
# variable points at the scratch root and the rule file lives two levels below it.
#
# Output is measured, not estimated: CPU time is read from the process object at two
# points and divided by wall time. `pct_of_machine` is the Task Manager definition
# (percent of all cores); `pct_of_one_core` is the same delta as a share of a single
# core, which is what a profile chart shows.
#
# Usage: .\measure-guard-cpu.ps1 [-Seconds 60] [-EnginePath <path>] [-KeepScratch] [-RealRules]
param(
  [int]$Seconds = 60,
  [string]$EnginePath = "",
  [switch]$KeepScratch,
  [switch]$RealRules
)

$ErrorActionPreference = "Stop"

function Resolve-Engine([string]$path) {
  if ($path) {
    if (-not (Test-Path $path)) { throw "engine not found: $path" }
    return (Resolve-Path $path).Path
  }
  $candidates = @(
    (Join-Path $PSScriptRoot "..\engine\target\release\mics-engine.exe"),
    (Join-Path $PSScriptRoot "..\dist\MICS-portable\mics-engine.exe")
  )
  foreach ($c in $candidates) { if (Test-Path $c) { return (Resolve-Path $c).Path } }
  throw "no mics-engine.exe found - pass -EnginePath"
}

$engine = Resolve-Engine $EnginePath
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$scratch = Join-Path $env:TEMP ("mics-guard-cpu-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$rulesDir = Join-Path $scratch "rules\guard"
if (-not $RealRules) {
  New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null
  # One rule that cannot match anything: keeps `load_rules` away from the starter pack.
  @'
[
  { "id": "GR-000", "name": "inert (CPU measurement)", "severity": "info", "child_image": "mics-never-a-real-image.exe", "action": "alert" }
]
'@ | Set-Content -Path (Join-Path $rulesDir "inert.json") -Encoding ASCII
}

Write-Output "engine : $engine"
Write-Output "scratch: $scratch"
Write-Output "cores  : $cores"
Write-Output "rules  : $(if ($RealRules) { 'the shipped starter pack (alerts and kills armed)' } else { 'one inert rule' })"
Write-Output "window : ${Seconds}s wall time per mode"
Write-Output ""

$results = @()
foreach ($mode in @("on", "off")) {
  $modeDir = Join-Path $scratch $mode
  New-Item -ItemType Directory -Force -Path $modeDir | Out-Null
  $out = Join-Path $scratch "$mode.out"
  $err = Join-Path $scratch "$mode.err"
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_PIPE_NAME = "mics_guard_cpu_$mode`_$([guid]::NewGuid().ToString('N').Substring(0,6))"
  $env:MICS_HELPER_PIPE = "mics_guard_cpu_helper_$mode"
  $env:MICS_DATA_DIR = (Join-Path $modeDir "data")
  $env:MICS_RULES_DIR = $scratch
  if ($mode -eq "off") { $env:MICS_NO_GUARD = "1" } else { Remove-Item Env:\MICS_NO_GUARD -ErrorAction SilentlyContinue }

  $proc = Start-Process -FilePath $engine -ArgumentList "service" -PassThru -NoNewWindow -WorkingDirectory $modeDir `
    -RedirectStandardOutput $out -RedirectStandardError $err
  try {
    Start-Sleep -Seconds 5
    if ($proc.HasExited) { throw "the engine exited during startup (mode=$mode)" }
    $proc.Refresh()
    $cpu0 = $proc.TotalProcessorTime.TotalSeconds
    $wall0 = [DateTime]::UtcNow
    Start-Sleep -Seconds $Seconds
    $proc.Refresh()
    $cpu1 = $proc.TotalProcessorTime.TotalSeconds
    $wall1 = [DateTime]::UtcNow
    $cpu = $cpu1 - $cpu0
    $wall = ($wall1 - $wall0).TotalSeconds
    $oneCore = 100.0 * $cpu / $wall
    $machine = $oneCore / $cores
    $results += [pscustomobject]@{
      Mode = $mode; CpuSeconds = [math]::Round($cpu, 3); WallSeconds = [math]::Round($wall, 1)
      PctOfOneCore = [math]::Round($oneCore, 3); PctOfMachine = [math]::Round($machine, 4)
    }
  } finally {
    if ($proc -and -not $proc.HasExited) { $proc.Kill(); [void]$proc.WaitForExit(5000) }
  }
}

Write-Output "results:"
$results | Format-Table -AutoSize | Out-String -Width 120 | Write-Output

$on = ($results | Where-Object { $_.Mode -eq "on" }).PctOfMachine
$off = ($results | Where-Object { $_.Mode -eq "off" }).PctOfMachine
$delta = $on - $off
Write-Output ("guard cost: {0:N4}% of the machine (on) - {1:N4}% (off) = {2:N4} points" -f $on, $off, $delta)
Write-Output ("            {0:N3}% - {1:N3}% of one core, same subtraction {2:N3}" -f `
  ($results | Where-Object { $_.Mode -eq "on" }).PctOfOneCore, `
  ($results | Where-Object { $_.Mode -eq "off" }).PctOfOneCore, `
  ((($results | Where-Object { $_.Mode -eq "on" }).PctOfOneCore) - (($results | Where-Object { $_.Mode -eq "off" }).PctOfOneCore)))

if (-not $KeepScratch) { Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue }
else { Write-Output "kept: $scratch" }
exit 0