<#
.SYNOPSIS
  Proves the app's half of the single-instance handoff (D-041, D-059) on this
  machine: a second launch ends without ever opening a window the user can see.
.DESCRIPTION
  Explorer's "Scan with MI CS" verb starts a new MI CS process with
  `--scan "<path>"` (installer/mics.nsi), and so does every later launch. That
  process asks the engine whether a window is already there to take the handover
  and ends when one is - `scripts\verify-handoff.ps1` measures the engine's half
  of that with two raw pipe clients.

  This script measures the half the user sees. The window used to be shown by the
  runner on the first Flutter frame, before the process knew whether it was the
  window, so a launch that handed itself over was a window that appeared and
  closed: reported on 2026-11-13 as "right-click opens a second window". D-059
  creates the window hidden and lets only the process that turns out to be the
  window show it.

  The instrument is Windows' own answer about top-level windows and their
  visibility, enumerated per process:
    0. the first launch shows a window - the positive control, without which
       "no visible window" would also be true of a detector that never sees one;
    1. a second launch, started the way Explorer starts it, creates no window
       that is ever visible;
    2. it ends by itself, so the handover reached the window that was open;
    3. one window is left on screen, not two.
.PARAMETER App
  The mics_app.exe to measure. Defaults to the newest of the release build and
  the packaged dist, either of which needs mics-engine.exe resolvable.
.PARAMETER TimeoutSeconds
  How long to wait for each launch to do its part.
.PARAMETER Keep
  Leave the scratch folder and its logs in place.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-single-instance.ps1
.NOTES
  Needs a built app: powershell -ExecutionPolicy Bypass -File scripts\pipeline.ps1
  -Tier full, or flutter build windows --release.
  Runs the two launches on a private pipe (MICS_PIPE_NAME), so it can be run while
  the app is already open.
  ASCII only on purpose (docs/TODO.md 8.9).
#>
param(
  [string]$App,
  [int]$TimeoutSeconds = 25,
  [switch]$Keep
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not $App) {
  # Newest, not first-found: a stale dist next to a fresh build would otherwise
  # be probed as if it were the current code.
  # Array on purpose, outside the pipeline: one candidate would otherwise be a
  # bare string and `$candidates[0]` its first character.
  $candidates = @(@(
    (Join-Path $root "build\windows\x64\runner\Release\mics_app.exe"),
    (Join-Path $root "dist\mics_app.exe")
  ) | Where-Object { Test-Path $_ } | Sort-Object { (Get-Item $_).LastWriteTime } -Descending)
  if ($candidates.Count -gt 0) { $App = $candidates[0] }
}
if (-not $App -or -not (Test-Path $App)) {
  Write-Output "RESULT: FAIL - no app binary; build it (flutter build windows --release) or pass -App"
  exit 1
}
$App = (Resolve-Path $App).Path

# The engine has to be there, or `app.activate` fails and every launch correctly
# decides it is the window - which would make check 1 fail for the wrong reason.
$engine = $null
foreach ($candidate in @(
    (Join-Path (Split-Path -Parent $App) "mics-engine.exe"),
    (Join-Path $root "engine\target\release\mics-engine.exe"),
    (Join-Path $root "engine\target\debug\mics-engine.exe")
  )) {
  if (Test-Path $candidate) { $engine = (Resolve-Path $candidate).Path; break }
}
if (-not $engine) {
  Write-Output "RESULT: FAIL - no mics-engine.exe to resolve; build it (scripts\pipeline.ps1 -Tier full)"
  exit 1
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

// Every top-level window of one process, each tagged with whether Windows
// considers it visible. EnumWindows only walks top-level windows, which is what
// a user would see in the taskbar; the visibility tag is read from the window
// itself rather than inferred, so "hidden" and "shown and withdrawn" are told
// apart.
public class MicsWindows {
  private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
  [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextLength(IntPtr hWnd);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

  public static List<string> Of(uint pid) {
    List<string> found = new List<string>();
    EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
      uint owner;
      GetWindowThreadProcessId(hWnd, out owner);
      if (owner == pid) {
        int length = GetWindowTextLength(hWnd);
        StringBuilder text = new StringBuilder(length + 2);
        GetWindowText(hWnd, text, text.Capacity);
        found.Add((IsWindowVisible(hWnd) ? "visible" : "hidden") + "|" + text.ToString());
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@

$script:checks = 0
$script:failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$text) {
  $script:checks++
  if ($ok) { Write-Output "PASS  $text" }
  else { $script:failures.Add($text); Write-Output "FAIL  $text" }
}

function VisibleTitles([int]$ProcessId) {
  return @(([MicsWindows]::Of([uint32]$ProcessId)) | Where-Object { $_ -like "visible|*" } |
    ForEach-Object { $_.Substring("visible|".Length) })
}

$scratch = Join-Path $env:TEMP ("mics-single-instance-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$scanDir = Join-Path $scratch "handed-over"
New-Item -ItemType Directory -Path $scanDir -Force | Out-Null

Write-Output "app:    $App"
Write-Output "engine: $engine"
Write-Output "scratch: $scratch"

# The engine and the pipe are named outright, so the two launches this probe
# makes are a world of their own: an MI CS the user already has open is on the
# default pipe and this probe neither disturbs it nor is answered by it.
# The data directory is left alone on purpose - the app and the engine resolve it
# the same way a normal launch does, which is what keeps them on one pipe name.
$env:MICS_ENGINE_PATH = $engine
$env:MICS_PIPE_NAME = "\\.\pipe\mics-single-instance-" + [guid]::NewGuid().ToString("N").Substring(0, 8)

$started = Get-Date
$first = $null
$second = $null
try {
  # --- 0. the first launch is the window, and shows one -----------------------
  $first = Start-Process -FilePath $App -PassThru
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  $firstTitles = @()
  while ((Get-Date) -lt $deadline) {
    if ($first.HasExited) { break }
    $firstTitles = VisibleTitles $first.Id
    if ($firstTitles.Count -gt 0) { break }
    Start-Sleep -Milliseconds 100
  }
  Check ($firstTitles.Count -gt 0) "the first launch shows a window ($($firstTitles -join ', '))"

  # The handover listener is registered after the window is up; a second launch
  # before that would be answered by nobody.
  Start-Sleep -Seconds 2

  # --- 1. a second launch, started the way Explorer starts it ----------------
  $second = Start-Process -FilePath $App -ArgumentList @("--scan", "`"$scanDir`"") -PassThru
  $seenVisible = @()
  $seenAny = @()
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    if ($second.HasExited) { break }
    $windows = @([MicsWindows]::Of([uint32]$second.Id))
    foreach ($window in $windows) {
      if ($seenAny -notcontains $window) { $seenAny += $window }
      if ($window -like "visible|*") {
        if ($seenVisible -notcontains $window) { $seenVisible += $window }
      }
    }
    Start-Sleep -Milliseconds 25
  }

  Check ($seenVisible.Count -eq 0) "the second launch never had a visible window (windows seen: $(if ($seenAny.Count -gt 0) { $seenAny -join ', ' } else { 'none' }))"

  # --- 2. it ended by itself, which is what the handover means ---------------
  $deadline = (Get-Date).AddSeconds(5)
  while (-not $second.HasExited -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 50
  }
  # 0 and not "some code": a handed-over launch that dies with 0xC000041D is a
  # crash that leaves Windows Error Reporting entries behind on every right-click
  # scan (trap 34, fixed by the same change as D-059).
  $code = if ($second.HasExited) { $second.ExitCode } else { 'still running' }
  Check ($second.HasExited -and $code -eq 0) "the second launch ends by itself, cleanly (exit code $code)"

  # --- 3. one window is left, not two ----------------------------------------
  $firstTitles = VisibleTitles $first.Id
  Check ($firstTitles.Count -eq 1) "the window that was already open is the one left ($($firstTitles -join ', '))"
}
finally {
  foreach ($process in @($second, $first)) {
    if ($process -and -not $process.HasExited) {
      Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
  }
  # The engine is the app's child and the app was killed, so it has to be stopped
  # by hand - but only one this probe started, and only from the binary it named.
  foreach ($engineProcess in @(Get-Process -Name "mics-engine" -ErrorAction SilentlyContinue)) {
    try {
      if ($engineProcess.Path -ne $engine) { continue }
      if ($engineProcess.StartTime -lt $started) { continue }
      Stop-Process -Id $engineProcess.Id -Force -ErrorAction SilentlyContinue
    } catch {
      # A process this probe cannot look inside is not one it started.
    }
  }
  if (-not $Keep) { Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue }
  else { Write-Output "scratch kept: $scratch" }
}

if ($script:failures.Count -gt 0) {
  Write-Output ""
  Write-Output "RESULT: FAIL - $($script:failures.Count) of $($script:checks) checks failed"
  exit 1
}
Write-Output ""
Write-Output "RESULT: OK - $($script:checks) checks passed (D-059: a launch that hands itself over opens no window)"
exit 0
