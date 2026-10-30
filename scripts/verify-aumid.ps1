<#
.SYNOPSIS
  Checks that MI CS registered its AppUserModelID, and that Windows agrees.

.DESCRIPTION
  "Windows labels the card's source MI CS" is a claim Windows makes, not one this
  repo can assume, so this probe reads back everything
  scripts\register-aumid.ps1 writes and then asks the Shell for its own view:

    1. HKCU\Software\Classes\AppUserModelId\MICS carries DisplayName "MI CS" and
       an IconUri that points at a real mics_app.exe - this is the key the Action
       Center and Settings -> Notifications read the label from;
    2. each known shortcut carries System.AppUserModel.ID = MICS;
    3. Get-StartApps - the Shell's own start-menu index - files the entry "MI CS"
       under AppID `MICS` instead of under the exe path. That index is cached and
       refreshes a few seconds after a shortcut changes, so this check waits for
       it instead of failing on the cache (measured: ~5 s on this machine).

  Exit code 0 = every expectation held; 1 = something measured differently.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-aumid.ps1

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9). Read-only: no key, no shortcut and no
  card is touched, and it needs no elevation.
#>
param(
  [string]$Aumid = "MICS",
  [string]$DisplayName = "MI CS",
  [int]$RefreshWaitMs = 15000
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]

function Note([string]$text) { Write-Output "      $text" }
function Fail([string]$text) {
  [void]$failures.Add($text)
  Write-Output "FAIL  $text"
}
function Pass([string]$text) { Write-Output "PASS  $text" }

. (Join-Path $PSScriptRoot "aumid-interop.ps1")

$keyPath = "HKCU:\Software\Classes\AppUserModelId\$Aumid"
if (-not (Test-Path $keyPath)) {
  Fail "no $keyPath - run scripts\register-aumid.ps1"
} else {
  $props = Get-ItemProperty -Path $keyPath
  if ($props.DisplayName -eq $DisplayName) {
    Pass "DisplayName is '$DisplayName'"
  } else {
    Fail "DisplayName is '$($props.DisplayName)', expected '$DisplayName'"
  }
  if ($props.IconUri -and (Test-Path -LiteralPath $props.IconUri)) {
    Pass "IconUri points at a file that exists"
    Note $props.IconUri
  } else {
    Fail "IconUri is '$($props.IconUri)', which is not an existing file"
  }
}

$shortcuts = @(
  (Join-Path ([Environment]::GetFolderPath("Desktop")) "MICS.lnk"),
  (Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\MI CS.lnk")
)
foreach ($lnk in $shortcuts) {
  if (-not (Test-Path $lnk)) {
    Note "skip (no such shortcut): $lnk"
    continue
  }
  $full = (Resolve-Path $lnk).Path
  $id = [MicsAumid]::Read($full)
  if ($id -eq $Aumid) {
    Pass "$(Split-Path -Leaf $full) carries System.AppUserModel.ID = $Aumid"
  } else {
    Fail "$(Split-Path -Leaf $full) carries '[$id]', expected '$Aumid'"
  }
}

$apps = @()
$entry = @()
$waited = 0
while ($true) {
  try { $apps = @(Get-StartApps) } catch { $apps = @() }
  $entry = @($apps | Where-Object { $_.Name -eq $DisplayName })
  if ($entry.Count -gt 0 -and $entry[0].AppID -eq $Aumid) { break }
  if ($waited -ge $RefreshWaitMs) { break }
  Start-Sleep -Milliseconds 1000
  $waited += 1000
}
if ($entry.Count -eq 0) {
  Fail "Get-StartApps has no '$DisplayName' entry ($($apps.Count) entries seen)"
} elseif ($entry[0].AppID -eq $Aumid) {
  Pass "the Shell files '$DisplayName' under AppID '$Aumid'"
  if ($waited -gt 0) {
    Note "the start-menu index needed ${waited} ms to pick the shortcut up"
  }
} else {
  Fail ("Get-StartApps still files '$DisplayName' under AppID " +
    "'$($entry[0].AppID)', expected '$Aumid' after waiting $($waited) ms")
}

Write-Output ""
if ($failures.Count -eq 0) {
  Write-Output "RESULT: PASS ($($Aumid) is registered, and Windows reports it as '$DisplayName')"
  exit 0
}
Write-Output "RESULT: FAIL ($($failures.Count) problem(s))"
foreach ($f in $failures) { Write-Output "  - $f" }
exit 1