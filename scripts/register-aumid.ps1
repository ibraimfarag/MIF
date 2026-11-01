<#
.SYNOPSIS
  Registers the MI CS AppUserModelID so Windows names the notification source
  "MI CS" instead of the raw id "MICS".

.DESCRIPTION
  The engine raises cards under AUMID "MICS" (engine/src/notify/toast.rs). Windows
  takes the *name* and *icon* it shows in the Action Center and in Settings ->
  Notifications from whatever is registered for that AUMID, so without this the
  source is labelled with the id itself. This script writes:

    1. HKCU\Software\Classes\AppUserModelId\MICS
         DisplayName = "MI CS"
         IconUri     = <AppDir>\mics_app.exe   (the icon the app already ships)
    2. System.AppUserModel.ID = MICS on the shortcuts, so the Shell files them
       under the same id (Get-StartApps then reports AppID `MICS` instead of the
       exe path).

  Everything lives under the current user's own hive and their own shortcuts:
  no elevation, no new file, and `-Remove` puts both back. Card delivery does not
  depend on any of this - a toast already reaches the desktop without it - so the
  only thing that changes is what Windows calls the sender.

  The shortcut property is a Shell property, not a WScript field, so it is written
  through IPropertyStore (scripts\aumid-interop.ps1) rather than by rewriting the
  .lnk with WScript.Shell.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\register-aumid.ps1
  powershell -ExecutionPolicy Bypass -File scripts\register-aumid.ps1 -AppDir "$env:LOCALAPPDATA\MI CS"
  powershell -ExecutionPolicy Bypass -File scripts\register-aumid.ps1 -Remove

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9). `scripts\verify-aumid.ps1` reads all of it back.

  Calling this from a native command line (`powershell -File ... -Shortcut "a" "b"`)
  binds only the first value to the array parameter and leaves the rest unbound and
  silent, so tag one shortcut per call - that is what installer\mics.nsi does. From
  a PowerShell session `-Shortcut @("a", "b")` does what it looks like.
#>
param(
  [string]$AppDir = "",
  [string[]]$Shortcut = @(),
  [switch]$Remove
)

$ErrorActionPreference = "Stop"
$Aumid = "MICS"
$DisplayName = "MI CS"

. (Join-Path $PSScriptRoot "aumid-interop.ps1")

if (-not $AppDir) {
  # The installed copy is what the shortcuts launch, so it is the default.
  $AppDir = Join-Path $env:LOCALAPPDATA "MI CS"
}
$exe = Join-Path $AppDir "mics_app.exe"
if (-not $Remove -and -not (Test-Path $exe)) {
  throw "mics_app.exe not found in $AppDir - pass -AppDir"
}

$keyPath = "HKCU:\Software\Classes\AppUserModelId\$Aumid"

if ($Remove) {
  if (Test-Path $keyPath) {
    Remove-Item $keyPath -Recurse -Force
    Write-Output "removed $keyPath"
  } else {
    Write-Output "already absent: $keyPath"
  }
} else {
  New-Item -Path $keyPath -Force | Out-Null
  New-ItemProperty -Path $keyPath -Name DisplayName -Value $DisplayName `
    -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $keyPath -Name IconUri -Value $exe `
    -PropertyType String -Force | Out-Null
  Write-Output "registered $keyPath  (DisplayName: $DisplayName, IconUri: $exe)"
}

if ($Shortcut.Count -eq 0) {
  $Shortcut = @(
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "MICS.lnk"),
    (Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\MI CS.lnk")
  )
}

foreach ($lnk in $Shortcut) {
  if (-not (Test-Path $lnk)) {
    Write-Output "skip (no such shortcut): $lnk"
    continue
  }
  $full = (Resolve-Path $lnk).Path
  if ($Remove) {
    [MicsAumid]::Clear($full)
    Write-Output "cleared System.AppUserModel.ID on $full"
  } else {
    [MicsAumid]::Write($full, $Aumid)
    Write-Output "tagged $full with System.AppUserModel.ID = $Aumid"
  }
}