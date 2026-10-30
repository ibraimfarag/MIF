<#
.SYNOPSIS
  Creates (or removes) the MI CS shortcuts.

.DESCRIPTION
  One product, one icon: both shortcuts point at `mics_app.exe` and take their
  icon from it, so the desktop, the taskbar, Alt-Tab, Explorer and the engine's
  entry in Task Manager all show the same art.

    Desktop shortcut      -> MICS.lnk        (target and icon: mics_app.exe)
    Start Menu shortcut   -> MI CS.lnk       (target and icon: mics_app.exe)

  `-AppDir` selects which copy of the app they launch; the default is the folder
  this script lives in, so pass the install folder to point at a real install.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\create-shortcuts.ps1 -AppDir "$env:LOCALAPPDATA\MI CS"
  powershell -ExecutionPolicy Bypass -File scripts\create-shortcuts.ps1 -Remove
#>
param(
  [string]$AppDir = "",
  [switch]$Remove,
  [switch]$AllUsers
)

$ErrorActionPreference = "Stop"

if (-not $AppDir) {
  $AppDir = Split-Path -Parent $PSScriptRoot
}
$AppDir = (Resolve-Path $AppDir).Path
$exe = Join-Path $AppDir "mics_app.exe"
if (-not $Remove -and -not (Test-Path $exe)) {
  throw "mics_app.exe not found in $AppDir"
}

$targets = @()
$targets += Join-Path ([Environment]::GetFolderPath("Desktop")) "MICS.lnk"
$startMenu = if ($AllUsers) {
  Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
} else {
  Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs"
}
$targets += Join-Path $startMenu "MI CS.lnk"

$shell = New-Object -ComObject WScript.Shell
foreach ($path in $targets) {
  if ($Remove) {
    if (Test-Path $path) { Remove-Item $path -Force; Write-Output "removed $path" }
    continue
  }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
  $lnk = $shell.CreateShortcut($path)
  $lnk.TargetPath = $exe
  $lnk.WorkingDirectory = $AppDir
  $lnk.IconLocation = "$exe,0"
  $lnk.Description = "MI CS - Smart. Transparent. Open-source defense."
  $lnk.Save()
  Write-Output "created $path  (target: $exe, icon: $($lnk.IconLocation))"
}
