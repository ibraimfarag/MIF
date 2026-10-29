<#
.SYNOPSIS
  Creates (or removes) the MI CS shortcuts.

.DESCRIPTION
  Windows picks the icon for a shortcut from its own icon location, so the
  desktop can show the dedicated "Desktop" art while the taskbar, Alt-Tab and
  Explorer use the icon embedded in mics_app.exe ("task" art):

    Desktop shortcut      -> assets/icons/desktop.ico
    Start Menu shortcut   -> mics_app.exe (embedded task art)

  Both point at mics_app.exe next to this script's parent folder.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\create-shortcuts.ps1
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
$exe = Join-Path $AppDir "mics_app.exe"
if (-not $Remove -and -not (Test-Path $exe)) {
  throw "mics_app.exe not found in $AppDir"
}

# Prefer a copy beside the executable (packaged layout), else the bundled asset.
$desktopIcon = Join-Path $AppDir "desktop.ico"
if (-not (Test-Path $desktopIcon)) {
  $desktopIcon = Join-Path $AppDir "data\flutter_assets\assets\icons\desktop.ico"
}
if (-not (Test-Path $desktopIcon)) {
  Write-Warning "desktop.ico not found — the desktop shortcut will use the app icon"
  $desktopIcon = $exe
}

$targets = @()
$targets += Join-Path ([Environment]::GetFolderPath("Desktop")) "MI CS.lnk"
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
  $isDesktop = $path -like "$([Environment]::GetFolderPath('Desktop'))*"
  $lnk = $shell.CreateShortcut($path)
  $lnk.TargetPath = $exe
  $lnk.WorkingDirectory = $AppDir
  $lnk.IconLocation = if ($isDesktop) { "$desktopIcon,0" } else { "$exe,0" }
  $lnk.Description = "MI CS — Smart. Transparent. Open-source defense."
  $lnk.Save()
  Write-Output "created $path  (icon: $(Split-Path -Leaf $lnk.IconLocation))"
}
