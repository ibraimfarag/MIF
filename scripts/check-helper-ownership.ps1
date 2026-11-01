<#
.SYNOPSIS
  Answers whether the installed MI CS privileged helper points at one install folder.

.DESCRIPTION
  The MICSHelper service is created by the app, never by the installer (D-022), and
  its binPath names the mics-engine.exe of the copy whose Settings -> Engine page
  installed it. Removing that copy while the service still points at it would leave
  a service aimed at a deleted binary, so installer\mics.nsi asks this before it
  deletes anything, and the release verifiers reuse the same answer instead of
  re-implementing the comparison.

  The parse is deliberately liberal: `sc create` stores `"<exe>" helper-service`
  (quoted, because "Program Files" contains a space), but an unquoted definition or
  one carrying other arguments must not be mistaken for a different copy.

  Exit codes (the uninstaller removes only on 0):
    0  SAFE     no such service, or it points at a different folder
    2  OWNED    the service's binary lives in -InstallDir
    1  UNKNOWN  the service exists but its definition could not be read

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\check-helper-ownership.ps1 -InstallDir "$env:LOCALAPPDATA\MI CS"
  if ($LASTEXITCODE -eq 2) { "the helper belongs to that copy - remove it in the app first" }

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9). Read-only: it never touches the service
  and needs no elevation.
#>
param(
  [Parameter(Mandatory = $true)][string]$InstallDir,
  [string]$ServiceKey = "HKLM\SYSTEM\CurrentControlSet\Services\MICSHelper"
)

$ErrorActionPreference = "Stop"

function Resolve-ServiceKeyPath([string]$key) {
  if ($key.StartsWith("HKLM\")) { return "HKLM:\" + $key.Substring(5) }
  if ($key.StartsWith("HKCU\")) { return "HKCU:\" + $key.Substring(5) }
  return $key
}

function Get-BinaryFromImagePath([string]$imagePath) {
  $text = $imagePath.Trim()
  if ($text.StartsWith('"')) {
    $end = $text.IndexOf('"', 1)
    if ($end -gt 1) { return $text.Substring(1, $end - 1) }
    return $text.Trim('"')
  }
  # Unquoted: drop the subcommand that follows the executable rather than guess
  # where a space-containing path would end.
  return ($text -replace '\s+helper-service(\s.*)?$', '').Trim()
}

Write-Output "helper service : $ServiceKey"

$provider = Resolve-ServiceKeyPath $ServiceKey
if (-not (Test-Path -LiteralPath $provider)) {
  Write-Output "  state        : not installed"
  Write-Output "RESULT: SAFE (no '$ServiceKey')"
  exit 0
}

$imagePath = ""
try {
  $item = Get-ItemProperty -LiteralPath $provider -Name ImagePath -ErrorAction Stop
  $imagePath = [string]$item.ImagePath
} catch {
  $imagePath = ""
}
if (-not $imagePath) {
  Write-Output "  state        : installed, but ImagePath is missing or unreadable"
  Write-Output "RESULT: UNKNOWN (cannot read the helper's binary path)"
  exit 1
}

$exe = Get-BinaryFromImagePath $imagePath
Write-Output "  ImagePath    : $imagePath"
Write-Output "  helper binary: $exe"

try {
  $exeDir = [System.IO.Path]::GetDirectoryName(
    [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($exe)))
  $installFull = [System.IO.Path]::GetFullPath($InstallDir)
} catch {
  Write-Output "  state        : a path could not be resolved ($($_.Exception.Message))"
  Write-Output "RESULT: UNKNOWN (unreadable path)"
  exit 1
}

Write-Output "  helper dir   : $exeDir"
Write-Output "  install dir  : $installFull"

if ([string]::Equals($exeDir.TrimEnd('\'), $installFull.TrimEnd('\'),
    [System.StringComparison]::OrdinalIgnoreCase)) {
  Write-Output "RESULT: OWNED (the helper points at this copy - remove it in the app first)"
  exit 2
}
Write-Output "RESULT: SAFE (the helper points at another copy)"
exit 0
