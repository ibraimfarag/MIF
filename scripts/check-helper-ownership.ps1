<#
.SYNOPSIS
  Answers whether the installed MI CS privileged helper points at one install folder,
  and with -Remove takes that service away when it does.

.DESCRIPTION
  The MICSHelper service is created by the app on a portable copy and by the
  installer on an installed one (B4/D-026), and its binPath names the
  mics-engine.exe of the copy whose Settings -> Engine page installed it. Removing
  that copy while the service still points at it would leave a service aimed at a
  deleted binary, so installer\mics.nsi asks this before it deletes anything.

  Two callers, one comparison:

    * without -Remove it only answers - the release verifiers and a human use it;
    * with -Remove the uninstaller asks it to also stop and delete the service it
      just proved is this copy's own. That is the half B4 moved into the installer:
      the same elevated run that created the service removes it, so an uninstall is
      still one prompt and never leaves a LocalSystem service aimed at a deleted
      folder. Removal needs elevation; without it the delete fails and the answer
      stays OWNED, which is what makes the uninstaller refuse rather than proceed.

  The service name used for removal is the **leaf of -ServiceKey**, not a constant:
  the caller may have pointed -ServiceKey at a synthetic key (verify-installer.ps1
  does), and a probe must never be able to delete the machine's real MICSHelper.

  The parse is deliberately liberal: `sc create` stores `"<exe>" helper-service`
  (quoted, because "Program Files" contains a space), but an unquoted definition or
  one carrying other arguments must not be mistaken for a different copy.

  Exit codes (the uninstaller removes only on 0):
    0  SAFE     no such service, or it points at a different folder, or -Remove
                took it away
    2  OWNED    the service's binary lives in -InstallDir and it is still there
    1  UNKNOWN  the service exists but its definition could not be read

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\check-helper-ownership.ps1 -InstallDir "$env:LOCALAPPDATA\MI CS"
  if ($LASTEXITCODE -eq 2) { "the helper belongs to that copy - remove it in the app first" }

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\check-helper-ownership.ps1 -InstallDir "$INSTDIR" -Remove

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9). Without -Remove it never touches the
  service and needs no elevation; with -Remove it stops and deletes one service.
#>
param(
  [Parameter(Mandatory = $true)][string]$InstallDir,
  [string]$ServiceKey = "HKLM\SYSTEM\CurrentControlSet\Services\MICSHelper",
  [switch]$Remove
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

if (-not [string]::Equals($exeDir.TrimEnd('\'), $installFull.TrimEnd('\'),
    [System.StringComparison]::OrdinalIgnoreCase)) {
  Write-Output "RESULT: SAFE (the helper points at another copy)"
  exit 0
}

if (-not $Remove) {
  Write-Output "RESULT: OWNED (the helper points at this copy - remove it in the app first)"
  exit 2
}

# -Remove: the caller created this service and is about to delete the folder it
# points at (D-026). The name comes from -ServiceKey's leaf so a verification build
# aimed at a synthetic key cannot touch the machine's real MICSHelper.
$name = Split-Path -Leaf $ServiceKey
Write-Output "  removing     : the '$name' service (stop, then delete)"

& sc.exe stop $name 2>&1 | ForEach-Object { Write-Output "    sc stop  : $_" }
$stopExit = $LASTEXITCODE
if ($stopExit -ne 0) { Write-Output "    sc stop  : exit $stopExit (a stopped service answers 1062; the delete below still applies)" }

& sc.exe delete $name 2>&1 | ForEach-Object { Write-Output "    sc delete: $_" }
$deleteExit = $LASTEXITCODE
Write-Output "    sc delete: exit $deleteExit"

# The SCM drops the key asynchronously (the service can be "marked for deletion"
# while a handle is open), so give it a moment and then ask the same question again
# instead of trusting sc's exit code.
$deadline = (Get-Date).AddSeconds(5)
while ((Get-Date) -lt $deadline -and (Test-Path -LiteralPath $provider)) {
  Start-Sleep -Milliseconds 250
}
if (-not (Test-Path -LiteralPath $provider)) {
  Write-Output "RESULT: SAFE (the helper was stopped and removed with this copy)"
  exit 0
}
Write-Output "RESULT: OWNED (the helper is still there - remove it in the app, or run elevated)"
exit 2
