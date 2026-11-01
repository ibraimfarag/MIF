<#
.SYNOPSIS
  Builds the MI CS Windows installer from the assembled package.

.DESCRIPTION
  Takes dist\MICS-portable (the artifact make-release.ps1 produces and
  verify-release.ps1 proves) and compiles installer\mics.nsi around it with
  NSIS, writing dist\MICS-setup-<version>-x64.exe.

  The script does not trust the folder it is handed: it re-runs
  verify-hardening.ps1 on the binaries it is about to package, so an
  installer can never ship what the ZIP gate would have refused.

  NSIS is looked up in this order: -Makensis, PATH, %LOCALAPPDATA%\mics-tools,
  then the two Program Files locations. A portable copy is enough — building
  an installer needs no elevation, only running the per-machine one does.

.PARAMETER Version
  Product version (default: read from engine\Cargo.toml).

.PARAMETER PackageDir
  Folder to package (default: dist\MICS-portable).

.PARAMETER TestUser
  Builds the per-user variant: same script, installs under %LOCALAPPDATA% with
  no UAC prompt. scripts\verify-installer.ps1 uses it to install and remove the
  product without a human clicking anything.

.PARAMETER HelperServiceKey
  Registry path of the privileged helper service the uninstaller asks about.
  Default: HKLM\SYSTEM\CurrentControlSet\Services\MICSHelper, the real service.
  ONLY a verification build passes anything else, so the "refuse to uninstall a
  copy the helper points at" path can be exercised without touching a real
  service.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\make-installer.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\make-installer.ps1 -TestUser -Out dist\test-setup.exe
#>
[CmdletBinding()]
param(
  [string]$Version,
  [string]$PackageDir,
  [string]$Makensis,
  [string]$Out,
  [string]$HelperServiceKey,
  [switch]$TestUser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Version) {
  $cargo = Join-Path $root "engine\Cargo.toml"
  $line = Select-String -Path $cargo -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
  if ($line -and $line.Matches.Count -gt 0) {
    $Version = $line.Matches[0].Groups[1].Value
  } else {
    throw "cannot read the version from engine\Cargo.toml - pass -Version"
  }
}
if (-not $PackageDir) { $PackageDir = Join-Path $root "dist\MICS-portable" }
if (-not (Test-Path $PackageDir)) {
  Write-Output "RESULT: FAIL - no package at $PackageDir"
  Write-Output "  run scripts\make-release.ps1 first (it builds and checks the folder)"
  exit 1
}
if (-not $Out) {
  $name = if ($TestUser) { "MICS-setup-$Version-x64-test.exe" } else { "MICS-setup-$Version-x64.exe" }
  $Out = Join-Path $root ("dist\" + $name)
}
if (-not $Makensis) {
  $candidates = @()
  $onPath = Get-Command makensis.exe -ErrorAction SilentlyContinue
  if ($onPath) { $candidates += $onPath.Source }
  $candidates += (Get-ChildItem "$env:LOCALAPPDATA\mics-tools" -Filter makensis.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
  $candidates += (Get-ChildItem "$env:ProgramFiles\NSIS\makensis.exe", "${env:ProgramFiles(x86)}\NSIS\makensis.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
  $candidates = @($candidates | Where-Object { $_ -and (Test-Path $_) })
  if ($candidates.Count -eq 0) {
    Write-Output "RESULT: FAIL - makensis.exe not found"
    Write-Output "  install NSIS (choco install nsis -y), unzip nsis-<ver>.zip under %LOCALAPPDATA%\mics-tools,"
    Write-Output "  or pass -Makensis <path to makensis.exe>"
    exit 1
  }
  $Makensis = $candidates[0]
}

# What goes in must already be what we mean to ship.
$required = @("mics_app.exe", "mics-engine.exe", "VERSION", "THIRD-PARTY-NOTICES", "sbom.cdx.json",
              "data\app.so", "data\icudtl.dat", "rules\yara\starter.yar", "rules\guard\starter.json")
$missing = @($required | Where-Object { -not (Test-Path (Join-Path $PackageDir $_)) })
if ($missing.Count -gt 0) {
  Write-Output ("RESULT: FAIL - the package is missing: {0}" -f ($missing -join ", "))
  exit 1
}

Write-Host "checking the package's binaries are hardened..."
$stopPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-hardening.ps1") -Path $PackageDir
  $hardeningExit = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $stopPreference
}
if ($hardeningExit -ne 0) {
  Write-Output "RESULT: FAIL - the package is not hardened; refusing to wrap it in an installer"
  exit 1
}

$nsi = Join-Path $root "installer\mics.nsi"

# The installer embeds these (into its temporary plugins folder, never into the
# package): register-aumid.ps1 writes the shortcuts' System.AppUserModel.ID
# through IPropertyStore, which NSIS has no command for, and
# check-helper-ownership.ps1 is what the uninstaller asks before removing a copy
# the privileged helper still points at.
$scriptDir = Join-Path $root "scripts"
$embedded = @("register-aumid.ps1", "aumid-interop.ps1", "check-helper-ownership.ps1")
$missingScripts = @($embedded | Where-Object { -not (Test-Path (Join-Path $scriptDir $_)) })
if ($missingScripts.Count -gt 0) {
  Write-Output ("RESULT: FAIL - the installer's scripts are missing: {0}" -f ($missingScripts -join ", "))
  exit 1
}

$defines = @(
  "/DVERSION=$Version",
  "/DSRCDIR=$PackageDir",
  "/DSCRIPTDIR=$scriptDir",
  "/DOUTFILE=$Out"
)
if ($TestUser) { $defines += "/DTESTUSER" }
if ($HelperServiceKey) { $defines += "/DHELPER_SVC_KEY=$HelperServiceKey" }

Write-Host "compiling $nsi with $Makensis ..."
$log = Join-Path $env:TEMP "mics-nsis.log"
& $Makensis /V2 /NOCD @defines $nsi 2>&1 | Tee-Object -FilePath $log | Out-Null
$nsisExit = $LASTEXITCODE
if ($nsisExit -ne 0 -or -not (Test-Path $Out)) {
  Write-Output "RESULT: FAIL - makensis exited $nsisExit"
  Get-Content $log -Tail 25 | ForEach-Object { Write-Output "  $_" }
  exit 1
}

$hash = (Get-FileHash $Out -Algorithm SHA256).Hash
$size = (Get-Item $Out).Length
Write-Output ""
Write-Output ("MI CS {0} installer{1}" -f $Version, $(if ($TestUser) { " (per-user test build)" } else { "" }))
Write-Output ("  exe   : {0}  ({1:N1} MB)" -f $Out, ($size / 1MB))
Write-Output ("  sha256: {0}" -f $hash)
Write-Output ("  source: {0}" -f $PackageDir)
Write-Output ("  scope : {0}" -f $(if ($TestUser) { "current user, no UAC (verification only)" } else { "all users, one UAC prompt" }))
Write-Output "RESULT: PASS"
