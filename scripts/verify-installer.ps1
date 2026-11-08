<#
.SYNOPSIS
  Installs the MI CS installer into %TEMP%, measures what it wrote, removes it again,
  and proves the uninstaller refuses a copy the privileged helper still points at.

.DESCRIPTION
  The installer's promises are the kind only a real install can measure: a shortcut
  the Shell files under AppID MICS rather than under the exe path, an uninstaller
  that leaves nothing behind, and a refusal that stops a helper being left aimed at a
  deleted mics-engine.exe. This probe installs a per-user build into %TEMP% - never
  Program Files, so no UAC prompt is needed - and measures all three.

  What it does, in order:

    1. install: silent install into a scratch folder; the app, the engine, the rule
       packs and the uninstaller are all there; both shortcuts carry
       System.AppUserModel.ID = MICS (a Shell property on the .lnk, which is the half
       WriteRegStr cannot write); the AUMID key and the Apps & features entry point at
       this copy; and Get-StartApps files "MI CS" under AppID MICS with no entry under
       the copy's exe path - an entry there is the exact symptom step 1 shipped, when
       the desktop shortcut came out untagged. The Explorer verb (D-041) is measured
       the same way: one under `*`, one under `Directory` and one under
       `Directory\Background`, each labelled "Scan with MI CS", carrying this copy's
       icon and running `"<install>\mics_app.exe" --scan "%1"` - `%V` for the empty
       space behind a folder, which is the folder itself. The menu Explorer paints
       from those keys cannot be read from a script; the keys are the half it consumes.
    2. the helper check: scripts\check-helper-ownership.ps1 answers SAFE for this
       copy and SAFE for a service that is not there, and - when this machine's
       MICSHelper points at %LOCALAPPDATA%\MI CS - OWNED for that copy, which is the
       answer the real uninstaller acts on. A machine without the service is
       reported, not failed.
    3. uninstall: exit 0, and the folder, both shortcuts, the AUMID key, the Apps &
       features entry and all three Explorer verbs are gone, while the machine's
       helper definition and state and the user's own copy are exactly as they were.
    4. refusal: a second build compiled with -HelperServiceKey against a synthetic
       HKCU key whose ImagePath names that copy. Since B4 the uninstaller tries to
       *remove* the service first, and this one it cannot: the key's leaf is not a
       real service name, so the delete fails and the run refuses - error level 5,
       read the documented way (`uninstall.exe /S _?=$INSTDIR`, the switch last) -
       and leaves the program, the uninstaller, both shortcuts and the Apps &
       features entry in place; once the key is gone the same uninstaller exits 0 and
       removes everything. A plain `uninstall.exe /S` answers 0 no matter what, which
       the script asserts too: NSIS copies an uninstaller to %TEMP% and runs it from
       there (manual, appendix D.1). This part also proves the refusal dialogs stay
       out of a silent run: they used to wait for a click nobody was there to make and
       the exit code never arrived (measured - the run sat on it for 532 s until the
       dialog was killed), so both MessageBoxes are guarded by `${IfNot} ${Silent}`.

  It restores what it touched: the machine's AUMID key is exported first and
  re-imported in a finally block, and every folder, key and shortcut the run created
  is removed there too. Because it owns the names it creates, it refuses to start
  when this account already has an MI CS shortcut or per-user Apps & features entry -
  that install would be the one it deleted.

.PARAMETER Setup
  A per-user setup to test (scripts\make-installer.ps1 -TestUser produces one).
  Default: build one into the scratch folder. A setup inside dist\ is copied out
  first: that folder is Low-integrity (docs/TODO.md section 8, trap 21), so a setup
  started from there exits 0 without installing anything.

.PARAMETER RefreshWaitMs
  How long to wait for the start-menu index to pick a new shortcut up (default 15000;
  it is cached and took ~5 s on the machine this was written on).

.PARAMETER KeepScratch
  Leave the scratch folder, its builds and its logs in place after the run.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-installer.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-installer.ps1 -Setup dist\MICS-setup-0.1.0-x64.exe

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9). Needs dist\MICS-portable (the refusal
  build is compiled from it) and, for the real OWNED case, an installed
  %LOCALAPPDATA%\MI CS - which it only reads. No elevation, no UAC prompt.
#>
param(
  [string]$Setup,
  [int]$RefreshWaitMs = 15000,
  [switch]$KeepScratch
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$packageDir = Join-Path $root "dist\MICS-portable"
$scratch = Join-Path $env:TEMP "mics-verify-installer"
$install = Join-Path $scratch "install"
$installRefuse = Join-Path $scratch "install-refuse"
$desktop = [Environment]::GetFolderPath("Desktop")
$startPrograms = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs"
$userCopy = Join-Path $env:LOCALAPPDATA "MI CS"

$appName = "MI CS"
$appId = "MICS"
$aumidKey = "HKCU\Software\Classes\AppUserModelId\$appId"
$aumidProvider = "HKCU:\Software\Classes\AppUserModelId\$appId"
$arpProvider = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$appId"
$helperKey = "HKLM\SYSTEM\CurrentControlSet\Services\MICSHelper"
$syntheticKey = "HKCU\Software\MICS-verify-helper"
$syntheticProvider = "HKCU:\Software\MICS-verify-helper"

# Explorer's "Scan with MI CS" verb (D-041). One per thing a user can point at:
# a file (`*`), a folder (`Directory`), and the empty space inside one
# (`Directory\Background`, whose %V is the folder itself). The `*` key really is
# a literal asterisk, so every read of it has to be -LiteralPath.
$verbClasses = @("*", "Directory", "Directory\Background")
function Get-VerbProvider([string]$class) { "HKCU:\Software\Classes\$class\shell\MICS" }

$deskLnk = Join-Path $desktop "$appName.lnk"
$smDir = Join-Path $startPrograms $appName
$smLnk = Join-Path $smDir "$appName.lnk"
$smUninstallLnk = Join-Path $smDir "Uninstall $appName.lnk"

$failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$text) {
  if ($ok) {
    Write-Output "PASS  $text"
  } else {
    [void]$failures.Add($text)
    Write-Output "FAIL  $text"
  }
}
function Note([string]$text) { Write-Output "      $text" }
function Section([string]$text) { Write-Output ""; Write-Output "== $text ==" }

. (Join-Path $PSScriptRoot "aumid-interop.ps1")

function Read-Aumid([string]$lnk) { return [MicsAumid]::Read($lnk) }

function Resolve-KeyProvider([string]$key) {
  if ($key.StartsWith("HKLM\")) { return "HKLM:\" + $key.Substring(5) }
  if ($key.StartsWith("HKCU\")) { return "HKCU:\" + $key.Substring(5) }
  return $key
}

# The service definition, or "" when there is no such key. Read-only.
function Get-ImagePath([string]$key) {
  $provider = Resolve-KeyProvider $key
  if (-not (Test-Path -LiteralPath $provider)) { return "" }
  try {
    return [string](Get-ItemProperty -LiteralPath $provider -Name ImagePath -ErrorAction Stop).ImagePath
  } catch {
    return ""
  }
}

function Get-ServiceState([string]$name) {
  $text = (& sc.exe query $name) 2>$null
  $line = @($text | Where-Object { $_ -match "STATE" })[0]
  if (-not $line) { return "not installed" }
  return ($line -replace "\s+", " ").Trim()
}

# Runs the shipped checker the way the uninstaller does - a child process, because
# the checker answers with its exit code - and returns that code. Its lines go to
# the host, not into this function's return value.
function Invoke-Checker([string]$installDir, [string]$serviceKey) {
  $argv = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
    (Join-Path $PSScriptRoot "check-helper-ownership.ps1"), "-InstallDir", $installDir)
  if ($serviceKey) { $argv += @("-ServiceKey", $serviceKey) }
  $out = & powershell @argv
  foreach ($line in @($out)) { if ("$line") { Write-Host "      $line" } }
  return $LASTEXITCODE
}

function Get-StartAppsNamed([string]$name) {
  try { return @(Get-StartApps | Where-Object { $_.Name -eq $name }) } catch { return @() }
}

if (-not (Test-Path (Join-Path $packageDir "mics_app.exe"))) {
  throw "no assembled package at $packageDir - run scripts\make-release.ps1 first"
}

# This probe owns the names it creates, so a pre-existing MI CS install under this
# account would be the one it removed. Refuse instead of guessing.
if ((Test-Path -LiteralPath $deskLnk) -or (Test-Path -LiteralPath $smDir) -or (Test-Path -LiteralPath $arpProvider) -or
    (Test-Path -LiteralPath (Get-VerbProvider "Directory"))) {
  throw ("this account already has an '$appName' install (desktop shortcut: $(Test-Path -LiteralPath $deskLnk), " +
    "Start-Menu folder: $(Test-Path -LiteralPath $smDir), Apps & features entry: $(Test-Path -LiteralPath $arpProvider), " +
    "Explorer verb: $(Test-Path -LiteralPath (Get-VerbProvider 'Directory'))). " +
    "This probe installs into %TEMP% and must own those names - remove that install first or run on a clean account.")
}

New-Item -ItemType Directory -Force -Path $scratch | Out-Null

# ---------- what the machine looks like before anything is touched ----------
$backupAumid = Join-Path $scratch "aumid-backup.reg"
if (Test-Path $aumidProvider) { & reg.exe export $aumidKey $backupAumid /y | Out-Null }
$helperBefore = Get-ImagePath $helperKey
$helperStateBefore = Get-ServiceState "MICSHelper"
$userEngineHash = ""
$userFiles = 0
if (Test-Path (Join-Path $userCopy "mics-engine.exe")) {
  $userEngineHash = (Get-FileHash (Join-Path $userCopy "mics-engine.exe") -Algorithm SHA256).Hash
  $userFiles = (Get-ChildItem $userCopy -Recurse -File | Measure-Object).Count
}

$started = Get-Date
Section "this machine before the run"
$aumidBefore = "(none)"
if (Test-Path $aumidProvider) {
  $props = Get-ItemProperty $aumidProvider
  $aumidBefore = "$($props.DisplayName) / $($props.IconUri)"
}
Write-Output "AUMID key            : $aumidBefore"
Write-Output "helper service       : [$helperBefore] [$helperStateBefore]"
Write-Output "user copy            : $userFiles files, engine [$userEngineHash]"
Write-Output "apps entries '$appName': $((Get-StartAppsNamed $appName | ForEach-Object { $_.AppID }) -join ', ')"
Write-Output "SysWOW64 powershell  : $(Test-Path (Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'))"

try {
  # ============ part 1 - install ============
  Section "part 1 - install a per-user build into $install"

  if ($Setup) {
    $setupPath = (Resolve-Path $Setup).Path
    if ($setupPath.StartsWith((Join-Path $root "dist"), [System.StringComparison]::OrdinalIgnoreCase)) {
      $copy = Join-Path $scratch "MICS-setup-copied.exe"
      Copy-Item -LiteralPath $setupPath -Destination $copy -Force
      Note "copied out of dist\ first (Low integrity: a setup started there installs nothing)"
      $setupPath = $copy
    }
  } else {
    $setupPath = Join-Path $scratch "MICS-setup-test.exe"
    Write-Output "building a per-user test build into $setupPath ..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "make-installer.ps1") `
      -TestUser -Out $setupPath | Select-Object -Last 4 | ForEach-Object { Note $_ }
    Check ($LASTEXITCODE -eq 0) "scripts\make-installer.ps1 -TestUser produced a setup"
  }
  Note "setup: $setupPath ($([Math]::Round((Get-Item $setupPath).Length / 1MB, 1)) MB, sha256 $((Get-FileHash $setupPath -Algorithm SHA256).Hash))"

  $p = Start-Process -FilePath $setupPath -ArgumentList "/S", "/D=$install" -Wait -PassThru
  Check ($p.ExitCode -eq 0) "the installer exited 0"

  foreach ($rel in @("mics_app.exe", "mics-engine.exe", "uninstall.exe", "data\app.so",
      "rules\guard\starter.json", "rules\yara\starter.yar", "sbom.cdx.json", "VERSION")) {
    Check (Test-Path -LiteralPath (Join-Path $install $rel)) "installed: $rel"
  }
  $installedFiles = 0
  if (Test-Path $install) { $installedFiles = (Get-ChildItem $install -Recurse -File | Measure-Object).Count }
  Note "$installedFiles files in the install folder"
  Check ($installedFiles -ge 60) "the install holds the whole package ($installedFiles files)"

  Check (Test-Path -LiteralPath $smLnk) "the Start-Menu shortcut exists"
  Check (Test-Path -LiteralPath $smUninstallLnk) "the Start-Menu uninstall shortcut exists"
  Check (Test-Path -LiteralPath $deskLnk) "the desktop shortcut exists"

  if (Test-Path -LiteralPath $smLnk) {
    $smId = Read-Aumid $smLnk
    Note "System.AppUserModel.ID on the Start-Menu shortcut: [$smId]"
    Check ($smId -eq $appId) "the Start-Menu shortcut carries System.AppUserModel.ID = $appId"
  }
  if (Test-Path -LiteralPath $deskLnk) {
    $deskId = Read-Aumid $deskLnk
    Note "System.AppUserModel.ID on the desktop shortcut: [$deskId]"
    Check ($deskId -eq $appId) "the desktop shortcut carries System.AppUserModel.ID = $appId"
  }

  $reg = Get-ItemProperty $aumidProvider -ErrorAction SilentlyContinue
  Check ($null -ne $reg -and $reg.DisplayName -eq $appName) "the AUMID registry key says DisplayName '$appName'"
  Check ($null -ne $reg -and $reg.IconUri -eq (Join-Path $install "mics_app.exe")) "the AUMID IconUri points at the installed app"

  $arp = Get-ItemProperty $arpProvider -ErrorAction SilentlyContinue
  Note "Apps & features: $(if ($arp) { $arp.DisplayName + ' / ' + $arp.UninstallString } else { '(none)' })"
  Check ($null -ne $arp -and $arp.UninstallString -eq "`"$(Join-Path $install 'uninstall.exe')`"") "the Apps & features entry points at this copy's uninstaller"

  # The Explorer verb (D-041). The menu itself cannot be read from a script, so
  # what is proved is the half Explorer actually consumes: the keys exist under
  # this user, and each command line is the one that hands a path to this copy.
  # `%1` is the file or folder the user clicked; `%V` is the folder the click
  # happened in, which is why the Background verb differs.
  foreach ($class in $verbClasses) {
    $provider = Get-VerbProvider $class
    $verb = Get-ItemProperty -LiteralPath $provider -ErrorAction SilentlyContinue
    $command = Get-ItemProperty -LiteralPath "$provider\command" -ErrorAction SilentlyContinue
    $argument = if ($class -eq "Directory\Background") { "%V" } else { "%1" }
    $expected = "`"$(Join-Path $install 'mics_app.exe')`" --scan `"$argument`""
    Note "verb on '$class': [$($verb.'(default)')] -> [$($command.'(default)')]"
    Check ($null -ne $verb -and $verb.'(default)' -eq "Scan with $appName") "the verb on '$class' is labelled 'Scan with $appName'"
    Check ($null -ne $verb -and $verb.Icon -eq (Join-Path $install "mics_app.exe")) "the verb on '$class' carries the app's icon"
    Check ($null -ne $command -and $command.'(default)' -eq $expected) "the verb on '$class' runs: $expected"
  }

  # The Shell's own start-menu index, which is cached and refreshes a few seconds
  # after a shortcut changes. Both facts matter: the app must be filed under AppID
  # MICS, and nothing may be filed under the exe path instead (the untagged-shortcut
  # symptom).
  $apps = @()
  $waited = 0
  while ($true) {
    $apps = Get-StartAppsNamed $appName
    $underMics = @($apps | Where-Object { $_.AppID -eq $appId })
    $underExe = @($apps | Where-Object { $_.AppID -like "*$install*" })
    if ($underMics.Count -gt 0 -and $underExe.Count -eq 0) { break }
    if ($waited -ge $RefreshWaitMs) { break }
    Start-Sleep -Milliseconds 1000
    $waited += 1000
  }
  $ids = @($apps | ForEach-Object { $_.AppID })
  Note "Get-StartApps '$appName': $($apps.Count) entr(ies): $($ids -join ', ') (waited ${waited} ms)"
  Check (@($ids | Where-Object { $_ -eq $appId }).Count -gt 0) "the Shell files '$appName' under AppID $appId"
  Check (@($ids | Where-Object { $_ -like "*$install*" }).Count -eq 0) "no '$appName' entry is filed under this copy's exe path"

  # ============ part 2 - the ownership checker ============
  Section "part 2 - scripts\check-helper-ownership.ps1"
  $code = Invoke-Checker -installDir $install
  Check ($code -eq 0) "SAFE for this copy, which the helper does not point at (exit 0)"

  $code = Invoke-Checker -installDir $install -serviceKey "HKLM\SYSTEM\CurrentControlSet\Services\NoSuchMicsService"
  Check ($code -eq 0) "SAFE for a service that does not exist (exit 0)"

  if ($helperBefore -eq "") {
    Note "no real OWNED case to read: this machine has no MICSHelper service to point anywhere"
    Note "part 4 proves that branch against a synthetic one"
  } else {
    $code = Invoke-Checker -installDir $userCopy
    if ($code -eq 2) {
      Check $true "OWNED for $userCopy, which this machine's helper points at (exit 2)"
    } elseif ($code -eq 0) {
      Note "the machine's helper points elsewhere ($helperBefore) - SAFE for $userCopy (exit 0)"
      Check $true "a helper that points at another copy reads SAFE"
    } else {
      Check $false "OWNED/SAFE for $userCopy (the checker answered $code)"
    }
  }

  # ============ part 3 - uninstall ============
  Section "part 3 - uninstall"
  $u = Start-Process -FilePath (Join-Path $install "uninstall.exe") -ArgumentList "/S" -Wait -PassThru
  Check ($u.ExitCode -eq 0) "the uninstaller exited 0"
  Check (-not (Test-Path -LiteralPath $install)) "the install folder is gone"
  Check (-not (Test-Path -LiteralPath $smLnk)) "the Start-Menu shortcut is gone"
  Check (-not (Test-Path -LiteralPath $deskLnk)) "the desktop shortcut is gone"
  Check (-not (Test-Path -LiteralPath $aumidProvider)) "the AUMID registry key is gone"
  Check (-not (Test-Path -LiteralPath $arpProvider)) "the Apps & features entry is gone"
  foreach ($class in $verbClasses) {
    Check (-not (Test-Path -LiteralPath (Get-VerbProvider $class))) "the Explorer verb on '$class' is gone"
    Check (-not (Test-Path -LiteralPath "$(Get-VerbProvider $class)\command")) "its command key is gone too ('$class')"
  }
  Check ((Get-ImagePath $helperKey) -eq $helperBefore) "the machine's helper definition is unchanged by the uninstall"
  Check ((Get-ServiceState "MICSHelper") -eq $helperStateBefore) "the machine's helper state is unchanged"
  if ($userEngineHash) {
    Check ((Get-FileHash (Join-Path $userCopy "mics-engine.exe") -Algorithm SHA256).Hash -eq $userEngineHash) "the user's engine binary is unchanged"
    Check ((Get-ChildItem $userCopy -Recurse -File | Measure-Object).Count -eq $userFiles) "the user's copy still has $userFiles files"
  }

  # ============ part 4 - the refusal ============
  Section "part 4 - refuse to uninstall a copy the helper points at"
  $refuseSetup = Join-Path $scratch "MICS-setup-refuse.exe"
  Write-Output "building a verification build with -HelperServiceKey $syntheticKey ..."
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "make-installer.ps1") `
    -TestUser -HelperServiceKey $syntheticKey -Out $refuseSetup | Select-Object -Last 3 | ForEach-Object { Note $_ }
  Check ($LASTEXITCODE -eq 0) "the refusal-test build was produced"

  $p2 = Start-Process -FilePath $refuseSetup -ArgumentList "/S", "/D=$installRefuse" -Wait -PassThru
  Check ($p2.ExitCode -eq 0) "the refusal-test build installed"
  Check (Test-Path -LiteralPath (Join-Path $installRefuse "mics-engine.exe")) "it installed an engine to point at"

  New-Item -Path $syntheticProvider -Force | Out-Null
  New-ItemProperty -Path $syntheticProvider -Name ImagePath `
    -Value "`"$(Join-Path $installRefuse 'mics-engine.exe')`" helper-service" -PropertyType String -Force | Out-Null
  Note "$syntheticKey -> $((Get-ItemProperty $syntheticProvider).ImagePath)"

  $code = Invoke-Checker -installDir $installRefuse -serviceKey $syntheticKey
  Check ($code -eq 2) "the checker reads OWNED for the synthetic service (exit 2)"

  # Only the in-place form reports the error level: NSIS copies an uninstaller to
  # %TEMP% and runs it from there, so the plain exit code is always 0 (manual,
  # appendix D.1). _?= has to be the last switch, or NSIS swallows the rest of the
  # command line into $INSTDIR.
  $u2 = Start-Process -FilePath (Join-Path $installRefuse "uninstall.exe") `
    -ArgumentList "/S", "_?=$installRefuse" -Wait -PassThru
  Check ($u2.ExitCode -eq 5) "it refused with error level 5 (uninstall.exe /S _?=`$INSTDIR)"
  $u2b = Start-Process -FilePath (Join-Path $installRefuse "uninstall.exe") -ArgumentList "/S" -Wait -PassThru
  Check ($u2b.ExitCode -eq 0) "a plain /S still answers 0, as NSIS documents (appendix D.1)"

  Check (Test-Path -LiteralPath (Join-Path $installRefuse "mics_app.exe")) "the refused run left the program in place"
  Check (Test-Path -LiteralPath (Join-Path $installRefuse "uninstall.exe")) "the refused run left the uninstaller in place"
  Check (Test-Path -LiteralPath (Get-VerbProvider "Directory")) "the refused run left the Explorer verb in place"
  Check (Test-Path -LiteralPath $smLnk) "the refused run left the Start-Menu shortcut in place"
  Check (Test-Path -LiteralPath $deskLnk) "the refused run left the desktop shortcut in place"
  Check (Test-Path -LiteralPath $arpProvider) "the refused run left the Apps & features entry in place"
  Check ((Get-ImagePath $helperKey) -eq $helperBefore) "the refused run did not touch the machine's helper"

  Remove-Item $syntheticProvider -Recurse -Force
  $u3 = Start-Process -FilePath (Join-Path $installRefuse "uninstall.exe") -ArgumentList "/S" -Wait -PassThru
  Check ($u3.ExitCode -eq 0) "with the helper gone the same uninstaller exits 0"
  Check (-not (Test-Path -LiteralPath $installRefuse)) "and removes that copy"
  Check (-not (Test-Path -LiteralPath $arpProvider)) "and its Apps & features entry"
} catch {
  Check $false "the run stopped early: $($_.Exception.Message)"
} finally {
  Section "restore"
  foreach ($target in @($aumidProvider, $syntheticProvider, $arpProvider)) {
    Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path -LiteralPath $backupAumid) { & reg.exe import $backupAumid | Out-Null }
  Remove-Item -LiteralPath $deskLnk -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $smDir -Recurse -Force -ErrorAction SilentlyContinue
  foreach ($dir in @($install, $installRefuse)) {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  }

  $r = Get-ItemProperty $aumidProvider -ErrorAction SilentlyContinue
  $aumidAfter = "(none)"
  if ($r) { $aumidAfter = "$($r.DisplayName) / $($r.IconUri)" }
  Write-Output "AUMID key      : $aumidAfter"
  Write-Output "helper service : [$(Get-ImagePath $helperKey)] [$(Get-ServiceState 'MICSHelper')]"
  Write-Output "stray desktop  : $(Test-Path -LiteralPath $deskLnk)"
  Write-Output "stray menu dir : $(Test-Path -LiteralPath $smDir)"
  Write-Output "stray ARP key  : $(Test-Path -LiteralPath $arpProvider)"
  Write-Output "took           : $([Math]::Round(((Get-Date) - $started).TotalSeconds, 1)) s"
  if ($KeepScratch) {
    Write-Output "kept           : $scratch"
  } else {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Output ""
if ($failures.Count -eq 0) {
  Write-Output "RESULT: PASS - the installer installed, tagged, uninstalled and refused as promised"
  exit 0
}
Write-Output "RESULT: FAIL ($($failures.Count) problem(s))"
foreach ($f in $failures) { Write-Output "  - $f" }
exit 1