<#
.SYNOPSIS
  Proves the firewall is driven through Windows' own COM API - not `netsh` - and
  that a rule MI CS creates is the rule Windows enforces and removes.

.DESCRIPTION
  The engine used to shell out to `netsh advfirewall` and parse its English text
  (register 7, MED). It now speaks `INetFwPolicy2` / `INetFwRules` / `INetFwRule`,
  the same surface `wf.msc` uses. A unit test cannot see the difference, so this
  probe measures it against this machine:

    1. the trap is a trap: a fake `netsh.exe` is put at the front of the engine's
       PATH, and a direct `netsh advfirewall show allprofiles` is shown to stop
       working under it (otherwise "the engine kept working" would prove nothing);
    2. reads agree with Windows: `fw.default_deny.status` and `fw.rules.list`
       are compared field by field with `Get-NetFirewallProfile` and
       `Get-NetFirewallRule -PolicyStore ActiveStore` while the trap is active;
    3. a write is real and reversible: one rule is created through the engine,
       read back from Windows with the exact fields that were asked for, then
       removed, and Windows is asked again - the rule is gone. The cleanup runs
       even when a check fails, so a broken run does not leave a rule behind;
       and then the same rule is created again under the *prefixed* spelling to
       prove the two spellings name one rule: `MICS-<rule>` is created as
       `MICS-<rule>` (not `MICS-MICS-<rule>`), and the unprefixed spelling
       removes it (register 7, MED);
    4. nothing in the engine's log mentions `netsh`.

  Writes need either an elevated shell or a running `MICSHelper` service (D-007).
  Without either, the engine refuses with a reason and part 3 records that as a
  skip instead of a pass - the probe never claims what it did not measure.

  It never changes a profile policy: `set_default_deny_outbound` is only *read*
  here, because flipping a machine's default outbound policy - even for a second
  - would cut the network of whatever else is running. Everything else happens
  against a private data directory and a private pipe under
  %TEMP%\mics-verify-firewall-<guid8>, removed unless -Keep is passed.

.PARAMETER EngineExe
  The engine to drive. Default: engine\target\release\mics-engine.exe, then
  engine\target\debug\mics-engine.exe.

.PARAMETER Keep
  Leave the scratch folder and its logs in place.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-firewall.ps1

.NOTES
  ASCII only on purpose (docs/TODO.md 8.9).
#>
param(
  [string]$EngineExe,
  [switch]$Keep
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if (-not $EngineExe) {
  foreach ($candidate in @(
      (Join-Path $root "engine\target\release\mics-engine.exe"),
      (Join-Path $root "engine\target\debug\mics-engine.exe"))) {
    if (Test-Path $candidate) { $EngineExe = $candidate; break }
  }
}
if (-not $EngineExe -or -not (Test-Path $EngineExe)) {
  Write-Output "RESULT: FAIL - no engine binary; build it (scripts\pipeline.ps1 -Tier full) or pass -EngineExe"
  exit 1
}

$script:checks = 0
$script:skips = New-Object System.Collections.Generic.List[string]
$script:failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$text) {
  $script:checks++
  if ($ok) { Write-Output "PASS  $text" }
  else { $script:failures.Add($text); Write-Output "FAIL  $text" }
}
function Skip([string]$text) {
  $script:skips.Add($text)
  Write-Output "SKIP  $text"
}

$started = Get-Date
$scratch = Join-Path $env:TEMP ("mics-verify-firewall-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$data = Join-Path $scratch "data"
$trap = Join-Path $scratch "trap"
New-Item -ItemType Directory -Path $data, $trap -Force | Out-Null

# The trap: a real file named netsh.exe that is not netsh. CreateProcess finds it
# before the real one, prints nothing about a firewall policy, and fails - so an
# engine that still shelled out could not answer the questions below.
Copy-Item -LiteralPath (Join-Path $env:SystemRoot "System32\cmd.exe") -Destination (Join-Path $trap "netsh.exe")

function Invoke-Rpc([string]$pipeName, [string]$method, $params, [int]$id = 1) {
  $payload = @{ jsonrpc = "2.0"; id = $id; method = $method }
  if ($null -ne $params) { $payload["params"] = $params }
  $text = ($payload | ConvertTo-Json -Depth 8 -Compress) + "`n"
  $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
  try {
    $client.Connect(5000)
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $writer.Write($text)
    $reader = New-Object System.IO.StreamReader($client)
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
      $line = $reader.ReadLine()
      if ($null -eq $line) { break }
      $obj = $null
      try { $obj = $line | ConvertFrom-Json } catch { continue }
      if ($obj.PSObject.Properties.Name -contains "id" -and $obj.id -eq $id) { return $obj }
    }
    return $null
  } finally {
    $client.Dispose()
  }
}

$savedPath = $env:PATH
$env:PATH = "$trap;$savedPath"
$env:MICS_DATA_DIR = $data
$env:MICS_PIPE_NAME = "mics-verify-firewall"
$env:MICS_NO_SINGLETON = "1"
$env:MICS_NO_GUARD = "1"
$env:MICS_NO_AUTO_RESUME = "1"
$env:MICS_NO_SCAN_SCHEDULE = "1"
$out = Join-Path $scratch "stdout.log"
$err = Join-Path $scratch "stderr.log"

Write-Output ""
Write-Output "== engine: $EngineExe"
Write-Output "== scratch: $scratch"

$proc = $null
$ruleName = "PROBE-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$fullName = "MICS-$ruleName"
$created = $false
try {
  # ---- 1. the trap really is a trap ----------------------------------------
  Write-Output ""
  Write-Output "== part 1 - the fake netsh breaks a real netsh call"
  $direct = & cmd /c "netsh advfirewall show allprofiles 2>&1"
  Check (-not ($direct -match "Firewall Policy")) "a direct netsh under the trap no longer reports a policy"
  Check ($null -ne (Get-Command netsh -ErrorAction SilentlyContinue) -and ((Get-Command netsh -ErrorAction SilentlyContinue).Source -eq (Join-Path $trap "netsh.exe"))) "the trap is what PATH resolves netsh to"

  # ---- start the engine under the trap ------------------------------------
  $proc = Start-Process -FilePath $EngineExe -ArgumentList @("service") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
  $deadline = (Get-Date).AddSeconds(25)
  $log = ""
  while ((Get-Date) -lt $deadline) {
    $log = (Get-Content $err -ErrorAction SilentlyContinue) -join "`n"
    if ($log -match "Starting Named Pipe server") { break }
    Start-Sleep -Milliseconds 250
  }
  Check ($log -match "Starting Named Pipe server") "the engine started under the trap"

  # ---- 2. reads agree with Windows ----------------------------------------
  Write-Output ""
  Write-Output "== part 2 - what the engine reads is what Windows has"
  $status = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.default_deny.status" -params $null
  $engineOff = $null
  if ($status -and $null -ne $status.result) { $engineOff = $status.result.default_deny_outbound }
  Check ($null -ne $engineOff) "the engine reported the default outbound policy"
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
  $windowsBlocking = @($profiles | Where-Object { $_.DefaultOutboundAction -eq "Block" }).Count
  $expectedOn = ($profiles.Count -gt 0 -and $windowsBlocking -eq $profiles.Count)
  Check ($null -ne $engineOff -and [bool]$engineOff -eq $expectedOn) `
    ("the answer matches Get-NetFirewallProfile (blocking {0} of {1} profiles -> default_deny_outbound = {2})" -f $windowsBlocking, $profiles.Count, $expectedOn)

  $rules = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.rules.list" -params $null -id 2
  $engineRules = @()
  if ($rules -and $null -ne $rules.result) { $engineRules = @($rules.result) }
  $windowsRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName "MICS-*" -ErrorAction SilentlyContinue)
  Check ($null -ne $rules.result) "the engine listed its rules"
  Check ($engineRules.Count -eq $windowsRules.Count) `
    ("the same number of MICS- rules ({0} engine, {1} Windows)" -f $engineRules.Count, $windowsRules.Count)

  # Field by field for every rule both sides know about. This is the payoff of
  # the API: no parsing, so `Direction`/`Action`/`Enabled`/`RemoteAddresses` can
  # be compared with the words Windows itself prints.
  $matched = 0
  foreach ($er in $engineRules) {
    $wr = $windowsRules | Where-Object { $_.DisplayName -eq $er.name } | Select-Object -First 1
    if (-not $wr) { continue }
    $dirOk = ($er.direction -eq "Out" -and "$($wr.Direction)" -eq "Outbound") -or ($er.direction -eq "In" -and "$($wr.Direction)" -eq "Inbound")
    $actOk = "$($er.action)" -eq "$($wr.Action)"
    $enOk = [bool]$er.enabled -eq [bool]$wr.Enabled
    if ($dirOk -and $actOk -and $enOk) { $matched++ }
    else { Write-Output ("      mismatch on {0}: engine {1}/{2}/{3} vs Windows {4}/{5}/{6}" -f $er.name, $er.direction, $er.action, $er.enabled, $wr.Direction, $wr.Action, $wr.Enabled) }
  }
  Check ($matched -eq $engineRules.Count) ("every listed rule agrees with Windows, field by field ({0}/{1})" -f $matched, $engineRules.Count)

  # ---- 3. a write is real, and reversible ---------------------------------
  Write-Output ""
  Write-Output "== part 3 - one rule, created through the engine, then removed"
  $program = Join-Path $env:SystemRoot "System32\notepad.exe"
  $add = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.rules.add" -params @{
    name      = $ruleName
    direction = "out"
    action    = "block"
    protocol  = "tcp"
    local_port = "59999"
    program   = $program
  } -id 3
  $writeRefused = ($null -eq $add -or $null -ne $add.error)
  if ($writeRefused) {
    $reason = "no reason"
    if ($add -and $add.error) { $reason = "$($add.error.message)" }
    Skip ("the write needs elevation or a running MICSHelper: $reason")
    $afterAdd = @(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $fullName -ErrorAction SilentlyContinue)
    Check ($afterAdd.Count -eq 0) "a refused write left nothing behind in Windows"
  } else {
    Check ($add.result.status -eq "created" -and $add.result.name -eq $fullName) "the engine reported the rule it created ($fullName)"
    $created = $true
    $wr = Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $fullName -ErrorAction SilentlyContinue
    Check ($null -ne $wr) "Windows has the rule the engine reported"
    if ($null -ne $wr) {
      Check ("$($wr.Direction)" -eq "Outbound") "Windows agrees the direction is outbound"
      Check ("$($wr.Action)" -eq "Block") "Windows agrees the action is block"
      Check ([bool]$wr.Enabled) "Windows agrees the rule is enabled"
      $pf = @($wr | Get-NetFirewallPortFilter)
      Check ($pf.Count -ge 1 -and "$($pf[0].LocalPort)" -eq "59999") "Windows has the port the request named"
      $af = @($wr | Get-NetFirewallApplicationFilter)
      Check ($af.Count -ge 1 -and "$($af[0].Program)" -eq $program) "Windows has the program the request named"
      Check ("$($wr.Profile)" -eq "Any") "the rule covers every profile, not none (the API default is none)"
      Check ("$($wr.Group)" -eq "MI CS") "the rule is grouped under `"MI CS`" in the Windows UI"
      $listed = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.rules.list" -params $null -id 4
      $listedNames = @()
      if ($listed -and $null -ne $listed.result) { $listedNames = @($listed.result | ForEach-Object { $_.name }) }
      Check ($listedNames -contains $fullName) "the rule appears in the engine's own list"
    }
    $remove = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.rules.remove" -params @{ name = $ruleName } -id 5
    Check ($null -ne $remove -and $null -eq $remove.error -and $remove.result.status -eq "removed") "the engine removed it"
    $created = $false
    $gone = @(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $fullName -ErrorAction SilentlyContinue)
    Check ($gone.Count -eq 0) "Windows no longer has it"
    $removeAgain = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.rules.remove" -params @{ name = $ruleName } -id 6
    Check ($null -ne $removeAgain -and $null -eq $removeAgain.error) "removing it twice is a no-op, not an error"

    # The prefix marks ownership, not spelling. Adding `MICS-<rule>` must create
    # the one rule `MICS-<rule>` - never `MICS-MICS-<rule>` - and the unprefixed
    # spelling must then remove that same rule (register 7, MED). Without this,
    # the removal above can report success while a stray blocking rule stays.
    $prefixed = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.rules.add" -params @{
      name      = $fullName
      direction = "out"
      action    = "block"
      protocol  = "tcp"
      local_port = "59999"
      program   = $program
    } -id 7
    Check ($null -ne $prefixed -and $null -eq $prefixed.error -and $prefixed.result.name -eq $fullName) `
      "a name that already carries the prefix is created as one prefix ($fullName)"
    $created = $true
    $doubled = @(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName "MICS-$fullName" -ErrorAction SilentlyContinue)
    Check ($doubled.Count -eq 0) "Windows has no doubly-prefixed rule"
    $byShortName = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.rules.remove" -params @{ name = $ruleName } -id 8
    Check ($null -ne $byShortName -and $null -eq $byShortName.error -and $byShortName.result.status -eq "removed") `
      "the unprefixed spelling removed the rule the prefixed spelling created"
    $created = $false
    $goneTwice = @(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $fullName -ErrorAction SilentlyContinue)
    Check ($goneTwice.Count -eq 0) "Windows no longer has it after that removal"
  }

  # ---- 4. no netsh anywhere ------------------------------------------------
  Write-Output ""
  Write-Output "== part 4 - the engine never mentioned the tool it used to call"
  $engineErr = (Get-Content $err -ErrorAction SilentlyContinue) -join "`n"
  Check (-not ($engineErr -match "netsh")) "the engine's log has no netsh call or failure"
  $engineOut = (Get-Content $out -ErrorAction SilentlyContinue) -join "`n"
  Check (-not ($engineOut -match "netsh")) "the engine's output has no netsh line either"
} finally {
  if ($created) {
    $cleanup = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.rules.remove" -params @{ name = $ruleName } -id 99
    if ($cleanup -and $null -eq $cleanup.error) { Write-Output "      (cleaned up $fullName after a failed run)" }
  }
  if ($proc) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
  }
  $env:PATH = $savedPath
  Remove-Item Env:MICS_DATA_DIR, Env:MICS_PIPE_NAME, Env:MICS_NO_SINGLETON, Env:MICS_NO_GUARD, Env:MICS_NO_AUTO_RESUME, Env:MICS_NO_SCAN_SCHEDULE -ErrorAction SilentlyContinue
  $left = @(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName "MICS-*PROBE-*" -ErrorAction SilentlyContinue)
  if ($left.Count -gt 0) {
    Write-Output "WARN  a probe rule is still on this machine, remove it by hand:"
    $left | ForEach-Object { Write-Output ("      " + $_.DisplayName) }
  }
  if (-not $Keep) {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
  } else {
    Write-Output ""
    Write-Output "kept: $scratch"
  }
}

$seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
Write-Output ""
foreach ($s in $script:skips) { Write-Output "not measured: $s" }
Write-Output ("{0} check(s), {1} skipped section(s), {2} failure(s), {3} s" -f $script:checks, $script:skips.Count, $script:failures.Count, $seconds)
if ($script:failures.Count -eq 0) {
  Write-Output "RESULT: PASS - the firewall is driven through the COM API, and a created rule is the rule Windows enforces"
  exit 0
}
Write-Output "RESULT: FAIL"
foreach ($f in $script:failures) { Write-Output "  - $f" }
Write-Output "--- engine stderr:"
Get-Content $err -ErrorAction SilentlyContinue | Select-Object -Last 20
exit 1