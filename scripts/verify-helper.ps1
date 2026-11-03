<#
.SYNOPSIS
  Proves the privileged-helper protocol (D-007) without a UAC prompt.

.DESCRIPTION
  The one step that needs elevation is the service install. Everything else - the
  closed operation set, the payload validation, the refusal paths, the audit
  trail and the status reporting - can be proven on an unelevated shell, and this
  probe does exactly that:

    1. starts `mics-engine.exe helper-console` on a private pipe with a private
       audit log, in the portable layout: `PROGRAMDATA` points at an empty folder
       so there is no installer account to compare against, which is the F-2
       fallback;
    2. asks from a client that is **not** the engine image first - the helper must
       refuse it, and must say in its log that the image check is the only check
       on this machine;
    3. speaks the real protocol, one connection per request: ping, version, a
       privileged op that must be refused without an elevated token, a hosts
       document without the MI CS marker, a malformed firewall rule and an
       operation that is not in the closed set;
    4. checks the audit log kept the intent and the outcome but never the payload,
       and that `helper-status` reports the helper as reachable.

  Exit code 0 = every expectation held; 1 = something answered differently.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-helper.ps1
  powershell -ExecutionPolicy Bypass -File scripts\verify-helper.ps1 -EnginePath .\mics-engine.exe

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9). Run this unelevated - it is meant to prove what an
  unelevated helper refuses, so elevation would change the answers.
#>
param(
  [string]$EnginePath = "",
  [string]$PipeName = "mics_helper_verify",
  [int]$SettleMs = 1200
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]

function Resolve-Engine([string]$path) {
  if ($path) {
    if (-not (Test-Path $path)) { throw "engine not found: $path" }
    return (Resolve-Path $path).Path
  }
  $candidates = @(
    (Join-Path $PSScriptRoot "..\dist\MICS-portable\mics-engine.exe"),
    (Join-Path $PSScriptRoot "..\build\windows\x64\runner\Release\mics-engine.exe"),
    (Join-Path $PSScriptRoot "..\engine\target\release\mics-engine.exe")
  )
  foreach ($c in $candidates) {
    if (Test-Path $c) { return (Resolve-Path $c).Path }
  }
  throw "no mics-engine.exe found - pass -EnginePath"
}

function Send-Op([string]$json) {
  $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
  try {
    $pipe.Connect(5000)
    $writer = New-Object System.IO.StreamWriter($pipe)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($pipe)
    $writer.WriteLine($json)
    return $reader.ReadLine()
  } finally {
    $pipe.Dispose()
  }
}

# The helper writes its stderr to this file while it runs, so a plain read fails
# with a sharing violation. Read it with the sharing the writer allows.
function Read-HelperLog([string]$path) {
  if (-not (Test-Path $path)) { return "" }
  try {
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open,
      [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $reader = New-Object System.IO.StreamReader($stream)
      return $reader.ReadToEnd()
    } finally {
      $stream.Dispose()
    }
  } catch {
    return ""
  }
}

function Expect([string]$label, [string]$answer, [string]$mustContain) {
  $ok = $answer -and ($answer -like "*$mustContain*")
  $state = if ($ok) { "PASS" } else { "FAIL" }
  Write-Output ("  [{0}] {1,-22} {2}" -f $state, $label, $answer)
  if (-not $ok) { $script:failures.Add("$label did not contain '$mustContain'") }
}

$engine = Resolve-Engine $EnginePath
$log = Join-Path $env:TEMP ("mics-helper-verify-" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".log")
$err = Join-Path $env:TEMP ("mics-helper-verify-" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".err")

Write-Output "engine : $engine"
Write-Output "pipe   : $PipeName"
Write-Output "audit  : $log"

$env:MICS_HELPER_PIPE = $PipeName
$env:MICS_HELPER_LOG = $log
$env:MICS_NO_SINGLETON = "1"
$env:MICS_NO_GUARD = "1"
# The portable layout F-2 describes: an engine with its own data directory while
# `%PROGRAMDATA%\MICS` - the only record of the account MI CS was installed for -
# does not exist. The helper must then fall back to the caller's image name, and
# say so once.
$portableRoot = Join-Path $env:TEMP ("mics-portable-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path (Join-Path $portableRoot "programdata") | Out-Null
$env:PROGRAMDATA = Join-Path $portableRoot "programdata"
$env:MICS_DATA_DIR = Join-Path $portableRoot "data"
Remove-Item Env:\MICS_ENGINE_PATH -ErrorAction SilentlyContinue

# Phase 1: a helper with no recorded installer account and no path pin. A client
# that is not the engine image must be refused - and the helper must say why the
# image check is the only one it has. The helper reads MICS_ENGINE_PATH once, from
# its own environment, so the pin can only be added by a *new* helper (phase 2).
Write-Output "portable fallback (no installer account, no path pin):"
$helper = Start-Process -FilePath $engine -ArgumentList "helper-console" `
  -PassThru -NoNewWindow -RedirectStandardError $err
Start-Sleep -Milliseconds $SettleMs
if ($helper.HasExited) {
  Write-Output "RESULT: FAIL - the helper exited during startup"
  if (Test-Path $err) { Get-Content $err | Select-Object -Last 8 }
  exit 1
}
try {
  # This script is that client: it speaks the protocol itself.
  Expect "a non-engine caller" (Send-Op '{"op":"ping"}') "only serves the MI CS engine"
  $helperLog = Read-HelperLog $err
  if ($helperLog -match "no installer account recorded") {
    Write-Output "  [PASS] the helper logged the missing record once"
  } else {
    $failures.Add("the helper never said it had no installer account to compare (F-2)")
    Write-Output "  [FAIL] the helper logged the missing record once"
  }
} finally {
  if ($helper -and -not $helper.HasExited) { $helper.Kill(); [void]$helper.WaitForExit(5000) }
}

# Phase 2: the same helper with the documented path pin (the hook the installer
# records) naming this script. That is how a differently named client is served -
# deliberately, not by loosening the check for everyone.
$env:MICS_ENGINE_PATH = (Get-Process -Id $PID).Path
$err = Join-Path $env:TEMP ("mics-helper-verify-" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".err")
$helper = Start-Process -FilePath $engine -ArgumentList "helper-console" `
  -PassThru -NoNewWindow -RedirectStandardError $err
Start-Sleep -Milliseconds $SettleMs
if ($helper.HasExited) {
  Write-Output "RESULT: FAIL - the helper exited during startup"
  if (Test-Path $err) { Get-Content $err | Select-Object -Last 8 }
  exit 1
}

try {
  Write-Output "protocol:"
  Expect "ping" (Send-Op '{"op":"ping"}') '"pong":true'
  Expect "version" (Send-Op '{"op":"version"}') '"version"'
  Expect "hardening.run unelevated" (Send-Op '{"op":"hardening.run","action":"smbv1_off"}') "elevated token"
  Expect "hosts without marker" (Send-Op '{"op":"hosts.write","content":"127.0.0.1 example.test"}') "marker"
  Expect "malformed firewall rule" (Send-Op '{"op":"firewall.add_rule","rule":{"name":"x","direction":"sideways","action":"block"}}') "direction"
  Expect "operation outside the set" (Send-Op '{"op":"shell.exec","cmd":"whoami"}') "unknown variant"

  Write-Output "audit log:"
  Start-Sleep -Milliseconds 300
  $text = Read-HelperLog $log
  if ($text -match "phase=start ping") { Write-Output "  [PASS] records the intent" } else { $failures.Add("no phase=start ping in the audit log"); Write-Output "  [FAIL] records the intent" }
  if ($text -match "phase=done ok=true") { Write-Output "  [PASS] records the outcome" } else { $failures.Add("no phase=done ok=true"); Write-Output "  [FAIL] records the outcome" }
  if ($text -match "sha256=") { Write-Output "  [PASS] hashes the payload" } else { $failures.Add("no sha256 in the audit log"); Write-Output "  [FAIL] hashes the payload" }
  if ($text -match "example.test") { $failures.Add("the audit log carries the payload"); Write-Output "  [FAIL] does not carry the payload" } else { Write-Output "  [PASS] does not carry the payload" }
  if ($text -match "ok=false") { Write-Output "  [PASS] records the refusals" } else { $failures.Add("no refusal recorded"); Write-Output "  [FAIL] records the refusals" }

  Write-Output "status:"
  # Both streams go to files on purpose: Windows PowerShell 5.1 can deadlock when
  # a native command's stderr is redirected into a PowerShell stream (`2>$null`),
  # and the engine is chatty on stderr.
  $statusJson = Join-Path $env:TEMP ("mics-helper-status-" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".json")
  $statusErr = "$statusJson.err"
  $statusProc = Start-Process -FilePath $engine -ArgumentList "helper-status", "--json" `
    -PassThru -NoNewWindow -Wait -RedirectStandardOutput $statusJson -RedirectStandardError $statusErr
  $status = if (Test-Path $statusJson) { [System.IO.File]::ReadAllText($statusJson) } else { "" }
  Remove-Item $statusJson, $statusErr -ErrorAction SilentlyContinue
  if ($status -match '"reachable":\s*true') { Write-Output "  [PASS] helper-status sees the helper" } else { $failures.Add("helper-status did not report reachable"); Write-Output "  [FAIL] helper-status sees the helper" }
} finally {
  if ($helper -and -not $helper.HasExited) { $helper.Kill() }
}

Remove-Item $log, $err -ErrorAction SilentlyContinue
Remove-Item $portableRoot -Recurse -Force -ErrorAction SilentlyContinue

if ($failures.Count -eq 0) {
  Write-Output "RESULT: PASS - the helper protocol, validation, refusals and audit trail hold"
  exit 0
}
Write-Output "failures:"
foreach ($f in $failures) { Write-Output "  - $f" }
Write-Output "RESULT: FAIL - the helper did not behave as documented"
exit 1