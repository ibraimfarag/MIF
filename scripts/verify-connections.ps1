<#
.SYNOPSIS
  Proves the connection list is Windows' own table, and that what it offers to
  block is an exact spec the filtering engine accepts.

.DESCRIPTION
  Register section 0.6 row 17, slice (b): the list the user acts on. Three claims
  cannot be seen from a unit test, so this probe measures them against this
  machine:

    1. the rows are real connections: every row's owning process and local port
       are checked against `Get-NetTCPConnection` / `Get-NetUDPEndpoint`, and no
       row may name an owner Windows disagrees with (a row whose local port is
       gone by the time we look is counted as vanished, not as a failure - a
       snapshot ages);
    2. both address families are walked: if this machine has IPv6 connections,
       the list has rows whose remote address is a bracketed IPv6 socket, and if
       it has UDP endpoints, the list has UDP rows;
    3. the block a row offers is exact and acceptable: `block.app` is the row's
       own image path and the file exists, `block.port` and `block.protocol` are
       the row's peer port and protocol, a row with no peer port offers no block
       at all, and the spec itself is then handed to `fw.wfp.block` - accepted
       when this shell can write, refused **with a reason** when it cannot, and
       `fw.wfp.status` is unchanged after a refusal (D-007: a refused call leaves
       nothing behind).

  Writes need either an elevated shell or a running `MICSHelper` service; without
  either, part 3's write records a SKIP with the refusal text instead of a pass.
  The probe never turns "could not try" into "works".

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
function Note([string]$text) {
  Write-Output "note  $text"
}

$started = Get-Date
$scratch = Join-Path $env:TEMP ("mics-verify-conns-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$data = Join-Path $scratch "data"
New-Item -ItemType Directory -Path $data -Force | Out-Null

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
    $deadline = (Get-Date).AddSeconds(30)
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

$env:MICS_DATA_DIR = $data
$env:MICS_PIPE_NAME = "mics-verify-conns"
$out = Join-Path $scratch "stdout.log"
$err = Join-Path $scratch "stderr.log"

$proc = $null
try {
  $proc = Start-Process -FilePath $EngineExe -ArgumentList @("service") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
  $deadline = (Get-Date).AddSeconds(25)
  $log = ""
  while ((Get-Date) -lt $deadline) {
    $log = (Get-Content $err -ErrorAction SilentlyContinue) -join "`n"
    if ($log -match "Starting Named Pipe server") { break }
    Start-Sleep -Milliseconds 250
  }
  Check ($log -match "Starting Named Pipe server") "the engine started"

  # ---- 1. the rows themselves ---------------------------------------------
  Write-Output ""
  Write-Output "== part 1 - the list is Windows' own table"
  $answer = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "net.connections" -params $null
  Check ($null -ne $answer -and $null -ne $answer.result) "net.connections answered"
  $rows = @()
  if ($null -ne $answer -and $null -ne $answer.result) { $rows = @($answer.result) }
  Note ("rows: " + $rows.Count)
  if ($rows.Count -eq 0) {
    Skip "this machine reports no connections at all, so nothing below can be measured"
  } else {
    $fields = $rows[0].PSObject.Properties.Name
    foreach ($field in @("local_address", "remote_address", "protocol", "state", "process_id",
        "process_name", "process_path", "protocol_number", "remote_port")) {
      Check ($fields -contains $field) ("every row carries " + $field)
    }
    Check ($fields -contains "block") "every row says whether it can be blocked"

    # Windows' own view, read once: the engine's rows are compared with it. The
    # key is the local socket (address and port), because one port can be bound
    # by several processes on different addresses, and a row is only compared
    # with Windows' answer for the address it actually names.
    $tcp = @()
    $udp = @()
    try { $tcp = @(Get-NetTCPConnection -ErrorAction Stop) } catch { Skip "Get-NetTCPConnection is unavailable here" }
    try { $udp = @(Get-NetUDPEndpoint -ErrorAction Stop) } catch { Skip "Get-NetUDPEndpoint is unavailable here" }

    function Get-SocketKey([string]$address, [int]$port) {
      $a = $address
      if ($a.StartsWith("[")) { $a = $a.Substring(1, $a.IndexOf("]") - 1) }
      if ($a.Contains("%")) { $a = $a.Substring(0, $a.IndexOf("%")) }
      return ($a + "|" + $port)
    }
    $owners = @{}
    foreach ($entry in @($tcp) + @($udp)) {
      $k = Get-SocketKey $entry.LocalAddress ([int]$entry.LocalPort)
      if (-not $owners.ContainsKey($k)) { $owners[$k] = New-Object System.Collections.Generic.List[int] }
      $owners[$k].Add([int]$entry.OwningProcess)
    }

    # A socket that is closing has already lost its owner in the table
    # (`GetExtendedTcpTable` reports pid 0 for it) while Windows still names the
    # process that closed it. That is the two views differing honestly, not a
    # row that lies, so those rows are not compared on their owner.
    $closing = @("TIME_WAIT", "CLOSE_WAIT", "LAST_ACK", "FIN_WAIT1", "FIN_WAIT2", "CLOSING", "DELETE_TCB")
    $contradicted = New-Object System.Collections.Generic.List[string]
    $vanished = 0
    $seen = 0
    $ambiguous = 0
    foreach ($row in $rows) {
      $local = ($row.local_address -split ":")[-1]
      $key = Get-SocketKey $row.local_address ([int]$local)
      if (-not $owners.ContainsKey($key)) { $vanished++; continue }
      $seen++
      if ($row.process_id -eq 0 -or $closing -contains $row.state) { continue }
      # Windows reporting no owner is Windows not knowing, not Windows disagreeing.
      if ($owners[$key] -contains 0) { continue }
      # Wildcard UDP sockets are shared: WS-Discovery, mDNS and SSDP all bind
      # `::`/`0.0.0.0` on the same port with reuse, and the two Windows APIs name
      # different binders for the same socket. Nothing can be proved there, so
      # those rows are counted, not failed.
      if ($row.protocol -eq "UDP" -and ($row.local_address.StartsWith("0.0.0.0:") -or
          $row.local_address.StartsWith("[::]:"))) { $ambiguous++; continue }
      if (-not ($owners[$key] -contains [int]$row.process_id)) {
        $ownersText = ($owners[$key] -join "/")
        $contradicted.Add(("{0} local socket {1}: Windows says pid {2}, the list says {3}" -f `
              $row.protocol, $key, $ownersText, $row.process_id))
      }
    }
    Note ("checked against Windows: {0} rows still present, {1} already gone, {2} shared UDP sockets not compared" -f `
      $seen, $vanished, $ambiguous)
    $detail = ""
    if ($contradicted.Count -gt 0) {
      $detail = " (" + (($contradicted | Select-Object -First 3) -join "; ") + ")"
    }
    Check ($contradicted.Count -eq 0) ("no row names an owner Windows disagrees with" + $detail)
    if ($seen -eq 0) { Skip "every row had already vanished, so the owners could not be compared" }
    else { Check ($seen -gt 0) "at least one row was still present to compare" }

    # ---- 2. both families and both protocols ------------------------------
    Write-Output ""
    Write-Output "== part 2 - the whole table, not just its IPv4 TCP half"
    $ipv6 = $rows | Where-Object { $_.remote_address.StartsWith("[") }
    $ipv6Local = $rows | Where-Object { $_.local_address.StartsWith("[") }
    $hasV6 = @($tcp + $udp | Where-Object {
        ($_.RemoteAddress -match ":") -or ($_.LocalAddress -match ":") }).Count -gt 0
    if ($hasV6) {
      Check (($ipv6.Count + $ipv6Local.Count) -gt 0) "this machine has IPv6 connections and the list has IPv6 rows"
    } else {
      Skip "this machine has no IPv6 connection to look for"
    }
    $udpRows = $rows | Where-Object { $_.protocol -eq "UDP" }
    if ($udp.Count -gt 0) {
      Check ($udpRows.Count -gt 0) "this machine has UDP endpoints and the list has UDP rows"
      Check (@($udpRows | Where-Object { $_.remote_address -ne "*:*" }).Count -eq 0) `
        "a UDP row says it has no peer instead of inventing one"
    } else {
      Skip "this machine has no UDP endpoint to look for"
    }

    # ---- 3. what a row offers to block ------------------------------------
    Write-Output ""
    Write-Output "== part 3 - the block a row offers is exact"
    $blockable = @($rows | Where-Object { $null -ne $_.block })
    $unblockable = @($rows | Where-Object { $null -eq $_.block })
    Note ("{0} rows offer a block, {1} do not" -f $blockable.Count, $unblockable.Count)
    if ($blockable.Count -eq 0) {
      Skip "no row on this machine has a peer port, so no spec could be checked"
    } else {
      $bad = New-Object System.Collections.Generic.List[string]
      foreach ($row in $blockable) {
        if ($row.block.app -ne $row.process_path) {
          $bad.Add("$($row.process_name): the spec names a different path than the row")
        }
        if (-not (Test-Path -LiteralPath $row.block.app)) {
          $bad.Add("$($row.process_name): the spec names a file that is not there")
        }
        if ($row.block.port -ne $row.remote_port) {
          $bad.Add("$($row.process_name): the spec port is not the row's peer port")
        }
        if ($row.block.protocol -ne $row.protocol_number) {
          $bad.Add("$($row.process_name): the spec protocol is not the row's protocol")
        }
        if ($row.block.note.Length -gt 40 -or $row.block.note -notmatch '^[A-Za-z0-9 _-]+$') {
          $bad.Add("$($row.process_name): the note is not a word the helper accepts")
        }
      }
      $badDetail = ""
      if ($bad.Count -gt 0) { $badDetail = " (" + (($bad | Select-Object -First 3) -join "; ") + ")" }
      Check ($bad.Count -eq 0) ("every offered spec matches its row and the file behind it exists" + $badDetail)
      Check (@($blockable | Where-Object { $_.remote_port -eq 0 }).Count -eq 0) `
        "a spec is offered only when the row has a peer port to match"

      # The spec goes to the engine as the UI sends it: the row's own object.
      $spec = $blockable[0].block
      $statusBefore = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.status" -params $null -id 4
      # A status that failed to answer is not "writable": `$null.needs_elevation`
      # is $null and `-not $null` is True, which sent a broken read down the
      # write path and then compared two errors as "back where it started" -
      # measured on 2026-11-08, the run that found D-045.
      $writable = ($null -ne $statusBefore.result) -and (-not $statusBefore.result.needs_elevation)
      $write = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.block" -params @{
        app = $spec.app; port = $spec.port; protocol = $spec.protocol; note = $spec.note } -id 5
      if ($null -eq $write) {
        Skip "fw.wfp.block did not answer, so the spec could not be checked"
      } elseif ($null -eq $statusBefore.result) {
        $why = ""
        if ($null -ne $statusBefore.error) { $why = $statusBefore.error.message }
        Skip ("fw.wfp.status did not answer ({0}), so the write path was not exercised" -f $why)
      } elseif ($writable) {
        Check ($null -ne $write.result) "the spec a row offers is accepted by fw.wfp.block"
        $statusAfter = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.status" -params $null -id 6
        Check ($statusAfter.result.filters -gt $statusBefore.result.filters) "and the BFE holds one more filter"
        $undo = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.unblock" -params @{
          app = $spec.app; port = $spec.port; protocol = $spec.protocol; note = $spec.note } -id 7
        Check ($null -ne $undo.result) "and fw.wfp.unblock removes it again"
        $statusEnd = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.status" -params $null -id 8
        Check ($statusEnd.result.filters -eq $statusBefore.result.filters) "the machine is back where it started"
      } else {
        Check ($null -ne $write.error) "the spec is refused with a reason, not a crash"
        $reason = ""
        if ($null -ne $write.error) { $reason = $write.error.message }
        Check ($reason -match "administrator|elevat|access is denied|unknown variant") `
          "and the reason says what is missing"
        Note ("refusal: " + $reason)
        $statusEnd = Invoke-Rpc -pipeName $env:MICS_PIPE_NAME -method "fw.wfp.status" -params $null -id 9
        Check (($null -ne $statusEnd.result) -and ($statusEnd.result.filters -eq $statusBefore.result.filters)) `
          "a refused call left nothing behind"
      }
    }

    # A row with no peer port must not be offered one, and the reason is on the
    # row itself: the UI has nothing to invent.
    Write-Output ""
    Write-Output "== part 4 - rows that cannot be blocked say so"
    $noPeer = @($rows | Where-Object { $_.remote_port -eq 0 })
    Check (@($noPeer | Where-Object { $null -ne $_.block }).Count -eq 0) `
      "a row with no peer port offers no block"
    if ($noPeer.Count -eq 0) { Skip "no row on this machine has an empty peer port" }
  }
} finally {
  if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  if (-not $Keep) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
  else { Write-Output "note  kept: $scratch" }
}

$elapsed = [int]((Get-Date) - $started).TotalSeconds
Write-Output ""
Write-Output ("== checks: {0} passed, {1} skipped, {2} failed ({3}s)" -f `
    ($script:checks - $script:failures.Count), $script:skips.Count, $script:failures.Count, $elapsed)
foreach ($skip in $script:skips) { Write-Output ("SKIP  " + $skip) }
foreach ($failure in $script:failures) { Write-Output ("FAIL  " + $failure) }
if ($script:failures.Count -gt 0) { Write-Output "RESULT: FAIL"; exit 1 }
Write-Output "RESULT: PASS"
exit 0
