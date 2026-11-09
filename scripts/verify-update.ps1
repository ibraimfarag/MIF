<#
.SYNOPSIS
  Proves where `update.check` looks for its manifest, and that a feed which does
  not match its own hash is refused before anything is staged (D-046).

.DESCRIPTION
  Register section 0.6 row 5 (the update row), slice 1. The update path used to do
  nothing at all until the user pasted a manifest URL into Settings; now the
  channel carries a compiled-in default (the project's own release assets) and the
  screen has to be able to say which feed answered.

  Four things have to be measured against a real engine:

    1. `MICS_UPDATE_MANIFEST_URL=off` switches checks off - the one value that
       means "do not look", and it is what a probe or an offline machine uses;
    2. a URL the user saved is what gets fetched, the answer echoes that URL back
       as `manifest_url` so the screen can show it, and the download the manifest
       names really is fetched and staged;
    3. a manifest whose `sha256` does not describe the bytes it points at is
       refused with that reason, and nothing is staged;
    4. a cleartext feed that is not loopback is refused by `settings.set`, so the
       default can never be downgraded by a typo.

  The feed is served by this probe from 127.0.0.1 on an ephemeral port over a raw
  TcpListener, so no network is involved and the run works offline. The engine's
  own compiled-in default (github.com/ibraimfarag/MIF) is *not* fetched here: two
  engine unit tests cover it
  (`the_compiled_in_update_feed_passes_the_same_gate_as_a_typed_one`,
  `the_update_url_resolves_in_order_and_an_empty_env_switches_it_off`), and this
  probe owns the "which URL is actually used, and is what it names really
  verified" half.

  What this probe does NOT prove:
    * that the published default answers - the v0.1.0 draft is not published yet
      (section 0.6 row 1 is that click), so that URL is a 404 until then;
    * that a real release ZIP extracts and replaces the running binaries: that
      needs a signed payload (D-016) and belongs to the release gate;
    * that a signature covers the manifest itself - that is row 5's slice 2.

  Which binary it measures: with no -EngineExe it picks the *newest* of the two
  build outputs, and it refuses to run when the one it has predates `engine\src`.
  Both guards exist for the same reason (D-045): a stale binary answers as if the
  change under test were missing, which reads exactly like a defect.

  Usage:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-update.ps1
    ... -EngineExe engine\target\debug\mics-engine.exe -Keep
#>
param(
  [string]$EngineExe,
  [switch]$Keep
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if (-not $EngineExe) {
  # The newest build output wins. Testing a candidate list in a fixed order makes
  # a leftover `release` binary from before the change answer first, and the run
  # then reports the change as missing (D-045's lesson).
  $EngineExe = @(
      (Join-Path $root "engine\target\release\mics-engine.exe"),
      (Join-Path $root "engine\target\debug\mics-engine.exe")) |
    Where-Object { Test-Path -LiteralPath $_ } |
    Sort-Object { (Get-Item -LiteralPath $_).LastWriteTime } -Descending |
    Select-Object -First 1
}
if (-not $EngineExe -or -not (Test-Path -LiteralPath $EngineExe)) {
  Write-Output "RESULT: FAIL - no engine binary; build it (scripts\pipeline.ps1 -Tier full) or pass -EngineExe"
  exit 1
}

# A source file newer than the binary means this run would measure the old
# engine; that is a reason to stop, not a reason to report a missing feature.
$newestSource = Get-ChildItem -LiteralPath (Join-Path $root "engine\src") -Recurse -Filter *.rs |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($newestSource -and
    (Get-Item -LiteralPath $EngineExe).LastWriteTime -lt $newestSource.LastWriteTime) {
  Write-Output ("RESULT: FAIL - {0} predates engine\src\{1}; build the engine or pass -EngineExe" -f `
      $EngineExe, $newestSource.Name)
  exit 1
}

# A relative -EngineExe is usable in this shell and fatal for a helper that runs
# with its own working directory, so every probe resolves it once (D-045).
$EngineExe = (Resolve-Path -LiteralPath $EngineExe).Path

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
$scratch = Join-Path $env:TEMP ("mics-verify-update-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null

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

function Start-Engine([string]$pipeName, [hashtable]$extra, [string]$tag) {
  $scenarioData = Join-Path $scratch ("data-" + $tag)
  New-Item -ItemType Directory -Path $scenarioData -Force | Out-Null
  $env:MICS_DATA_DIR = $scenarioData
  $env:MICS_PIPE_NAME = $pipeName
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $env:MICS_NO_SCAN_SCHEDULE = "1"
  Remove-Item Env:MICS_UPDATE_MANIFEST_URL -ErrorAction SilentlyContinue
  foreach ($key in $extra.Keys) { Set-Item -Path ("Env:" + $key) -Value $extra[$key] }
  $out = Join-Path $scratch ("stdout-" + $tag + ".log")
  $err = Join-Path $scratch ("stderr-" + $tag + ".log")
  $proc = Start-Process -FilePath $EngineExe -ArgumentList @("service") -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err
  $deadline = (Get-Date).AddSeconds(25)
  while ((Get-Date) -lt $deadline) {
    $log = (Get-Content $err -ErrorAction SilentlyContinue) -join "`n"
    if ($log -match "Starting Named Pipe server") { break }
    Start-Sleep -Milliseconds 250
  }
  return @{ proc = $proc; err = $err; data = $scenarioData }
}

function Stop-Engine($handle) {
  if ($handle -and $handle.proc -and -not $handle.proc.HasExited) {
    Stop-Process -Id $handle.proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
  }
}

# A free port is picked here, not in the job: a background job gets its arguments
# serialized, so it cannot hand a port back.
function Get-FreePort {
  $probe = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
  $probe.Start()
  $port = $probe.LocalEndpoint.Port
  $probe.Stop()
  return $port
}

function Start-Feed([int]$Port, [string]$ManifestJson, [string]$BadJson, [string]$ZipText) {
  $job = Start-Job -ScriptBlock {
    param($feedPort, $manifestBody, $badBody, $zipBody)
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $feedPort)
    $listener.Start()
    $zip = [System.Text.Encoding]::UTF8.GetBytes($zipBody)
    $json = [System.Text.Encoding]::UTF8.GetBytes($manifestBody)
    $bad = [System.Text.Encoding]::UTF8.GetBytes($badBody)
    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Date) -lt $deadline) {
      if (-not $listener.Pending()) { Start-Sleep -Milliseconds 40; continue }
      $client = $listener.AcceptTcpClient()
      try {
        $stream = $client.GetStream()
        $request = ""
        $buffer = New-Object byte[] 2048
        while ($request -notmatch "`r`n`r`n") {
          $read = $stream.Read($buffer, 0, $buffer.Length)
          if ($read -le 0) { break }
          $request += [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        }
        $path = "/"
        $first = ($request -split "`r`n")[0]
        if ($first -match "^\S+\s+(\S+)") { $path = $matches[1] }
        $body = New-Object byte[] 0
        $type = "text/plain"
        $status = "404 Not Found"
        if ($path -eq "/update.json") { $body = $json; $type = "application/json"; $status = "200 OK" }
        elseif ($path -eq "/bad.json") { $body = $bad; $type = "application/json"; $status = "200 OK" }
        elseif ($path -match "^/MICS-portable-.*\.zip$") { $body = $zip; $type = "application/zip"; $status = "200 OK" }
        $head = "HTTP/1.1 $status`r`nContent-Type: $type`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
        $headBytes = [System.Text.Encoding]::ASCII.GetBytes($head)
        $stream.Write($headBytes, 0, $headBytes.Length)
        $stream.Write($body, 0, $body.Length)
        $stream.Flush()
      } finally {
        $client.Close()
      }
    }
    $listener.Stop()
  } -ArgumentList $Port, $ManifestJson, $BadJson, $ZipText
  return @{ job = $job; port = $Port }
}

function Stop-Feed($feed) {
  if ($feed -and $feed.job) {
    Stop-Job $feed.job -ErrorAction SilentlyContinue
    Remove-Job $feed.job -Force -ErrorAction SilentlyContinue
  }
}

function New-Manifest([string]$Version, [string]$ZipUrl, [string]$Sha) {
  return (@{
      version = $Version
      url = $ZipUrl
      sha256 = $Sha
      size = $script:zipBytes.Length
      notes_en = "probe manifest"
      notes_ar = "probe manifest"
    } | ConvertTo-Json -Compress -Depth 5)
}

# A one-kilobyte "zip": the download path hashes what it gets, and only
# `update.apply` would unpack it, so the body never has to be a real archive.
$zipText = "PKfake-update-zip-for-the-probe-" + ("x" * 900)
$script:zipBytes = [System.Text.Encoding]::UTF8.GetBytes($zipText)
$zipSha = ([System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash($script:zipBytes)) -replace "-", "").ToLower()

$feedPort = Get-FreePort
$goodUrl = "http://127.0.0.1:$feedPort/update.json"
$badUrl = "http://127.0.0.1:$feedPort/bad.json"
$zipUrl = "http://127.0.0.1:$feedPort/MICS-portable-9.9.9-x64.zip"
$manifestGood = New-Manifest -Version "9.9.9" -ZipUrl $zipUrl -Sha $zipSha
$manifestBad = New-Manifest -Version "9.9.9" -ZipUrl $zipUrl -Sha ("0" * 64)

$elevated = $false
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $elevated = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $elevated = $false }
Note ("engine: $EngineExe")
Note ("this shell: elevated=$elevated (the update path needs no elevation)")

$a = $null; $b = $null; $c = $null; $feed = $null
try {
  # ---- 1. the one value that means "do not look" ------------------------------
  Write-Output ""
  Write-Output "== part 1 - updates switched off"
  $a = Start-Engine -pipeName "mics-update-a" -extra @{ MICS_UPDATE_MANIFEST_URL = "off" } -tag "a"
  $off = Invoke-Rpc -pipeName "mics-update-a" -method "update.check" -params $null
  if ($off -and $null -ne $off.result) {
    Check ($off.result.status -eq "disabled") ("MICS_UPDATE_MANIFEST_URL=off means disabled (got " + $off.result.status + ")")
    Check (("" + $off.result.detail) -match "switched off") "the reason says update checks are switched off"
    Check (($off.result.PSObject.Properties.Name -notcontains "manifest_url")) "a disabled answer names no feed, because none was fetched"
  } else { Check $false "update.check answered while switched off" }

  # ---- 2. a feed this probe serves, reached the way a user's URL is -----------
  Write-Output ""
  Write-Output "== part 2 - a manifest served from loopback"
  # The lying manifest lives at /bad.json on the same listener, so the only thing
  # that differs in part 3 is the hash.
  $feed = Start-Feed -Port $feedPort -ManifestJson $manifestGood -BadJson $manifestBad -ZipText $zipText
  Start-Sleep -Milliseconds 300
  Note ("feed: " + $goodUrl)

  $b = Start-Engine -pipeName "mics-update-b" -extra @{} -tag "b"
  $saved = Invoke-Rpc -pipeName "mics-update-b" -method "settings.set" -params @{ update_manifest_url = $goodUrl } -id 2
  Check ($null -eq $saved.error) "settings.set accepted a loopback http:// feed"
  $answer = Invoke-Rpc -pipeName "mics-update-b" -method "update.check" -params $null -id 3
  if ($answer -and $null -ne $answer.result) {
    $r = $answer.result
    Check ($r.status -eq "available") ("a newer version on the feed is 'available' (got " + $r.status + ")")
    Check ($r.latest -eq "9.9.9") "the manifest's version is reported"
    Check (("" + $r.manifest_url) -eq $goodUrl) ("the answer echoes the feed that answered (got " + $r.manifest_url + ")")
    Check (([string]$r.sha256).ToLower() -eq $zipSha) "the manifest's sha256 is carried through"
    Check (("" + $r.download_url) -eq $zipUrl) "the manifest's download URL is carried through"
    Note ("status=" + $r.status + " latest=" + $r.latest + " feed=" + $r.manifest_url)
  } else { Check $false "update.check answered for a served manifest" }

  # The URL the manifest names has to be the one downloaded, hashed and staged.
  $staged = Invoke-Rpc -pipeName "mics-update-b" -method "update.download" -params $null -id 4
  Check ($null -ne $staged -and $null -eq $staged.error) ("the download the feed names is accepted: " + `
      $(if ($staged -and $staged.error) { $staged.error.message } else { "no error" }))
  $zipPath = Join-Path $b.data "update\update.zip"
  Check (Test-Path $zipPath) "the verified download is staged under the data directory"
  if (Test-Path $zipPath) {
    $onDisk = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
          [System.IO.File]::ReadAllBytes($zipPath))) -replace "-", "").ToLower()
    Check ($onDisk -eq $zipSha) "the staged bytes hash to what the manifest promised"
  }

  # ---- 3. a manifest that describes other bytes is refused -------------------
  Write-Output ""
  Write-Output "== part 3 - a hash that does not describe the download"
  $c = Start-Engine -pipeName "mics-update-c" -extra @{} -tag "c"
  $null = Invoke-Rpc -pipeName "mics-update-c" -method "settings.set" -params @{ update_manifest_url = $badUrl } -id 5
  $refused = Invoke-Rpc -pipeName "mics-update-c" -method "update.download" -params $null -id 6
  $why = "no answer"
  if ($null -ne $refused -and $null -ne $refused.error) { $why = $refused.error.message }
  Check ($null -ne $refused -and $null -ne $refused.error) "a manifest whose sha256 is wrong is refused"
  Check ($why -match "SHA256 mismatch") ("the refusal names the mismatch: " + $why)
  Check (-not (Test-Path (Join-Path $c.data "update\update.zip"))) "the refused download left no update.zip behind"

  # ---- 4. the cleartext gate: the default can never be downgraded by a typo ---
  Write-Output ""
  Write-Output "== part 4 - the settings gate on the URL"
  $cleartext = Invoke-Rpc -pipeName "mics-update-c" -method "settings.set" -params @{ update_manifest_url = "http://example.com/update.json" } -id 7
  Check ($null -ne $cleartext -and $null -ne $cleartext.error) "a cleartext non-loopback feed is refused"
  if ($null -ne $cleartext -and $null -ne $cleartext.error) {
    Check ($cleartext.error.message -match "must use https") ("the refusal says https is required: " + $cleartext.error.message)
  }
  $kept = Invoke-Rpc -pipeName "mics-update-c" -method "settings.get" -params $null -id 8
  if ($kept -and $null -ne $kept.result) {
    $still = "" + $kept.result.update_manifest_url
    Check ($still -ne "http://example.com/update.json") ("the refused patch left the previous feed in place (got '" + $still + "')")
  } else { Check $false "settings.get answered after a refused patch" }
} finally {
  foreach ($handle in @($a, $b, $c)) { Stop-Engine $handle }
  Stop-Feed $feed
  if ($Keep) { Write-Output "note  kept: $scratch" }
  else { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
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