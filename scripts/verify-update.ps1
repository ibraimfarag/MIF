<#
.SYNOPSIS
  Proves where `update.check` looks for its manifest, that only a manifest signed
  by a key this engine pins is read at all, and that a feed which does not match
  its own hash is refused before anything is staged (D-046, D-047).

.DESCRIPTION
  Register section 0.6 row 5 (the update row). Slice 1 gave the update path a
  compiled-in feed per channel and a screen that can say which feed answered.
  Slice 2 (D-047) is the half that decides whether to believe it: `update.json`
  ships with a detached PKCS#7 beside it, the engine verifies that signature over
  the exact bytes it downloaded, and pins the signer's thumbprint to the
  certificate over the engine itself - or to MICS_UPDATE_SIGNER_THUMBPRINT, which
  is the environment-only way a probe can test a certificate it minted seconds
  ago (AGENTS.md rule 5).

  Nine things have to be measured against a real engine:

    1. `MICS_UPDATE_MANIFEST_URL=off` switches checks off - the one value that
       means "do not look", and it is what a probe or an offline machine uses;
    2. a URL the user saved is what gets fetched, the answer echoes that URL back
       as `manifest_url`, names the signer and says `pinned: true` when the
       signature was checked against the pin, and the download the manifest names
       really is fetched and staged;
    3. a manifest with no signature beside it is refused, and says that is why;
    4. a manifest signed by another key is refused, naming both the key that
       signed it and the pin it was checked against;
    5. a manifest whose bytes changed after signing is refused with the signature
       as the reason, not a hash mismatch in its own fields;
    6. a manifest that is signed correctly but describes other bytes is still
       refused by the SHA-256 check, so the signature did not replace it;
    7. the same honest feed under the *wrong* pin is refused: the pin is what is
       compared, not merely "somebody signed this";
    8. a development engine - no signature of its own - falls back to the signer's
       name and reports the weaker check as weaker, and refuses a stranger's name;
    9. a cleartext feed that is not loopback is refused by `settings.set`, so the
       compiled-in default can never be downgraded by a typo.

  Every refusal also has to leave nothing staged: the point of verifying before
  parsing is that a bad feed cannot get as far as a file on disk.

  The feed is served by this probe from 127.0.0.1 on an ephemeral port over a raw
  TcpListener, so no network is involved and the run works offline. The two
  signing certificates are minted in memory by this probe
  (`CertificateRequest.CreateSelfSigned`), so no certificate store is read or
  written and no private key outlives the run: what is proved is that the engine
  compares the signer against the pin it was given, not that this machine can be
  persuaded to trust anything. The engine's own compiled-in default
  (github.com/ibraimfarag/MIF) is *not* fetched here: two engine unit tests cover
  it (`the_compiled_in_update_feed_passes_the_same_gate_as_a_typed_one`,
  `the_update_url_resolves_in_order_and_an_empty_env_switches_it_off`), and this
  probe owns the "which URL is actually used, and is what it names really
  verified" half.

  What this probe does NOT prove:
    * that the published default answers - `v0.1.0` is published (2026-11-10,
      section 0.6 row 1 is that click) but carries no `update.json`: its assets
      are the zip, the installer, `report.md` and `SHA256SUMS`, so
      `releases/latest/download/update.json` answers 404 today. The Release
      workflow uploads `dist/update.json` and its `.sig` with the rest of the
      assets (`.github/workflows/release.yml`), so the next published release is
      what makes that URL answer - measured on 2026-11-12;
    * that a real release ZIP extracts and replaces the running binaries: that
      needs a signed payload (D-016) and belongs to the release gate;
    * that `scripts/make-release.ps1 -Sign` signs the manifest it publishes: that
      needs the release key, and `scripts/update-manifest.ps1` reads its own
      signature back plus the release gate checks the package.

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
  # Both feed variables are cleared before the scenario's own are applied: a pin
  # left over from part 2 would answer for the part that must run without one.
  Remove-Item Env:MICS_UPDATE_MANIFEST_URL -ErrorAction SilentlyContinue
  Remove-Item Env:MICS_UPDATE_SIGNER_THUMBPRINT -ErrorAction SilentlyContinue
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

# One route of the probe's feed: the bytes and the content type they are served
# with. Bytes rather than strings because a signature covers bytes (D-047).
function New-Route([byte[]]$Body, [string]$Type = "application/json") {
  return @{ body = $Body; type = $Type }
}

# The feed itself: a path -> route table, so a new scenario is a new route rather
# than a new named parameter. A path that is not in the table is a 404, which is
# also how "the signature is not there" is served (part 3).
function Start-Feed([int]$Port, [hashtable]$Routes) {
  $job = Start-Job -ScriptBlock {
    param($feedPort, $table)
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $feedPort)
    $listener.Start()
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
        if ($table.ContainsKey($path)) {
          $body = $table[$path].body
          $type = $table[$path].type
          $status = "200 OK"
        }
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
  } -ArgumentList $Port, $Routes
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

# SignedCms - the detached PKCS#7 the release lane writes as update.json.sig - is
# not loaded by default in Windows PowerShell.
Add-Type -AssemblyName System.Security

# A code-signing certificate minted here and thrown away with the run. Nothing is
# written to a certificate store: what has to be proved is that the engine
# compares a signer against the pin it was given, not that this machine can be
# persuaded to trust a certificate. The two names are the release name and a
# stranger's, because that is the fallback for an engine with no pin of its own.
function New-ProbeCertificate([string]$CommonName) {
  $key = [System.Security.Cryptography.RSA]::Create(2048)
  $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    ("CN=" + $CommonName), $key,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  return $request.CreateSelfSigned(
    [System.DateTimeOffset]::UtcNow.AddMinutes(-5),
    [System.DateTimeOffset]::UtcNow.AddDays(30))
}

# A detached PKCS#7 over exactly these bytes: the same shape
# `scripts/sign.ps1 -DataFile` writes for a release, so what the engine accepts
# here is what a release publishes. SHA-256, the digest the release lane signs
# with, and EndCertOnly, so the certificate travels with the signature and no
# store has to know it.
function New-DetachedSignature(
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
    [byte[]]$Content) {
  $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
    [System.Security.Cryptography.Pkcs.ContentInfo]::new($Content), $true)
  $signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new($Cert)
  $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
  $signer.DigestAlgorithm = [System.Security.Cryptography.Oid]::new("2.16.840.1.101.3.4.2.1")
  $cms.ComputeSignature($signer)
  $encoded = $cms.Encode()
  # Read it back the way the engine's provider will: signature only, no chain. A
  # probe that cannot verify its own signature would be reporting on itself.
  $recheck = [System.Security.Cryptography.Pkcs.SignedCms]::new(
    [System.Security.Cryptography.Pkcs.ContentInfo]::new($Content), $true)
  $recheck.Decode($encoded)
  $recheck.CheckSignature($true)
  return $encoded
}

# A one-kilobyte "zip": the download path hashes what it gets, and only
# `update.apply` would unpack it, so the body never has to be a real archive.
$zipText = "PKfake-update-zip-for-the-probe-" + ("x" * 900)
$script:zipBytes = [System.Text.Encoding]::UTF8.GetBytes($zipText)
$zipSha = ([System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash($script:zipBytes)) -replace "-", "").ToLower()

$feedPort = Get-FreePort
$baseUrl = "http://127.0.0.1:$feedPort"
$goodUrl = "$baseUrl/update.json"
$badUrl = "$baseUrl/bad.json"
$unsignedUrl = "$baseUrl/unsigned.json"
$otherUrl = "$baseUrl/other.json"
$tamperedUrl = "$baseUrl/tampered.json"
$zipUrl = "$baseUrl/MICS-portable-9.9.9-x64.zip"
$manifestGood = New-Manifest -Version "9.9.9" -ZipUrl $zipUrl -Sha $zipSha
$manifestBad = New-Manifest -Version "9.9.9" -ZipUrl $zipUrl -Sha ("0" * 64)
# A different manifest, used only as "the bytes that were signed" in part 5: the
# signature beside tampered.json is genuine, over something else.
$manifestElsewhere = New-Manifest -Version "9.9.8" -ZipUrl $zipUrl -Sha $zipSha
$goodBytes = [System.Text.Encoding]::UTF8.GetBytes($manifestGood)
$badBytes = [System.Text.Encoding]::UTF8.GetBytes($manifestBad)
$elsewhereBytes = [System.Text.Encoding]::UTF8.GetBytes($manifestElsewhere)

$ours = New-ProbeCertificate -CommonName "MI CS Code Signing"
$stranger = New-ProbeCertificate -CommonName "Some Other Signer"
$pinOurs = $ours.Thumbprint.ToLower()
$pinStranger = $stranger.Thumbprint.ToLower()

$routes = @{
  "/update.json"        = New-Route $goodBytes
  "/update.json.sig"    = New-Route (New-DetachedSignature -Cert $ours -Content $goodBytes) "application/pkcs7-signature"
  "/bad.json"           = New-Route $badBytes
  "/bad.json.sig"       = New-Route (New-DetachedSignature -Cert $ours -Content $badBytes) "application/pkcs7-signature"
  "/unsigned.json"      = New-Route $goodBytes
  "/other.json"         = New-Route $goodBytes
  "/other.json.sig"     = New-Route (New-DetachedSignature -Cert $stranger -Content $goodBytes) "application/pkcs7-signature"
  "/tampered.json"      = New-Route $goodBytes
  "/tampered.json.sig"  = New-Route (New-DetachedSignature -Cert $ours -Content $elsewhereBytes) "application/pkcs7-signature"
  "/MICS-portable-9.9.9-x64.zip" = New-Route $script:zipBytes "application/zip"
}

$elevated = $false
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $elevated = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $elevated = $false }
Note ("engine: $EngineExe")
Note ("this shell: elevated=$elevated (the update path needs no elevation)")
Note ("pinned key for parts 2-6: $pinOurs (minted by this probe, in memory)")

$a = $null; $b = $null; $c = $null; $d = $null; $e = $null; $feed = $null
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

  # ---- 2. a signed feed, reached the way a user's URL is ----------------------
  Write-Output ""
  Write-Output "== part 2 - a signed feed served from loopback, under the pin"
  $feed = Start-Feed -Port $feedPort -Routes $routes
  Start-Sleep -Milliseconds 300
  Note ("feed: " + $goodUrl)

  $b = Start-Engine -pipeName "mics-update-b" -extra @{ MICS_UPDATE_SIGNER_THUMBPRINT = $pinOurs } -tag "b"
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
    Check ($r.signature -eq "verified") "the answer says the manifest's signature was verified"
    Check (("" + $r.signer_thumbprint) -eq $pinOurs) ("the answer names the certificate that signed the feed (got " + $r.signer_thumbprint + ")")
    Check ($r.signer -eq "MI CS Code Signing") ("the answer names the signer a person can read (got " + $r.signer + ")")
    Check ($r.pinned -eq $true) "the answer says the signer was checked against the pin"
    Note ("status=" + $r.status + " latest=" + $r.latest + " signer=" + $r.signer + " pinned=" + $r.pinned)
  } else { Check $false "update.check answered for a signed manifest" }

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

  # ---- 3. a manifest with no signature at all ---------------------------------
  Write-Output ""
  Write-Output "== part 3 - a manifest nothing signed"
  $c = Start-Engine -pipeName "mics-update-c" -extra @{ MICS_UPDATE_SIGNER_THUMBPRINT = $pinOurs } -tag "c"
  $null = Invoke-Rpc -pipeName "mics-update-c" -method "settings.set" -params @{ update_manifest_url = $unsignedUrl } -id 5
  $unsigned = Invoke-Rpc -pipeName "mics-update-c" -method "update.check" -params $null -id 6
  $why = "no answer"
  if ($null -ne $unsigned -and $null -ne $unsigned.error) { $why = $unsigned.error.message }
  Check ($null -ne $unsigned -and $null -ne $unsigned.error) "a manifest with no signature beside it is refused"
  Check ($why -match "no signature") ("the refusal names the missing signature: " + $why)
  Check ($why -notmatch "SHA256") "the refusal is about the signature, not about a hash in the manifest"
  Check (-not (Test-Path (Join-Path $c.data "update\update.zip"))) "the unsigned manifest staged nothing"

  # ---- 4. a manifest signed by another key ------------------------------------
  Write-Output ""
  Write-Output "== part 4 - a manifest signed by another key"
  $null = Invoke-Rpc -pipeName "mics-update-c" -method "settings.set" -params @{ update_manifest_url = $otherUrl } -id 7
  $other = Invoke-Rpc -pipeName "mics-update-c" -method "update.check" -params $null -id 8
  $whyOther = "no answer"
  if ($null -ne $other -and $null -ne $other.error) { $whyOther = $other.error.message }
  Check ($null -ne $other -and $null -ne $other.error) "a manifest signed by another key is refused"
  Check ($whyOther -match "Some Other Signer") ("the refusal names the signer it found: " + $whyOther)
  Check ($whyOther -match $pinOurs) "the refusal names the pin it was checked against"
  Check ($whyOther -match $pinStranger) "the refusal names the thumbprint that signed"
  Check (-not (Test-Path (Join-Path $c.data "update\update.zip"))) "the other-key manifest staged nothing"

  # ---- 5. bytes that changed after signing ------------------------------------
  Write-Output ""
  Write-Output "== part 5 - a manifest whose body changed after signing"
  $null = Invoke-Rpc -pipeName "mics-update-c" -method "settings.set" -params @{ update_manifest_url = $tamperedUrl } -id 9
  $changed = Invoke-Rpc -pipeName "mics-update-c" -method "update.check" -params $null -id 10
  $whyChanged = "no answer"
  if ($null -ne $changed -and $null -ne $changed.error) { $whyChanged = $changed.error.message }
  Check ($null -ne $changed -and $null -ne $changed.error) "a manifest whose body changed after signing is refused"
  Check ($whyChanged -match "does not verify") ("the refusal says the signature does not verify: " + $whyChanged)
  Check (-not (Test-Path (Join-Path $c.data "update\update.zip"))) "the changed manifest staged nothing"

  # ---- 6. signed correctly, describing other bytes ----------------------------
  Write-Output ""
  Write-Output "== part 6 - a good signature over a lying manifest"
  $null = Invoke-Rpc -pipeName "mics-update-c" -method "settings.set" -params @{ update_manifest_url = $badUrl } -id 11
  $lying = Invoke-Rpc -pipeName "mics-update-c" -method "update.check" -params $null -id 12
  if ($lying -and $null -ne $lying.result) {
    Check ($lying.result.signature -eq "verified") "a manifest that is signed but lies is read: the signature is not the hash check"
  } else { Check $false "a signed manifest was refused by the signature gate" }
  $refused = Invoke-Rpc -pipeName "mics-update-c" -method "update.download" -params $null -id 13
  $whyHash = "no answer"
  if ($null -ne $refused -and $null -ne $refused.error) { $whyHash = $refused.error.message }
  Check ($null -ne $refused -and $null -ne $refused.error) "a manifest whose sha256 is wrong is refused"
  Check ($whyHash -match "SHA256 mismatch") ("the refusal names the mismatch: " + $whyHash)
  Check (-not (Test-Path (Join-Path $c.data "update\update.zip"))) "the refused download left no update.zip behind"

  # ---- 7. the same honest feed, under the wrong pin ---------------------------
  Write-Output ""
  Write-Output "== part 7 - the pin is what is compared"
  $d = Start-Engine -pipeName "mics-update-d" -extra @{ MICS_UPDATE_SIGNER_THUMBPRINT = $pinStranger } -tag "d"
  $null = Invoke-Rpc -pipeName "mics-update-d" -method "settings.set" -params @{ update_manifest_url = $goodUrl } -id 14
  $wrongPin = Invoke-Rpc -pipeName "mics-update-d" -method "update.check" -params $null -id 15
  $whyPin = "no answer"
  if ($null -ne $wrongPin -and $null -ne $wrongPin.error) { $whyPin = $wrongPin.error.message }
  Check ($null -ne $wrongPin -and $null -ne $wrongPin.error) "a correctly signed feed is refused under a pin that is not the signer"
  Check ($whyPin -match $pinOurs) ("the refusal names the key that signed: " + $whyPin)
  Check ($whyPin -match $pinStranger) "the refusal names the pin"
  Check (-not (Test-Path (Join-Path $d.data "update\update.zip"))) "the wrongly pinned feed staged nothing"

  # ---- 8. an engine with no certificate of its own ----------------------------
  Write-Output ""
  Write-Output "== part 8 - an engine that carries no signature of its own"
  $engineSignature = Get-AuthenticodeSignature -LiteralPath $EngineExe
  if ($engineSignature.Status -ne "NotSigned") {
    # A signed engine pins its own certificate, and this probe cannot re-sign it,
    # so the fallback cannot be reached from here. Say so rather than pretend.
    Skip ("the name fallback needs an unsigned engine binary; this one is " + $engineSignature.Status)
  } else {
    # A cargo build: nothing to pin, so the release name is the contract and the
    # answer has to report the weaker check as weaker (D-047).
    $e = Start-Engine -pipeName "mics-update-e" -extra @{} -tag "e"
    $null = Invoke-Rpc -pipeName "mics-update-e" -method "settings.set" -params @{ update_manifest_url = $goodUrl } -id 16
    $byName = Invoke-Rpc -pipeName "mics-update-e" -method "update.check" -params $null -id 17
    if ($byName -and $null -ne $byName.result) {
      Check ($byName.result.signature -eq "verified") "the signature is verified even when there is nothing to pin it to"
      Check ($byName.result.pinned -eq $false) "the answer reports the name check instead of claiming a pin"
      Check (("" + $byName.result.signer_thumbprint) -eq $pinOurs) "the answer still names the certificate that signed"
    } else { Check $false "an unsigned engine read a manifest signed under the release name" }

    $null = Invoke-Rpc -pipeName "mics-update-e" -method "settings.set" -params @{ update_manifest_url = $otherUrl } -id 18
    $strangerName = Invoke-Rpc -pipeName "mics-update-e" -method "update.check" -params $null -id 19
    $whyName = "no answer"
    if ($null -ne $strangerName -and $null -ne $strangerName.error) { $whyName = $strangerName.error.message }
    Check ($null -ne $strangerName -and $null -ne $strangerName.error) "a manifest signed under another name is refused when there is no pin"
    Check ($whyName -match "MI CS Code Signing") ("the refusal names the name it expects: " + $whyName)
    Check (-not (Test-Path (Join-Path $e.data "update\update.zip"))) "the stranger's manifest staged nothing"
  }

  # ---- 9. the cleartext gate: the default can never be downgraded by a typo ---
  Write-Output ""
  Write-Output "== part 9 - the settings gate on the URL"
  $cleartext = Invoke-Rpc -pipeName "mics-update-c" -method "settings.set" -params @{ update_manifest_url = "http://example.com/update.json" } -id 20
  Check ($null -ne $cleartext -and $null -ne $cleartext.error) "a cleartext non-loopback feed is refused"
  if ($null -ne $cleartext -and $null -ne $cleartext.error) {
    Check ($cleartext.error.message -match "must use https") ("the refusal says https is required: " + $cleartext.error.message)
  }
  $kept = Invoke-Rpc -pipeName "mics-update-c" -method "settings.get" -params $null -id 21
  if ($kept -and $null -ne $kept.result) {
    $still = "" + $kept.result.update_manifest_url
    Check ($still -ne "http://example.com/update.json") ("the refused patch left the previous feed in place (got '" + $still + "')")
  } else { Check $false "settings.get answered after a refused patch" }
} finally {
  foreach ($handle in @($a, $b, $c, $d, $e)) { Stop-Engine $handle }
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
