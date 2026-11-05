<#
.SYNOPSIS
  Proves that a tampered MI CS package is refused by the release gate and reported
  by the app itself.

.DESCRIPTION
  c2 (D-025) gave the package a manifest of itself, carried inside the engine's
  Authenticode signature, and gave the engine a start-up check that answers
  `status.integrity`. This probe is the adversarial half of that story: it tampers
  with one thing at a time in a private copy of the package and asks both halves
  what they think.

    - the release gate: `scripts\verify-manifest.ps1` must refuse the copy;
    - the app: the packaged engine - started from the copy on a private pipe, with
      a private data directory - must answer `unverified`, name what changed in its
      log, and push the card that names it.

  A pristine copy is the control: both halves must accept it. Without that, "every
  tampered copy is refused" would also be true of a probe that refuses everything.

  The cases (docs/TODO.md 0.3c, t2):

    1. one byte flipped in each of the nine shipped binaries. The eight the
       manifest lists are refused by the gate and reported by the app one at a
       time, naming the file. `mics-engine.exe` is never listed in its own
       manifest - its integrity is its signature - so the gate must refuse a code
       edit of it, and the app is not asked to run bytes that were edited in code
       (case 3 changes the engine's bytes too, in its resource, which is safe to
       run and still breaks the signature that covered them).
    2. a swapped DLL, twice: a Windows system DLL in place of a plugin, and one
       plugin renamed over another. Both are refused and both named - the manifest
       covers the DLLs by hash, not by their own signatures, so a DLL that is
       signed by us is no more welcome than a foreign one.
    3. an edited manifest: the resource is rewritten with a hash this build never
       wrote. The gate refuses it and the app reports it - the document's
       authenticity was the signature it just lost.
    3b. a repack: the published manifest injected into an unsigned engine of the
       same build, which is what copying the document into a rebuild looks like.
       The gate refuses it (no signer at all is not "an unsigned local build") and
       the app reports it.
    4. a copied install: accepted by both halves, because a copy of the published
       bytes *is* the published bytes - the manifest is about bytes, not paths -
       and reported the moment one file in the copy changes. What refuses a copy
       used as a *client* is the caller rule (D-015, proved by
       `scripts\verify-pipe-acl.ps1` and `caller::tests`), not the manifest.

  Nothing here touches `dist\MICS-portable`: every case works on a copy under
  %TEMP%, which is Medium integrity, so the engine serves it through its real
  startup path without the `MICS_ALLOW_LOW_INTEGRITY` hook (the workspace tree is
  Low, docs/TODO.md trap 21).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-tamper.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-tamper.ps1 -Path "$env:TEMP\mics-staging" -Keep

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9). The app's own copy is Arabic; this probe never prints it, it
  checks that the card mentions the ASCII path.
#>
param(
  [string]$Path = "",
  [int]$WaitMs = 20000,
  [switch]$Keep
)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
if ($Path -eq "") { $Path = Join-Path $repo "dist\MICS-portable" }
. (Join-Path $PSScriptRoot "manifest-resource.ps1")

$script:failures = New-Object System.Collections.Generic.List[string]
$script:checks = 0

function Check([string]$label, [bool]$ok, [string]$detail) {
  $script:checks++
  $state = if ($ok) { "PASS" } else { "FAIL" }
  if (-not $ok) { $script:failures.Add($label) }
  Write-Output ("  [{0}] {1}" -f $state, $label)
  if ($detail) { Write-Output ("         {0}" -f $detail) }
}

# One byte, xor 0xff, at a fixed offset past the DOS and PE headers: the byte
# changes, the length does not, so no check can pass by noticing a size.
function Set-FlippedByte([string]$file, [int]$offset = 1024) {
  $bytes = [System.IO.File]::ReadAllBytes($file)
  if ($bytes.Length -le $offset) { throw "file too short to flip a byte at $offset : $file" }
  $before = $bytes[$offset]
  $bytes[$offset] = $bytes[$offset] -bxor 0xFF
  [System.IO.File]::WriteAllBytes($file, $bytes)
  return [PSCustomObject]@{ Offset = $offset; Before = $before; After = $bytes[$offset] }
}

# Another file's bytes, forced to a given length (padded with zeroes or cut). A
# swap is proved by the *hash* this way: a check that only compared sizes would
# pass a same-size impostor, which is exactly what a careful repackager makes.
function Set-BytesOf([string]$source, [string]$destination, [int]$length) {
  $bytes = [System.IO.File]::ReadAllBytes($source)
  $result = New-Object byte[] $length
  [Array]::Copy($bytes, 0, $result, 0, [Math]::Min($bytes.Length, $length))
  [System.IO.File]::WriteAllBytes($destination, $result)
}

# The release gate, run as a child process: its exit code is the verdict.
function Get-ManifestVerdict([string]$folder) {
  $text = @(& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "verify-manifest.ps1") -Path $folder)
  $code = $LASTEXITCODE
  $line = [string]($text | Where-Object { $_ -like "RESULT:*" } | Select-Object -Last 1)
  $reasons = @($text | Where-Object { $_ -like "  - *" })
  $reason = ""
  if ($reasons.Count -gt 0) {
    $reason = [string]$reasons[0]
    if ($reasons.Count -gt 1) { $reason = "$reason  (+$($reasons.Count - 1) more)" }
  }
  return [PSCustomObject]@{ Ok = ($code -eq 0); Result = $line; Reason = $reason; Text = ($text -join "`n") }
}

# The app, started the way the product starts it: a private pipe, a private data
# directory, no singleton fight with a running MI CS. The first frame it pushes can
# be an alert (the card) before it answers, so the reply is read by id.
function Get-EngineVerdict([string]$folder, [string]$tag) {
  $engine = Join-Path $folder "mics-engine.exe"
  $pipe = "mics_tamper_$tag"
  $data = Join-Path $script:scratch "data-$tag"
  if (Test-Path -LiteralPath $data) { Remove-Item -LiteralPath $data -Recurse -Force }
  New-Item -ItemType Directory -Path $data -Force | Out-Null

  $env:MICS_DATA_DIR = $data
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $env:MICS_PIPE_NAME = "\\.\pipe\$pipe"

  $out = Join-Path $data "engine.out"
  $err = Join-Path $data "engine.err"
  $proc = Start-Process -FilePath $engine -ArgumentList "service" -PassThru -NoNewWindow `
    -RedirectStandardOutput $out -RedirectStandardError $err

  $verdict = ""
  $alert = ""
  $started = $false
  $client = $null
  $deadline = (Get-Date).AddMilliseconds($WaitMs)
  while (-not $client -and (Get-Date) -lt $deadline) {
    try {
      $candidate = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipe, [System.IO.Pipes.PipeDirection]::InOut)
      $candidate.Connect(300)
      $client = $candidate
    } catch { Start-Sleep -Milliseconds 150 }
  }
  if ($client) {
    $started = $true
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($client)
    $writer.WriteLine('{"jsonrpc":"2.0","id":1,"method":"status"}')
    $answer = $null
    $read = (Get-Date).AddSeconds(30)
    while (-not $answer -and (Get-Date) -lt $read) {
      $line = $reader.ReadLine()
      if (-not $line) { continue }
      if ($line -like '*"id":1*') { $answer = $line } else { $alert = $line }
    }
    $client.Dispose()
    if ($answer) {
      try {
        $document = $answer | ConvertFrom-Json
        if ($document.result) { $verdict = [string]$document.result.integrity }
      } catch { $verdict = "" }
    }
  }
  if (-not $proc.HasExited) { $proc.Kill() }
  Start-Sleep -Milliseconds 250

  $detail = ""
  $log = Join-Path $data "logs\engine.log"
  if (Test-Path -LiteralPath $log) {
    $line = Get-Content -LiteralPath $log | Where-Object { $_ -match "package integrity:" } | Select-Object -Last 1
    if ($line) { $detail = ($line -replace "^.*package integrity: ", "") }
  }
  return [PSCustomObject]@{ Started = $started; Verdict = $verdict; Detail = $detail; Alert = $alert }
}

if (-not (Test-Path -LiteralPath $Path)) {
  Write-Output "RESULT: FAIL - no package at $Path"
  Write-Output "  run scripts\make-release.ps1 first, or pass -Path"
  exit 1
}
$root = (Resolve-Path -LiteralPath $Path).Path
$engine = Join-Path $root "mics-engine.exe"
if (-not (Test-Path -LiteralPath $engine)) {
  Write-Output "RESULT: FAIL - the package has no mics-engine.exe, so it carries no manifest"
  exit 1
}

$script:scratch = Join-Path $env:TEMP ("mics-tamper-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$base = Join-Path $script:scratch "base"
$work = Join-Path $script:scratch "work"
New-Item -ItemType Directory -Path $base -Force | Out-Null
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
Write-Output "package : $root"
Write-Output "scratch : $script:scratch"
Write-Output "engine  : $engine"
Write-Output ""
Write-Output "copying the published package (the control, and the base of every case)"
Copy-Item -Path (Join-Path $root "*") -Destination $base -Recurse -Force

function Reset-Work {
  if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
  Copy-Item -Path $base -Destination $work -Recurse -Force
}

# The published document, for the cases that keep it and change the files, and for
# the repack that keeps it and changes the engine.
$publishedJson = Read-MicsManifestResource -Exe $engine
$published = ConvertFrom-MicsManifest -Json $publishedJson

Write-Output ""
Write-Output "control - the published bytes, copied, must be accepted by both halves"
Reset-Work
$gate = Get-ManifestVerdict $work
Check "control: the release gate accepts the copy" $gate.Ok $gate.Result
$app = Get-EngineVerdict $work "control"
# D-025 has three answers, not two. A build signed with our certificate on a machine that has
# not trusted its root reports `untrusted-certificate`: every listed file hashes as published,
# and the only thing missing is a chain Windows recognises - which is exactly a release
# runner, where the self-signed certificate deliberately never enters the root store (see
# scripts/codesign-cert.ps1). Both answers mean "nothing was edited"; `unverified` is the one
# that means tampering or another signer, and it still fails here.
$settled = @("ok", "untrusted-certificate")
Check "control: the app says ok" ($settled -contains $app.Verdict) ("integrity=$($app.Verdict) $($app.Detail)")
Check "control: no card is raised" (($app.Alert -eq "")) $(if ($app.Alert) { $app.Alert } else { "" })

Write-Output ""
Write-Output "1 - one byte flipped in each shipped binary ($($published.Files.Count) listed, plus the engine)"
$index = 0
foreach ($entry in ($published.Files | Where-Object { $_.Path -match "\.(exe|dll|so)$" })) {
  $index++
  Reset-Work
  $at = Set-FlippedByte (Join-Path $work ($entry.Path -replace "/", "\"))
  $gate = Get-ManifestVerdict $work
  Check ("$($entry.Path): the release gate refuses the byte at $($at.Offset)") (-not $gate.Ok) $gate.Reason
  $app = Get-EngineVerdict $work ("flip$index")
  $named = $entry.Path.Replace("\", "\\")
  Check ("$($entry.Path): the app reports it and names the file") `
    (($app.Verdict -eq "unverified") -and ($app.Detail -like "*$($entry.Path)*")) `
    ("integrity=$($app.Verdict) $($app.Detail)")
  Check ("$($entry.Path): the card names the file") `
    (($app.Alert -like '*"kind":"integrity"*') -and ($app.Alert -like "*$named*")) `
    $(if ($app.Alert) { "card pushed" } else { "no card was pushed" })
}

Reset-Work
$at = Set-FlippedByte (Join-Path $work "mics-engine.exe")
$gate = Get-ManifestVerdict $work
Check "mics-engine.exe: the release gate refuses a code edit" (-not $gate.Ok) $gate.Reason

Write-Output ""
Write-Output "2 - a swapped DLL"
$systemDll = Join-Path $env:SystemRoot "System32\version.dll"
Reset-Work
$dartjni = Join-Path $work "dartjni.dll"
$dartjniLength = (Get-Item -LiteralPath $dartjni).Length
if (Test-Path -LiteralPath $systemDll) {
  Set-BytesOf $systemDll $dartjni $dartjniLength
  $gate = Get-ManifestVerdict $work
  Check "a system DLL in place of a plugin, same size: the gate refuses it" (-not $gate.Ok) $gate.Reason
  $app = Get-EngineVerdict $work "swapforeign"
  Check "a system DLL in place of a plugin, same size: the app reports it" `
    (($app.Verdict -eq "unverified") -and ($app.Detail -like "*dartjni.dll*")) ("integrity=$($app.Verdict) $($app.Detail)")
} else {
  Check "a system DLL in place of a plugin, same size: the probe has a DLL to swap in" $false "no $systemDll on this machine"
}

Reset-Work
Set-BytesOf (Join-Path $work "tray_manager_plugin.dll") $dartjni $dartjniLength
$gate = Get-ManifestVerdict $work
Check "one plugin renamed over another, same size: the gate refuses it" (-not $gate.Ok) $gate.Reason
$app = Get-EngineVerdict $work "swapours"
Check "one plugin renamed over another, same size: the app reports it" `
  (($app.Verdict -eq "unverified") -and ($app.Detail -like "*dartjni.dll*")) ("integrity=$($app.Verdict) $($app.Detail)")

Write-Output ""
Write-Output "3 - an edited manifest"
Reset-Work
$target = ($published.Files | Where-Object { $_.Path -match "\.(exe|dll|so)$" } | Select-Object -First 1).Path
$doctored = New-MicsManifestJson -Version $published.Version -Files @(
  foreach ($file in $published.Files) {
    if ($file.Path -eq $target) {
      [PSCustomObject]@{ Path = $file.Path; Bytes = $file.Bytes; Sha256 = ("0" * 64) }
    } else {
      [PSCustomObject]@{ Path = $file.Path; Bytes = $file.Bytes; Sha256 = $file.Sha256 }
    }
  }
)
Write-MicsManifestResource -Exe (Join-Path $work "mics-engine.exe") -Json $doctored
$signature = Get-AuthenticodeSignature (Join-Path $work "mics-engine.exe")
$gate = Get-ManifestVerdict $work
Check "a hash this build never wrote: the gate refuses it" (-not $gate.Ok) $gate.Reason
$app = Get-EngineVerdict $work "manifestedit"
Check "a hash this build never wrote: the app reports it" (($app.Verdict -eq "unverified")) `
  ("integrity=$($app.Verdict) $($app.Detail) (engine signature $($signature.Status))")
Check "a hash this build never wrote: the card is raised" ($app.Alert -like '*"kind":"integrity"*') `
  $(if ($app.Alert) { "card pushed" } else { "no card was pushed" })

Write-Output ""
Write-Output "3b - the published manifest copied into an unsigned engine (a repack)"
$unsigned = Join-Path $repo "engine\target\release\mics-engine.exe"
if (Test-Path -LiteralPath $unsigned) {
  Reset-Work
  Copy-Item -LiteralPath $unsigned -Destination (Join-Path $work "mics-engine.exe") -Force
  Write-MicsManifestResource -Exe (Join-Path $work "mics-engine.exe") -Json $publishedJson
  $gate = Get-ManifestVerdict $work
  Check "an engine with the manifest but none of our signatures: the gate refuses it" (-not $gate.Ok) $gate.Reason
  $app = Get-EngineVerdict $work "repack"
  Check "an engine with the manifest but none of our signatures: the app reports it" `
    (($app.Verdict -eq "unverified")) ("integrity=$($app.Verdict) $($app.Detail)")
} else {
  Check "an engine with the manifest but none of our signatures: the probe has an unsigned engine" $false `
    "no $unsigned - build it first (cargo build --release in engine\)"
}

Write-Output ""
Write-Output "4 - a copied install"
Reset-Work
$gate = Get-ManifestVerdict $work
Check "a copy of the published bytes: the gate accepts it" ($gate.Ok) $gate.Result
$app = Get-EngineVerdict $work "copy"
Check "a copy of the published bytes: the app says ok" ($settled -contains $app.Verdict) "integrity=$($app.Verdict)"
Set-FlippedByte (Join-Path $work "data\app.so") | Out-Null
$gate = Get-ManifestVerdict $work
Check "the same copy with one changed file: the gate refuses it" (-not $gate.Ok) $gate.Reason
$app = Get-EngineVerdict $work "copychanged"
Check "the same copy with one changed file: the app reports it" `
  (($app.Verdict -eq "unverified") -and ($app.Detail -like "*app.so*")) ("integrity=$($app.Verdict) $($app.Detail)")
Write-Output "  note: what refuses a copy used as a client is the caller rule (D-015), not the manifest:"
Write-Output "        scripts\verify-pipe-acl.ps1 drives that, and caller::tests pin it in Rust."

Write-Output ""
$stopwatch.Stop()
Write-Output ("  {0} check(s), {1} failure(s), {2:N1} s" -f $script:checks, $script:failures.Count, $stopwatch.Elapsed.TotalSeconds)
if (-not $Keep) { Remove-Item -LiteralPath $script:scratch -Recurse -Force }
if ($script:failures.Count -eq 0) {
  Write-Output "RESULT: PASS - every tampered copy was refused or reported, and the published package was not"
  exit 0
}
Write-Output "failures:"
foreach ($failure in $script:failures) { Write-Output "  - $failure" }
Write-Output "RESULT: FAIL - a tampered copy passed a half that should have caught it"
exit 1
