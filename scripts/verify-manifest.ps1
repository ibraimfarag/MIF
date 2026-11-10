<#
.SYNOPSIS
  Proves that a package's manifest describes that package.

.DESCRIPTION
  `scripts\make-release.ps1` builds the package manifest from the staged bytes,
  injects it into `mics-engine.exe` as the `MICS_MANIFEST` resource and signs the
  engine again (c2, D-025). This probe reads that resource back **out of the
  package** and re-hashes every file it lists, so the manifest cannot describe
  bytes that are not there: a package whose manifest does not describe it never
  leaves the staging folder.

  What it checks:

    1. the packaged engine carries a readable `MICS_MANIFEST` resource;
    2. the document is the format the reader speaks (`format: 1`, a version, a
       sorted, duplicate-free list of relative paths);
    3. every listed file exists, has the recorded byte count and its SHA-256 is
       the recorded one;
    4. the engine's own signature is the one this project signs with - `Valid`, or
       an untrusted root with the same subject on a machine that has not trusted
       the self-signed certificate yet, and always the pinned identity: the
       certificate's **thumbprint** when `MICS_UPDATE_SIGNER_THUMBPRINT` is set
       (the hook the engine reads too, D-051), the release common name otherwise.
       A `HashMismatch`
       means the bytes changed after signing, no signer at all means the document
       has lost its authenticity (someone stripped the signature and kept the
       manifest), and another subject is another publisher: all three refuse the
       package. The engine is not in its own manifest, so this signature is the
       only thing that covers it;
    5. files the package carries that the manifest does not list are printed. That
       is not a failure - `VERSION` is written after the manifest, by design - but
       it is the list a human should read before publishing.

  `-Measure` prints the document and says nothing else: it is the "what does this
  package claim" half, while the default run is the verdict.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-manifest.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-manifest.ps1 -Measure -Path "$env:TEMP\mics-staging"

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9).
#>
param(
  [string]$Path = "",
  [switch]$Measure
)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
if ($Path -eq "") { $Path = Join-Path $repo "dist\MICS-portable" }
. (Join-Path $PSScriptRoot "manifest-resource.ps1")

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

$signature = Get-AuthenticodeSignature $engine
$signer = ""
if ($signature.SignerCertificate) { $signer = $signature.SignerCertificate.Subject }

# Which publisher is ours, asked the way the engine asks it (D-051): the
# thumbprint when one is configured - `MI CS Code Signing` is a CN the day a
# certificate is bought, and no CA may issue that string - and the release
# common name otherwise. `scripts\make-release.ps1`, the engine and this probe
# all read the one hook below, so a certificate that changes the publisher name
# is a settings change rather than a code change.
$pinThumbprint = $env:MICS_UPDATE_SIGNER_THUMBPRINT
$pinIsThumbprint = -not [string]::IsNullOrWhiteSpace($pinThumbprint)
if ($pinIsThumbprint -and ($pinThumbprint -notmatch '^[0-9A-Fa-f]{40}$')) {
  Write-Output "RESULT: FAIL - MICS_UPDATE_SIGNER_THUMBPRINT is not a 40-digit certificate thumbprint: $pinThumbprint"
  exit 1
}
$pinnedPrint = ""
if ($signature.SignerCertificate) {
  $pinnedPrint = $signature.SignerCertificate.Thumbprint
}

$json = Read-MicsManifestResource -Exe $engine
if (-not $json) {
  Write-Output "RESULT: FAIL - $engine carries no MICS_MANIFEST resource"
  Write-Output "  the package cannot describe itself; it was not produced by make-release.ps1"
  exit 1
}
try {
  $manifest = ConvertFrom-MicsManifest -Json $json
} catch {
  Write-Output "RESULT: FAIL - the manifest resource is not readable: $($_.Exception.Message)"
  exit 1
}

if ($Measure) {
  Write-Output "MICS_MANIFEST in $engine"
  Write-Output ("  format  : {0}" -f $manifest.Format)
  Write-Output ("  version : {0}" -f $manifest.Version)
  Write-Output ("  files   : {0}" -f $manifest.Files.Count)
  Write-Output ("  bytes   : {0}" -f $json.Length)
  Write-Output ("  signature: {0} {1}" -f $signature.Status, $signer)
  Write-Output ""
  Write-Output ("  {0,-46} {1,12}  {2}" -f "path", "bytes", "sha256")
  foreach ($entry in $manifest.Files) {
    Write-Output ("  {0,-46} {1,12}  {2}" -f $entry.Path, $entry.Bytes, $entry.Sha256)
  }
  Write-Output ""
  Write-Output "RESULT: MEASURED - nothing was verified; run without -Measure for the verdict"
  exit 0
}

Write-Output "manifest in $engine"
Write-Output ("  format  : {0}   version : {1}   files : {2}" -f $manifest.Format, $manifest.Version, $manifest.Files.Count)
Write-Output ("  signature: {0} {1}" -f $signature.Status, $signer)

$failures = New-Object System.Collections.Generic.List[string]
$listed = @{}
$verified = 0
foreach ($entry in $manifest.Files) {
  $listed[$entry.Path.ToLowerInvariant()] = $true
  $full = Join-Path $root ($entry.Path -replace '/', '\')
  if (-not (Test-Path -LiteralPath $full)) {
    $failures.Add("listed but missing: $($entry.Path)")
    continue
  }
  $bytes = (Get-Item -LiteralPath $full).Length
  if ($bytes -ne $entry.Bytes) {
    $failures.Add(("{0}: {1} bytes on disk, the manifest says {2}" -f $entry.Path, $bytes, $entry.Bytes))
    continue
  }
  $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($hash -ne $entry.Sha256) {
    $failures.Add(("{0}: sha256 is {1}, the manifest says {2}" -f $entry.Path, $hash, $entry.Sha256))
    continue
  }
  $verified++
}

# The engine is not in its own manifest, so its signature is the only thing that
# covers it. Three ways it can stop being ours, and all three refuse the package:
# the bytes changed after signing (`HashMismatch`), the signature was stripped or
# never made (no signer certificate - the manifest then has nothing behind it),
# or somebody else signed it (the pin `signature.rs` enforces at run time, D-051:
# the certificate's thumbprint when one is configured, else the release CN).
$signed_by_us = $false
if ($signature.SignerCertificate) {
  if ($pinIsThumbprint) {
    $signed_by_us = ($pinnedPrint -ieq $pinThumbprint)
  } else {
    $signed_by_us = $signature.SignerCertificate.Subject -like "*CN=$script:MicsSignerCn,*"
  }
}
$pinLabel = if ($pinIsThumbprint) { "thumbprint $pinThumbprint" } else { "'$script:MicsSignerCn'" }
$sawLabel = if ($signature.SignerCertificate) {
  "signer $signer (thumbprint $pinnedPrint)"
} else {
  "no signer"
}
if ($signature.Status -eq "HashMismatch") {
  $failures.Add("mics-engine.exe changed after it was signed (HashMismatch): the manifest it carries is not trustworthy")
} elseif (-not $signed_by_us) {
  $failures.Add(("mics-engine.exe is not signed by {0} (status {1}, {2}): the manifest it carries is not authentic" -f `
      $pinLabel, $signature.Status, $sawLabel))
} elseif ($signature.Status -ne "Valid" -and $signature.Status -ne "UnknownError") {
  $failures.Add(("mics-engine.exe signature is {0}: {1}" -f $signature.Status, $signature.StatusMessage))
}

# Informational: what the package carries that the manifest does not describe.
$extra = New-Object System.Collections.Generic.List[string]
foreach ($relative in Get-ChildItem -LiteralPath $root -Recurse -File -Name) {
  if ((-not $listed.ContainsKey($relative.ToLowerInvariant())) -and ($relative -ine "mics-engine.exe")) {
    $extra.Add($relative)
  }
}

if ($failures.Count -eq 0) {
  Write-Output ("  re-hashed: {0} file(s) under {1}" -f $verified, $root)
  if ($extra.Count -gt 0) {
    Write-Output ("  not listed (written after the manifest): {0}" -f ($extra -join ", "))
  }
  Write-Output ("RESULT: PASS - all {0} listed file(s) hash as the signed manifest says" -f $verified)
  exit 0
}

Write-Output "failures:"
foreach ($failure in $failures) { Write-Output "  - $failure" }
Write-Output "RESULT: FAIL - the package is not the one its manifest describes"
exit 1
