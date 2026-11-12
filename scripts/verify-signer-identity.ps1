<#
.SYNOPSIS
  Proves that a release lane *can* sign two builds with one identity - and that
  the way this lane signs by default cannot.

.DESCRIPTION
  Register section 0.6 row 18 (one signing identity per release). D-051 made the
  update path judge a feed by the
  certificate over the engine that is already installed: `update_pin()` in
  `engine\src\platform\windows\signature.rs` reads the identity out of the running
  binary (or out of
  `MICS_UPDATE_SIGNER_THUMBPRINT`), and a manifest signed by anything else is
  refused. That is fail-closed, and it makes the identity of a release a *promise
  about the next one*: an update from build A to build B only exists if B carries
  the certificate A pins.

  `scripts\make-release.ps1` signs with whatever identity is configured, and
  otherwise falls back to `scripts\codesign-cert.ps1`, whose key lives in
  `%TEMP%\mics-signing` - a folder the same script deletes before it returns, and
  which on a fresh CI runner never existed at all. So the fallback mints a promise
  the next release cannot keep, once per build: measured 2026-11-11, this user's
  stores held 12 distinct certificates with the identical subject
  `CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)` - the pile every release run
  leaves behind, with their private keys gone with the TEMP folder.

  Nothing here needs an engine, a build or a store write: the signature this probe
  reads is a detached PKCS#7 over a scratch file, the same object
  `dist\update.json.sig` is (`sign.ps1 -DataFile`), so a scratch identity stands in
  for a release identity exactly.

  What it checks:

    1. one PFX signs two separate builds and both signatures carry the **same**
       thumbprint, equal to the certificate inside that PFX - so one identity
       across releases is a configured thing, not a hope;
    2. a second PFX produces a **different** thumbprint, which is what the engine's
       pin sees when a release is signed by the wrong identity - the refusal itself
       is `scripts\verify-update.ps1` case 7 ("the same honest feed, under the wrong
       pin") and case 4 ("a manifest signed by another key"), already measured;
    3. the lane keeps the identity decision in one place and refuses to sign a PFX
       without its password, and both of its sign calls - the staged binaries and
       `dist\update.json` - pass the same `@signArgs`, so the engine and the feed
       cannot disagree about the release key;
    4. the workflow secret names and the environment variable the lane reads them
       as are the pair the docs tell a human to create. This is the check that would
       have caught D-047's own wiring bug (the workflow handed the PFX to a variable
       name nothing read, so a donated certificate would have been quietly replaced
       by a self-signed one);
    5. the fallback really is per build: `-SelfSigned` when nothing is configured,
       and `Remove-Item` on the key folder before the script returns;
    6. the pin's one hook is read by all three readers (`signature.rs`,
       `verify-manifest.ps1`, `verify-update.ps1`), so "the release key" cannot come
       to mean three things.

  It does NOT mint anything into a trust store and does not touch
  `%TEMP%\mics-signing`: a probe that changed the state it measures would be worse
  than no probe. The pile it counts is printed, not added to.

  Runs in seconds; no elevation, no network, no Windows SDK (`-DataFile` signing is
  managed code, docs\SIGNING.md).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-signer-identity.ps1

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9).
#>
param(
  # Keep the scratch folder (the two PFXes and the signed files) for inspection.
  [switch]$Keep
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$signScript = Join-Path $PSScriptRoot "sign.ps1"
$releaseScript = Join-Path $PSScriptRoot "make-release.ps1"
$workflow = Join-Path $root ".github\workflows\release.yml"

$checks = New-Object System.Collections.Generic.List[string]
$failures = New-Object System.Collections.Generic.List[string]
function Check([string]$name, [bool]$ok, [string]$detail) {
  if ($ok) {
    $checks.Add($name)
    Write-Output ("  ok    {0}{1}" -f $name, $(if ($detail) { " - $detail" } else { "" }))
  } else {
    $failures.Add("$name - $detail")
    Write-Output ("  FAIL  {0} - {1}" -f $name, $detail)
  }
}
function Note([string]$text) { Write-Output "  note  $text" }

$scratch = Join-Path $env:TEMP ("mics-verify-identity-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $scratch | Out-Null
Add-Type -AssemblyName System.Security

# A code-signing certificate with no store anywhere near it: the same shape the
# lane's own scripts\codesign-cert.ps1 mints (RSA 3072, SHA-256, codeSigning EKU),
# written to a PFX in the scratch folder instead of the user's stores. Two of them,
# because "the next build was signed by another certificate" is the whole scenario.
function New-ScratchIdentity([string]$name, [string]$password) {
  $rsa = [System.Security.Cryptography.RSA]::Create(3072)
  try {
    $dn = "CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)"
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
      $dn, $rsa,
      [System.Security.Cryptography.HashAlgorithmName]::SHA256,
      [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
      [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))) | Out-Null
    $oids = New-Object System.Security.Cryptography.OidCollection
    $oids.Add("1.3.6.1.5.5.7.3.3") | Out-Null
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oids, $true))) | Out-Null
    $cert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddYears(3))
    $pfx = Join-Path $scratch "$name.pfx"
    [System.IO.File]::WriteAllBytes($pfx, $cert.Export(
      [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
    return @{ Pfx = $pfx; Password = $password; Thumbprint = $cert.Thumbprint }
  } finally {
    $rsa.Dispose()
  }
}

# Sign a scratch file the way the lane signs the feed: sign.ps1 -DataFile, run in
# its own process (it `exit`s), and then read the thumbprint back *out of the bytes
# it wrote* rather than out of its console - that is what a verifier sees.
function Sign-Scratch([hashtable]$identity, [string]$build) {
  $data = Join-Path $scratch "update-$build.json"
  $sig = "$data.sig"
  Set-Content -LiteralPath $data -Value "{""build"":""$build""}" -NoNewline
  & powershell -ExecutionPolicy Bypass -File $signScript `
    -PfxPath $identity.Pfx -PfxPassword $identity.Password -DataFile $data -DataSignature $sig | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "sign.ps1 failed for $build (exit $LASTEXITCODE)" }
  $content = [System.IO.File]::ReadAllBytes($data)
  $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
    [System.Security.Cryptography.Pkcs.ContentInfo]::new($content), $true)
  $cms.Decode([System.IO.File]::ReadAllBytes($sig))
  $cms.CheckSignature($true)
  return @{ Thumbprint = $cms.SignerInfos[0].Certificate.Thumbprint; Signature = $sig }
}

Write-Output "signer identity - one certificate across builds (0.6 row 18)"
Write-Output "scratch: $scratch"

# ---- 1. the fix, measured: one identity, two builds -------------------------
Write-Output ""
Write-Output "one PFX, two builds:"
$identityA = New-ScratchIdentity -name "release-a" -password "scratch-a"
$identityB = New-ScratchIdentity -name "release-b" -password "scratch-b"
$pfxCertA = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
  $identityA.Pfx, $identityA.Password,
  [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
Check "identity A is a code-signing certificate" `
  ([bool]($pfxCertA.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.5.5.7.3.3" })) `
  "$($pfxCertA.Subject) $($pfxCertA.Thumbprint)"

$one = Sign-Scratch -identity $identityA -build "1"
$two = Sign-Scratch -identity $identityA -build "2"
Check "two builds signed by one PFX carry the same thumbprint" ($one.Thumbprint -eq $two.Thumbprint) `
  "build 1 $($one.Thumbprint), build 2 $($two.Thumbprint)"
Check "that thumbprint is the certificate inside the PFX" ($one.Thumbprint -eq $pfxCertA.Thumbprint) `
  "PFX $($pfxCertA.Thumbprint)"

# ---- 2. the other half: a second identity is a different identity -----------
Write-Output ""
Write-Output "a second PFX (what a fresh build mints):"
$three = Sign-Scratch -identity $identityB -build "3"
Check "a second PFX signs as a different identity" ($three.Thumbprint -ne $one.Thumbprint) `
  "build 3 $($three.Thumbprint)"
Note "the refusal this produces in the engine is measured by scripts\verify-update.ps1"
Note "  case 7 (wrong pin) and case 4 (another key signed it) - not re-run here."

# ---- 3. the lane: one decision, one identity -------------------------------
Write-Output ""
Write-Output "the release lane:"
$release = Get-Content -LiteralPath $releaseScript -Raw
Check "the lane signs with a PFX it was given (-PfxPath to scripts\sign.ps1)" `
  ($release -match '"-PfxPath",\s*\$signPfxTemp' -and $release -match '"-PfxPath",\s*\(Resolve-Path') `
  "both the base64 secret and the on-disk path reach sign.ps1 as a PFX"
Check "the lane reads the three identity variables CI can fill" `
  (($release -match '\$env:MICS_PFX_B64') -and ($release -match '\$env:MICS_PFX_PATH') -and ($release -match '\$env:MICS_CERT_THUMBPRINT')) `
  "MICS_PFX_B64, MICS_PFX_PATH, MICS_CERT_THUMBPRINT"
Check "a PFX without its password is refused, twice (base64 and path)" `
  (([regex]::Matches($release, 'is set without MICS_PFX_PASSWORD')).Count -eq 2) `
  "$(([regex]::Matches($release, 'is set without MICS_PFX_PASSWORD')).Count) refusal(s)"
Check "both sign calls pass the same @signArgs (binaries and the feed)" `
  (([regex]::Matches($release, '@signArgs')).Count -ge 3) `
  "$(([regex]::Matches($release, '@signArgs')).Count) uses of the one argument list"
Check "the fallback is a self-signed certificate minted per build" `
  ($release -match '\$signArgs = @\("-SelfSigned"\)') `
  "-SelfSigned when no identity is configured"
Check "the fallback's key does not outlive the build it signed" `
  ($release -match 'Remove-Item -LiteralPath \(Join-Path \$env:TEMP "mics-signing"\)') `
  "Remove-Item %TEMP%\mics-signing before RESULT: PASS"

# ---- 4. the names, end to end: workflow, lane, docs ------------------------
Write-Output ""
Write-Output "the wiring (the failure mode D-047 hit):"
$wf = Get-Content -LiteralPath $workflow -Raw
Check "release.yml hands secrets.MICS_PFX to MICS_PFX_B64" `
  ($wf -match 'MICS_PFX_B64:\s*\$\{\{\s*secrets\.MICS_PFX\s*\}\}') `
  "the repository secret is MICS_PFX, the variable the lane reads is MICS_PFX_B64"
Check "release.yml hands secrets.MICS_PFX_PASSWORD to MICS_PFX_PASSWORD" `
  ($wf -match 'MICS_PFX_PASSWORD:\s*\$\{\{\s*secrets\.MICS_PFX_PASSWORD\s*\}\}') `
  "a PFX with no password is refused by the lane, so the pair must be handed together"
$docs = @("docs\SIGNING.md", "docs\COST.md")
foreach ($doc in $docs) {
  $path = Join-Path $root $doc
  if (-not (Test-Path -LiteralPath $path)) { continue }
  $text = Get-Content -LiteralPath $path -Raw
  Check "$doc names the same two secrets" `
    (($text -match 'MICS_PFX') -and ($text -match 'MICS_PFX_PASSWORD')) `
    "a human following the docs creates the secrets the workflow reads"
}

# ---- 5. one hook, three readers -------------------------------------------
Write-Output ""
Write-Output "the pin's hook:"
$hookReaders = @{
  "engine\src\platform\windows\signature.rs" = "the engine that judges a feed (ENV_UPDATE_SIGNER_THUMBPRINT)"
  "scripts\verify-manifest.ps1" = "the release gate over a package"
  "scripts\verify-update.ps1" = "the update probe"
}
foreach ($reader in $hookReaders.Keys) {
  $path = Join-Path $root $reader
  $text = if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw } else { "" }
  Check "$reader reads MICS_UPDATE_SIGNER_THUMBPRINT" `
    ($text -match 'MICS_UPDATE_SIGNER_THUMBPRINT') `
    $hookReaders[$reader]
}
$updateProbe = Get-Content -LiteralPath (Join-Path $root "scripts\verify-update.ps1") -Raw
Check "verify-update.ps1 carries the wrong-pin case" `
  ($updateProbe -match 'the same honest feed, under the wrong pin') `
  "the refusal a second identity produces is measured, not assumed"

# ---- informational: the pile this row is about -----------------------------
$subject = "CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)"
$pile = @()
foreach ($store in @("TrustedPublisher", "TrustedPeople", "My")) {
  $pile += @(Get-ChildItem "Cert:\CurrentUser\$store" -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $subject })
}
$pileDistinct = @($pile | Select-Object -ExpandProperty Thumbprint -Unique)
Write-Output ""
Write-Output "informational: this machine's release identities"
Write-Output ("  subject   : {0}" -f $subject)
Write-Output ("  entries   : {0} in CurrentUser TrustedPublisher/TrustedPeople/My" -f $pile.Count)
Write-Output ("  distinct  : {0} thumbprint(s), so {0} certificate(s) have signed something" -f $pileDistinct.Count)
Write-Output "  private keys: gone with %TEMP%\mics-signing (make-release.ps1 deletes it), which is"
Write-Output "                why a release signed by any of them can never be signed again"

if (-not $Keep) { Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue }
else { Write-Output "kept: $scratch" }

if ($failures.Count -eq 0) {
  Write-Output ""
  Write-Output ("RESULT: PASS - {0} check(s): one PFX gives every build the same identity, a second PFX gives a different one, and the lane, the workflow and the docs agree on the names that carry it" -f $checks.Count)
  exit 0
}
Write-Output ""
Write-Output ("RESULT: FAIL - {0} of {1} check(s) failed:" -f $failures.Count, ($checks.Count + $failures.Count))
foreach ($failure in $failures) { Write-Output ("  - {0}" -f $failure) }
exit 1
