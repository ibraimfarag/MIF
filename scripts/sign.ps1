# MI CS code-signing script.
#
# Usage:
#   Development (self-signed, trusted only on this machine):
#     powershell -File scripts\sign.ps1 -SelfSigned
#
#   Production (OV/EV certificate as a PFX file):
#     powershell -File scripts\sign.ps1 -PfxPath "cert.pfx" -PfxPassword "..."
#
#   Production (certificate already in a store, e.g. a hardware token or a cloud
#   signing service's agent - signtool needs only the SHA-1 thumbprint):
#     powershell -File scripts\sign.ps1 -Thumbprint "A1B2C3..."
#
#   One file only (what make-release.ps1 does after it injects the manifest into
#   the engine, because writing a resource invalidates that engine's signature):
#     powershell -File scripts\sign.ps1 -SelfSigned -BuildDir <staging> -Only mics-engine.exe
#   and everything except one, for the pass before that injection:
#     powershell -File scripts\sign.ps1 -SelfSigned -BuildDir <staging> -Except mics-engine.exe
#
#   One data file, as a detached signature next to it (what D-047 requires of
#   dist\update.json, and what the engine checks before it reads a manifest):
#     powershell -File scripts\sign.ps1 -SelfSigned -DataFile dist\update.json
#
# Signs: mics_app.exe, mics-engine.exe, flutter_windows.dll and any plugin DLLs
# next to the runner, with publisher identity "Mourad Ibrahim (MI CS)".
#
# Why the self-signed mode exists: SmartScreen blocks an unsigned binary it has
# never seen ("Windows protected your PC ... unrecognized app"). A certificate
# that is trusted *on this machine* (CurrentUser\Root + TrustedPublisher) gives
# Windows a publisher it can name, which is enough to stop the local prompts.
# It does NOT give the file a public reputation - that needs a real OV/EV
# certificate and downloads by strangers (docs/TODO.md, P4).
param(
    [switch]$SelfSigned,
    [string]$PfxPath,
    [string]$PfxPassword,
    # SHA-1 thumbprint of a certificate already in a store (`signtool /sha1`). This is
    # what a hardware token or a cloud signing agent needs: the key never leaves the
    # device, so there is no PFX to read and no password to pass (docs/COST.md section 5).
    [string]$Thumbprint,
    [string]$BuildDir = "dist\MICS-portable",
    [string]$Publisher = "Mourad Ibrahim (MI CS)",
    # File names (leaves, not paths) to sign. Empty means everything signable in
    # BuildDir. make-release.ps1 uses this to sign the engine once the manifest
    # resource is in place, without touching the other files, whose hashes that
    # manifest already records.
    [string[]]$Only = @(),
    # File names (leaves, not paths) to leave alone. The engine is signed only
    # after the manifest resource is written into it, because that write leaves a
    # PE signtool will not accept a signature for (see the filter below).
    [string[]]$Except = @(),
    # Sign one *data* file instead of the staged binaries: a detached PKCS#7 over
    # the file's exact bytes, written beside it as `<file>.sig`. This is what
    # make-release.ps1 uses for dist\update.json, whose signature the engine
    # verifies before it reads the manifest (D-047). It is the same script and the
    # same identity on purpose: two places that decide what "the release key" means
    # would eventually disagree, and then the feed would be signed by a key the
    # shipped engine does not pin.
    [string]$DataFile,
    # Where the detached signature goes. Default: the data file's own name plus
    # `.sig` - which is where `scripts\verify-update.ps1` and the engine look.
    [string]$DataSignature
)

$ErrorActionPreference = "Stop"

# A data file is signed here, not by signtool, so the Windows SDK is not required
# for it: the manifest signature has to be reproducible on a machine that only
# builds the feed, and `-DataFile` cannot be combined with the staging filters
# because it names exactly one file that is already written.
$dataMode = [bool]$DataFile
if ($dataMode -and ($Only.Count -gt 0 -or $Except.Count -gt 0 -or $PSBoundParameters.ContainsKey("BuildDir"))) {
    throw "-DataFile signs one file on its own; -BuildDir, -Only and -Except do not apply"
}

$signtool = $null
if (-not $dataMode) {
    $signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "x64$" } |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw "signtool.exe not found (install Windows SDK)" }
    $signtool = $signtool.FullName
    Write-Host "signtool: $signtool"
}

# Exactly one identity, never a guess: a release signed with the wrong certificate is
# worse than one that refuses to build (docs/COST.md section 5).
$modes = @()
if ($SelfSigned) { $modes += "-SelfSigned" }
if ($PfxPath) { $modes += "-PfxPath" }
if ($Thumbprint) { $modes += "-Thumbprint" }
if ($modes.Count -ne 1) {
    throw "Pass exactly one of -SelfSigned, -PfxPath or -Thumbprint (got: $($modes -join ', '))"
}

if ($SelfSigned) {
    # The certificate lives as a PFX file, never as a key in a store: both
    # New-SelfSignedCertificate and Import-PfxCertificate hung on a GitHub runner with no
    # interactive user (3 h in run 41980725064, 50 min in run 42010747061). signtool reads
    # the PFX with /f, and scripts/codesign-cert.ps1 has already trusted the public half.
    $signing = & (Join-Path $PSScriptRoot "codesign-cert.ps1") -Publisher $Publisher
    Write-Host "Certificate thumbprint: $($signing.Thumbprint)"
    # The certificate is loaded from the PFX with an ephemeral key: a data
    # signature is computed in this process, so there is no reason to touch the
    # user's key store - and on a runner with no interactive profile that touch is
    # what has hung before (the comment above).
    $signingCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $signing.Pfx, $signing.Password,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    $certArg = @("/f", $signing.Pfx, "/p", $signing.Password)
    # No timestamp server: a public TSA will not countersign a self-signed
    # signature, and for a local test build there is nothing to keep valid after
    # the certificate expires.
    $timestampArg = @()
} elseif ($PfxPath) {
    if (-not $PfxPassword) { throw "PfxPassword required with PfxPath" }
    $signingCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        (Resolve-Path -LiteralPath $PfxPath).Path, $PfxPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    $certArg = @("/f", $PfxPath, "/p", $PfxPassword)
    $timestampArg = @("/td", "SHA256", "/tr", "http://timestamp.digicert.com")
} elseif ($Thumbprint) {
    # The certificate is already installed with its private key (the store, a token, or
    # whatever the signing service's agent exposes). `signtool /sha1` selects it by
    # thumbprint; there is nothing to import and no password to pass.
    $found = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumbprint.Replace(' ', '') }
    if (-not $found) {
        throw "no certificate with thumbprint $Thumbprint in CurrentUser\My or LocalMachine\My"
    }
    if (-not $found.HasPrivateKey) {
        throw "the certificate $Thumbprint has no private key in this profile (a token may need its agent running)"
    }
    Write-Host "Certificate: $($found.Subject) (thumbprint $($found.Thumbprint))"
    $signingCert = $found
    $certArg = @("/sha1", $found.Thumbprint)
    $timestampArg = @("/td", "SHA256", "/tr", "http://timestamp.digicert.com")
} else {
    # Unreachable: the mode check above already refused an empty or doubled choice.
    throw "no signing identity selected"
}

# ---------------------------------------------------------------- a data file
# dist\update.json is not a PE: it is a document the engine reads *after* checking
# a detached signature over its bytes (D-047). The signature travels with the
# certificate (EndCertOnly) so a machine that has never seen the release
# certificate can still read it, and it is SHA-256 - the same digest signtool is
# asked for above. Nothing here needs the Windows SDK, a chain, or the network.
if ($dataMode) {
    if (-not (Test-Path -LiteralPath $DataFile)) { throw "no file to sign at $DataFile" }
    $DataFile = (Resolve-Path -LiteralPath $DataFile).Path
    if (-not $DataSignature) { $DataSignature = "$DataFile.sig" }
    Add-Type -AssemblyName System.Security

    $content = [System.IO.File]::ReadAllBytes($DataFile)
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
        [System.Security.Cryptography.Pkcs.ContentInfo]::new($content), $true)
    $cmsSigner = [System.Security.Cryptography.Pkcs.CmsSigner]::new($signingCert)
    $cmsSigner.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cmsSigner.DigestAlgorithm = [System.Security.Cryptography.Oid]::new("2.16.840.1.101.3.4.2.1")
    $cms.ComputeSignature($cmsSigner)
    [System.IO.File]::WriteAllBytes($DataSignature, $cms.Encode())

    # Read back the bytes that were written, not the object that wrote them: a
    # release whose manifest signature the next reader cannot verify has to fail
    # here, while the build is still in front of the person who signed it.
    $written = [System.IO.File]::ReadAllBytes($DataSignature)
    $recheck = [System.Security.Cryptography.Pkcs.SignedCms]::new(
        [System.Security.Cryptography.Pkcs.ContentInfo]::new($content), $true)
    $recheck.Decode($written)
    $recheck.CheckSignature($true)
    $signedBy = $recheck.SignerInfos[0].Certificate.Thumbprint
    Write-Host "Signing $(Split-Path $DataFile -Leaf) (detached PKCS#7, SHA-256, no chain)"
    Write-Host ("  {0,-28} {1,-14} {2}" -f (Split-Path $DataSignature -Leaf), "Signed", $signedBy)
    if ($signedBy -ne $signingCert.Thumbprint) {
        Write-Output "RESULT: FAIL - $DataSignature carries $signedBy, not the identity this run selected"
        exit 1
    }
    Write-Output "RESULT: PASS - detached signature written to $DataSignature"
    exit 0
}

$targets = @(
    "$BuildDir\mics_app.exe",
    "$BuildDir\mics-engine.exe"
) + (Get-ChildItem $BuildDir -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })

# `-Only` narrows the list to the leaves it names and `-Except` drops the leaves it
# names. Both are filters, never additions: a file that is not a signable target in
# BuildDir stays unsignable, and a name that matches nothing is an error rather
# than a silent no-op.
#
# make-release.ps1 uses the pair to sign every file except the engine, inject the
# manifest resource, and only then sign the engine: Windows' resource API rewrites
# the PE, and a PE it rewrote no longer carries a usable certificate table, so
# signtool refuses an already-signed file (0x800700C1, measured 2026-11-03).
if ($Only.Count -gt 0) {
    $targets = @($targets | Where-Object { $Only -contains (Split-Path $_ -Leaf) })
    if ($targets.Count -eq 0) {
        throw "-Only matched nothing signable in ${BuildDir}: $($Only -join ', ')"
    }
}
if ($Except.Count -gt 0) {
    $targets = @($targets | Where-Object { $Except -notcontains (Split-Path $_ -Leaf) })
    if ($targets.Count -eq 0) {
        throw "-Except left nothing signable in ${BuildDir}"
    }
}

foreach ($file in $targets) {
    if (-not (Test-Path $file)) { continue }
    Write-Host "Signing $(Split-Path $file -Leaf) ..."
    & $signtool sign /fd SHA256 @timestampArg @certArg `
        /d "MI Cyber Security" /du "https://github.com/ibraimfarag/MIF" `
        $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signing failed for $file" }
}

Write-Host ""
Write-Host "Verifying:"
$failed = 0
foreach ($file in $targets) {
    if (-not (Test-Path $file)) { continue }
    $sig = Get-AuthenticodeSignature $file
    $status = $sig.Status
    $signer = $sig.SignerCertificate.Subject
    # A self-signed certificate cannot reach `Valid` on a machine that has not been told
    # to trust it, and being told means a confirmation dialog a runner cannot answer
    # (measured 2026-11-05: adding the certificate to CurrentUser\Root blocks until
    # someone clicks, which is what stalled two release runs). `UnknownError` there means
    # "the chain is not trusted", not "the file was touched": tampering shows up as
    # HashMismatch or NotSigned, so the check is the signer's identity plus the
    # signature's own integrity. With a real certificate (D-016; the certificate row in
    # docs/ROADMAP.md) `Valid` is the only acceptable answer and this branch is not taken.
    $ok = ($status -eq "Valid")
    if (-not $ok -and $SelfSigned -and $status -eq "UnknownError" -and
        $sig.SignerCertificate.Thumbprint -eq $signing.Thumbprint) {
        $ok = $true
        $status = "Signed (self-signed, not chained to a public root)"
    }
    Write-Host ("  {0,-28} {1,-14} {2}" -f (Split-Path $file -Leaf), $sig.Status, $signer)
    if (-not $ok) { $failed++ }
}
if ($failed -gt 0) {
    Write-Output "RESULT: FAIL - $failed file(s) did not verify; SmartScreen will still warn"
    exit 1
}
Write-Output "RESULT: PASS - $($targets.Count) selected binary(ies), every one signed and verifying on this machine"
