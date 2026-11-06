# Acceptance probe for the release signing identities (scripts/sign.ps1 and
# scripts/make-release.ps1). Run it from the repository root:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-signing.ps1
#
# What it proves, on a machine with no CA-issued certificate:
#   1. the mode guard refuses zero identities, two identities, and an unknown
#      thumbprint - before signtool is asked to do anything;
#   2. -Thumbprint finds a certificate in a store, signs a real PE with *that*
#      certificate, and then refuses to call the result verified, because the local
#      certificate is not chained to a public root. That refusal is the point: with a
#      CA-issued certificate `Valid` is the only answer it accepts (D-016).
#
# What it cannot prove, and says so instead of guessing: the `Valid` end of that branch
# needs a certificate a stranger's Windows trusts, which is the certificate row in
# docs/ROADMAP.md. Nothing here touches the network, and nothing it writes outlives the run: the signed
# copy lives under %TEMP%\mics-signtest, and a certificate it imports into
# CurrentUser\My is removed again.
param(
    # The PE to sign. Defaults to the repository's release engine, then to the
    # CARGO_TARGET_DIR build the pipeline uses on this machine.
    [string]$EngineExe = "",
    # A PFX with a private key, and its password. Defaults to the throwaway certificate
    # scripts/codesign-cert.ps1 keeps in %TEMP%\mics-signing (created on demand by
    # `make-release.ps1 -Sign`).
    [string]$Pfx = "",
    [string]$PfxPassword = "",
    # Keep the signed copy for inspection instead of deleting it.
    [switch]$Keep
)

$ErrorActionPreference = "Continue"

$repo = Split-Path $PSScriptRoot -Parent
$sign = Join-Path $PSScriptRoot "sign.ps1"
$checks = 0
$failed = 0
$skipped = 0
function Pass($m) { $script:checks++; Write-Host "  PASS  $m" }
function Fail($m) { $script:checks++; $script:failed++; Write-Host "  FAIL  $m" }
function Skip($m) { $script:skipped++; Write-Host "  SKIP  $m" }
function Check($ok, $what) { if ($ok) { Pass $what } else { Fail $what } }

if (-not $EngineExe) {
    foreach ($candidate in @(
        (Join-Path $repo "engine\target\release\mics-engine.exe"),
        (Join-Path $env:TEMP "mics-target\release\mics-engine.exe")
    )) {
        if (Test-Path $candidate) { $EngineExe = $candidate; break }
    }
}
if (-not $Pfx) {
    $default = Join-Path $env:TEMP "mics-signing\codesign.pfx"
    if (Test-Path $default) {
        $Pfx = $default
        if (-not $PfxPassword) {
            $passFile = Join-Path $env:TEMP "mics-signing\codesign.pass"
            if (Test-Path $passFile) { $PfxPassword = (Get-Content $passFile -Raw).Trim() }
        }
    }
}

Write-Host "signing-identity probe"
Write-Host "  repo   : $repo"
Write-Host "  engine : $(if ($EngineExe) { $EngineExe } else { '(not found)' })"
Write-Host "  pfx    : $(if ($Pfx) { $Pfx } else { '(not found)' })"

if (-not (Test-Path $sign)) {
    Write-Output "RESULT: FAIL - $sign is missing"
    exit 1
}
if (-not $EngineExe -or -not (Test-Path $EngineExe)) {
    Write-Output "RESULT: FAIL - no engine to sign; pass -EngineExe (build one with 'cargo build --release' in engine\)"
    exit 1
}

$work = Join-Path $env:TEMP "mics-signtest"
New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item $EngineExe (Join-Path $work "mics-engine.exe") -Force

function Invoke-Sign([string[]]$extra) {
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $sign @extra -BuildDir $work -Only "mics-engine.exe" 2>&1 | Out-String
    return @{ Text = $out; Code = $LASTEXITCODE }
}

# ---------------------------------------------------------------- the mode guard
Write-Host ""
Write-Host "1) exactly one identity, never a guess"
$r = Invoke-Sign @()
Check ($r.Code -ne 0) "no identity exits non-zero (exit $($r.Code))"
Check ($r.Text -match "Pass exactly one of -SelfSigned, -PfxPath or -Thumbprint") "no identity names all three"

$r = Invoke-Sign @("-SelfSigned", "-Thumbprint", "0000000000000000000000000000000000000000")
Check ($r.Code -ne 0) "two identities exit non-zero (exit $($r.Code))"
Check ($r.Text -match "got: -SelfSigned, -Thumbprint") "two identities names the pair it saw"

$r = Invoke-Sign @("-Thumbprint", "0000000000000000000000000000000000000000")
Check ($r.Code -ne 0) "an unknown thumbprint exits non-zero (exit $($r.Code))"
Check ($r.Text -match "no certificate with thumbprint 0000000000000000000000000000000000000000") "an unknown thumbprint is named, not ignored"
Check ($r.Text -notmatch "Signing mics-engine.exe") "an unknown thumbprint never reaches signtool"

# ---------------------------------------------------------------- the real certificate
Write-Host ""
Write-Host "2) a certificate from a store"
if (-not $Pfx -or -not (Test-Path $Pfx) -or -not $PfxPassword) {
    Skip "no PFX with a password on this machine (run 'make-release.ps1 -Sign' once, or pass -Pfx/-PfxPassword)"
} else {
    $imported = $null
    $thumb = ""
    try {
        $local = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Pfx, $PfxPassword)
        $thumb = $local.Thumbprint
        Write-Host "  cert   : $($local.Subject)"
        Write-Host "  sha1   : $thumb"

        $sec = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
        $imported = Import-PfxCertificate -FilePath $Pfx -Password $sec -CertStoreLocation Cert:\CurrentUser\My
        Check ($null -ne $imported) "the certificate imports into CurrentUser\My"

        $r = Invoke-Sign @("-Thumbprint", $thumb)
        Check ($r.Text -match "Certificate: CN=MI CS Code Signing") "the mode prints the certificate it found"
        Check ($r.Text -match "Signing mics-engine.exe") "signtool was asked to sign"
        Check ($r.Text -notmatch "signing failed for") "signtool signed without error"
        $sig = Get-AuthenticodeSignature (Join-Path $work "mics-engine.exe")
        Check ($sig.SignerCertificate.Thumbprint -eq $thumb) "the signature carries the requested certificate"
        Check ($r.Text -match "did not verify") "an untrusted chain is refused instead of called verified"
        Check ($r.Code -ne 0) "and the run exits non-zero (exit $($r.Code))"

        # The pre-existing PFX mode, which is what a CA-issued PFX uses.
        $r = Invoke-Sign @("-PfxPath", $Pfx, "-PfxPassword", $PfxPassword)
        Check ($r.Text -match "Signing mics-engine.exe") "-PfxPath still signs (regression)"
        Check ($r.Text -notmatch "Pass exactly one of") "-PfxPath is accepted on its own"
        $sig = Get-AuthenticodeSignature (Join-Path $work "mics-engine.exe")
        Check ($sig.SignerCertificate.Thumbprint -eq $thumb) "-PfxPath applies the same certificate"
    } finally {
        if ($imported) {
            Remove-Item ("Cert:\CurrentUser\My\" + $imported.Thumbprint) -Force -ErrorAction SilentlyContinue
            $left = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb }
            Check ($null -eq $left) "the imported certificate is removed from the store afterwards"
        }
    }
}

if (-not $Keep) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "  the 'Valid' end of the branch needs a CA-issued certificate: the certificate row, docs/ROADMAP.md"
Write-Host "  the workflow passes a real one as MICS_PFX + MICS_PFX_PASSWORD - docs/COST.md section 5"
if ($failed -gt 0) {
    Write-Output "RESULT: FAIL - $failed of $checks check(s) failed"
    exit 1
}
Write-Output "RESULT: PASS - $checks check(s)$(if ($skipped -gt 0) { ", $skipped skipped" })"
