# MI CS code-signing script.
#
# Usage:
#   Development (self-signed, trusted only on this machine):
#     powershell -File scripts\sign.ps1 -SelfSigned
#
#   Production (OV/EV certificate):
#     powershell -File scripts\sign.ps1 -PfxPath "cert.pfx" -PfxPassword "..."
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
    [string]$BuildDir = "dist\MICS-portable",
    [string]$Publisher = "Mourad Ibrahim (MI CS)"
)

$ErrorActionPreference = "Stop"

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -match "x64$" } |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found (install Windows SDK)" }
$signtool = $signtool.FullName
Write-Host "signtool: $signtool"

if ($SelfSigned) {
    $cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -like "*MI CS Code Signing*" } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) {
        Write-Host "Creating self-signed code-signing certificate (valid 3 years)..."
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject "CN=MI CS Code Signing, O=$Publisher" `
            -KeyUsage DigitalSignature `
            -KeySpec Signature `
            -NotAfter (Get-Date).AddYears(3) `
            -CertStoreLocation "Cert:\CurrentUser\My"
    }
    # Trust it locally so the signature verifies without a warning. CurrentUser\Root
    # makes the chain valid for this user; TrustedPublisher is what Explorer and
    # SmartScreen look at when they decide to name the publisher instead of
    # refusing the app. Neither needs elevation.
    $cer = Join-Path $env:TEMP "mics-codesign.cer"
    Export-Certificate -Cert $cert -FilePath $cer -Type CERT | Out-Null
    foreach ($store in @("Root", "TrustedPublisher")) {
        & certutil -user -addstore $store $cer | Out-Null
        Write-Host ("trust {0,-16}: exit {1}" -f $store, $LASTEXITCODE)
    }
    Remove-Item $cer -Force -ErrorAction SilentlyContinue
    Write-Host "Certificate thumbprint: $($cert.Thumbprint)"
    $certArg = @("/sha1", $cert.Thumbprint)
    # No timestamp server: a public TSA will not countersign a self-signed
    # signature, and for a local test build there is nothing to keep valid after
    # the certificate expires.
    $timestampArg = @()
} elseif ($PfxPath) {
    if (-not $PfxPassword) { throw "PfxPassword required with PfxPath" }
    $certArg = @("/f", $PfxPath, "/p", $PfxPassword)
    $timestampArg = @("/td", "SHA256", "/tr", "http://timestamp.digicert.com")
} else {
    throw "Pass -SelfSigned or -PfxPath/-PfxPassword"
}

$targets = @(
    "$BuildDir\mics_app.exe",
    "$BuildDir\mics-engine.exe"
) + (Get-ChildItem $BuildDir -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })

foreach ($file in $targets) {
    if (-not (Test-Path $file)) { continue }
    Write-Host "Signing $(Split-Path $file -Leaf) ..."
    & $signtool sign /fd SHA256 @timestampArg @certArg `
        /d "MIF" /du "https://github.com/mourad-ibrahim/mi-cs" `
        $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signing failed for $file" }
}

Write-Host ""
Write-Host "Verifying:"
$failed = 0
foreach ($file in $targets) {
    if (-not (Test-Path $file)) { continue }
    $status = (Get-AuthenticodeSignature $file).Status
    $signer = (Get-AuthenticodeSignature $file).SignerCertificate.Subject
    Write-Host ("  {0,-28} {1,-14} {2}" -f (Split-Path $file -Leaf), $status, $signer)
    if ($status -ne "Valid") { $failed++ }
}
if ($failed -gt 0) {
    Write-Output "RESULT: FAIL - $failed file(s) did not verify; SmartScreen will still warn"
    exit 1
}
Write-Output "RESULT: PASS - every binary is signed and verifies on this machine"
