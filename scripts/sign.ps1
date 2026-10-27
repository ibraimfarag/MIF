# MI CS code-signing script.
#
# Usage:
#   Development (self-signed, trusted only on this machine):
#     powershell -File scripts\sign.ps1 -SelfSigned
#
#   Production (OV/EV certificate):
#     powershell -File scripts\sign.ps1 -PfxPath "cert.pfx" -PfxPassword "..."
#
# Signs: mics_app.exe, mics_engine.exe, flutter_windows.dll and any plugin DLLs
# next to the runner, with publisher identity "Mourad Ibrahim (MI CS)".
param(
    [switch]$SelfSigned,
    [string]$PfxPath,
    [string]$PfxPassword,
    [string]$BuildDir = "dist\MICS-portable",
    [string]$Publisher = "Mourad Ibrahim (MI CS)"
)

$ErrorActionPreference = "Stop"

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" |
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
        # Trust it locally so signatures verify without warnings.
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","CurrentUser")
        $store.Open("ReadWrite")
        $store.Add($cert)
        $store.Close()
        Write-Host "Certificate thumbprint: $($cert.Thumbprint)"
    }
    $certArg = @("/sha1", $cert.Thumbprint)
} elseif ($PfxPath) {
    if (-not $PfxPassword) { throw "PfxPassword required with PfxPath" }
    $certArg = @("/f", $PfxPath, "/p", $PfxPassword)
} else {
    throw "Pass -SelfSigned or -PfxPath/-PfxPassword"
}

$targets = @(
    "$BuildDir\mics_app.exe",
    "$BuildDir\mics-engine.exe"
) + (Get-ChildItem $BuildDir -Filter "*.dll" | ForEach-Object { $_.FullName })

foreach ($file in $targets) {
    if (-not (Test-Path $file)) { continue }
    Write-Host "Signing $file ..."
    & $signtool sign /fd SHA256 /td SHA256 /tr "http://timestamp.digicert.com" `
        @certArg /d "MI CS Command Center" /du "https://github.com/mourad-ibrahim/mi-cs" `
        $file | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signing failed for $file" }
}

Write-Host ""
Write-Host "Verifying signatures:"
& $signtool verify /pa /all $BuildDir\mics_app.exe
Write-Host "Done."
