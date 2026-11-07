# Create (or reuse) the throwaway self-signed certificate MI CS signs its test builds
# with, without ever writing a private key into a certificate store.
#
# Why not New-SelfSignedCertificate or Import-PfxCertificate: on a GitHub runner both
# hung - the first for three hours (run 41980725064), the second for the fifty minutes
# its timeout allowed (run 42010747061), each after printing the line below. They write
# the private key into the user's key container, and that runner has no interactive user
# to own it. The certificate is therefore built in memory, kept as a PFX file in the
# job's own TEMP, and handed to signtool with /f, which never registers it.
#
# Only the *public* half goes into a store - CurrentUser\TrustedPeople and
# TrustedPublisher, never Root - so a signature made with it verifies on this machine
# without a warning (D-016, and docs/TODO.md row ب5 for what a real certificate would
# add).
#
# Returns an object with Pfx, Password, Thumbprint and Subject.

[CmdletBinding()]
param(
    [string]$Publisher = "Mourad Ibrahim (MI CS)",
    # Days the certificate stays valid. 1095 = three years.
    [int]$Days = 1095
)

$ErrorActionPreference = "Stop"

$keyDir = Join-Path $env:TEMP "mics-signing"
$pfxPath = Join-Path $keyDir "codesign.pfx"
$passPath = Join-Path $keyDir "codesign.pass"

function New-Certificate([string]$password) {
    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    try {
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=MI CS Code Signing, O=$Publisher", $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))) | Out-Null
        $oids = New-Object System.Security.Cryptography.OidCollection
        $oids.Add("1.3.6.1.5.5.7.3.3") | Out-Null   # extendedKeyUsage = codeSigning
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oids, $true))) | Out-Null
        return $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays($Days))
    } finally {
        $rsa.Dispose()
    }
}

if ((Test-Path -LiteralPath $pfxPath) -and (Test-Path -LiteralPath $passPath)) {
    $password = (Get-Content -LiteralPath $passPath -Raw).Trim()
    Write-Host "reusing the self-signed certificate in $keyDir"
} else {
    Write-Host "creating the self-signed code-signing certificate (valid $Days days)..."
    $password = [guid]::NewGuid().ToString("N")
    $fresh = New-Certificate -password $password
    Write-Host "certificate created in memory: $($fresh.Thumbprint)"
    New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
    [System.IO.File]::WriteAllBytes($pfxPath, $fresh.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
    Write-Host "pfx written: $pfxPath"
    Set-Content -LiteralPath $passPath -Value $password -NoNewline
}

Write-Host "reading the certificate back from the pfx..."
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxPath, $password)
Write-Host "certificate read: $($cert.Subject) ($($cert.Thumbprint))"
if (-not ($cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.5.5.7.3.3" })) {
    throw "the certificate in $pfxPath is not a code-signing certificate"
}

# Trust the public half only, in the stores meant for individual certificates.
#
# Not CurrentUser\Root: adding a certificate *authority* there raises a confirmation
# dialog, and on a machine with nobody to answer it the call never returns - measured
# here, `certutil -addstore Root` printed `Root "Trusted Root Certification
# Authorities"` and then sat until killed, and `X509Store.Add` on Root did the same. That
# was the real cause of both stuck release runs (3 h in 41980725064, 50 min in
# 42010747061); the certificate itself was never the problem.
#
# TrustedPeople and TrustedPublisher take an entry without asking, and they are what
# Explorer and SmartScreen consult before naming a publisher. The consequence is stated
# where it matters: a self-signed signature cannot verify as `Valid` on a machine that has
# not trusted its root, so scripts/sign.ps1 accepts `UnknownError` *with our own signer*
# (integrity intact, chain not publicly trusted) and a real certificate is what turns that
# into `Valid` - row ب5 in docs/ROADMAP.md.
$cer = Join-Path $keyDir "codesign.cer"
[System.IO.File]::WriteAllBytes($cer, $cert.Export(
    [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

# Add the certificate read back from those public bytes, not the object we just signed
# with. The two are not the same: the signing object carries its private key, and
# `X509Store.Add` persists that association, so adding it - which is what this script did
# until 2026-11-07 - puts a private key container in the user's profile for every
# certificate the script ever mints, exactly what the header of this file says it never
# does. Measured: eight earlier MI CS entries in CurrentUser\TrustedPeople, every one of
# them HasPrivateKey = True.
$publicOnly = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cer)
if ($publicOnly.HasPrivateKey) { throw "the exported .cer unexpectedly carries a private key" }
foreach ($storeName in @("TrustedPeople", "TrustedPublisher")) {
    Write-Host ("trust {0,-16}: opening" -f $storeName)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "CurrentUser")
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        Write-Host ("trust {0,-16}: adding" -f $storeName)
        $store.Add($publicOnly)
        Write-Host ("trust {0,-16}: added" -f $storeName)
    } finally {
        $store.Close()
    }
}

# Say it out loud when the machine is carrying certificates from earlier runs. Losing
# %TEMP%\mics-signing is what makes this script mint a new certificate - the private key
# lives only in that pfx, so a store entry can never be reused for signing - and nothing
# else in the project notices the pile growing. Removing them is a human decision, not a
# build step: they are trust anchors in somebody's profile.
$stale = @(Get-ChildItem Cert:\CurrentUser\TrustedPeople, Cert:\CurrentUser\TrustedPublisher -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $cert.Subject -and $_.Thumbprint -ne $cert.Thumbprint })
if ($stale.Count -gt 0) {
    Write-Host ("note: {0} earlier MI CS Code Signing certificate(s) are still trusted in your stores " -f $stale.Count)
    Write-Host "      (this run's certificate is the one just added; the others are not reused for signing,"
    Write-Host "      because their private keys lived only in a pfx that is gone)"
}

[pscustomobject]@{
    Pfx        = $pfxPath
    Password   = $password
    Thumbprint = $cert.Thumbprint
    Subject    = $cert.Subject
}