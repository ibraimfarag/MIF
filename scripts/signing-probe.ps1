# Prove that code signing works on this machine before a long build depends on it.
#
# This step would have saved two release runs: signing hung on the runner for three hours
# (41980725064) and then for fifty minutes (42010747061), both times long after the build
# was worth keeping. The hang was a confirmation dialog that adding a certificate to the
# root store raises and nothing answers; the whole path now takes seconds, and the
# workflow caps this probe at five minutes.
#
#     powershell -File scripts\signing-probe.ps1
#
# RESULT: PASS means the certificate can be created, trusted and used to sign, and - when
# an unsigned PE is available - that signtool and this machine's verification agree.

$ErrorActionPreference = "Stop"

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -match "x64$" } |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) {
    Write-Output "RESULT: FAIL - signtool.exe not found (install the Windows SDK)"
    exit 1
}

$signing = & (Join-Path $PSScriptRoot "codesign-cert.ps1")
if (-not $signing -or -not (Test-Path -LiteralPath $signing.Pfx)) {
    Write-Output "RESULT: FAIL - the certificate was not created"
    exit 1
}
Write-Output ("certificate: {0} ({1})" -f $signing.Subject, $signing.Thumbprint)

# The private key has to be readable from the file: that is what signtool will use.
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($signing.Pfx, $signing.Password)
if (-not $cert.HasPrivateKey) {
    Write-Output "RESULT: FAIL - the certificate in $($signing.Pfx) has no usable private key"
    exit 1
}
Write-Output "private key: present and readable from the pfx"

# signtool on a real PE, when one exists: a fresh runner has no build yet, and this probe
# exists to run *before* the build, so the absence is reported rather than treated as a
# failure. The packaging step exercises signtool on the actual binaries.
$unsigned = Join-Path $PSScriptRoot "..\engine\target\release\mics-engine.exe"
if (Test-Path -LiteralPath $unsigned) {
    $copy = Join-Path $env:TEMP ("mics-signprobe-" + [guid]::NewGuid().ToString("N") + ".exe")
    try {
        Copy-Item -LiteralPath $unsigned -Destination $copy -Force
        & $signtool.FullName sign /fd SHA256 /f $signing.Pfx /p $signing.Password `
            /d "MI CS signing probe" $copy | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Output "RESULT: FAIL - signtool could not sign a copy of mics-engine.exe (exit $LASTEXITCODE)"
            exit 1
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $copy
        Write-Output ("signtool   : {0} - {1}" -f $sig.Status, $sig.SignerCertificate.Subject)
        if ($sig.SignerCertificate.Thumbprint -ne $signing.Thumbprint) {
            Write-Output "RESULT: FAIL - the signature on the probe copy is not ours"
            exit 1
        }
    } finally {
        Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Output "signtool   : no unsigned PE on this machine yet, the packaging step will sign the real ones"
}

Write-Output "RESULT: PASS - the certificate is created, trusted and usable for signing on this machine"
exit 0