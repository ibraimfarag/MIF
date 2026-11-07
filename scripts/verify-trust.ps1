# Judges one artifact against the only question the signing work exists to answer:
#
#   would a stranger's Windows trust this file?
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-trust.ps1 -Path dist\MICS-portable\mics-engine.exe
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-trust.ps1 -Path dist\MICS-0.1.0.0-x64.msix
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-trust.ps1 -SelfTest
#
# Exit code 0 means the answer is yes. Everything else - unsigned, self-signed, a chain that
# does not reach a root this machine trusts - is a failure with the reason printed.
#
# Why this is not `verify-signing.ps1`: that one proves the *wiring* (the mode guard, the
# store lookup, signtool being handed the right thing, and the refusal to call a local
# certificate verified). This one judges a *file* a user would download, and it answers the
# local-`Valid` trap directly: a self-signed certificate that someone imported into their own
# trust store makes `Get-AuthenticodeSignature` report `Valid` while a stranger's Windows
# still says "Unknown publisher". The two are told apart by the certificate's issuer, the
# chain and which root store the chain ends in - never by `Status` alone.
#
# What it does not do, and says so instead of guessing:
#   * It never touches the network, so revocation is not checked. A certificate revoked after
#     this run would still be judged trusted here.
#   * It cannot see where the private key lives, so the CA/Browser Forum requirement that a
#     code signing key sit in a hardware crypto module is out of its reach.
#   * For an AppX/MSIX it reads what `signtool verify /pa /v` prints. .NET's `SignedCms`
#     refuses the encoding AppX uses (`ASN1 bad tag value met`, measured 2026-11-07), and the
#     package's own digest linkage is Windows' install-time check, so the SDK's tool is the
#     reader here. Without the SDK the package is reported as unjudged, never as trusted.
#
# Nothing it writes outlives the run, and it modifies nothing: it only reads.
[CmdletBinding()]
param(
    # The artifact to judge: a PE (.exe, .dll, .msi) or an AppX/MSIX package.
    [string]$Path = "",
    # Run both controls instead: this repository's own signed engine (must NOT be judged
    # publicly trusted) and a Microsoft-signed system binary (must be).
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"

# The CA/Browser Forum code signing rules this project researched apply from this date, and
# they cap a publicly trusted code signing certificate's validity at 460 days.
$csbrFrom = Get-Date "2026-03-01"
$csbrMaxDays = 460
$codeSigningEku = "1.3.6.1.5.5.7.3.3"

function Write-Line {
    param([string]$Text, [string]$Colour = "Gray")
    Write-Host $Text -ForegroundColor $Colour
}

function Write-Info {
    param([string]$Key, [string]$Value)
    Write-Host ("  {0,-15}: {1}" -f $Key, $Value)
}

# Release requirements. These are reported, not silently folded into the verdict: a
# certificate can be publicly trusted and still make an unusable release signature.
$script:Noted = 0
function Write-Note {
    param([bool]$Ok, [string]$Text)
    $script:Noted++
    if ($Ok) { Write-Line ("  [ok]  {0}" -f $Text) "DarkGray" }
    else { Write-Line ("  [!!]  {0}" -f $Text) "Yellow" }
}

function Write-FileHashLine {
    param([string]$File)
    $item = Get-Item -LiteralPath $File
    $hash = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash
    Write-Info "file" ("{0} ({1:N0} bytes)" -f $item.Name, $item.Length)
    Write-Info "sha256" $hash
}

# A CA-issued signature is one whose signer was issued *by somebody else* and whose chain ends
# in a root this machine's machine-wide store holds - the store AppX and installers read.
function Get-TrustVerdict {
    param($Facts, [string]$Status)
    if ($Status -eq "HashMismatch") {
        return @{ Verdict = "tampered"; Why = "the file does not match the hash inside its own signature - it changed after it was signed" }
    }
    if ($Facts.SelfSigned) {
        return @{ Verdict = "self-signed"; Why = "the certificate signs itself, so it is trusted only on machines where someone put it - a stranger's Windows shows ""Unknown publisher""" }
    }
    if (-not $Facts.ChainBuilt -or $Facts.ChainFlags -contains "UntrustedRoot" -or $Facts.ChainFlags -contains "PartialChain") {
        return @{ Verdict = "untrusted-ca"; Why = ("the chain does not build to a trusted root ({0})" -f ($Facts.ChainFlags -join ", ")) }
    }
    if (-not $Facts.RootInMachine) {
        return @{ Verdict = "untrusted-ca"; Why = "the chain ends in a root that is not in this machine's trusted root store, which is the store AppX and installers read" }
    }
    return @{ Verdict = "public-ca"; Why = "the signer was issued by a CA and the chain ends in a root in this machine's trusted root store" }
}

function Get-CertificateFacts {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    $built = $chain.Build($Cert)

    $flags = @()
    foreach ($status in $chain.ChainStatus) { $flags += $status.Status.ToString() }
    $elements = @($chain.ChainElements)
    $root = if ($elements.Count -gt 0) { $elements[$elements.Count - 1].Certificate } else { $Cert }

    $eku = $null
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq "2.5.29.37") {
            $usage = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ext
            $eku = @($usage.EnhancedKeyUsages | ForEach-Object { $_.Value })
        }
    }

    $policies = @()
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq "2.5.29.32") {
            $rendered = $ext.Format($false)
            foreach ($match in [regex]::Matches($rendered, "\d+(\.\d+){3,}")) { $policies += $match.Value }
        }
    }

    [pscustomobject]@{
        SelfSigned     = ($Cert.Subject -eq $Cert.Issuer)
        ChainBuilt     = $built
        ChainFlags     = $flags
        ChainElements  = $elements.Count
        Root           = $root
        RootInMachine  = (Test-Path ("Cert:\LocalMachine\Root\" + $root.Thumbprint))
        RootInUserRoot = (Test-Path ("Cert:\CurrentUser\Root\" + $root.Thumbprint))
        Eku            = $eku
        Policies       = $policies
        LifetimeDays   = [int]($Cert.NotAfter - $Cert.NotBefore).TotalDays
    }
}

function Find-SignTool {
    $found = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "x64" } | Sort-Object FullName -Descending | Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

# What the SDK's own tool says about an AppX/MSIX signature, read out of its verbose output.
function Get-AppxSignatureFacts {
    param([string]$File)
    $signtool = Find-SignTool
    if (-not $signtool) { return $null }
    # signtool reports a refused chain on stderr and exits non-zero; under this script's
    # "Stop" preference Windows PowerShell would turn that into a terminating error, so the
    # call is made with the preference relaxed and the exit code read instead.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $signtool verify /pa /v $File 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $lines = @($output | ForEach-Object { $_.ToString() })
    $text = $lines -join "`n"
    $subjects = @([regex]::Matches($text, "Issued to:\s*(.+)") | ForEach-Object { $_.Groups[1].Value.Trim() })
    $issuers = @([regex]::Matches($text, "Issued by:\s*(.+)") | ForEach-Object { $_.Groups[1].Value.Trim() })
    $thumbs = @([regex]::Matches($text, "SHA1 hash:\s*([0-9A-Fa-f]{40})") | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() })
    $errorLine = $lines | Where-Object { $_ -match "SignTool Error|Error:" } | Select-Object -First 1
    [pscustomobject]@{
        Signtool       = $signtool
        ExitCode       = $code
        Present        = ($text -match "Signing Certificate Chain:")
        Verified       = ($code -eq 0)
        Signer         = $(if ($subjects.Count) { $subjects[0] } else { "" })
        Issuer         = $(if ($issuers.Count) { $issuers[0] } else { "" })
        ChainLength    = $subjects.Count
        RootThumbprint = $(if ($thumbs.Count) { $thumbs[-1] } else { "" })
        Timestamped    = (($text -match "Signing Certificate Chain:") -and -not ($text -match "File is not timestamped"))
        Error          = $(if ($errorLine) { $errorLine.Trim() } else { "" })
    }
}

function Invoke-AppxJudgement {
    param([string]$File)
    $facts = Get-AppxSignatureFacts -File $File
    if ($null -eq $facts) {
        Write-Info "signature" "not judged: signtool.exe is not installed (Windows SDK)"
        Write-Line ""
        Write-Line "VERDICT: unknown - reading an AppX signature needs the SDK's signtool, and this machine has none" "Red"
        Write-Line "RESULT: FAIL - nothing was judged" "Red"
        return $false
    }

    if (-not $facts.Present) {
        Write-Info "signature" "absent (the package carries no signature)"
        Write-Line ""
        Write-Line ("VERDICT: unsigned - {0}" -f $facts.Error) "Red"
        Write-Line "RESULT: FAIL - the package is not signed, so every Windows shows ""Unknown publisher""" "Red"
        return $false
    }

    Write-Info "signature" ("present (signtool verify /pa: {0})" -f $(if ($facts.Verified) { "chain trusted on this machine" } else { "not trusted here, exit $($facts.ExitCode)" }))
    Write-Info "signer" $facts.Signer
    Write-Info "issuer" $facts.Issuer
    Write-Info "chain" ("{0} element(s) printed" -f $facts.ChainLength)
    if ($facts.RootThumbprint) {
        Write-Info "root" ("{0}  [LocalMachine\Root: {1}]" -f $facts.RootThumbprint, (Test-Path ("Cert:\LocalMachine\Root\" + $facts.RootThumbprint)))
    }
    Write-Info "timestamp" $(if ($facts.Timestamped) { "present" } else { "none" })
    if ($facts.Error) { Write-Info "signtool" $facts.Error }

    Write-Line ""
    Write-Line "release requirements:" "White"
    Write-Note $facts.Timestamped "the signature carries a timestamp, so it outlives the certificate"
    Write-Line "  note: the certificate's EKU, validity window and the 460-day limit are judged on the" "DarkGray"
    Write-Line "  PE files this package carries, which are signed by the same certificate." "DarkGray"

    Write-Line ""
    $selfSigned = ($facts.Signer -eq $facts.Issuer -and $facts.Signer -ne "")
    if ($selfSigned) {
        Write-Line ("VERDICT: self-signed - {0} signs itself, so it is trusted only where someone put it" -f $facts.Signer) "Red"
        Write-Line "RESULT: FAIL - the package is not trusted by a stranger's Windows" "Red"
        return $false
    }
    if ($facts.Verified) {
        Write-Line "VERDICT: public-ca - signtool verified the chain against a root this machine trusts, and the signer was issued by a CA" "Green"
        Write-Line "RESULT: PASS - a stranger's Windows trusts this signature" "Green"
        return $true
    }
    Write-Line ("VERDICT: untrusted-ca - {0}" -f $facts.Error) "Red"
    Write-Line "RESULT: FAIL - the package is not trusted by a stranger's Windows" "Red"
    return $false
}

function Invoke-Judgement {
    param([string]$File)
    Write-Line ""
    Write-Line ("verify-trust.ps1 - judging {0}" -f (Split-Path $File -Leaf)) "White"
    Write-FileHashLine -File $File

    $extension = [System.IO.Path]::GetExtension($File).ToLowerInvariant()
    if ($extension -in @(".msix", ".appx", ".msixbundle", ".appxbundle")) {
        return Invoke-AppxJudgement -File $File
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $File
    $status = $signature.Status.ToString()
    $cert = $signature.SignerCertificate
    $timestamped = $null -ne $signature.TimeStamperCertificate
    $timeStamper = if ($timestamped) { $signature.TimeStamperCertificate.Subject } else { "" }
    Write-Info "signature" $(if ($cert) { "present (status {0} on this machine)" -f $status } else { "absent" })

    if (-not $cert) {
        Write-Line ""
        Write-Line "VERDICT: unsigned - there is no signature at all, so every Windows shows ""Unknown publisher""" "Red"
        Write-Line "RESULT: FAIL - the artifact is not signed" "Red"
        return $false
    }

    $facts = Get-CertificateFacts -Cert $cert
    Write-Info "signer" $cert.Subject
    Write-Info "issuer" $cert.Issuer
    Write-Info "thumbprint" $cert.Thumbprint
    Write-Info "validity" ("{0:yyyy-MM-dd} .. {1:yyyy-MM-dd} ({2} days)" -f $cert.NotBefore, $cert.NotAfter, $facts.LifetimeDays)
    Write-Info "key usage" $(if ($facts.Eku) { $facts.Eku -join ", " } else { "not restricted" })
    Write-Info "timestamp" $(if ($timestamped) { "present ($timeStamper)" } else { "none" })
    Write-Info "chain" ("{0} element(s) built, status {1}" -f $facts.ChainElements, $(if ($facts.ChainFlags.Count) { $facts.ChainFlags -join ", " } else { "NoError" }))
    Write-Info "root" ("{0}  [LocalMachine\Root: {1}, CurrentUser\Root: {2}]" -f $facts.Root.Subject, $facts.RootInMachine, $facts.RootInUserRoot)
    if ($facts.Policies.Count) { Write-Info "policy oid" ($facts.Policies -join ", ") }

    Write-Line ""
    Write-Line "release requirements:" "White"
    Write-Note (($facts.Eku -contains $codeSigningEku) -or (-not $facts.Eku)) "the certificate allows code signing (EKU $codeSigningEku)"
    Write-Note $timestamped "the signature carries a timestamp, so it outlives the certificate"
    if ($cert.NotBefore -ge $csbrFrom) {
        Write-Note ($facts.LifetimeDays -le $csbrMaxDays) ("validity is within the {0} days the CA/Browser Forum allows for certificates issued on or after {1:yyyy-MM-dd} ({2} days)" -f $csbrMaxDays, $csbrFrom, $facts.LifetimeDays)
    } else {
        Write-Note $true ("issued before {0:yyyy-MM-dd}, so the {1}-day limit does not apply ({2} days)" -f $csbrFrom, $csbrMaxDays, $facts.LifetimeDays)
    }

    $verdict = Get-TrustVerdict -Facts $facts -Status $status
    Write-Line ""
    if ($verdict.Verdict -eq "public-ca") {
        Write-Line ("VERDICT: public-ca - {0}" -f $verdict.Why) "Green"
        Write-Line "RESULT: PASS - a stranger's Windows trusts this signature" "Green"
        return $true
    }
    Write-Line ("VERDICT: {0} - {1}" -f $verdict.Verdict, $verdict.Why) "Red"
    if ($status -eq "Valid") {
        Write-Line "  note: this machine reports the signature as Valid because the certificate is trusted *here*." "Yellow"
        Write-Line "  That is not the question. The verdict above is the answer for a machine that has never seen it." "Yellow"
    }
    Write-Line "RESULT: FAIL - the artifact is not trusted by a stranger's Windows" "Red"
    return $false
}

if ($SelfTest) {
    Write-Line "verify-trust.ps1 - SelfTest" "White"
    Write-Line "Two controls, one of each kind. Both must land where they belong, or the instrument is broken:"
    Write-Line "  negative: this repository's own engine, signed with the project's self-signed certificate"
    Write-Line "  positive: a Microsoft-signed system binary"
    Write-Line ""

    $negative = Join-Path (Split-Path $PSScriptRoot -Parent) "dist\MICS-portable\mics-engine.exe"
    $positive = Join-Path $env:WINDIR "System32\kernel32.dll"
    $ok = $true

    if (-not (Test-Path $negative)) {
        Write-Line ("  [!!]  the negative control is missing: {0} (build the portable package first)" -f $negative) "Yellow"
        $ok = $false
    } else {
        $raw = (Get-AuthenticodeSignature -LiteralPath $negative).Status.ToString()
        # Judged in-process rather than by exit code, so both controls run in one pass.
        $signature = Get-AuthenticodeSignature -LiteralPath $negative
        if (-not $signature.SignerCertificate) {
            Write-Line "  [!!]  the negative control is unsigned, which cannot distinguish anything" "Yellow"
            $ok = $false
        } else {
            $facts = Get-CertificateFacts -Cert $signature.SignerCertificate
            $verdict = Get-TrustVerdict -Facts $facts -Status $raw
            Write-Line ("  negative: {0}  (raw status on this machine: {1})" -f $verdict.Verdict, $raw) "Gray"
            if ($verdict.Verdict -eq "public-ca") {
                Write-Line "  [!!]  the self-signed engine was judged publicly trusted - the instrument is wrong" "Yellow"
                $ok = $false
            } elseif ($raw -eq "Valid") {
                Write-Line "  [ok]  locally Valid, correctly judged not publicly trusted - this is the trap working" "DarkGray"
            } else {
                Write-Line "  [ok]  judged not publicly trusted" "DarkGray"
            }
        }
    }

    if (-not (Test-Path $positive)) {
        Write-Line ("  [!!]  the positive control is missing: {0}" -f $positive) "Yellow"
        $ok = $false
    } else {
        $signature = Get-AuthenticodeSignature -LiteralPath $positive
        if (-not $signature.SignerCertificate) {
            Write-Line "  [!!]  the positive control is unsigned, which cannot distinguish anything" "Yellow"
            $ok = $false
        } else {
            $facts = Get-CertificateFacts -Cert $signature.SignerCertificate
            $verdict = Get-TrustVerdict -Facts $facts -Status $signature.Status.ToString()
            Write-Line ("  positive: {0}  ({1})" -f $verdict.Verdict, $signature.SignerCertificate.Subject) "Gray"
            if ($verdict.Verdict -eq "public-ca") {
                Write-Line "  [ok]  a CA-issued signature is recognised as publicly trusted" "DarkGray"
            } else {
                Write-Line ("  [!!]  a Microsoft-signed binary was judged {0} - the instrument is wrong" -f $verdict.Verdict) "Yellow"
                $ok = $false
            }
        }
    }

    Write-Line ""
    if ($ok) { Write-Line "RESULT: PASS - the instrument separates the two cases" "Green"; exit 0 }
    Write-Line "RESULT: FAIL - the controls did not land where they belong" "Red"
    exit 1
}

if (-not $Path) {
    Write-Line "usage: verify-trust.ps1 -Path <artifact> | -SelfTest" "Yellow"
    exit 2
}
if (-not (Test-Path -LiteralPath $Path)) {
    Write-Line ("verify-trust.ps1: no such file: {0}" -f $Path) "Red"
    exit 2
}

if (Invoke-Judgement -File (Resolve-Path -LiteralPath $Path).Path) { exit 0 }
exit 1
