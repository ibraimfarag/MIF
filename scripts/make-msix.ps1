# Packages the portable build as an MSIX - the artifact the free Microsoft Store
# signing route needs (docs/SIGNING.md route A, D-036).
#
# What this script does NOT claim: that the package will pass Store certification.
# Packing and signing prove the *local* half - the manifest is valid, the payload
# is complete, the signature verifies - and nothing about the three unknowns the
# document lists (restricted-capability approval, whether a packaged service can
# still write the real hosts file and drive the firewall, and whether the product
# category certifies at all). `-Install` measures the first of those here.
#
#   .\scripts\make-msix.ps1                                  # pack, unsigned
#   .\scripts\make-msix.ps1 -SelfSigned -Install             # pack, sign locally, install
#   .\scripts\make-msix.ps1 -Publisher "CN=..., O=..." -Thumbprint <sha1>
#
# The self-signed mode exists for the same reason it exists in sign.ps1: it makes
# the *pipeline* testable on a machine that has no CA certificate. It does not
# make a package a stranger's Windows will trust - that is the Store's signature
# or OSSign's, never ours.
[CmdletBinding()]
param(
    # The portable build to package. make-release.ps1 produces it.
    [string]$Source = "dist\MICS-portable",
    [string]$Out,
    # Identity Name. The Store assigns its own (Partner Center -> Product identity)
    # and it must be used verbatim for a Store submission; this default is what a
    # sideloaded test package uses.
    [string]$Identity = "MICS.Desktop",
    [string]$Version = "0.1.0.0",
    [string]$DisplayName = "MI CS",
    [string]$PublisherDisplayName = "MI CS",
    [string]$Description = "Local security posture, detection and hardening for Windows. Every OS call lives in one auditable Rust engine; the UI speaks JSON-RPC.",
    # The certificate subject. MSIX requires this to match the signing
    # certificate exactly, so with -SelfSigned it is taken from the certificate
    # instead of being passed in.
    [string]$Publisher,
    [switch]$SelfSigned,
    [string]$Thumbprint,
    # Sign a copy and leave the machine's state alone unless this is passed.
    [switch]$Install,
    [string]$StageDir
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

function Find-SdkTool([string]$name) {
    $root = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (-not (Test-Path $root)) { return $null }
    return Get-ChildItem $root -Recurse -Filter $name -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
}

# --- inputs -------------------------------------------------------------------

$makeappx = Find-SdkTool "makeappx.exe"
if (-not $makeappx) { throw "makeappx.exe not found under C:\Program Files (x86)\Windows Kits\10\bin (install the Windows SDK, or the Microsoft.Windows.SDK.BuildTools NuGet package)" }

if ($Version -notmatch '^\d{1,5}\.\d{1,5}\.\d{1,5}\.\d{1,5}$') { throw "Version must be four numeric parts (major.minor.build.revision), got '$Version'" }
foreach ($part in $Version.Split('.')) { if ([int]$part -gt 65535) { throw "Version part '$part' exceeds 65535" } }
if ($Version -match '^0\.0\.0\.0$') { throw "Version 0.0.0.0 is not a release version" }

if (-not (Test-Path -LiteralPath $Source)) { throw "Source '$Source' does not exist - run scripts\make-release.ps1 first" }
$Source = (Resolve-Path -LiteralPath $Source).Path

foreach ($required in @("mics_app.exe", "mics-engine.exe", "flutter_windows.dll")) {
    if (-not (Test-Path -LiteralPath (Join-Path $Source $required))) { throw "Source '$Source' is missing $required - this is not a portable build" }
}

$signing = $null
if ($SelfSigned) {
    $signing = & (Join-Path $PSScriptRoot "codesign-cert.ps1") -Publisher "Mourad Ibrahim (MI CS)"
    $Publisher = $signing.Subject
    Write-Host "publisher from the self-signed certificate: $Publisher"
} elseif ($Thumbprint) {
    if (-not $Publisher) { throw "-Thumbprint needs -Publisher: MSIX requires the manifest Publisher to equal the certificate subject, and only the certificate knows it" }
}
if (-not $Publisher) {
    # The manifest needs a publisher even for a packing-only run, and the only
    # subject this repository can name is the one D-016 pins for the self-signed
    # identity. Say so rather than inventing a name.
    $Publisher = "CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)"
    Write-Host "no -Publisher given: using the project's own subject '$Publisher' (only a package signed by that certificate will install)"
}

if (-not $Out) { $Out = Join-Path $repo ("dist\MICS-{0}-x64.msix" -f $Version) }
$Out = [IO.Path]::GetFullPath($Out)
$outDir = Split-Path -Parent $Out
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# --- stage --------------------------------------------------------------------

$stage = if ($StageDir) { [IO.Path]::GetFullPath($StageDir) } else { Join-Path $repo "build\msix-stage" }
# The stage directory is deleted and recreated, so refuse anything that is not a
# scratch path: the repository, its parent, a drive root, or the source itself.
foreach ($forbidden in @($repo, (Split-Path $repo -Parent), [IO.Path]::GetPathRoot($repo), $Source)) {
    if ($stage.TrimEnd('\') -eq ([IO.Path]::GetFullPath($forbidden)).TrimEnd('\')) { throw "Refusing to use '$stage' as the stage directory - it is not a scratch path" }
}
if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Write-Host "staging $Source -> $stage"
$sw = [Diagnostics.Stopwatch]::StartNew()
Copy-Item -Path (Join-Path $Source '*') -Destination $stage -Recurse -Force
$assetsDir = Join-Path $stage "Assets"
New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null

# MSIX logos. Generated from the shipped icon at the sizes the manifest names, so
# the package never depends on files a designer has to remember to export.
Add-Type -AssemblyName System.Drawing
$iconPath = Join-Path $repo "assets\icons\Desktop.png"
if (-not (Test-Path $iconPath)) { throw "assets\icons\Desktop.png is missing - the MSIX needs logo assets" }
$icon = [System.Drawing.Image]::FromFile($iconPath)
try {
    $logos = @(
        @{ Name = "StoreLogo.png";        W = 50;  H = 50  },
        @{ Name = "Square44x44Logo.png";  W = 44;  H = 44  },
        @{ Name = "Square150x150Logo.png"; W = 150; H = 150 },
        @{ Name = "Wide310x150Logo.png";  W = 310; H = 150 }
    )
    foreach ($logo in $logos) {
        $bmp = New-Object System.Drawing.Bitmap($logo.W, $logo.H)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $g.Clear([System.Drawing.Color]::Transparent)
            # Keep the aspect ratio and centre it: the icon is square, and the wide
            # tile is not, so stretching it would look wrong.
            $scale = [Math]::Min($logo.W / $icon.Width, $logo.H / $icon.Height)
            $dw = [int][Math]::Round($icon.Width * $scale)
            $dh = [int][Math]::Round($icon.Height * $scale)
            $dx = [int](($logo.W - $dw) / 2)
            $dy = [int](($logo.H - $dh) / 2)
            $g.DrawImage($icon, $dx, $dy, $dw, $dh)
        } finally { $g.Dispose() }
        $bmp.Save((Join-Path $assetsDir $logo.Name), [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
    }
} finally { $icon.Dispose() }

# The manifest: tokens are replaced, never shipped. A survivor is a hard failure.
$templatePath = Join-Path $repo "installer\msix\AppxManifest.xml"
$manifest = Get-Content -LiteralPath $templatePath -Raw
$tokens = [ordered]@{
    "__IDENTITY__"                = $Identity
    "__PUBLISHER__"               = $Publisher
    "__VERSION__"                 = $Version
    "__DISPLAY_NAME__"            = $DisplayName
    "__PUBLISHER_DISPLAY_NAME__"  = $PublisherDisplayName
    "__DESCRIPTION__"             = $Description
}
foreach ($key in $tokens.Keys) { $manifest = $manifest.Replace($key, $tokens[$key]) }
if ($manifest -match '__[A-Z][A-Z_]*__') { throw "The manifest still contains an unreplaced token: $($Matches[0])" }
$manifestPath = Join-Path $stage "AppxManifest.xml"
[IO.File]::WriteAllText($manifestPath, $manifest, (New-Object System.Text.UTF8Encoding($false)))

$fileCount = (Get-ChildItem $stage -Recurse -File).Count
Write-Host "staged $fileCount files in $([int]$sw.Elapsed.TotalSeconds) s"

# --- pack ---------------------------------------------------------------------

if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out -Force }
Write-Host "packing: $(Split-Path $makeappx.FullName -Parent | Split-Path -Parent | Split-Path -Leaf) makeappx pack"
$packSw = [Diagnostics.Stopwatch]::StartNew()
& $makeappx.FullName pack /o /d $stage /p $Out
if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed with exit code $LASTEXITCODE" }
$packSw.Stop()

$hash = (Get-FileHash -LiteralPath $Out -Algorithm SHA256).Hash
$sizeMb = [Math]::Round((Get-Item $Out).Length / 1MB, 2)
Write-Host ""
Write-Host ("package : {0}" -f $Out)
Write-Host ("size    : {0} MB" -f $sizeMb)
Write-Host ("sha256  : {0}" -f $hash)
Write-Host ("packed  : {0:N1} s for {1} files" -f $packSw.Elapsed.TotalSeconds, $fileCount)

# --- sign ---------------------------------------------------------------------

$signerSubject = $null
if ($SelfSigned -or $Thumbprint) {
    $signtool = Find-SdkTool "signtool.exe"
    if (-not $signtool) { throw "signtool.exe not found under C:\Program Files (x86)\Windows Kits\10\bin" }
    if ($SelfSigned) {
        $pfx = Join-Path $env:TEMP "mics-signing\codesign.pfx"
        $passFile = Join-Path $env:TEMP "mics-signing\codesign.pass"
        if (-not (Test-Path $pfx) -or -not (Test-Path $passFile)) { throw "The self-signed PFX is gone from $env:TEMP\mics-signing - run scripts\sign.ps1 -SelfSigned once to recreate it" }
        $pfxPassword = (Get-Content -LiteralPath $passFile -Raw).Trim()
        & $signtool.FullName sign /fd SHA256 /f $pfx /p $pfxPassword $Out
    } else {
        & $signtool.FullName sign /fd SHA256 /sha1 $Thumbprint $Out
    }
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed with exit code $LASTEXITCODE" }
    $sig = Get-AuthenticodeSignature -LiteralPath $Out
    Write-Host ("signature: {0} - {1}" -f $sig.Status, $sig.SignerCertificate.Subject)
    if (-not $sig.SignerCertificate) { throw "The package has no signer certificate after signing" }
    # MSIX only installs when the certificate is trusted for the package's
    # publisher; say so instead of letting Add-AppxPackage fail with 0x800B0109.
    $trusted = Get-ChildItem "Cert:\CurrentUser\TrustedPeople" | Where-Object { $_.Thumbprint -eq $sig.SignerCertificate.Thumbprint }
    Write-Host ("trusted for install (CurrentUser\TrustedPeople): {0}" -f [bool]$trusted)
} else {
    Write-Host "signature: none (packed only) - Windows will refuse to install an unsigned MSIX"
}

# --- install (optional, and the only part that touches the machine) ------------

if ($Install) {
    if (-not $SelfSigned -and -not $Thumbprint) { throw "-Install needs a signed package (-SelfSigned or -Thumbprint)" }
    Write-Host ""
    Write-Host "installing $Out ..."
    $installSw = [Diagnostics.Stopwatch]::StartNew()
    try {
        Add-AppxPackage -Path $Out -ErrorAction Stop
        $installSw.Stop()
        $pkg = Get-AppxPackage -Name $Identity
        Write-Host ("install  : OK in {0:N1} s" -f $installSw.Elapsed.TotalSeconds)
        Write-Host ("package  : {0} {1} -> {2}" -f $pkg.Name, $pkg.Version, $pkg.InstallLocation)
        $svc = Get-Service -Name "MICSHelper" -ErrorAction SilentlyContinue
        Write-Host ("service  : {0}" -f $(if ($svc) { "$($svc.Status) - $($svc.StartType)" } else { "MICSHelper NOT created" }))
        Write-Host ""
        Write-Host "Remove it with:  Remove-AppxPackage -Package $($pkg.PackageFullName)"
    } catch {
        $installSw.Stop()
        Write-Host ("install  : FAILED in {0:N1} s - {1}" -f $installSw.Elapsed.TotalSeconds, $_.Exception.Message)
        throw
    }
}

Write-Host ""
Write-Host "Not answered by this script, and not answerable locally: whether Microsoft grants"
Write-Host "the two restricted capabilities in certification, whether a packaged service can"
Write-Host "still write the real hosts file and drive the firewall, and whether the product"
Write-Host "category certifies. See docs/SIGNING.md section 3."