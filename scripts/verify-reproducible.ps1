<#
.SYNOPSIS
    Rebuild the package from this source and compare it with a published copy.

.DESCRIPTION
    F-11 in docs/THREAT-MODEL.md: with no certificate purchased (D-035) the
    load-bearing claim is that a stranger can re-derive the published bytes from
    this source and compare them. This is the exit code for that claim.
    `docs/REPRODUCIBLE.md` is the recipe; this script is the check.

    What is compared, and on what basis:

      * every file that is not a PE: its SHA-256, exact;
      * every PE file (both exes, `flutter_windows.dll`, the plugin DLLs): the
        signature-independent content hash, i.e. the file with the Authenticode
        blob, the optional-header checksum and the security data directory taken
        out. Authenticode embeds the signing time and a random RSA value, so the
        blob can never be reproduced; the code it covers can;
      * `mics-engine.exe` when even its content hash differs: explained, not
        ignored. The engine carries MICS_MANIFEST, a document that records the
        SHA-256 of every other shipped file *as signed* - so a different
        signature changes the document and therefore the engine. The explanation
        is accepted only if both engines' documents list the same files in the
        same order and agree on every entry that is not a PE; the PE entries are
        already covered by the content hashes above.

    Exit code 0 means every file is identical, identical as content, or explained
    by one of those two documented reasons. Anything else is a real difference
    and prints the rows that differ.

.PARAMETER Reference
    The published artifact: a portable `.zip`, or an extracted package folder.

.PARAMETER Built
    The folder to compare with the reference. When omitted the script rebuilds
    from this source first (`make-release.ps1 -Reproducible`) and compares
    `dist\MICS-portable`.

.PARAMETER NoBuild
    Never rebuild; requires -Built. Used when a caller already has a build.

.PARAMETER Keep
    Keep the extracted reference and the rebuild log for inspection.

.PARAMETER SelfTest
    Check the primitives this script stands on (the build time, the deterministic
    ZIP, the unsigned content hash, the row comparison) against fixtures, without
    building anything or needing a published artifact. Seconds, not minutes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify-reproducible.ps1 `
      -Reference dist\MICS-portable-0.1.0-x64.zip

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify-reproducible.ps1 -SelfTest

.NOTES
    ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
    docs/TODO.md 8.9).
#>
param(
    [string]$Reference = "",
    [string]$Built = "",
    [switch]$NoBuild,
    [switch]$Keep,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
. (Join-Path $PSScriptRoot "reproducible.ps1")
. (Join-Path $PSScriptRoot "manifest-resource.ps1")

# --------------------------------------------------------------------- fixtures
# A synthetic PE big enough for the header walk in Get-MicsUnsignedHash: DOS
# header, COFF header, a PE32+ optional header with one data directory beyond the
# certificate table, a code region, and - when signed - a blob after it. Only the
# fields the hash function reads are written, because writing the rest would
# describe a file this project never ships.
function New-TestPe {
    param(
        [byte]$Code = 0x11,
        [byte[]]$Blob = $null,
        [uint32]$CheckSum = 0,
        [uint32]$TimeStamp = 0
    )
    $bodyEnd = 0x140
    $size = if ($Blob) { $bodyEnd + $Blob.Length } else { $bodyEnd }
    $bytes = New-Object byte[] $size
    $bytes[0] = 0x4D   # M
    $bytes[1] = 0x5A   # Z
    [Array]::Copy([BitConverter]::GetBytes([int32]0x40), 0, $bytes, 0x3C, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x00004550), 0, $bytes, 0x40, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$TimeStamp), 0, $bytes, 0x48, 4)
    $opt = 0x58
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x20B), 0, $bytes, $opt, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$CheckSum), 0, $bytes, $opt + 64, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]16), 0, $bytes, $opt + 108, 4)
    for ($i = 0x100; $i -lt $bodyEnd; $i++) { $bytes[$i] = $Code }
    if ($Blob) {
        [Array]::Copy($Blob, 0, $bytes, $bodyEnd, $Blob.Length)
        [Array]::Copy([BitConverter]::GetBytes([uint32]$bodyEnd), 0, $bytes, $opt + 112 + 32, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]$Blob.Length), 0, $bytes, $opt + 112 + 36, 4)
    }
    return , $bytes
}

function Invoke-SelfTest {
    # Script scope, not local: Assert below is a nested function, and a nested
    # function's `$script:` is this file, not Invoke-SelfTest.
    $script:selfTestChecks = 0
    $script:selfTestFailed = New-Object System.Collections.Generic.List[string]
    function Assert($condition, $message) {
        if ($condition) { $script:selfTestChecks++ } else { $script:selfTestFailed.Add($message) }
    }

    # The build time: an explicit value wins, SOURCE_DATE_EPOCH is read as seconds.
    $t = Get-MicsBuildTime -BuildTime "2026-11-08T11:54:33+00:00"
    Assert ($t.UtcDateTime.ToString("s") -eq "2026-11-08T11:54:33") "explicit -BuildTime was not parsed ($($t.ToString('o')))"
    $old = $env:SOURCE_DATE_EPOCH
    try {
        $env:SOURCE_DATE_EPOCH = "1762593273"
        $t = Get-MicsBuildTime
        Assert ($t.ToUnixTimeSeconds() -eq 1762593273) "SOURCE_DATE_EPOCH was not read ($($t.ToUnixTimeSeconds()))"
    } finally {
        if ($old) { $env:SOURCE_DATE_EPOCH = $old } else { Remove-Item Env:SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue }
    }

    # The unsigned content hash: two signatures over the same code agree, a changed
    # code byte does not, and an unsigned copy agrees with a signed one.
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("mics-selftest-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $blobA = New-Object byte[] 64
        for ($i = 0; $i -lt 64; $i++) { $blobA[$i] = 0xAA }
        $blobB = New-Object byte[] 64
        for ($i = 0; $i -lt 64; $i++) { $blobB[$i] = 0xBB }
        $signedA = Join-Path $work "signed-a.bin"
        $signedB = Join-Path $work "signed-b.bin"
        $unsigned = Join-Path $work "unsigned.bin"
        $changed = Join-Path $work "changed.bin"
        [System.IO.File]::WriteAllBytes($signedA, (New-TestPe -Blob $blobA -CheckSum 0x12345678))
        [System.IO.File]::WriteAllBytes($signedB, (New-TestPe -Blob $blobB -CheckSum 0x23456789))
        [System.IO.File]::WriteAllBytes($unsigned, (New-TestPe))
        [System.IO.File]::WriteAllBytes($changed, (New-TestPe -Code 0x22))
        $payloadA = Get-MicsUnsignedHash -Path $signedA
        Assert ($payloadA -eq (Get-MicsUnsignedHash -Path $signedB)) "two signatures over the same code hashed differently"
        Assert ($payloadA -eq (Get-MicsUnsignedHash -Path $unsigned)) "a signed and an unsigned copy of the same code hashed differently"
        Assert ($payloadA -ne (Get-MicsUnsignedHash -Path $changed)) "a changed code byte did not change the content hash"

        # The deterministic ZIP: same content and timestamp twice, one hash; a
        # changed byte, a different hash; and no directory entries (which
        # Compress-Archive adds and which carry the folder's timestamps).
        $tree = Join-Path $work "tree"
        New-Item -ItemType Directory -Force -Path (Join-Path $tree "sub") | Out-Null
        Set-Content -Path (Join-Path $tree "b.txt") -Value "second" -Encoding ASCII
        Set-Content -Path (Join-Path $tree "a.txt") -Value "first" -Encoding ASCII
        Set-Content -Path (Join-Path $tree "sub\c.txt") -Value "third" -Encoding ASCII
        $stamp = [DateTimeOffset]::new(2026, 11, 8, 11, 54, 32, [TimeSpan]::Zero)
        $z1 = Join-Path $work "one.zip"
        $z2 = Join-Path $work "two.zip"
        New-MicsDeterministicZip -Source $tree -Destination $z1 -Timestamp $stamp
        Start-Sleep -Milliseconds 1100
        New-MicsDeterministicZip -Source $tree -Destination $z2 -Timestamp $stamp
        Assert ((Get-FileHash $z1).Hash -eq (Get-FileHash $z2).Hash) "two ZIPs of the same content and timestamp differ"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($z1)
        try {
            $names = @($archive.Entries | ForEach-Object { $_.FullName })
            Assert ($names.Count -eq 3) "the ZIP has $($names.Count) entries for 3 files (directory entries?)"
            Assert (($names -join ',') -eq "a.txt,b.txt,sub/c.txt") "the ZIP entries are not in ordinal order: $($names -join ',')"
            # A ZIP timestamp is a clock face with no zone in it, so the archive
            # bytes are identical whether the build ran in Cairo or in UTC - which
            # is what makes one fixed timestamp the right fix. If the writer ever
            # started converting to the machine's zone, this reads back shifted.
            Assert ($archive.Entries[0].LastWriteTime.DateTime.ToString("s") -eq "2026-11-08T11:54:32") "the ZIP entry timestamp is $($archive.Entries[0].LastWriteTime.ToString('o'))"
        } finally { $archive.Dispose() }
        Set-Content -Path (Join-Path $tree "a.txt") -Value "first!" -Encoding ASCII
        $z3 = Join-Path $work "three.zip"
        New-MicsDeterministicZip -Source $tree -Destination $z3 -Timestamp $stamp
        Assert ((Get-FileHash $z1).Hash -ne (Get-FileHash $z3).Hash) "changed content did not change the ZIP"

        # The row comparison: the four verdicts.
        $reference = @(
            [pscustomobject]@{ path = "same.txt"; bytes = 1; sha256 = "aa"; payload = "" },
            [pscustomobject]@{ path = "code.dll"; bytes = 2; sha256 = "bb"; payload = "cc" },
            [pscustomobject]@{ path = "gone.txt"; bytes = 3; sha256 = "dd"; payload = "" }
        )
        $candidate = @(
            [pscustomobject]@{ path = "same.txt"; bytes = 1; sha256 = "aa"; payload = "" },
            [pscustomobject]@{ path = "code.dll"; bytes = 2; sha256 = "ee"; payload = "cc" },
            [pscustomobject]@{ path = "new.txt"; bytes = 4; sha256 = "ff"; payload = "" }
        )
        $rows = Compare-MicsInventory -Reference $reference -Candidate $candidate
        $byPath = @{}
        foreach ($row in $rows) { $byPath[$row.path] = $row }
        Assert ($byPath["same.txt"].basis -eq "file") "an identical file was not reported as identical"
        Assert ($byPath["code.dll"].basis -eq "unsigned") "a PE that only differs in its signature was not reported as content-identical"
        Assert ($byPath["gone.txt"].status -eq "missing") "a file only in the reference was not reported as missing"
        Assert ($byPath["new.txt"].status -eq "added") "a file only in the rebuild was not reported as added"

        # VERSION: the one text file that follows the signature. Only the engine
        # line may differ; a version line, an app-hash line or a different shape
        # must not be explained away.
        $hash = "a" * 64
        $other = "b" * 64
        $versionBase = @(
            "MI CS 0.1.0 (portable, x64)",
            "built   2026-11-08 11:54:32 +00:00 (source revision 3ac3f3e)",
            "engine  $hash",
            "app     $hash",
            "rules   24 file(s) hot-reloaded from rules\"
        )
        $referenceVersion = Join-Path $work "version-reference.txt"
        Set-Content -Path $referenceVersion -Value $versionBase -Encoding ASCII
        $engineOnly = Join-Path $work "version-engine.txt"
        Set-Content -Path $engineOnly -Value ($versionBase | ForEach-Object { if ($_ -like "engine  *") { "engine  $other" } else { $_ } }) -Encoding ASCII
        Assert ((Compare-MicsVersionFile -Reference $referenceVersion -Candidate $engineOnly).Explained) "a VERSION differing only in the engine hash was not explained"
        $appMoved = Join-Path $work "version-app.txt"
        Set-Content -Path $appMoved -Value ($versionBase | ForEach-Object { if ($_ -like "app     *") { "app     $other" } else { $_ } }) -Encoding ASCII
        Assert (-not (Compare-MicsVersionFile -Reference $referenceVersion -Candidate $appMoved).Explained) "a VERSION whose app hash moved was explained away"
        $builtMoved = Join-Path $work "version-built.txt"
        Set-Content -Path $builtMoved -Value ($versionBase | ForEach-Object { if ($_ -like "built*") { "built   2026-11-09 01:02:03 +00:00 (source revision deadbee)" } else { $_ } }) -Encoding ASCII
        Assert (-not (Compare-MicsVersionFile -Reference $referenceVersion -Candidate $builtMoved).Explained) "a VERSION built at a different time was explained away"
    } finally {
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($script:selfTestFailed.Count -gt 0) {
        foreach ($message in $script:selfTestFailed) { Write-Output "  FAIL $message" }
        Write-Output ("SELFTEST: FAIL - {0} of {1} check(s) failed" -f $script:selfTestFailed.Count, ($script:selfTestChecks + $script:selfTestFailed.Count))
        $script:selfTestExit = 1
        return
    }
    Write-Output ("SELFTEST: PASS - {0} checks" -f $script:selfTestChecks)
    $script:selfTestExit = 0
}

if ($SelfTest) {
    Invoke-SelfTest
    exit $script:selfTestExit
}

if (-not $Reference) {
    Write-Output "RESULT: FAIL - pass -Reference <published .zip or extracted folder>, or -SelfTest"
    exit 1
}
if (-not (Test-Path -LiteralPath $Reference)) {
    Write-Output ("RESULT: FAIL - the reference does not exist: {0}" -f $Reference)
    exit 1
}

# --------------------------------------------------------------- the reference
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("mics-reproducible-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $referenceFolder = $Reference
    if (Test-Path -LiteralPath $Reference -PathType Leaf) {
        $referenceFolder = Join-Path $work "reference"
        Expand-Archive -LiteralPath $Reference -DestinationPath $referenceFolder -Force
        Write-Output ("reference: {0} (extracted)" -f (Resolve-Path -LiteralPath $Reference).Path)
    } else {
        Write-Output ("reference: {0}" -f (Resolve-Path -LiteralPath $Reference).Path)
    }
    if (-not (Test-Path -LiteralPath (Join-Path $referenceFolder "VERSION"))) {
        Write-Output "RESULT: FAIL - the reference has no VERSION file, so it is not a MI CS portable package"
        exit 1
    }
    $versionLine = (Get-Content -LiteralPath (Join-Path $referenceFolder "VERSION") | Select-Object -First 1)
    $Version = ""
    $Arch = ""
    if ($versionLine -match '^MI CS (\S+) \(portable, (x64|arm64)\)$') {
        $Version = $Matches[1]
        $Arch = $Matches[2]
    } else {
        Write-Output ("RESULT: FAIL - the reference VERSION does not name a portable build: {0}" -f $versionLine)
        exit 1
    }

    # ------------------------------------------------------------------ rebuild
    if (-not $Built) {
        if ($NoBuild) {
            Write-Output "RESULT: FAIL - -NoBuild needs -Built <folder>"
            exit 1
        }
        Write-Output ("rebuilding {0} ({1}) from this source ..." -f $Version, $Arch)
        # `-Sign` with no PFX and no thumbprint mints a local self-signed identity
        # (sign.ps1 -SelfSigned), which is how this project has always produced a
        # package (D-035: nothing is bought). It has to be signed, because the
        # release path gates the package on the engine carrying our signer - and a
        # *different* self-signed key is exactly the situation this check is about:
        # the code must match, the signature must not be expected to.
        & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "make-release.ps1") `
            -Reproducible -Sign -Version $Version -Arch $Arch
        if ($LASTEXITCODE -ne 0) {
            Write-Output "RESULT: FAIL - the rebuild did not finish; nothing was compared"
            exit 1
        }
        $Built = Join-Path $root "dist\MICS-portable"
    }
    if (-not (Test-Path -LiteralPath $Built)) {
        Write-Output ("RESULT: FAIL - no rebuilt package at {0}" -f $Built)
        exit 1
    }

    # --------------------------------------------------------------- comparison
    $referenceRows = Get-MicsInventory -Path $referenceFolder
    $builtRows = Get-MicsInventory -Path $Built
    $rows = Compare-MicsInventory -Reference $referenceRows -Candidate $builtRows

    # The engine's own document: when only mics-engine.exe differs, the reason is
    # that MICS_MANIFEST records the hashes of the files as signed. Accept that
    # only if the two documents agree on everything that is not a signature.
    $engineRow = $rows | Where-Object { $_.path -eq "mics-engine.exe" }
    if ($engineRow -and $engineRow.status -eq "differs") {
        $explained = $false
        $why = ""
        try {
            $referenceJson = Read-MicsManifestResource -Exe (Join-Path $referenceFolder "mics-engine.exe")
            $builtJson = Read-MicsManifestResource -Exe (Join-Path $Built "mics-engine.exe")
            if (-not $referenceJson -or -not $builtJson) {
                $why = "one of the two engines carries no MICS_MANIFEST"
            } else {
                $referenceManifest = ConvertFrom-MicsManifest -Json $referenceJson
                $builtManifest = ConvertFrom-MicsManifest -Json $builtJson
                $referencePaths = @($referenceManifest.Files | ForEach-Object { $_.Path })
                $builtPaths = @($builtManifest.Files | ForEach-Object { $_.Path })
                if ($referencePaths.Count -ne $builtPaths.Count) {
                    $why = ("the two documents list {0} and {1} files" -f $referencePaths.Count, $builtPaths.Count)
                } elseif (($referencePaths -join "`n") -ne ($builtPaths -join "`n")) {
                    $why = "the two documents list different files"
                } else {
                    $bad = New-Object System.Collections.Generic.List[string]
                    for ($i = 0; $i -lt $referencePaths.Count; $i++) {
                        $path = $referencePaths[$i]
                        if ($path -match '\.(exe|dll)$') { continue }
                        if ($referenceManifest.Files[$i].Sha256 -ne $builtManifest.Files[$i].Sha256) {
                            $bad.Add($path)
                        }
                    }
                    if ($bad.Count -eq 0) {
                        $explained = $true
                    } else {
                        $why = ("the documents disagree on {0} non-PE file(s): {1}" -f $bad.Count, (($bad | Select-Object -First 3) -join ", "))
                    }
                }
            }
        } catch {
            $why = $_.Exception.Message
        }
        if ($explained) {
            $engineRow.status = "explained"
            $engineRow.detail = "its MICS_MANIFEST records the hashes of the other files as signed"
        } else {
            $engineRow.detail = "same size, different bytes; the manifest does not explain it: $why"
        }
    }

    # VERSION follows the engine, for the same reason and no other: the hash it
    # writes down for `mics-engine.exe` is a content hash, and the content moved
    # when the manifest inside it changed (the document records the other files as
    # signed). Exactly one line may differ - the `engine` one - and every other
    # line, the version and the revision included, must match.
    $versionRow = $rows | Where-Object { $_.path -eq "VERSION" }
    if ($versionRow -and $versionRow.status -eq "differs") {
        $versionCheck = Compare-MicsVersionFile -Reference (Join-Path $referenceFolder "VERSION") -Candidate (Join-Path $Built "VERSION")
        if ($versionCheck.Explained) {
            $versionRow.status = "explained"
            $versionRow.detail = "it records the engine's content hash, which moved with the manifest; no other line differs"
        } else {
            $versionRow.detail = "the engine's content hash moved with the manifest, but that is not the only difference: $($versionCheck.Why)"
        }
    }

    # ------------------------------------------------------------------ report
    $identicalFiles = @($rows | Where-Object { $_.status -eq "identical" -and $_.basis -eq "file" }).Count
    $identicalContent = @($rows | Where-Object { $_.status -eq "identical" -and $_.basis -eq "unsigned" }).Count
    $explainedRows = @($rows | Where-Object { $_.status -eq "explained" }).Count
    $bad = @($rows | Where-Object { $_.status -notin @("identical", "explained") })
    function Plural($n, $one, $many) { if ($n -eq 1) { return "$n $one" } else { return "$n $many" } }
    Write-Output ("rebuild  : {0}  ({1} file(s))" -f (Resolve-Path -LiteralPath $Built).Path, $builtRows.Count)
    Write-Output ("  identical, byte for byte : {0}" -f $identicalFiles)
    Write-Output ("  identical, content only  : {0}  (the Authenticode blob differs by design)" -f $identicalContent)
    if ($explainedRows -gt 0) {
        Write-Output ("  explained                : {0}" -f $explainedRows)
        foreach ($row in ($rows | Where-Object { $_.status -eq "explained" })) {
            Write-Output ("    {0}: {1}" -f $row.path, $row.detail)
        }
    }
    if ($bad.Count -gt 0) {
        Write-Output ("  differs                  : {0}" -f $bad.Count)
        foreach ($row in $bad) {
            Write-Output ("    {0,-40} {1} ({2})" -f $row.path, $row.status, $row.detail)
        }
        Write-Output ("RESULT: FAIL - {0} of {1} file(s) do not match the reference" -f $bad.Count, $builtRows.Count)
        exit 1
    }
    Write-Output ("RESULT: PASS - {0} identical, {1} content-identical, {2} explained, 0 unexpected" -f `
        $identicalFiles, $identicalContent, $explainedRows)
    exit 0
} finally {
    if (-not $Keep) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
    else { Write-Output ("work kept at {0}" -f $work) }
}
