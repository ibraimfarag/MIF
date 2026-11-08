<#
.SYNOPSIS
    The parts of a release a second build needs in order to be comparable with
    the first: one timestamp, one inventory, one hash per file, and a ZIP whose
    bytes do not depend on the clock.

.DESCRIPTION
    F-11 in docs/THREAT-MODEL.md is the row this file serves. With the certificate
    not purchased (D-035) the load-bearing claim is that a stranger can rebuild
    the published package from this source and compare it, so a release build must
    stop reading the wall clock and the comparison must know which differences are
    real and which are the signature:

      * Get-MicsBuildTime      the one timestamp a reproducible build uses. By
                               default it is the committer date of the revision
                               being built (`SOURCE_DATE_EPOCH`, the reproducible
                               -builds convention), never `Get-Date`.
      * Get-MicsInventory      path, size and SHA-256 of every file in a folder,
                               in ordinal path order - the same list the package
                               carries about itself in MICS_MANIFEST.
      * Get-MicsUnsignedHash   a PE's SHA-256 with the Authenticode blob, the
                               optional-header checksum and the security data
                               directory taken out. A signed and an unsigned copy
                               of the same build share this hash; signing is not
                               reproducible (it embeds a timestamp and a random
                               RSA signature), so this is the hash a rebuild can
                               be compared on.
      * New-MicsDeterministicZip  a ZIP written from a sorted file list with a
                               fixed timestamp per entry, so the archive bytes are
                               a function of the content and not of the build
                               machine's clock.
      * Compare-MicsInventory  reference against candidate, row by row, with the
                               reason each row matched or did not.

.NOTES
    ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
    docs/TODO.md 8.9). Dot-source this file; it defines the functions above.
#>

# The one place the reproducible-build convention is read. Explicit -BuildTime
# wins, then SOURCE_DATE_EPOCH (seconds since the Unix epoch, as the reproducible
# -builds project defines it), then the revision's own committer date. A tree
# without git or without a commit is not reproducible and says so.
function Get-MicsBuildTime {
    [CmdletBinding()]
    [OutputType([DateTimeOffset])]
    param(
        [string]$Repo = "",
        [string]$BuildTime = ""
    )
    if ($BuildTime) {
        $parsed = [DateTimeOffset]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                  [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if (-not [DateTimeOffset]::TryParse($BuildTime,
                [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
            throw "-BuildTime is not a date: '$BuildTime' (use ISO 8601, e.g. 2026-11-08T13:54:33+02:00)"
        }
        return $parsed
    }
    if ($env:SOURCE_DATE_EPOCH) {
        $seconds = [int64]0
        if (-not [int64]::TryParse($env:SOURCE_DATE_EPOCH, [ref]$seconds)) {
            throw "SOURCE_DATE_EPOCH is not a number of seconds: '$($env:SOURCE_DATE_EPOCH)'"
        }
        return ([DateTimeOffset]::new(1970, 1, 1, 0, 0, 0, [TimeSpan]::Zero)).AddSeconds($seconds)
    }
    if (-not $Repo) {
        throw "no build time: pass -BuildTime, set SOURCE_DATE_EPOCH, or pass -Repo so the revision's date can be read"
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "no build time: git is not on PATH, so the revision's committer date cannot be read; pass -BuildTime or set SOURCE_DATE_EPOCH"
    }
    $iso = @(& git -C $Repo log -1 --format=%cI HEAD 2>$null) | Select-Object -First 1
    if (-not $iso) {
        throw "no build time: '$Repo' has no commit to take a date from; pass -BuildTime or set SOURCE_DATE_EPOCH"
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($iso.Trim(),
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        throw "git returned a date this script cannot read: '$iso'"
    }
    return $parsed
}

# SHA-256 as lowercase hex, the spelling the manifest, SHA256SUMS and the docs use.
function Get-MicsSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# The PE hash a rebuild can match: the Authenticode blob is appended after the
# sections and three header fields change when a file is signed (the checksum, the
# security directory's offset and its size), so all four are taken out before
# hashing. A file that is not a PE, or a PE that is not signed, hashes whole -
# which is what makes signed and unsigned copies comparable on one number.
function Get-MicsUnsignedHash {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $len = $bytes.Length
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        if ($len -lt 0x40) { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($peOffset -le 0 -or ($peOffset + 0x18) -ge $len) { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }
        if ([BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }
        $optOffset = $peOffset + 0x18
        if (($optOffset + 0x70) -ge $len) { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }
        $magic = [BitConverter]::ToUInt16($bytes, $optOffset)
        # CheckSum is at optional-header offset 64 in both PE32 and PE32+.
        $checkSumOffset = $optOffset + 64
        $pe32 = $magic -eq 0x10B
        if ($pe32) { $dataDirOffset = $optOffset + 96; $dirCountOffset = $optOffset + 92 }
        elseif ($magic -eq 0x20B) { $dataDirOffset = $optOffset + 112; $dirCountOffset = $optOffset + 108 }
        else { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }
        if (($dataDirOffset + 40) -ge $len) { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }
        $dirCount = [BitConverter]::ToUInt32($bytes, $dirCountOffset)
        # Data directory index 4 is the certificate table.
        $securityOffset = $dataDirOffset + (4 * 8)
        $blob = [BitConverter]::ToUInt32($bytes, $securityOffset)
        $blobSize = [BitConverter]::ToUInt32($bytes, $securityOffset + 4)
        $signed = ($dirCount -gt 4) -and ($blob -gt 0) -and ($blobSize -gt 0) -and ($blob -lt $len)
        if (-not $signed) { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "") }

        for ($i = 0; $i -lt 4; $i++) { $bytes[$checkSumOffset + $i] = 0 }
        for ($i = 0; $i -lt 8; $i++) { $bytes[$securityOffset + $i] = 0 }
        $digest = $sha.ComputeHash($bytes, 0, [int]$blob)
        return (($digest | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally { $sha.Dispose() }
}

# One row per file: the package's own way of describing itself (manifest-resource.ps1
# writes the same three fields into MICS_MANIFEST). `payload` is the same SHA-256 for
# a signed and an unsigned copy of a PE; `sha256` is the file exactly as it sits on
# disk. Comparing a rebuild to a published package needs both.
function Get-MicsInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$NoPayload
    )
    $root = (Resolve-Path -Path $Path).Path
    $rows = @{}
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($file in (Get-ChildItem -Path $root -Recurse -File)) {
        $relative = $file.FullName.Substring($root.Length + 1)
        $names.Add($relative)
        $row = [pscustomobject]@{
            path    = $relative
            bytes   = $file.Length
            sha256  = Get-MicsSha256 -Path $file.FullName
            payload = ""
        }
        if (-not $NoPayload -and $file.Extension -match '^\.(exe|dll)$') {
            $row.payload = Get-MicsUnsignedHash -Path $file.FullName
        }
        $rows[$relative] = $row
    }
    $sorted = $names.ToArray()
    [Array]::Sort($sorted, [System.StringComparer]::Ordinal)
    return @($sorted | ForEach-Object { $rows[$_] })
}

# A ZIP whose bytes are a function of the content, not of the clock or of the
# folder's timestamps: entries are added in ordinal path order, with forward
# slashes, and every entry carries the same fixed timestamp. Compress-Archive
# stores each file's own LastWriteTime, so the same tree zipped twice differs.
function New-MicsDeterministicZip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Timestamp,
        [ValidateSet("Optimal", "Fastest", "NoCompression")]
        [string]$Level = "Optimal"
    )
    Add-Type -AssemblyName System.IO.Compression | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

    $root = (Resolve-Path -Path $Source).Path
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($file in (Get-ChildItem -Path $root -Recurse -File)) {
        $names.Add($file.FullName.Substring($root.Length + 1).Replace('\', '/'))
    }
    $sorted = $names.ToArray()
    [Array]::Sort($sorted, [System.StringComparer]::Ordinal)

    # The DOS timestamp an entry stores is the clock face of the value handed to
    # LastWriteTime; passing the instant at offset zero keeps that clock face the
    # same on every machine, whatever zone the build runs in. The format stores
    # seconds in two-second steps, so the value is truncated here rather than
    # silently by the writer (measured: 11:54:33 comes back as 11:54:32).
    $evenTicks = [int64]([math]::Floor($Timestamp.UtcDateTime.Ticks / 20000000) * 20000000)
    $stamp = [DateTimeOffset]::new($evenTicks, [TimeSpan]::Zero)
    $target = [System.IO.File]::Open($Destination, [System.IO.FileMode]::Create)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($target, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($name in $sorted) {
                $onDisk = Join-Path $root ($name.Replace('/', '\'))
                $entry = $zip.CreateEntry($name, [System.IO.Compression.CompressionLevel]::$Level)
                $entry.LastWriteTime = $stamp
                $entryStream = $entry.Open()
                try {
                    # Named `$reader`, not `$source`: PowerShell variables are
                    # case-insensitive, so a local `$source` would be the
                    # `$Source` parameter itself.
                    $reader = [System.IO.File]::OpenRead($onDisk)
                    try { $reader.CopyTo($entryStream) } finally { $reader.Dispose() }
                } finally { $entryStream.Dispose() }
            }
        } finally { $zip.Dispose() }
    } finally { $target.Dispose() }
}

# Reference (what was published) against candidate (what was just built). A row is
# `identical` when the file hashes match, `identical/unsigned` when only the PE
# payload does - the signature is the documented non-reproducible part - and
# `differs` otherwise. Returns the rows so a caller can print them or fail on them.
function Compare-MicsInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Reference,
        [Parameter(Mandatory = $true)][object[]]$Candidate
    )
    $index = @{}
    foreach ($row in $Reference) { $index[$row.path] = $row }
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($candidateRow in $Candidate) {
        $referenceRow = $index[$candidateRow.path]
        if ($null -eq $referenceRow) {
            $result.Add([pscustomobject]@{ path = $candidateRow.path; status = "added"; basis = ""; detail = "not in the reference" })
            continue
        }
        $index.Remove($candidateRow.path)
        if ($referenceRow.bytes -ne $candidateRow.bytes) {
            $result.Add([pscustomobject]@{ path = $candidateRow.path; status = "differs"; basis = ""; detail = ("size {0} -> {1}" -f $referenceRow.bytes, $candidateRow.bytes) })
        } elseif ($referenceRow.sha256 -eq $candidateRow.sha256) {
            $result.Add([pscustomobject]@{ path = $candidateRow.path; status = "identical"; basis = "file"; detail = $candidateRow.sha256 })
        } elseif ($referenceRow.payload -and $referenceRow.payload -eq $candidateRow.payload) {
            $result.Add([pscustomobject]@{ path = $candidateRow.path; status = "identical"; basis = "unsigned"; detail = $candidateRow.payload })
        } else {
            $result.Add([pscustomobject]@{ path = $candidateRow.path; status = "differs"; basis = ""; detail = "same size, different bytes" })
        }
    }
    foreach ($leftover in $index.Values) {
        $result.Add([pscustomobject]@{ path = $leftover.path; status = "missing"; basis = ""; detail = "in the reference only" })
    }
    $sorted = @($result | Sort-Object -Property path)
    return $sorted
}

# `VERSION` is the one text file whose bytes follow the signature, so a signed
# published package and an unsigned rebuild of the same revision differ in it. It
# records the engine's content hash, and the engine's content moves when
# `MICS_MANIFEST` inside it writes down the other files as *signed* rather than as
# built (F-11, docs/REPRODUCIBLE.md). That makes exactly one line - the `engine`
# one - differ. This decides whether that is genuinely all that differs, and
# names the lines when it is not. It never says "identical": the caller only asks
# about two files whose bytes already differ.
function Compare-MicsVersionFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Reference,
        [Parameter(Mandatory = $true)][string]$Candidate
    )
    $referenceLines = @(Get-Content -LiteralPath $Reference)
    $candidateLines = @(Get-Content -LiteralPath $Candidate)
    if ($referenceLines.Count -ne $candidateLines.Count) {
        return [pscustomobject]@{ Explained = $false; Why = ("the two files have {0} and {1} lines" -f $referenceLines.Count, $candidateLines.Count) }
    }
    $other = New-Object System.Collections.Generic.List[string]
    $engineLines = 0
    for ($i = 0; $i -lt $referenceLines.Count; $i++) {
        if ($referenceLines[$i] -ceq $candidateLines[$i]) { continue }
        # Case-sensitive on purpose: the comparison is about a lowercase hex hash
        # in a file this project writes, not about matching a user's input.
        if ($i -gt 0 -and
            $referenceLines[$i] -cmatch '^engine\s+[0-9a-f]{64}\s*$' -and
            $candidateLines[$i] -cmatch '^engine\s+[0-9a-f]{64}\s*$') {
            $engineLines++
            continue
        }
        $other.Add(("line {0}" -f ($i + 1)))
    }
    if ($other.Count -gt 0) {
        return [pscustomobject]@{
            Explained = $false
            Why       = ("lines that are not the engine hash differ: {0}" -f (($other | Select-Object -First 3) -join ", "))
        }
    }
    if ($engineLines -eq 0) {
        return [pscustomobject]@{ Explained = $false; Why = "the bytes differ but no line does (line endings?)" }
    }
    return [pscustomobject]@{
        Explained = $true
        Why       = "only the engine's recorded content hash differs, and the engine moved with its manifest"
    }
}
