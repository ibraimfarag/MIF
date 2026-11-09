<#
.SYNOPSIS
  Writes the update manifest (`update.json`) that a release publishes next to its
  portable archive, so a MI CS whose owner never typed a feed can still check for
  updates (D-046).

.DESCRIPTION
  The engine reads `{version, url, sha256, size, notes_en, notes_ar}` from this
  file (`engine/src/update.rs`, `update.check`), and `url` + `sha256` describe the
  ZIP that ships beside it - which is why this runs after the archive exists and
  never before.

  The URL is *built*, not discovered: the release workflow uploads the archive
  under exactly `MICS-portable-<version>-<arch>.zip` to exactly the tag
  `v<version>`, so a manifest that guessed or probed would be worse than none. A
  file whose `url` names something other than the zip it describes would make the
  engine download the wrong bytes and refuse them at the hash - loudly, but late.

  The manifest is written as UTF-8 **without** a byte-order mark: a BOM is legal
  in some JSON readers and a parse error in others, and the engine is the one that
  has to read it.

  Notes are the release page's job to explain, so they default to a pointer at it;
  `-NotesAr` is empty unless somebody passes bilingual text, and an empty note is
  honest about that rather than a machine translation. (Scripts in this repository
  are ASCII, so Arabic notes belong in a file, not in a command line.)

  It checks its own output: the file is re-read, parsed, and compared against the
  archive, so a manifest that does not describe the zip it was given fails here
  instead of shipping.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\update-manifest.ps1 `
    -Zip dist\MICS-portable-0.1.0-x64.zip -Version 0.1.0

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9).
#>
param(
  [Parameter(Mandatory = $true)][string]$Zip,
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Arch = "x64",
  [string]$BaseUrl = "https://github.com/ibraimfarag/MIF/releases/download",
  [string]$NotesEn = "",
  [string]$NotesAr = "",
  [string]$Out
)

$ErrorActionPreference = "Stop"

function Fail([string]$reason) {
  Write-Output "RESULT: FAIL - $reason"
  exit 1
}

if (-not (Test-Path -LiteralPath $Zip)) { Fail "no archive at $Zip" }
if ([string]::IsNullOrWhiteSpace($Version)) { Fail "-Version is empty" }
if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.]+)?$') {
  Fail "-Version '$Version' does not look like a release version"
}

$zip = (Resolve-Path -LiteralPath $Zip).Path
$zipName = Split-Path -Leaf $zip
$expectedName = "MICS-portable-$Version-$Arch.zip"
if ($zipName -ne $expectedName) {
  Fail "the archive is '$zipName' but this version and arch publish '$expectedName'"
}
if (-not $Out) { $Out = Join-Path (Split-Path -Parent $zip) "update.json" }

$sha = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
$size = (Get-Item -LiteralPath $zip).Length
$base = $BaseUrl.TrimEnd('/')
$url = "$base/v$Version/$zipName"
if (-not $NotesEn) { $NotesEn = "MI CS $Version - see the release page for what changed." }

$manifest = [ordered]@{
  version  = $Version
  url      = $url
  sha256   = $sha
  size     = $size
  notes_en = $NotesEn
  notes_ar = $NotesAr
}

# UTF-8 without a BOM (see .DESCRIPTION), and no trailing newline so the file's
# hash is a function of its content alone.
$json = ($manifest | ConvertTo-Json -Depth 3) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false)))

# Read back what was written: the check is on the file, not on the hashtable.
$raw = [System.IO.File]::ReadAllText($Out)
$bytes = [System.IO.File]::ReadAllBytes($Out)
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
  Fail "$Out starts with a UTF-8 BOM"
}
$back = $null
try { $back = $raw | ConvertFrom-Json } catch { Fail "$Out is not JSON: $($_.Exception.Message)" }
foreach ($field in @("version", "url", "sha256", "size", "notes_en", "notes_ar")) {
  if ($back.PSObject.Properties.Name -notcontains $field) { Fail "$Out has no '$field'" }
}
if ($back.sha256 -ne $sha) { Fail "$Out says sha256 $($back.sha256), the archive hashes to $sha" }
if ([int64]$back.size -ne $size) { Fail "$Out says size $($back.size), the archive is $size bytes" }
if ($back.url -ne $url) { Fail "$Out says url $($back.url), expected $url" }
if ($back.version -ne $Version) { Fail "$Out says version $($back.version), expected $Version" }

Write-Output "update manifest: $Out"
Write-Output "  version : $Version ($Arch)"
Write-Output "  url     : $url"
Write-Output "  sha256  : $sha"
Write-Output "  size    : $size"
Write-Output "RESULT: PASS"
exit 0
