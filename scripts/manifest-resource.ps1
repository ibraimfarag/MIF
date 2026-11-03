<#
.SYNOPSIS
  Builds, injects and reads the MICS_MANIFEST resource.

.DESCRIPTION
  The package's integrity manifest (c2, D-025) is one JSON document stored as an
  RT_RCDATA resource named MICS_MANIFEST inside mics-engine.exe:

    {"format":1,"version":"0.1.0","files":[
      {"path":"data\\app.so","bytes":123,"sha256":"ab..."},...]}

  It is not a loose file: a document anyone can edit next to the binaries would
  make the app believe a repackaged copy. The engine's Authenticode signature
  covers the resource bytes, and the engine pins the signer's CN, so a rebuild
  signed with another certificate is visible (docs/DECISIONS.md D-025).

  The engine is never listed in its own manifest (self-reference): its integrity
  is that signature. Paths are relative to the package root, sorted ordinally and
  free of `..`, so both the reader and the verifier hash inside the package only.

  Dot-source this file; it defines the type MicsManifest and:

    Get-MicsManifestFiles      the file list of a folder, in manifest order
    New-MicsManifestJson       that list as the document
    Write-MicsManifestResource inject the document into an exe
    Read-MicsManifestResource  read it back out of an exe
    ConvertFrom-MicsManifest   parse and validate a document

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9). The C# below is compiled by the 5.1 compiler, so nothing
  newer than C# 5 belongs in it.
#>

# The format's contract, read by the engine's self-check, verify-manifest.ps1 and
# the tamper tests: the resource type, its name, and the envelope version.
$script:MicsManifestType = 10
$script:MicsManifestName = "MICS_MANIFEST"
$script:MicsManifestFormat = 1

# The signer the manifest's authenticity rests on (D-025 point 2). The engine
# pins the same name in `EXPECTED_SIGNER_CN`; verify-manifest.ps1 refuses a
# package whose engine is signed by anybody else, and test/package_integrity_test.dart
# fails if the two spellings ever drift apart.
$script:MicsSignerCn = "MI CS Code Signing"

if (-not ("MicsManifest" -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

// The resource carrier of the package manifest. Writing a resource rewrites the
// PE's resource directory, which is why make-release.ps1 signs the engine again
// afterwards: the signature it had no longer covers the file.
public static class MicsManifest {
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern IntPtr BeginUpdateResource(string fileName, bool deleteExistingResources);

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool UpdateResource(IntPtr update, IntPtr type, string name, ushort language, byte[] data, uint size);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool EndUpdateResource(IntPtr update, bool discard);

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern IntPtr LoadLibraryEx(string fileName, IntPtr file, uint flags);

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern IntPtr FindResource(IntPtr module, string name, IntPtr type);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr LoadResource(IntPtr module, IntPtr info);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern uint SizeofResource(IntPtr module, IntPtr info);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr LockResource(IntPtr info);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool FreeLibrary(IntPtr module);
}
'@
}

# LOAD_LIBRARY_AS_DATAFILE: map the exe as data only, so reading its resource
# never runs its code and never needs its dependencies.
$script:MicsManifestDataFile = 0x00000002

# A JSON string literal, escaped by hand: ConvertTo-Json's shape differs between
# PowerShell 5.1 and 7, and this document is a contract the engine parses.
function ConvertTo-MicsJsonString {
  param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

  $builder = New-Object System.Text.StringBuilder
  foreach ($character in $Text.ToCharArray()) {
    switch ($character) {
      '"' { [void]$builder.Append('\"') }
      '\' { [void]$builder.Append('\\') }
      "`b" { [void]$builder.Append('\b') }
      "`f" { [void]$builder.Append('\f') }
      "`n" { [void]$builder.Append('\n') }
      "`r" { [void]$builder.Append('\r') }
      "`t" { [void]$builder.Append('\t') }
      default {
        $code = [int]$character
        if ($code -lt 32 -or $code -gt 126) { [void]$builder.Append(('\u{0:x4}' -f $code)) }
        else { [void]$builder.Append($character) }
      }
    }
  }
  return $builder.ToString()
}

# A path the manifest may carry: relative to the package root, no traversal and no
# root separator. The reader refuses the same shapes, so a document that could
# make it hash outside the package is never written in the first place.
function Assert-MicsManifestPath {
  param([Parameter(Mandatory = $true)][string]$Path)

  if ($Path.Trim().Length -eq 0) { throw "the manifest cannot carry an empty path" }
  if ($Path.StartsWith('\') -or $Path.StartsWith('/')) {
    throw "the manifest path '$Path' starts at a root; paths are relative to the package"
  }
  if ($Path.Contains('..')) {
    throw "the manifest path '$Path' walks out of the package"
  }
}

<#
.SYNOPSIS
  Every file of a package, in manifest order, as path/bytes/sha256 rows.
.DESCRIPTION
  Sorted ordinally by relative path, because that order is part of the format:
  the reader may rely on it, and two runs over the same bytes produce the same
  document. The engine is skipped - it is the container, not a passenger.
#>
function Get-MicsManifestFiles {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$Skip = "mics-engine.exe"
  )

  if (-not (Test-Path -LiteralPath $Path)) { throw "no package to describe at $Path" }
  $root = (Resolve-Path -LiteralPath $Path).Path

  # -Name, then a join, rather than cutting the root off FullName: the provider
  # may hand back a longer (8.3-expanded) path for the folder than for a child.
  $paths = New-Object System.Collections.Generic.List[string]
  foreach ($name in Get-ChildItem -LiteralPath $root -Recurse -File -Name) {
    if ($name -ieq $Skip) { continue }
    Assert-MicsManifestPath -Path $name
    $paths.Add($name)
  }
  $paths.Sort([System.StringComparer]::Ordinal)

  $rows = New-Object System.Collections.Generic.List[object]
  foreach ($relative in $paths) {
    $full = Join-Path $root $relative
    $rows.Add([pscustomobject]@{
        Path   = $relative
        Bytes  = (Get-Item -LiteralPath $full).Length
        Sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
      })
  }
  return , $rows
}

<#
.SYNOPSIS
  The manifest document for a file list, as the bytes that go in the resource.
#>
function New-MicsManifestJson {
  param(
    [Parameter(Mandatory = $true)][object[]]$Files,
    [Parameter(Mandatory = $true)][string]$Version
  )

  if ($Files.Count -eq 0) { throw "a manifest with no files describes nothing" }
  $builder = New-Object System.Text.StringBuilder
  [void]$builder.Append('{"format":' + $script:MicsManifestFormat)
  [void]$builder.Append(',"version":"' + (ConvertTo-MicsJsonString -Text $Version) + '"')
  [void]$builder.Append(',"files":[')
  $first = $true
  foreach ($file in $Files) {
    Assert-MicsManifestPath -Path ([string]$file.Path)
    if (-not $first) { [void]$builder.Append(',') }
    $first = $false
    [void]$builder.Append('{"path":"' + (ConvertTo-MicsJsonString -Text ([string]$file.Path)) + '"')
    [void]$builder.Append(',"bytes":' + [int64]$file.Bytes)
    [void]$builder.Append(',"sha256":"' + ([string]$file.Sha256).ToLowerInvariant() + '"}')
  }
  [void]$builder.Append(']}')
  return $builder.ToString()
}

<#
.SYNOPSIS
  Injects the document as MICS_MANIFEST into an executable.
.DESCRIPTION
  Writing a resource rewrites the PE, so the file's Authenticode signature is no
  longer valid afterwards: the caller signs it again (docs/DECISIONS.md D-025).
#>
function Write-MicsManifestResource {
  param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Json
  )

  if (-not (Test-Path -LiteralPath $Exe)) { throw "no executable to inject into at $Exe" }
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
  $update = [MicsManifest]::BeginUpdateResource((Resolve-Path -LiteralPath $Exe).Path, $false)
  if ($update -eq [IntPtr]::Zero) {
    throw ("BeginUpdateResource failed for {0} (win32 {1})" -f $Exe, [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
  }
  $written = $false
  try {
    $written = [MicsManifest]::UpdateResource($update, [IntPtr]$script:MicsManifestType, $script:MicsManifestName, 0, $bytes, [uint32]$bytes.Length)
    if (-not $written) {
      throw ("UpdateResource failed for {0} (win32 {1})" -f $Exe, [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
  } finally {
    # Committing when the write succeeded and discarding when it did not: a failed
    # injection must not leave a half-rewritten resource directory behind.
    if (-not [MicsManifest]::EndUpdateResource($update, (-not $written))) {
      if ($written) {
        throw ("EndUpdateResource failed for {0} (win32 {1})" -f $Exe, [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
      }
    }
  }
}

<#
.SYNOPSIS
  The manifest document inside an executable, or $null when it carries none.
#>
function Read-MicsManifestResource {
  param([Parameter(Mandatory = $true)][string]$Exe)

  if (-not (Test-Path -LiteralPath $Exe)) { throw "no executable to read at $Exe" }
  $module = [MicsManifest]::LoadLibraryEx((Resolve-Path -LiteralPath $Exe).Path, [IntPtr]::Zero, $script:MicsManifestDataFile)
  if ($module -eq [IntPtr]::Zero) {
    throw ("LoadLibraryEx failed for {0} (win32 {1})" -f $Exe, [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
  }
  try {
    $info = [MicsManifest]::FindResource($module, $script:MicsManifestName, [IntPtr]$script:MicsManifestType)
    if ($info -eq [IntPtr]::Zero) { return $null }
    $size = [MicsManifest]::SizeofResource($module, $info)
    if ($size -eq 0) { return $null }
    $handle = [MicsManifest]::LoadResource($module, $info)
    if ($handle -eq [IntPtr]::Zero) {
      throw ("LoadResource failed for {0} (win32 {1})" -f $Exe, [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $pointer = [MicsManifest]::LockResource($handle)
    if ($pointer -eq [IntPtr]::Zero) {
      throw ("LockResource failed for {0} (win32 {1})" -f $Exe, [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $buffer = New-Object byte[] ([int]$size)
    [System.Runtime.InteropServices.Marshal]::Copy($pointer, $buffer, 0, [int]$size)
    return [System.Text.Encoding]::UTF8.GetString($buffer)
  } finally {
    [void][MicsManifest]::FreeLibrary($module)
  }
}

<#
.SYNOPSIS
  Parses and validates a manifest document.
.DESCRIPTION
  Throws on anything the format does not allow, so a caller never verifies
  against a document it only half understands: wrong envelope, no files, a
  traversal path, a count or a hash that is not whole, a list that is not sorted
  ordinally, or a duplicate path.
#>
function ConvertFrom-MicsManifest {
  param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Json)

  if ($Json.Trim().Length -eq 0) { throw "the manifest is empty" }
  try {
    $document = $Json | ConvertFrom-Json
  } catch {
    throw "the manifest is not JSON: $($_.Exception.Message)"
  }
  if ([int]$document.format -ne $script:MicsManifestFormat) {
    throw ("the manifest says format {0}, this reader speaks {1}" -f $document.format, $script:MicsManifestFormat)
  }
  $version = [string]$document.version
  if ($version.Trim().Length -eq 0) { throw "the manifest names no version" }

  $files = New-Object System.Collections.Generic.List[object]
  $previous = $null
  foreach ($entry in @($document.files)) {
    $path = [string]$entry.path
    Assert-MicsManifestPath -Path $path
    if ($null -ne $previous) {
      $order = [System.StringComparer]::Ordinal.Compare([string]$previous, $path)
      if ($order -eq 0) { throw "the manifest lists '$path' twice" }
      if ($order -gt 0) { throw "the manifest lists '$path' after '$previous': the paths are not sorted" }
    }
    $previous = $path
    $bytes = [int64]$entry.bytes
    if ($bytes -lt 0) { throw "the manifest gives '$path' a negative size" }
    $hash = ([string]$entry.sha256).Trim()
    if ($hash -notmatch '^[0-9a-fA-F]{64}$') { throw "the manifest gives '$path' no SHA-256" }
    $files.Add([pscustomobject]@{ Path = $path; Bytes = $bytes; Sha256 = $hash.ToLowerInvariant() })
  }
  if ($files.Count -eq 0) { throw "the manifest lists no files" }

  return [pscustomobject]@{ Format = $script:MicsManifestFormat; Version = $version; Files = $files }
}
