<#
.SYNOPSIS
  Reads the hardening back out of the shipped binaries instead of trusting the
  build flags.

.DESCRIPTION
  "We set /guard:cf" and "the file has Control Flow Guard" are two different
  claims, and only the second one is about the artifact a user runs. This probe
  parses the PE of every binary it is given and reports, per file:

    * the DllCharacteristics bits that decide the mitigation Windows applies:
      HIGH_ENTROPY_VA (0x20), DYNAMICBASE (0x40), NXCOMPAT (0x100) and
      GUARD_CF (0x4000);
    * the load-config GuardFlags, which is where CFG really lives:
      CF_INSTRUMENTED (0x100) and CF_FUNCTION_TABLE_PRESENT (0x400);
    * whether an EH-continuation table is present (CF_LONGJUMP_TABLE_PRESENT,
      0x10000) - it is what makes x64 CFG cover exceptions and not only calls;
    * the CET-compat marker (debug directory type 20, bit 0x1), when the linker
      wrote one;
    * the debug directory: a Release binary that still names a `.pdb` path
      leaks the build machine's layout and carries symbols we did not mean to
      ship.

  Ground truth is the file, not the build system: the script is run against a
  build folder by `make-release.ps1` (so an unhardened binary is never packaged)
  and against the extracted package by `verify-release.ps1`.

  x64 binaries only. `flutter_windows.dll` is the Flutter engine's own prebuilt
  file and is not ours to harden, so it is reported but never failed.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-hardening.ps1 -Path dist\MICS-portable
  powershell -ExecutionPolicy Bypass -File scripts\verify-hardening.ps1 -Path build\windows\x64\runner\Release\mics_app.exe

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9).
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Path,
  # Files that must not be judged: a third-party prebuilt DLL cannot be told to
  # grow CFG, and failing on it would only teach the reader to ignore this probe.
  [string[]]$SkipFile = @("flutter_windows.dll")
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]

# The two bits of a PE that answer "did the toolchain instrument this binary".
$DLLCHAR = [ordered]@{
  HIGH_ENTROPY_VA = 0x0020
  DYNAMICBASE     = 0x0040
  NXCOMPAT        = 0x0100
  GUARD_CF        = 0x4000
}
$GUARDFLAG = [ordered]@{
  CF_INSTRUMENTED          = 0x0100
  CF_FUNCTION_TABLE_PRESENT = 0x0400
  CF_LONGJUMP_TABLE_PRESENT = 0x10000
}

# IMAGE_LOAD_CONFIG_DIRECTORY64.GuardFlags sits at 0x90; the 32-bit structure is
# a different shape, so x86 files are reported as unsupported rather than read
# at the wrong offset.
$LOAD_CONFIG_GUARD_FLAGS_OFFSET = 0x90
$DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20
$CET_COMPAT_BIT = 0x0001

function Read-PeInfo([string]$file) {
  $bytes = [System.IO.File]::ReadAllBytes($file)
  if ($bytes.Length -lt 0x40) { throw "not a PE file (too short)" }
  $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
  if ($peOffset -le 0 -or $peOffset + 0x18 -ge $bytes.Length) { throw "not a PE file (bad e_lfanew)" }
  if ([BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) { throw "not a PE file (no PE\0\0 signature)" }

  $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
  $numberOfSections = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
  $sizeOfOptionalHeader = [BitConverter]::ToUInt16($bytes, $peOffset + 0x14)
  $optional = $peOffset + 0x18
  $magic = [BitConverter]::ToUInt16($bytes, $optional)

  $info = [ordered]@{
    Machine            = ("0x{0:X4}" -f $machine)
    Is64               = ($magic -eq 0x20B)
    DllCharacteristics = [BitConverter]::ToUInt16($bytes, $optional + 0x46)
    GuardFlags         = $null
    CetCompat          = $false
    DebugEntries       = 0
    PdbPath            = ""
  }

  # Section table, for RVA -> file offset.
  $sections = @()
  $sectionStart = $optional + $sizeOfOptionalHeader
  for ($i = 0; $i -lt $numberOfSections; $i++) {
    $s = $sectionStart + ($i * 40)
    if ($s + 40 -gt $bytes.Length) { break }
    $sections += @{
      VirtualAddress = [BitConverter]::ToUInt32($bytes, $s + 12)
      VirtualSize    = [BitConverter]::ToUInt32($bytes, $s + 8)
      RawPointer     = [BitConverter]::ToUInt32($bytes, $s + 20)
      RawSize        = [BitConverter]::ToUInt32($bytes, $s + 16)
    }
  }

  $dataDirs = if ($info.Is64) { $optional + 0x70 } else { $optional + 0x60 }
  $dirCount = [BitConverter]::ToUInt32($bytes, $(if ($info.Is64) { $optional + 0x6C } else { $optional + 0x5C }))

  function Convert-RvaToOffset([uint32]$rva) {
    foreach ($sec in $sections) {
      $span = [Math]::Max($sec.VirtualSize, $sec.RawSize)
      if ($rva -ge $sec.VirtualAddress -and $rva -lt ($sec.VirtualAddress + $span)) {
        return [int]($sec.RawPointer + ($rva - $sec.VirtualAddress))
      }
    }
    return -1
  }

  if ($info.Is64 -and $dirCount -gt 10) {
    $loadConfigRva = [BitConverter]::ToUInt32($bytes, $dataDirs + (10 * 8))
    $loadConfigSize = [BitConverter]::ToUInt32($bytes, $dataDirs + (10 * 8) + 4)
    if ($loadConfigRva -gt 0 -and $loadConfigSize -ge ($LOAD_CONFIG_GUARD_FLAGS_OFFSET + 4)) {
      $off = Convert-RvaToOffset $loadConfigRva
      if ($off -ge 0 -and ($off + $LOAD_CONFIG_GUARD_FLAGS_OFFSET + 4) -le $bytes.Length) {
        $info.GuardFlags = [BitConverter]::ToUInt32($bytes, $off + $LOAD_CONFIG_GUARD_FLAGS_OFFSET)
      }
    }
  }

  if ($dirCount -gt 6) {
    $debugRva = [BitConverter]::ToUInt32($bytes, $dataDirs + (6 * 8))
    $debugSize = [BitConverter]::ToUInt32($bytes, $dataDirs + (6 * 8) + 4)
    if ($debugRva -gt 0 -and $debugSize -ge 28) {
      $debugOff = Convert-RvaToOffset $debugRva
      if ($debugOff -ge 0) {
        $count = [int]($debugSize / 28)
        for ($i = 0; $i -lt $count; $i++) {
          $entry = $debugOff + ($i * 28)
          if ($entry + 28 -gt $bytes.Length) { break }
          $info.DebugEntries++
          $type = [BitConverter]::ToUInt32($bytes, $entry + 12)
          $size = [BitConverter]::ToUInt32($bytes, $entry + 16)
          $ptr = [BitConverter]::ToUInt32($bytes, $entry + 24)
          if ($type -eq $DEBUG_TYPE_EX_DLLCHARACTERISTICS -and $size -ge 2 -and $ptr + 2 -le $bytes.Length) {
            $flags = [BitConverter]::ToUInt16($bytes, $ptr)
            if ($flags -band $CET_COMPAT_BIT) { $info.CetCompat = $true }
          }
          if ($type -eq 2 -and $ptr -lt $bytes.Length) {   # IMAGE_DEBUG_TYPE_CODEVIEW
            $end = $ptr
            while ($end -lt $bytes.Length -and $bytes[$end] -ne 0 -and ($end - $ptr) -lt 512) { $end++ }
            if ($end -gt $ptr) {
              $text = [System.Text.Encoding]::ASCII.GetString($bytes, $ptr, $end - $ptr)
              if ($text -match "\.pdb") { $info.PdbPath = $text }
            }
          }
        }
      }
    }
  }

  return $info
}

function Get-FlagNames([int]$value, $table) {
  $names = @()
  foreach ($key in $table.Keys) { if ($value -band $table[$key]) { $names += $key } }
  if ($names.Count -eq 0) { return "none" }
  return ($names -join "|")
}

function Test-OneBinary([string]$file, [bool]$Required) {
  $leaf = Split-Path $file -Leaf
  Write-Output ("{0} ({1:N0} bytes)" -f $leaf, (Get-Item $file).Length)
  $info = $null
  try { $info = Read-PeInfo $file } catch {
    if ($Required) { $failures.Add("$leaf`: cannot read its PE headers ($($_.Exception.Message))") }
    else { Write-Output "  (skipped: $($_.Exception.Message))" }
    return
  }

  $dll = [int]$info.DllCharacteristics
  Write-Output ("  DllCharacteristics 0x{0:X4}: {1}" -f $dll, (Get-FlagNames $dll $DLLCHAR))
  $guard = if ($null -eq $info.GuardFlags) { "no load-config directory" }
           else { "0x{0:X8}: {1}" -f $info.GuardFlags, (Get-FlagNames ([int]$info.GuardFlags) $GUARDFLAG) }
  Write-Output ("  GuardFlags         {0}" -f $guard)
  Write-Output ("  CET compat         {0}" -f $(if ($info.CetCompat) { "yes" } else { "no marker" }))
  $pdb = if ($info.PdbPath) { $info.PdbPath } else { "none - the binary is stripped" }
  Write-Output ("  debug directory    {0} entr(ies), codeview: {1}" -f $info.DebugEntries, $pdb)

  if (-not $Required) { return }

  foreach ($key in $DLLCHAR.Keys) {
    if (-not ($dll -band $DLLCHAR[$key])) { $failures.Add("$leaf`: DllCharacteristics is missing $key") }
  }
  if ($null -eq $info.GuardFlags) {
    $failures.Add("$leaf`: has no load-config GuardFlags - Control Flow Guard is not on")
  } else {
    foreach ($key in $GUARDFLAG.Keys) {
      if (-not ([int]$info.GuardFlags -band $GUARDFLAG[$key])) { $failures.Add("$leaf`: GuardFlags is missing $key") }
    }
  }
  if ($info.PdbPath) { $failures.Add("$leaf`: still points at a PDB ($($info.PdbPath)) - it is not stripped") }
}

$targets = @()
if (Test-Path $Path -PathType Container) {
  foreach ($name in @("mics_app.exe", "mics-engine.exe", "flutter_windows.dll")) {
    $candidate = Join-Path $Path $name
    if (Test-Path $candidate) { $targets += $candidate }
  }
  if ($targets.Count -eq 0) {
    Write-Output "RESULT: FAIL - no mics_app.exe or mics-engine.exe under $Path"
    exit 1
  }
} else {
  $targets += (Resolve-Path $Path).Path
}

Write-Output "hardening of $Path"
foreach ($file in $targets) {
  $leaf = Split-Path $file -Leaf
  $required = -not ($SkipFile -contains $leaf)
  Test-OneBinary $file $required
  if (-not $required) { Write-Output "  (not judged: third-party prebuilt, see -SkipFile)" }
}

if ($failures.Count -eq 0) {
  Write-Output "RESULT: PASS - every MI CS binary is CFG-instrumented, ASLR/DEP-marked and stripped"
  exit 0
}
Write-Output "failures:"
foreach ($f in $failures) { Write-Output "  - $f" }
Write-Output "RESULT: FAIL - the binaries are not as hardened as the release claims"
exit 1
