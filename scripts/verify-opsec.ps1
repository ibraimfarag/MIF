<#
.SYNOPSIS
  Counts the build fingerprints in the shipped files and ratchets them down.

.DESCRIPTION
  A release package tells the reader where it was built. rustc records the source
  directory of every dependency it compiles, the Flutter engine carries its own
  strings, and a Dart AOT snapshot keeps the package name - so the engine used to
  name this machine's account 1239 times in `%USERPROFILE%\.cargo\registry\...`.
  That is a privacy leak as much as a fingerprint: it says who built the file and
  which toolchain they used.

  This probe reads the shipped bytes and compares them with
  `qa\opsec-baseline.json`:

    * a **forbidden** string must not appear at all. It is computed here, from
      the account running the probe (the profile path and its leaf directory), so
      the baseline never has to store the very path it forbids. The engine build
      removes it with `--remap-path-prefix` (docs/TODO.md, the fingerprint slice);
    * every **counted** marker (`flutter`, `dart`, `cargo`, `rustc`, `pubspec`)
      may only fall. A count above the baseline is a failure, and a count below
      it is reported so the baseline can be tightened;
    * the set of binary files must be exactly the baseline's, so a new binary has
      to be looked at and given a reason before it ships.

  Counting is a case-insensitive substring count over the whole file, decoded as
  ISO-8859-1 (one byte, one character). That is the definition the 2026-11-01
  baseline was measured with, so the old numbers in `docs/ROADMAP.md` and the new
  ones here are the same quantity.

  `-Measure` prints what it sees and the JSON to paste into the baseline, and
  writes nothing: raising a count is a decision a human records with a reason,
  not something a probe can do to its own allowlist.

  Run by `make-release.ps1` against the staging folder, so a leaking build is
  never packaged. `-Tier release` of `scripts\pipeline.ps1` calls it too (docs/TODO.md, the wiring slice).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-opsec.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-opsec.ps1 -Measure -Path "$env:TEMP\mics-opsec-staging"

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9).
#>
param(
  [string]$Path = "",
  [string]$Baseline = "",
  [switch]$Measure
)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
if ($Path -eq "") { $Path = Join-Path $repo "dist\MICS-portable" }
if ($Baseline -eq "") { $Baseline = Join-Path $repo "qa\opsec-baseline.json" }

# The markers that may only fall. Kept in step with `policy.counted` in the
# baseline by test/opsec_baseline_test.dart, so the two cannot drift apart.
$Counted = @("flutter", "dart", "cargo", "rustc", "pubspec")

$Extensions = @(".exe", ".dll", ".so")
# ISO-8859-1: every byte is one character, and no byte is dropped the way a
# UTF-8 decode would drop the malformed sequences a binary is full of.
$Latin1 = [System.Text.Encoding]::GetEncoding(28591)

if (-not (Test-Path $Path)) {
  Write-Output "RESULT: FAIL - no package at $Path"
  Write-Output "  run scripts\make-release.ps1 first, or pass -Path"
  exit 1
}
$root = (Resolve-Path $Path).Path

# The account that built this package, in the two shapes rustc records:
# `C:\Users\<name>\.cargo\...` (the profile path) and the bare name, which turns
# up in a few panic and assert messages.
$forbidden = New-Object System.Collections.Generic.List[string]
if ($env:USERPROFILE) {
  $forbidden.Add($env:USERPROFILE)
  $leaf = Split-Path $env:USERPROFILE -Leaf
  if ($leaf -and $leaf.Length -ge 4 -and -not $forbidden.Contains($leaf)) { $forbidden.Add($leaf) }
}
if ($env:USERNAME -and $env:USERNAME.Length -ge 4 -and -not $forbidden.Contains($env:USERNAME)) {
  $forbidden.Add($env:USERNAME)
}

function Get-Count([string]$text, [string]$needle) {
  return [regex]::Matches($text, [regex]::Escape($needle), 'IgnoreCase').Count
}

# Every shipped binary, by its path inside the package, sorted so the report and
# the baseline read the same way twice. `-Name` because the provider may return a
# longer (8.3-expanded) path for the folder than it returns for the children, and
# string-cutting one against the other is how a report ends up saying `aging\`.
$files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Name |
    Where-Object { $Extensions -contains ([System.IO.Path]::GetExtension($_)).ToLower() } |
    Sort-Object)

if ($files.Count -eq 0) {
  Write-Output "RESULT: FAIL - no .exe, .dll or .so under $root"
  exit 1
}

$measured = [ordered]@{}
$forbiddenHits = New-Object System.Collections.Generic.List[string]

foreach ($rel in $files) {
  $text = $Latin1.GetString([System.IO.File]::ReadAllBytes((Join-Path $root $rel)))
  $counts = [ordered]@{}
  foreach ($marker in $Counted) {
    $n = Get-Count $text $marker
    if ($n -gt 0) { $counts[$marker] = $n }
  }
  $measured[$rel] = $counts
  foreach ($needle in $forbidden) {
    $n = Get-Count $text $needle
    if ($n -gt 0) { $forbiddenHits.Add("${rel}: $n x '$needle'") }
  }
}

if ($Measure) {
  Write-Output "opsec markers under $root"
  Write-Output ("  {0,-38} {1}" -f "file", ($Counted -join "  "))
  $total = [ordered]@{}
  foreach ($rel in $measured.Keys) {
    $row = $measured[$rel]
    $cells = @()
    foreach ($marker in $Counted) {
      $n = 0
      if ($row.Contains($marker)) { $n = $row[$marker] }
      $cells += ("{0,7}" -f $n)
      if ($n -gt 0) {
        if (-not $total.Contains($marker)) { $total[$marker] = 0 }
        $total[$marker] = $total[$marker] + $n
      }
    }
    Write-Output ("  {0,-38} {1}" -f $rel, ($cells -join "  "))
  }
  Write-Output ""
  Write-Output "forbidden (must be zero):"
  if ($forbiddenHits.Count -eq 0) {
    Write-Output "  none - no shipped file names this machine's account"
  } else {
    foreach ($hit in $forbiddenHits) { Write-Output "  $hit" }
  }
  Write-Output ""
  Write-Output "totals:"
  foreach ($marker in $Counted) {
    $n = 0
    if ($total.Contains($marker)) { $n = $total[$marker] }
    Write-Output ("  {0,-8} {1}" -f $marker, $n)
  }
  Write-Output ""
  Write-Output "paste into qa\opsec-baseline.json (keep every reason a human wrote):"
  foreach ($rel in $measured.Keys) {
    $row = $measured[$rel]
    if ($row.Count -eq 0) { continue }
    Write-Output ("  ""{0}"": {{" -f ($rel -replace '\\', '\\'))
    $parts = @()
    foreach ($marker in $row.Keys) {
      $parts += ("      ""{0}"": {{ ""count"": {1}, ""reason"": """" }}" -f $marker, $row[$marker])
    }
    Write-Output ($parts -join ",`n")
    Write-Output "  },"
  }
  Write-Output ""
  Write-Output "RESULT: MEASURED - nothing was written; a count that rose needs a reason a human writes"
  exit 0
}

# ---------------------------------------------------------------- comparison

if (-not (Test-Path $Baseline)) {
  Write-Output "RESULT: FAIL - no baseline at $Baseline"
  exit 1
}
$baselineJson = Get-Content $Baseline -Raw | ConvertFrom-Json
$baselineFiles = @{}
foreach ($prop in $baselineJson.files.PSObject.Properties) { $baselineFiles[$prop.Name] = $prop.Value }
$policy = @()
if ($baselineJson.policy -and $baselineJson.policy.counted) { $policy = @($baselineJson.policy.counted) }

$failures = New-Object System.Collections.Generic.List[string]
$relaxed = New-Object System.Collections.Generic.List[string]

if (($policy -join ",") -ne ($Counted -join ",")) {
  $failures.Add("the baseline's policy.counted ($($policy -join ', ')) is not this probe's marker list ($($Counted -join ', '))")
}

foreach ($hit in $forbiddenHits) {
  $failures.Add("this machine's account is named in the package: $hit")
}

foreach ($rel in $measured.Keys) {
  if (-not $baselineFiles.ContainsKey($rel)) {
    $failures.Add("$rel is in the package but not in the baseline: look at it, then add it with a reason")
    continue
  }
  $entry = $baselineFiles[$rel]
  $base = @{}
  if ($entry.counts) {
    foreach ($prop in $entry.counts.PSObject.Properties) { $base[$prop.Name] = $prop.Value }
  }
  $row = $measured[$rel]
  foreach ($marker in $Counted) {
    $now = 0
    if ($row.Contains($marker)) { $now = $row[$marker] }
    $was = 0
    $reason = ""
    if ($base.ContainsKey($marker)) {
      $was = [int]$base[$marker].count
      $reason = [string]$base[$marker].reason
    }
    if ($now -gt $was) {
      $failures.Add(("{0}: '{1}' rose from {2} to {3}" -f $rel, $marker, $was, $now))
    } elseif ($now -lt $was -and $now -gt 0) {
      $relaxed.Add(("{0}: '{1}' fell from {2} to {3} - tighten the baseline" -f $rel, $marker, $was, $now))
    }
    if ($now -gt 0 -and $reason.Trim().Length -lt 20) {
      $failures.Add(("{0}: '{1}' is allowlisted without a written reason" -f $rel, $marker))
    }
  }
}
foreach ($rel in $baselineFiles.Keys) {
  if (-not $measured.Contains($rel)) {
    $failures.Add("$rel is in the baseline but not in the package: the baseline is stale")
  }
}

Write-Output "opsec markers under $root"
Write-Output ("  {0,-38} {1}" -f "file", ($Counted -join "  "))
foreach ($rel in $measured.Keys) {
  $row = $measured[$rel]
  $cells = @()
  foreach ($marker in $Counted) {
    $n = 0
    if ($row.Contains($marker)) { $n = $row[$marker] }
    $cells += ("{0,7}" -f $n)
  }
  Write-Output ("  {0,-38} {1}" -f $rel, ($cells -join "  "))
}
if ($relaxed.Count -gt 0) {
  Write-Output "counts that fell (re-measure and tighten the baseline in a commit):"
  foreach ($r in $relaxed) { Write-Output "  - $r" }
}

if ($failures.Count -eq 0) {
  Write-Output ("RESULT: PASS - {0} binaries, no shipped file names this machine's account, and no counted string above the baseline" -f $files.Count)
  exit 0
}
Write-Output "failures:"
foreach ($f in $failures) { Write-Output "  - $f" }
Write-Output "RESULT: FAIL - the package carries a build fingerprint the baseline does not allow"
exit 1