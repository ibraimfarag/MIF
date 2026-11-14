<#
.SYNOPSIS
  Measures what the engine does when it is started from a Low-integrity folder.

.DESCRIPTION
  D-058 is a decision about a folder label, so this probe makes the label itself
  the experiment: it labels a scratch folder Low with icacls, copies
  mics-engine.exe into it, and asks the engine to work from there. Windows gives
  a process the mandatory label of the folder its image sits in, and a Low
  process cannot write Medium state - which the engine must say once, in words
  that name the folder, instead of failing every write with two errors that read
  like unrelated bugs ("attempt to write a readonly database", "installed but
  not answering").

    1. an ordinary folder is the positive control: the same command in a copy
       outside any Low label runs and is not refused (without this, "refused"
       would also be true of a missing binary or a broken path);
    2. from the Low folder, no hatch: the process really is Low (the settings
       layer says so in its own warning), and the engine refuses to start,
       naming the folder it was started from, the two symptoms, the installed
       copy as the way out, and the hatch;
    3. the refusal is an exit code, not just a sentence: the process ends
       non-zero and never reaches the command;
    4. MICS_ALLOW_LOW_INTEGRITY=1 runs the same command from the same folder -
       and the settings warning stays, because the hatch buys the run, not the
       writability;
    5. helper-status is exempt from the guard on purpose: it only reads state and
       it is how a Low run is diagnosed, so it must answer from the Low folder
       without the hatch.

  A copy of the engine and per-run scratch data directories are used, so a
  running MI CS and the real %LOCALAPPDATA%\MICS are untouched.

  Exit code 0 = every expectation held; 1 = something measured differently.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-low-integrity.ps1
  powershell -ExecutionPolicy Bypass -File scripts\verify-low-integrity.ps1 -EnginePath .\mics-engine.exe

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9). Labelling a folder Low needs no administrator; removing the
  scratch folder at the end does the same work the probe did.
#>
param(
  [string]$EnginePath = ""
)

$ErrorActionPreference = "Stop"
$failures = New-Object System.Collections.Generic.List[string]

function Resolve-Engine([string]$path) {
  if ($path) {
    if (-not (Test-Path $path)) { throw "engine not found: $path" }
    return (Resolve-Path $path).Path
  }
  $candidates = @(
    (Join-Path $PSScriptRoot "..\dist\MICS-portable\mics-engine.exe"),
    (Join-Path $PSScriptRoot "..\build\windows\x64\runner\Release\mics-engine.exe"),
    (Join-Path $PSScriptRoot "..\engine\target\release\mics-engine.exe")
  )
  foreach ($c in $candidates) {
    if (Test-Path $c) { return (Resolve-Path $c).Path }
  }
  throw "no mics-engine.exe found - pass -EnginePath"
}

function Check([string]$label, [bool]$ok, [string]$detail) {
  $state = if ($ok) { "PASS" } else { "FAIL" }
  Write-Output ("  [{0}] {1,-40} {2}" -f $state, $label, $detail)
  if (-not $ok) { $script:failures.Add($label) }
}

# One run of the engine, everything it said in one string, and its exit code.
# Start-Process with redirects rather than `&`: the engine logs to stderr, and
# Windows PowerShell 5.1 turns a native command's stderr into a terminating
# error under $ErrorActionPreference = "Stop".
function Invoke-Engine([string]$exe, [string[]]$engineArgs, [string]$dataDir, [bool]$hatch) {
  if ($hatch) { $env:MICS_ALLOW_LOW_INTEGRITY = "1" }
  else { Remove-Item Env:\MICS_ALLOW_LOW_INTEGRITY -ErrorAction SilentlyContinue }
  $env:MICS_DATA_DIR = $dataDir
  $env:MICS_NO_SINGLETON = "1"
  $outFile = Join-Path $dataDir ("out-" + [guid]::NewGuid().ToString("N") + ".txt")
  $errFile = Join-Path $dataDir ("err-" + [guid]::NewGuid().ToString("N") + ".txt")
  $proc = Start-Process -FilePath $exe -ArgumentList $engineArgs -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $outFile -RedirectStandardError $errFile
  $text = (@($outFile, $errFile) | ForEach-Object {
      if (Test-Path $_) { Get-Content $_ -Raw }
    }) -join "`n"
  Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue
  return [pscustomobject]@{ Text = $text; Exit = $proc.ExitCode }
}

$engine = Resolve-Engine $EnginePath
Write-Output "engine: $engine"

$scratch = Join-Path $env:TEMP ("mics-low-verify-" + $PID)
$plain = Join-Path $scratch "plain"
$low = Join-Path $scratch "low"
$data = Join-Path $scratch "data"
New-Item -ItemType Directory -Path $plain, $low, $data -Force | Out-Null
Copy-Item $engine (Join-Path $plain 'mics-engine.exe')
Copy-Item $engine (Join-Path $low 'mics-engine.exe')
# (OI)(CI) so the copied image inherits the label as well as the folder.
icacls $low /setintegritylevel '(OI)(CI)L' | Out-Null

try {
  # 1. positive control: the same command where no folder carries a Low label.
  $ordinary = Invoke-Engine (Join-Path $plain 'mics-engine.exe') @('inventory', '--json') $data $false
  Check "an ordinary folder is not refused" `
    (-not ($ordinary.Text -match 'Low-integrity location')) `
    ("no refusal; engine said " + (($ordinary.Text -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1)))

  # 2. the mechanism the whole decision rests on: the process really is Low.
  $refused = Invoke-Engine (Join-Path $low 'mics-engine.exe') @('inventory', '--json') $data $false
  Check "a Low folder lowers the process" `
    ($refused.Text -match 'Low-integrity process') `
    "the engine's own settings layer reports the level it measured"

  # 3. and it refuses to start, in words that name the folder and the ways out.
  $namesFolder = $refused.Text -match 'mics-engine\.exe'
  $namesHatch = $refused.Text -match 'MICS_ALLOW_LOW_INTEGRITY=1'
  $namesSymptoms = ($refused.Text -match 'readonly database') -and ($refused.Text -match 'not answering')
  Check "the refusal names the folder and the ways out" `
    ($refused.Text -match 'Low-integrity location' -and $namesFolder -and $namesHatch -and $namesSymptoms) `
    ("folder=$namesFolder hatch=$namesHatch symptoms=$namesSymptoms")

  # 4. it is an exit code too, and the command behind it never ran.
  Check "the refused launch ends non-zero" `
    ($refused.Exit -ne 0) ("exit code " + $refused.Exit)

  # 5. the hatch is for a diagnostic probe: same folder, same command, it runs -
  #    with the settings warning still in front of it.
  $hatched = Invoke-Engine (Join-Path $low 'mics-engine.exe') @('inventory', '--json') $data $true
  $started = $hatched.Text -match 'mics_engine: MI CS engine .* starting'
  Check "the hatch runs it anyway" `
    (-not ($hatched.Text -match 'Low-integrity location') -and $started) `
    ("no refusal=$(-not ($hatched.Text -match 'Low-integrity location')) started=$started")

  Check "the hatch keeps the warning" `
    ($hatched.Text -match 'Low-integrity process') `
    "the hatch buys the run, not the writability"

  # 6. the diagnosis path stays open below Medium, which is the point of the
  #    exemption: no hatch, Low folder, and helper-status still answers.
  $helper = Invoke-Engine (Join-Path $low 'mics-engine.exe') @('helper-status', '--json') $data $false
  Check "helper-status is exempt below Medium" `
    (-not ($helper.Text -match 'Low-integrity location')) `
    "the command a Low run is diagnosed with still answers"
}
finally {
  Remove-Item Env:\MICS_ALLOW_LOW_INTEGRITY -ErrorAction SilentlyContinue
  Remove-Item Env:\MICS_DATA_DIR -ErrorAction SilentlyContinue
  Remove-Item Env:\MICS_NO_SINGLETON -ErrorAction SilentlyContinue
  Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -eq 0) {
  Write-Output "RESULT: OK - 6 checks passed (D-058: a Low launch is refused by name, the hatch is a probe's)"
  exit 0
}
Write-Output "failures:"
foreach ($f in $failures) { Write-Output "  - $f" }
Write-Output "RESULT: FAIL - the engine and the Low folder disagree with D-058"
exit 1
