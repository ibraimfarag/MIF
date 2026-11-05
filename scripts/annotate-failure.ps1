# Turn a tee'd build log into GitHub annotations, so a failed job names its cause
# without anyone opening the log.
#
# Job logs need a signed-in browser (the public API answers 403 on
# `actions/jobs/{id}/logs`), while annotations reach the check-run API anonymously -
# that is the whole reason this exists. GitHub keeps only the first few annotations
# of a step and drops the rest silently, so this emits three: the RESULT line, the
# case markers, and a short tail.
#
# Usage, from a workflow step that captured its own output:
#
#     & ./scripts/make-release.ps1 -Sign -Arch x64 -Version 0.1.0 *>&1 |
#         Tee-Object -FilePath build/release-x64.txt
#     if ($LASTEXITCODE -ne 0) { ./scripts/annotate-failure.ps1 -Path build/release-x64.txt; exit 1 }

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [int]$TailLines = 12
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Output "::error::no log at $Path - the step failed before it wrote one"
    exit 0
}

$lines = Get-Content -LiteralPath $Path

function Emit([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    # An annotation is one line by definition; keep it well under the API's message
    # limit and flatten the newlines the log carries.
    $flat = ($text -replace '\r?\n', ' | ').Trim()
    if ($flat.Length -gt 3800) { $flat = $flat.Substring(0, 3800) + ' ...' }
    Write-Output "::error:: $flat"
}

$result = $lines | Select-String -Pattern 'RESULT: FAIL' | Select-Object -Last 1
if ($result) { Emit $result.Line } else { Emit 'the step failed without a RESULT line' }

# The markers the three harnesses in this repository actually print: the contract
# harness and the QA report write "  FAIL  <case>", cargo writes a "failures:" block
# and "test result: FAILED", the packaging scripts write FAIL/<verb> lines, and the
# verification harnesses bracket theirs with "[FAIL] <case>".
$cases = $lines |
    Select-String -Pattern '^\s*FAIL\s{2,}|^\s*FAIL\b|\[FAIL\]|^\s+-\s|HARNESS FAILURE|^failures:$|test result: FAILED|is stale|differs at line|did not report a result|not hardened|NOT READY|Flutter [0-9]|FLUTTER_ROOT=|expected|refus|elevated' |
    Select-Object -First 8 | ForEach-Object { $_.Line.Trim() }
if ($cases) { Emit ($cases -join ' | ') }

Emit ('tail: ' + (($lines | Select-Object -Last $TailLines) -join ' | '))
exit 0
