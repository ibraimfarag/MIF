# The archive a user downloads, opened somewhere else altogether, has to come up.
#
# Every other gate in this folder runs the package where it was *built*. The
# failure this one exists for happened after that: the release zip was unpacked
# inside a web root (FlyEnv's `www`), Windows gave that folder a Low integrity
# label, and the engine refused to start from it - quietly, because the app starts
# the engine detached and nobody read its stderr. So this gate unpacks the zip into
# a fresh folder outside the repository and runs the pair from there. Three things
# have to hold: the named pipe answers a `status` call, the engine reports its own
# `package integrity:` line, and a second copy of the package - left in a folder of
# its own and scanned by this engine - is judged and cleared instead of being
# reported as a threat. An `-ExtractTo` inside the repository is refused,
# because a web root or the build tree is the situation under test, not a place to
# test in.

param(
  [string]$Zip = "",
  [string]$ExtractTo = "",
  [int]$WaitMs = 20000,
  [switch]$Keep
)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$proc = $null
$target = $null
$data = $null
$copy = $null

# One JSON-RPC call over the pipe, waiting for the answer with that id.
# Notifications the engine sends meanwhile are skipped, which is why the answer
# is matched on the id rather than read in order.
function Rpc([string]$pipeName, [int]$id, [string]$method, [hashtable]$params, [int]$waitMs) {
  $caller = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
  try {
    $caller.Connect(2000)
    $call = @{ jsonrpc = "2.0"; id = $id; method = $method }
    if ($params) { $call.params = $params }
    $writer = New-Object System.IO.StreamWriter($caller)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($caller)
    $writer.WriteLine(($call | ConvertTo-Json -Compress -Depth 4))
    $deadline = (Get-Date).AddMilliseconds($waitMs)
    while ((Get-Date) -lt $deadline) {
      $line = $reader.ReadLine()
      if (-not $line) { continue }
      if ($line -match ('"id"\s*:\s*' + $id + '(\D|$)')) { return ($line | ConvertFrom-Json) }
    }
    return $null
  } finally {
    $caller.Dispose()
  }
}

function Fail([string]$why, [string[]]$hints = @()) {
  Write-Output "RESULT: FAIL - $why"
  foreach ($hint in $hints) { Write-Output "  - $hint" }
  exit 1
}

function Cleanup {
  if ($proc -and -not $proc.HasExited) { $proc.Kill() }
  if (-not $Keep) {
    foreach ($dir in @($target, $data, $copy)) {
      if ($dir -and (Test-Path -LiteralPath $dir)) {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

# 1. Which archive.
if ($Zip -eq "") {
  $newest = Get-ChildItem -LiteralPath (Join-Path $repo "dist") -Filter "MICS-portable-*.zip" `
    -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $newest) { Fail "no MICS-portable-*.zip under dist" @("run scripts\make-release.ps1 first, or pass -Zip") }
  $Zip = $newest.FullName
}
if (-not (Test-Path -LiteralPath $Zip -PathType Leaf)) { Fail "no archive at $Zip" }

# 2. Where it goes. Outside the repository, always - see the header.
if ($ExtractTo -eq "") {
  $ExtractTo = Join-Path $env:TEMP ("mics-pair-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
}
$target = [System.IO.Path]::GetFullPath($ExtractTo)
$root = [System.IO.Path]::GetFullPath($repo) + [System.IO.Path]::DirectorySeparatorChar
if ($target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
  Fail "-ExtractTo is inside the repository: $target" @("unpack outside it: a web root or the build tree is the situation under test")
}

try {
  # 3. Unpack. The data folder lives outside the package too, so what is left on
  #    disk is exactly what the archive shipped.
  $data = Join-Path $env:TEMP ("mics-pair-data-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
  New-Item -ItemType Directory -Path $target -Force | Out-Null
  New-Item -ItemType Directory -Path $data -Force | Out-Null
  Write-Output "unpacked $([System.IO.Path]::GetFileName($Zip)) into $target"
  Expand-Archive -LiteralPath $Zip -DestinationPath $target -Force

  $engine = Join-Path $target "mics-engine.exe"
  if (-not (Test-Path -LiteralPath $engine)) { Fail "the archive carries no mics-engine.exe" @("nothing to run: the app would report a missing engine") }
  if (-not (Test-Path -LiteralPath (Join-Path $target "mics_app.exe"))) { Fail "the archive carries no mics_app.exe" }

  # 4. Start the engine the way the product does: private pipe, private data
  #    directory, no singleton fight with a running MI CS.
  $pipe = "mics_pair_" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
  $env:MICS_DATA_DIR = $data
  $env:MICS_NO_SINGLETON = "1"
  $env:MICS_NO_GUARD = "1"
  $env:MICS_NO_AUTO_RESUME = "1"
  $env:MICS_PIPE_NAME = "\\.\pipe\$pipe"

  $err = Join-Path $data "engine.err"
  $proc = Start-Process -FilePath $engine -ArgumentList "service" -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $data "engine.out") -RedirectStandardError $err

  # 5. The pipe has to answer. A refusal like "started from a Low-integrity
  #    location" is a sentence at the end of stderr, so that is what a failure
  #    quotes back.
  $client = $null
  $deadline = (Get-Date).AddMilliseconds($WaitMs)
  while (-not $client -and (Get-Date) -lt $deadline) {
    try {
      $candidate = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipe, [System.IO.Pipes.PipeDirection]::InOut)
      $candidate.Connect(300)
      $client = $candidate
    } catch {
      if ($proc.HasExited) { break }
      Start-Sleep -Milliseconds 150
    }
  }

  $verdict = ""
  if ($client) {
    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($client)
    $writer.WriteLine('{"jsonrpc":"2.0","id":1,"method":"status"}')
    $answer = $null
    $read = (Get-Date).AddSeconds(30)
    while (-not $answer -and (Get-Date) -lt $read) {
      $line = $reader.ReadLine()
      if (-not $line) { continue }
      if ($line -like '*"id":1*') { $answer = $line }
    }
    $client.Dispose()
    if ($answer) {
      try {
        $document = $answer | ConvertFrom-Json
        if ($document.result) { $verdict = [string]$document.result.integrity }
      } catch { $verdict = "" }
    }
  }

  # 7. A copy of the package, in a folder of its own, is the product - not a
  #    threat. The rules match our engine because it carries the very strings they
  #    look for, so a scan pointed at a folder holding a second copy reported the
  #    product as HIGH and listed it beside real malware. The copy sits outside
  #    the engine's own directory on purpose: the path test skips a file beside
  #    the engine, so only the certificate test can hold this one back. `scanned`
  #    is read as well, so a copy that was quietly skipped cannot pass for a copy
  #    that was judged and cleared.
  $copy = Join-Path $env:TEMP ("mics-pair-copy-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
  New-Item -ItemType Directory -Path $copy -Force | Out-Null
  Copy-Item -LiteralPath $engine -Destination (Join-Path $copy "mics-engine.exe") -Force

  $started = Rpc $pipe 2 "scan.start" @{ path = $copy; quarantine = $false } 30000
  $jobId = ""
  if ($started -and $started.result) { $jobId = [string]$started.result.job_id }
  if ($jobId -eq "") {
    Fail "the engine started no scan of a copy of its own package" ($tail + @("scan.start over the pipe did not answer with a job_id"))
  }

  $job = $null
  $scanDeadline = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $scanDeadline) {
    $answer = Rpc $pipe 3 "job.get" @{ job_id = $jobId } 30000
    if ($answer -and $answer.result -and $answer.result.job) {
      $job = $answer.result.job
      if (@("done", "failed", "cancelled") -contains $job.state) { break }
    }
    Start-Sleep -Milliseconds 400
  }
  if (-not $job) { Fail "the scan of $copy never reported a state" @("the engine is up and answered status: is the job queue running?") }
  if ($job.state -ne "done") {
    Fail "the scan of a copy of the package ended '$($job.state)'" @([string]$job.error)
  }
  if ([int]$job.scanned -lt 1) {
    Fail "the scan of $copy examined no file at all" @("a copy that was skipped is not a copy that was cleared")
  }
  if ([int]$job.findings_count -ne 0) {
    Fail "a copy of the package was reported as a threat ($($job.findings_count) findings) from $copy" @(
      "its own engine judged it: the signer test is what holds this back, and it did not fire")
  }
  $scanLine = "$($job.scanned) file(s) judged in a copy of the package, $($job.findings_count) findings"

  if ($proc -and -not $proc.HasExited) { $proc.Kill() }
  Start-Sleep -Milliseconds 250

  $tail = @(Get-Content -LiteralPath $err -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 4)

  if (-not $client) {
    $why = if ($proc.HasExited) { "the engine exited before its pipe came up" } else { "the pipe did not answer within $WaitMs ms" }
    Fail "$why, running from $target" ($tail + @("the same folder, run for real: does the engine accept where it was unpacked?"))
  }

  # 6. And it has to call its package whole: a truncated archive that still starts
  #    is the other half of "it runs, so it is fine".
  $log = Join-Path $data "logs\engine.log"
  $detail = ""
  if (Test-Path -LiteralPath $log) {
    $line = Get-Content -LiteralPath $log | Where-Object { $_ -match "package integrity:" } | Select-Object -Last 1
    if ($line) { $detail = ($line -replace "^.*package integrity: ", "").Trim() }
  }
  $whole = ($detail -like "ok*") -or ($verdict -like "ok*")

  if (-not $whole) {
    Fail "the engine answered but did not call its package whole (integrity '$verdict', log '$detail')" ($tail + @("re-run scripts\make-release.ps1 and publish the archive it writes"))
  }

  Write-Output "pipe answered (integrity '$verdict'), package integrity: $detail"
  Write-Output $scanLine
  Write-Output "RESULT: PASS - the published archive runs from $target, outside the repository, calls its package whole, and does not report a copy of itself"
  Cleanup
  exit 0
} catch {
  Cleanup
  Fail "$($_.Exception.Message)" @("at $target")
}
