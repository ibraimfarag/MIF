<#
.SYNOPSIS
  Measures the ACL of both MI CS pipes, and proves the transport still works.

.DESCRIPTION
  docs/THREAT-MODEL.md states two security descriptors that were measured, not
  assumed. This probe re-measures them on the machine in front of you, because a
  boundary that lives only in a document is a claim:

    1. starts mics-engine.exe in `service` mode on a private pipe name and a
       private data directory (test hooks: MICS_PIPE_NAME, MICS_DATA_DIR,
       MICS_NO_SINGLETON, MICS_NO_GUARD, MICS_NO_AUTO_RESUME);
    2. reads the engine pipe's DACL back with GetSecurityInfo and an SDDL
       conversion, and checks it grants full access to SYSTEM, Administrators and
       the current user - and to nobody else (no Everyone, no ANONYMOUS LOGON,
       no INTERACTIVE);
    3. drives a real JSON-RPC `status` call over that same hardened pipe, so the
       ACL cannot pass by locking the UI's own user out;
    4. reads the mandatory label of both pipes back the same way: Low with
       no-write-up (D-057), because a process below the object's label is refused
       the pipe no matter what the DACL grants it;
    5. starts `mics-engine.exe helper-console` on a private helper pipe and
       measures its ACL too: the documented INTERACTIVE grant, which is the open
       multi-user risk F-2 in the threat model. This probe reports it; it does
       not bless it.

  The DACL is the evidence for "another account is refused". Proving that with a
  second account would need a second account's credentials, which a probe must
  not ask for.

  Exit code 0 = every expectation held; 1 = something measured differently.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-pipe-acl.ps1
  powershell -ExecutionPolicy Bypass -File scripts\verify-pipe-acl.ps1 -EnginePath .\mics-engine.exe

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9). Nothing here touches the real pipes: both processes run on
  private names with a private data directory, so a running MI CS is unaffected.
#>
param(
  [string]$EnginePath = "",
  [string]$PipeName = "mics_engine_acl_verify",
  [string]$HelperPipeName = "mics_helper_acl_verify",
  [int]$SettleMs = 1500,
  [int]$WaitMs = 15000
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

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class MicsPipeAcl {
  const uint READ_CONTROL = 0x00020000;
  const uint SYNCHRONIZE = 0x00100000;
  const uint SHARE_ALL = 3;
  const uint OPEN_EXISTING = 3;
  const int SE_KERNEL_OBJECT = 6;
  const uint DACL_SECURITY_INFORMATION = 4;
  const uint LABEL_SECURITY_INFORMATION = 0x10;

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa,
                                   uint disp, uint flags, IntPtr templ);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern uint GetSecurityInfo(IntPtr h, int type, uint info, out IntPtr owner,
                                     out IntPtr group, out IntPtr dacl, out IntPtr sacl,
                                     out IntPtr sd);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
      IntPtr sd, uint revision, uint info, out IntPtr text, out uint length);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);

  /// The DACL of a pipe as SDDL, or a message that starts with "ERROR:".
  public static string DaclOf(string pipe) { return Of(pipe, DACL_SECURITY_INFORMATION); }

  /// The mandatory label of a pipe as SDDL, or a message that starts with
  /// "ERROR:". READ_CONTROL is enough for this half of the descriptor too, which
  /// is why an unelevated probe can measure it - the same read `icacls` prints
  /// labels with.
  public static string LabelOf(string pipe) { return Of(pipe, LABEL_SECURITY_INFORMATION); }

  static string Of(string pipe, uint what) {
    // READ_CONTROL is what reading a descriptor costs; opening the pipe also
    // completes the server's pending ConnectNamedPipe, which is harmless here.
    IntPtr h = CreateFileW(pipe, READ_CONTROL | SYNCHRONIZE, SHARE_ALL, IntPtr.Zero,
                           OPEN_EXISTING, 0, IntPtr.Zero);
    if (h == new IntPtr(-1)) return "ERROR: CreateFileW " + Marshal.GetLastWin32Error();
    try {
      IntPtr o, g, d, s, sd;
      uint r = GetSecurityInfo(h, SE_KERNEL_OBJECT, what,
                               out o, out g, out d, out s, out sd);
      if (r != 0) return "ERROR: GetSecurityInfo " + r;
      IntPtr text; uint len;
      if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
              sd, 1, what, out text, out len))
        return "ERROR: SDDL conversion " + Marshal.GetLastWin32Error();
      string result = Marshal.PtrToStringUni(text);
      LocalFree(text); LocalFree(sd);
      return result;
    } finally { CloseHandle(h); }
  }
}
'@

function Wait-Pipe([string]$name, [int]$timeoutMs) {
  $deadline = (Get-Date).AddMilliseconds($timeoutMs)
  while ((Get-Date) -lt $deadline) {
    try {
      $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $name, [System.IO.Pipes.PipeDirection]::InOut)
      $client.Connect(500)
      return $client
    } catch { Start-Sleep -Milliseconds 200 }
  }
  return $null
}

function Check([string]$label, [bool]$ok, [string]$detail) {
  $state = if ($ok) { "PASS" } else { "FAIL" }
  Write-Output ("  [{0}] {1,-38} {2}" -f $state, $label, $detail)
  if (-not $ok) { $script:failures.Add($label) }
}

function Expect-Acl([string]$what, [string]$sddl, [bool]$protected, [string[]]$grants, [string[]]$refuses, [int]$aces) {
  if ($sddl -like "ERROR:*") {
    Check "$what DACL is readable" $false $sddl
    return
  }
  Write-Output ("  {0,-12} {1}" -f $what, $sddl)
  if ($protected) {
    Check "$what DACL is protected" ($sddl.StartsWith("D:P(")) "must start with D:P("
  } else {
    Check "$what DACL is the documented one" ($sddl.StartsWith("D:(")) "must start with D:("
  }
  foreach ($ace in $grants) { Check "$what grants $ace" ($sddl -like "*$ace*") "" }
  foreach ($ace in $refuses) { Check "$what refuses $ace" ($sddl -notlike "*$ace*") "" }
  $found = ([regex]::Matches($sddl, "\(A;;")).Count
  Check "$what has exactly $aces ACEs" ($found -eq $aces) "$found found"
}

# The label is the other half of the boundary: the DACL says who, the label says
# at which integrity level. A process below it cannot open the pipe at all, which
# is why both pipes are labelled Low (D-057) - and the reason this reads the
# descriptor back instead of trusting the string that asked for it.
function Expect-Label([string]$what, [string]$label, [string[]]$levels) {
  if ($label -like "ERROR:*") {
    Check "$what label is readable" $false $label
    return
  }
  Write-Output ("  {0,-12} {1}" -f "$what label", $label)
  $ok = $false
  foreach ($level in $levels) { if ($label -like "*$level*") { $ok = $true } }
  # `LW` and the numeric `S-1-16-4096` are the same level, written the two ways
  # the SDDL converter uses; the kernel's own `AI` prefix is not ours to choose.
  Check "$what is Low, no-write-up" $ok "expected one of $($levels -join ', ')"
}

$engine = Resolve-Engine $EnginePath
$scratch = Join-Path $env:TEMP ("mics-pipe-acl-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $scratch | Out-Null
$engineOut = Join-Path $scratch "engine.out"
$engineErr = Join-Path $scratch "engine.err"
$helperOut = Join-Path $scratch "helper.out"
$helperErr = Join-Path $scratch "helper.err"
$helperLog = Join-Path $scratch "priv.log"

$env:MICS_DATA_DIR = $scratch
$env:MICS_NO_SINGLETON = "1"
$env:MICS_NO_GUARD = "1"
$env:MICS_NO_AUTO_RESUME = "1"
$env:MICS_PIPE_NAME = "\\.\pipe\$PipeName"
$env:MICS_HELPER_PIPE = $HelperPipeName
$env:MICS_HELPER_LOG = $helperLog
# These probes run the engine from wherever the build landed. On a checkout whose
# folder carries a Low integrity label the whole process is Low, and the engine
# refuses to serve state below Medium (docs/TODO.md trap 21) - right for the
# product, meaningless for a probe that tests the pipe ACL instead.
$env:MICS_ALLOW_LOW_INTEGRITY = "1"

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$engineProc = $null
$helperProc = $null

Write-Output "engine : $engine"
Write-Output "user   : $user"
Write-Output "scratch: $scratch"

try {
  # Both streams go to files on purpose: Windows PowerShell 5.1 can deadlock when
  # a native command's stderr is redirected into a PowerShell stream, and the
  # engine is chatty on stderr (docs/TODO.md 8.9).
  Write-Output "engine pipe (UI <-> engine):"
  $engineProc = Start-Process -FilePath $engine -ArgumentList "service" -PassThru -NoNewWindow `
    -RedirectStandardOutput $engineOut -RedirectStandardError $engineErr
  $client = Wait-Pipe $PipeName $WaitMs
  if (-not $client) {
    Check "engine pipe accepts a client" $false "nothing connected within $WaitMs ms"
    if (Test-Path $engineErr) { Write-Output "engine stderr:"; Get-Content $engineErr | Select-Object -Last 8 }
  } else {
    Expect-Acl "engine" ([MicsPipeAcl]::DaclOf("\\.\pipe\$PipeName")) $true `
      @("(A;;FA;;;SY)", "(A;;FA;;;BA)", "(A;;FA;;;$user)") @(";;;WD)", ";;;AN)", ";;;IU)") 3
    Expect-Label "engine" ([MicsPipeAcl]::LabelOf("\\.\pipe\$PipeName")) `
      @("(ML;;NW;;;LW)", "(ML;;NW;;;S-1-16-4096)")

    $writer = New-Object System.IO.StreamWriter($client)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($client)
    $writer.WriteLine('{"jsonrpc":"2.0","id":1,"method":"status"}')
    $answer = $null
    $deadline = (Get-Date).AddSeconds(15)
    while (-not $answer -and (Get-Date) -lt $deadline) { $answer = $reader.ReadLine() }
    $client.Dispose()
    Check "the same user still drives the pipe" `
      ($answer -and $answer -like '*"state":"running"*' -and $answer -like '*"version"*') $answer
  }

  Write-Output "helper pipe (engine <-> LocalSystem helper):"
  $helperProc = Start-Process -FilePath $engine -ArgumentList "helper-console" -PassThru -NoNewWindow `
    -RedirectStandardOutput $helperOut -RedirectStandardError $helperErr
  Start-Sleep -Milliseconds $SettleMs
  if ($helperProc.HasExited) {
    Check "helper-console stays up" $false "it exited during startup"
    if (Test-Path $helperErr) { Write-Output "helper stderr:"; Get-Content $helperErr | Select-Object -Last 8 }
  } else {
    Expect-Acl "helper" ([MicsPipeAcl]::DaclOf("\\.\pipe\$HelperPipeName")) $false `
      @("(A;;FA;;;SY)", "(A;;FA;;;BA)", "(A;;FA;;;IU)") @(";;;WD)", ";;;AN)") 3
    Expect-Label "helper" ([MicsPipeAcl]::LabelOf("\\.\pipe\$HelperPipeName")) `
      @("(ML;;NW;;;LW)", "(ML;;NW;;;S-1-16-4096)")
    Write-Output "  note: INTERACTIVE covers every logged-on account, standard users included - threat model F-2, still open"
  }
} finally {
  if ($engineProc -and -not $engineProc.HasExited) { $engineProc.Kill(); [void]$engineProc.WaitForExit(5000) }
  if ($helperProc -and -not $helperProc.HasExited) { $helperProc.Kill(); [void]$helperProc.WaitForExit(5000) }
  Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -eq 0) {
  Write-Output "RESULT: PASS - both pipes carry the ACL and the Low label docs/THREAT-MODEL.md says, and the engine still serves its own user"
  exit 0
}
Write-Output "failures:"
foreach ($f in $failures) { Write-Output "  - $f" }
Write-Output "RESULT: FAIL - a pipe measured differently from the threat model"
exit 1
