<#
.SYNOPSIS
  Proves a real MI CS notification card reached the desktop (not just "no
  exception thrown").

.DESCRIPTION
  The engine shows alerts through the WinRT toast platform. "Show() returned
  Ok" is not proof that a card appeared: a stale binary once reported success
  while the platform rejected every alert with a package-identity error, and a
  regression can silence the card without failing the call.

  So this probe reads the evidence Windows keeps when a toast is really shown:

    1. the AUMID's notification history is cleared first, then the card is
       triggered, then the history is read back and its text printed - a toast
       lands in the history only when the platform accepted and displayed it;
    2. optionally, the live notification window is read out of the UI
       Automation tree while the card is still above the taskbar.

  Exit code 0 = the card was observed; 1 = nothing appeared (with the reason).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\verify-toast.ps1
  powershell -ExecutionPolicy Bypass -File scripts\verify-toast.ps1 -ExpectText "test notification" -Shot _screens\p7-toast.png

  # Read the cards an already-running engine produced (scan/guard events):
  powershell -ExecutionPolicy Bypass -File scripts\verify-toast.ps1 -HistoryOnly -ExpectText "Threat found"

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI, so
  a stray em dash turns into mojibake and breaks parsing (see docs/TODO.md 8.9).
#>
param(
  [string]$EnginePath = "",
  [string]$Aumid = "MICS",
  [string]$ExpectText = "",
  [string]$Shot = "",
  [int]$SettleMs = 1500,
  [switch]$NoClear,
  [switch]$HistoryOnly
)

$ErrorActionPreference = "Stop"

function Resolve-Engine {
  param([string]$Explicit)
  if ($Explicit) { return (Resolve-Path $Explicit).Path }
  $root = Split-Path -Parent $PSScriptRoot
  $candidates = @(
    (Join-Path $root "dist\MICS-portable\mics-engine.exe"),
    (Join-Path $root "build\windows\x64\runner\Release\mics-engine.exe"),
    (Join-Path $env:TEMP "mics-target\debug\mics-engine.exe")
  )
  foreach ($c in $candidates) { if (Test-Path $c) { return (Resolve-Path $c).Path } }
  throw "mics-engine.exe not found - pass -EnginePath"
}

# WinRT projection needs both namespaces loaded, otherwise Content.GetXml()
# silently resolves to nothing.
function Initialize-ToastApi {
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
}

function Get-CardText {
  $history = [Windows.UI.Notifications.ToastNotificationManager]::History.GetHistory($Aumid)
  $cards = @()
  foreach ($t in $history) {
    $text = ""
    try { $text = (([xml]$t.Content.GetXml()).toast.visual.binding.text -join " | ") } catch { }
    $cards += $text
  }
  return @($cards)
}

# The window above the taskbar, read from the live UI Automation tree.
function Get-LiveToastWindow {
  Add-Type -AssemblyName UIAutomationClient
  Add-Type -AssemblyName UIAutomationTypes
  $found = @()
  $root = [System.Windows.Automation.AutomationElement]::RootElement
  $kids = $root.FindAll([System.Windows.Automation.TreeScope]::Children,
    [System.Windows.Automation.Condition]::TrueCondition)
  foreach ($w in $kids) {
    $cls = ""; $name = ""
    try { $cls = $w.Current.ClassName; $name = $w.Current.Name } catch { continue }
    if ($cls -notlike "*CoreWindow*" -and $name -notlike "*otification*" -and $name -notlike "*MI CS*") { continue }
    $texts = @()
    $desc = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants,
      [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($d in $desc) {
      try { if ($d.Current.Name) { $texts += $d.Current.Name } } catch { }
    }
    if ($texts.Count -gt 0) {
      $found += [PSCustomObject]@{ Class = $cls; Window = $name; Text = ($texts -join " | ") }
    }
  }
  return @($found)
}

$engine = Resolve-Engine $EnginePath
Initialize-ToastApi

if ($HistoryOnly) {
  # Read what an engine that is already running produced (scan/guard/firewall
  # events); nothing is cleared, so the caller decides the window.
  Write-Output "aumid  : $Aumid (history only)"
  $cards = Get-CardText
  Write-Output "cards found  : $($cards.Count)"
  foreach ($c in $cards) { Write-Output "  CARD: $c" }
  $ok = $cards.Count -gt 0
  if ($ExpectText) {
    $hit = @($cards | Where-Object { $_ -like "*$ExpectText*" }).Count -gt 0
    if (-not $hit) { Write-Warning "expected text '$ExpectText' not found in the card" }
    $ok = $ok -and $hit
  }
  if ($ok) { Write-Output "RESULT: PASS - the card is in the notification history"; exit 0 }
  Write-Output "RESULT: FAIL - no matching card"; exit 1
}

Write-Output "engine : $engine"
Write-Output "aumid  : $Aumid"

if (-not $NoClear) {
  [Windows.UI.Notifications.ToastNotificationManager]::History.Clear($Aumid)
  Write-Output "history: cleared (so any card found afterwards is the one under test)"
}

$dataDir = Join-Path $env:TEMP ("mics-toast-verify-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$stdin = Join-Path $dataDir "in.jsonl"
[System.IO.File]::WriteAllText($stdin,
  '{"jsonrpc":"2.0","id":1,"method":"notify.test"}' + "`n",
  (New-Object System.Text.UTF8Encoding($false)))

$env:MICS_DATA_DIR = $dataDir
$env:MICS_NO_SINGLETON = "1"
$env:MICS_NO_GUARD = "1"
# This probe runs the engine from wherever the build landed. On a checkout whose
# folder carries a Low integrity label the whole process is Low, and the engine
# refuses to serve state below Medium (docs/TODO.md trap 21) - right for the
# product, meaningless for a probe that tests something else.
$env:MICS_ALLOW_LOW_INTEGRITY = "1"
$stdout = Join-Path $dataDir "out.json"
$stderr = Join-Path $dataDir "err.txt"
$proc = Start-Process -FilePath $engine -ArgumentList "serve" `
  -RedirectStandardInput $stdin -RedirectStandardOutput $stdout `
  -RedirectStandardError $stderr -PassThru -NoNewWindow
Start-Sleep -Milliseconds $SettleMs

$live = Get-LiveToastWindow
if ($Shot) {
  Add-Type -AssemblyName System.Drawing
  Add-Type -AssemblyName System.Windows.Forms
  $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
  $bmp = New-Object System.Drawing.Bitmap($b.Width, $b.Height)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
  $bmp.Save($Shot, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Output "screenshot   : $Shot"
}

Start-Sleep -Milliseconds 1200
if ($proc -and -not $proc.HasExited) { $proc.Kill() }
$response = (Get-Content $stdout -ErrorAction SilentlyContinue) -join " "
Write-Output "rpc response : $response"
$logLine = (Get-Content $stderr -ErrorAction SilentlyContinue |
  Select-String "notify.test" | Select-Object -Last 1).Line
if ($logLine) { Write-Output "engine log   : $logLine" }

$cards = Get-CardText
Write-Output "cards found  : $($cards.Count)"
foreach ($c in $cards) { Write-Output "  CARD: $c" }

$ok = $cards.Count -gt 0
if (-not $ok) { Write-Warning "nothing reached the desktop for AUMID '$Aumid'" }

if ($live.Count -gt 0) {
  Write-Output "live window  :"
  foreach ($l in $live) { Write-Output "  [$($l.Class)] $($l.Window) -> $($l.Text)" }
} else {
  Write-Output "live window  : not captured at +$SettleMs ms (history is the primary proof)"
}

if ($ExpectText) {
  $hit = @($cards | Where-Object { $_ -like "*$ExpectText*" }).Count -gt 0
  if (-not $hit) { Write-Warning "expected text '$ExpectText' not found in the card" }
  $ok = $ok -and $hit
}

Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue
if ($ok) { Write-Output "RESULT: PASS - a real notification card reached the desktop"; exit 0 }
Write-Output "RESULT: FAIL - nothing reached the desktop"; exit 1
