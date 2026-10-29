<#
.SYNOPSIS
  Rasterises the MI CS icon SVGs into high-resolution PNG masters.

.DESCRIPTION
  Chrome/Edge headless renders the SVG inside a transparent, centred square and
  screenshots it. Nothing else in the toolchain can rasterise SVG offline, and
  a 1024 px master is what keeps the 256 px icon frame crisp.

  Written masters:
    assets/icons/task.png     <- assets/icons/task.svg     (taskbar/tray/exe)
    assets/icons/Desktop.png  <- assets/icons/Desktop.svg  (desktop shortcut)
#>
param(
  [int]$Size = 1024,
  [string]$Browser = "C:\Program Files\Google\Chrome\Application\chrome.exe"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$icons = Join-Path $root "assets\icons"

if (-not (Test-Path $Browser)) {
  $edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
  if (Test-Path $edge) { $Browser = $edge } else { throw "no Chromium browser found" }
}

$jobs = @(
  @{ Svg = "task.svg";    Png = "task.png" },
  @{ Svg = "Desktop.svg"; Png = "Desktop.png" }
)

$work = Join-Path $env:TEMP "mics-icon-render"
New-Item -ItemType Directory -Force -Path $work | Out-Null

foreach ($job in $jobs) {
  $svg = Join-Path $icons $job.Svg
  $png = Join-Path $icons $job.Png
  if (-not (Test-Path $svg)) { Write-Warning "missing $($job.Svg)"; continue }

  # object-fit keeps the aspect ratio; the flex box centres it on a transparent
  # canvas so non-square art (viewBox 576x541) still yields a square master.
  # The <img> needs an absolute file:// URL: a relative path would resolve
  # against the temporary HTML file, not against the icons folder.
  $svgUrl = "file:///" + $svg.Replace('\', '/')
  $html = @"
<!doctype html><meta charset="utf-8"><style>
html,body{margin:0;padding:0;width:${Size}px;height:${Size}px;background:transparent}
body{display:flex;align-items:center;justify-content:center}
img{width:100%;height:100%;object-fit:contain}
</style><img src="$svgUrl">
"@
  $htmlPath = Join-Path $work "$($job.Png).html"
  Set-Content -Path $htmlPath -Value $html -Encoding utf8

  $shot = Join-Path $work "$($job.Png).png"
  Remove-Item $shot -Force -ErrorAction SilentlyContinue

  & $Browser --headless=new --disable-gpu --hide-scrollbars `
    --default-background-color=00000000 --force-device-scale-factor=1 `
    --user-data-dir="$env:TEMP\mics-chrome-profile" `
    --window-size=$Size,$Size --screenshot=$shot `
    ("file:///" + $htmlPath.Replace('\', '/')) 2>$null | Out-Null

  if (-not (Test-Path $shot)) { throw "render failed for $($job.Svg)" }
  Copy-Item $shot $png -Force
  Write-Output ("{0,-12} -> {1} ({2:N0} bytes)" -f $job.Svg, $job.Png, (Get-Item $png).Length)
}
