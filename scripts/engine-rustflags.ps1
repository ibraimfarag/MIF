<#
.SYNOPSIS
  The rustflags the engine must be built with: what engine\.cargo\config.toml
  asks for, plus the path remap that keeps the build account out of the binary.

.DESCRIPTION
  `CARGO_ENCODED_RUSTFLAGS` (like `RUSTFLAGS`) does not add to the flags cargo
  reads from `.cargo\config.toml` - it replaces them. Setting it to the remap
  alone therefore turned `-C control-flow-guard=yes` off, and the release engine
  came out without a CFG table; the hardening gate in `make-release.ps1` refused
  the package on 2026-11-02 (DllCharacteristics 0x8160, no GUARD_CF, no
  longjump table). This file exists so the flags have one source of truth: the
  config is read the way cargo reads it (the target section, else `[build]`) and
  the remap is appended, never substituted.

  The result is unit-separator joined, ready for `CARGO_ENCODED_RUSTFLAGS`:

    . .\scripts\engine-rustflags.ps1
    $env:CARGO_ENCODED_RUSTFLAGS = Get-EngineRustFlags -Repo $root

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\engine-rustflags.ps1
  -C | control-flow-guard=yes | --remap-path-prefix=<profile>=/build

.NOTES
  ASCII only on purpose: Windows PowerShell 5.1 decodes .ps1 files as ANSI (see
  docs/TODO.md 8.9).
#>

function Get-QuotedFlags {
    param([string]$Text)
    $out = @()
    foreach ($m in [regex]::Matches($Text, "'([^']*)'|""([^""]*)""")) {
        $value = $m.Groups[1].Value
        if (-not $value) { $value = $m.Groups[2].Value }
        if ($value) { $out += $value }
    }
    return $out
}

function Get-EngineRustFlags {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repo,
        [string]$Remap = ""
    )
    if (-not $Remap) {
        $Remap = "--remap-path-prefix=$($env:USERPROFILE)=/build"
    }

    # Sections that may carry rustflags, in the order they appear in the file.
    $sections = [ordered]@{}
    $config = Join-Path $Repo 'engine\.cargo\config.toml'
    if (Test-Path $config) {
        $section = ''
        $collecting = $false
        $buffer = ''
        $sawRustflags = $false
        foreach ($line in (Get-Content $config)) {
            # This config is comments plus one array; a `#` inside a quoted value
            # would need a real TOML parser, and the guard below catches it.
            $code = $line -replace '#.*$', ''
            if ($collecting) {
                $buffer += ' ' + $code
                if ($code -match '\]') {
                    $collecting = $false
                    $sections[$section] = Get-QuotedFlags $buffer
                }
                continue
            }
            if ($code -match '^\s*\[(.+?)\]\s*$') {
                $section = $Matches[1].Trim()
                continue
            }
            if ($code -match '^\s*rustflags\s*=\s*\[') {
                $sawRustflags = $true
                if ($code -match '\]') {
                    $sections[$section] = Get-QuotedFlags $code
                } else {
                    $buffer = $code
                    $collecting = $true
                }
            }
        }
        if ($collecting -or ($sawRustflags -and $sections.Count -eq 0)) {
            throw "found rustflags in $config but could not read them; fix Get-EngineRustFlags before building"
        }
    }

    # Cargo's own order: a target section wins over `[build]`. On a multi-target
    # config the host triple wins, so an ARM64 section added later cannot take
    # over an x64 build.
    $chosen = @()
    foreach ($name in $sections.Keys) {
        if ($name -like '*x86_64-pc-windows-msvc*') { $chosen = $sections[$name]; break }
    }
    if ($chosen.Count -eq 0 -and $sections.Contains('build')) { $chosen = $sections['build'] }

    return (@($chosen) + $Remap -join [char]0x1f)
}

# Run the file directly to see what a build would use.
if ($MyInvocation.InvocationName -ne '.') {
    $encoded = Get-EngineRustFlags -Repo (Split-Path $PSScriptRoot -Parent)
    Write-Output ($encoded -replace [char]0x1f, ' | ')
}