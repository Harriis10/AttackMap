#requires -Version 5.1
<#
.SYNOPSIS
    Smoke tests for the AttackMap Windows frozen build.

.DESCRIPTION
    Validates that a built attackmap.exe can print its version, describe
    capabilities, list analyzer modules, and run a minimal scan. Defaults to
    the standard onedir output path; override with $Env:ATTACKMAP_EXE.
#>
[CmdletBinding()]
param(
    [string]$ExePath = ""
)

$ErrorActionPreference = "Stop"

if (-not $ExePath) {
    $ExePath = $Env:ATTACKMAP_EXE
}
if (-not $ExePath) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ExePath = Join-Path $scriptRoot "..\dist\attackmap\attackmap.exe"
}
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path

if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Executable not found: $ExePath"
}

function Invoke-AttackMapExe {
    param([string[]]$ArgumentList)
    & $ExePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "attackmap.exe exited with code $LASTEXITCODE for: $ArgumentList"
    }
}

Write-Host "== version =="
$versionOutput = Invoke-AttackMapExe -ArgumentList @("--version")
if (-not ($versionOutput -match "attackmap")) {
    throw "--version did not report 'attackmap'"
}

Write-Host "== capabilities =="
$capabilities = Invoke-AttackMapExe -ArgumentList @("capabilities") | ConvertFrom-Json
if (-not $capabilities.schema) {
    throw "capabilities output missing schema"
}
if (-not $capabilities.analyze.multi_repo) {
    throw "capabilities output missing analyze.multi_repo"
}

Write-Host "== modules =="
$modules = Invoke-AttackMapExe -ArgumentList @("modules", "--json") | ConvertFrom-Json
if ($modules.Count -lt 1) {
    throw "modules --json returned no analyzers"
}

Write-Host "== minimal scan =="
$repo = Join-Path $env:TEMP "attackmap-smoke-$(Get-Random)"
$out = "$repo-out"
New-Item -ItemType Directory -Path $repo -Force | Out-Null
"x = 1" | Out-File -Encoding utf8 -FilePath "$repo\app.py"
try {
    Invoke-AttackMapExe -ArgumentList @("analyze", $repo, "-o", $out, "--format", "json")
    $report = Join-Path $out "attackmap-report.json"
    if (-not (Test-Path -LiteralPath $report)) {
        throw "attackmap-report.json not created at $report"
    }
} finally {
    Remove-Item -Recurse -Force -LiteralPath $repo -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force -LiteralPath $out -ErrorAction SilentlyContinue
}

Write-Host "Smoke tests passed."
