#requires -Version 7.2
[CmdletBinding()]
param(
    [string]$PublishDirectory = (Join-Path $PSScriptRoot '../desktop/windows/artifacts/native-spike'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '../desktop/windows/artifacts/development-packages'),
    [string]$EngineDirectory,
    [string]$EngineVerificationPath
)
$ErrorActionPreference = 'Stop'
$publish = [IO.Path]::GetFullPath($PublishDirectory)
$output = [IO.Path]::GetFullPath($OutputDirectory)
if ($output.Equals($publish,[StringComparison]::OrdinalIgnoreCase) -or $output.StartsWith($publish.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Package output must be outside the published payload.' }
foreach ($required in @('AttackMap.NativeSpike.exe','AttackMap.NativeSpike.runtimeconfig.json','coreclr.dll','Microsoft.UI.Xaml.dll')) {
    if (!(Test-Path -LiteralPath (Join-Path $publish $required) -PathType Leaf)) { throw "Missing published runtime file: $required" }
}
$packageId = 'dev-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$stage = Join-Path $output $packageId
New-Item -ItemType Directory -Path (Join-Path $stage 'app') -Force | Out-Null
$files = @()
foreach ($entry in Get-ChildItem -LiteralPath $publish -Recurse -Force) {
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Published payload contains redirected entries.' }
    if ($entry.PSIsContainer) { continue }
    $relative = [IO.Path]::GetRelativePath($publish,$entry.FullName).Replace('\','/')
    if ($entry.Name -match 'smoke|^spike-error' -or $entry.Extension -in @('.pdb','.log')) { continue }
    $target = Join-Path (Join-Path $stage 'app') $relative
    New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($target)) -Force | Out-Null
    Copy-Item -LiteralPath $entry.FullName -Destination $target
    $files += [ordered]@{path=$relative;size_bytes=(Get-Item -LiteralPath $target).Length;sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$engineMetadata = [ordered]@{bundled=$false;discovery='Explicit absolute Python executable selected in desktop settings; no PATH probing or automatic downloads.';required_modules=@('attackmap.desktop_worker','attackmap.desktop_actions');run_schema_range='1.0-1.1';note='Requires compatible AttackMap engine and analyzers installed separately. Current development checkout is the verified engine.'}
if ($EngineDirectory) {
    $engine = [IO.Path]::GetFullPath($EngineDirectory)
    if (!$EngineVerificationPath) { $EngineVerificationPath = Join-Path $engine 'engine-verification.json' }
    $proof = Get-Content -LiteralPath $EngineVerificationPath -Raw | ConvertFrom-Json
    $engineExe = Join-Path $engine 'attackmap.exe'
    if (!(Test-Path -LiteralPath $engineExe -PathType Leaf) -or
        $proof.exe_sha256 -ne (Get-FileHash -LiteralPath $engineExe -Algorithm SHA256).Hash -or
        !$proof.version -or $proof.checks.modules_discovered -lt 15 -or
        !$proof.checks.native_broker_commands_present -or !$proof.checks.scan_atomic_current_ready -or
        !$proof.checks.frozen_compare_action_ready -or $proof.scan.exit_code -ne 0 -or $proof.action.exit_code -ne 0 -or
        $proof.scan.terminal.state -ne 'completed' -or $proof.scan.terminal.artifact_readiness -ne 'ready' -or
        $proof.action.terminal.state -ne 'completed' -or !$proof.payload_files) { throw 'Frozen engine requires matching successful version/modules/scan/action verification.' }
    $bound = @{}
    foreach ($file in $proof.payload_files) {
        if ($file.path -match '\\' -or $file.path.Split('/') -contains '..' -or [IO.Path]::IsPathRooted($file.path) -or $bound.ContainsKey($file.path)) { throw 'Unsafe frozen verification entry.' }
        $bound[$file.path]=$file
    }
    foreach ($entry in Get-ChildItem -LiteralPath $engine -Recurse -Force) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Frozen engine refuses redirected entries.' }
        if ($entry.PSIsContainer) { continue }
        $relative = [IO.Path]::GetRelativePath($engine,$entry.FullName).Replace('\','/')
        if ($relative -eq 'engine-verification.json') { continue }
        if (!$bound.ContainsKey($relative) -or $entry.Length -ne $bound[$relative].size_bytes -or (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash -ne $bound[$relative].sha256) { throw 'Frozen payload changed after verification.' }
        $target=Join-Path (Join-Path $stage 'app/engine') $relative
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($target)) -Force | Out-Null
        Copy-Item -LiteralPath $entry.FullName -Destination $target
        $files += [ordered]@{path=('engine/' + $relative);size_bytes=(Get-Item -LiteralPath $target).Length;sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()}
        $bound.Remove($relative)
    }
    if ($bound.Count -ne 0) { throw 'Frozen verification references missing payload files.' }
    $engineMetadata=[ordered]@{bundled=$true;executable='app/engine/attackmap.exe';runtime_kind='Frozen';version=$proof.version;analyzer_count=$proof.checks.modules_discovered;run_schema_range='1.0-1.1';verification_sha256=(Get-FileHash -LiteralPath $EngineVerificationPath -Algorithm SHA256).Hash.ToLowerInvariant();source_checksums_sha256=$proof.source_checksums_sha256;discovery='Exact bundled executable selected only when no engine path is configured; no PATH probing, automatic execution or downloads.';limitations=$proof.limitations}
}
$runtime = Get-Content -LiteralPath (Join-Path $publish 'AttackMap.NativeSpike.runtimeconfig.json') -Raw | ConvertFrom-Json
$manifest = [ordered]@{
    schema_version=1;package_id=$packageId;channel='unsigned-development';architecture='win-x64';minimum_windows='10.0.19041.0'
    native_runtime=[ordered]@{dotnet_self_contained=$true;included_frameworks=$runtime.runtimeOptions.includedFrameworks;windows_app_sdk_self_contained=$true;windows_app_sdk='2.4.0'}
    engine=$engineMetadata
    files=$files
}
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $stage 'package-manifest.json') -Encoding utf8
$deployment = @'
# Windows PowerShell 5.1 and PowerShell 7+ both run this installer; the
# unsigned dev channel is normally launched via Install-AttackMap.cmd,
# which supplies the per-process execution policy.
[CmdletBinding()]
param([ValidateSet('Install','Rollback','Uninstall')][string]$Mode='Install',
      [string]$InstallRoot=(Join-Path $env:LOCALAPPDATA 'Programs/AttackMapDevelopment'),[string]$Version)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($InstallRoot)
function Assert-NoLinks([string]$Path) {
    $candidate=[IO.Path]::GetFullPath($Path)
    while ($candidate) {
        if (Test-Path -LiteralPath $candidate) {
            if ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation refuses redirected paths.' }
        }
        $parent=[IO.Path]::GetDirectoryName($candidate)
        if ($parent -eq $candidate) { break }; $candidate=$parent
    }
}
function Assert-OwnedRoot {
    Assert-NoLinks $root
    if (!(Test-Path -LiteralPath (Join-Path $root '.attackmap-development-install'))) { throw 'Refusing an unowned installation directory.' }
}
function Validate-Payload([string]$Folder,[bool]$IncludeInstaller=$false) {
    Assert-NoLinks $Folder
    $manifest=Get-Content -LiteralPath (Join-Path $Folder 'package-manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.package_id -notmatch '^dev-[0-9]{14}-[a-f0-9]{8}$') { throw 'Unsupported package manifest.' }
    $expected=@('package-manifest.json')
    if ($IncludeInstaller) { $expected += 'Install-AttackMap.ps1'; $expected += 'Install-AttackMap.cmd' }
    foreach ($file in $manifest.files) {
        if ($file.path -notmatch '^[A-Za-z0-9_./ -]+$' -or $file.path.Split('/') -contains '..' -or [IO.Path]::IsPathRooted($file.path)) { throw 'Unsafe package entry.' }
        $path=Join-Path (Join-Path $Folder 'app') $file.path
        Assert-NoLinks $path
        if (!(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -ne $file.size_bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.sha256) { throw 'Package checksum mismatch; prior installation retained.' }
        $expected += 'app/' + $file.path
    }
    foreach ($entry in Get-ChildItem -LiteralPath $Folder -Recurse -Force) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected package entry.' }
        # Relative-path resolution without [IO.Path]::GetRelativePath, which
        # Windows PowerShell 5.1 (.NET Framework) does not provide.
        if (!$entry.PSIsContainer) {
            $relative = if ($entry.FullName.StartsWith($Folder.TrimEnd('\','/'), [StringComparison]::OrdinalIgnoreCase)) { $entry.FullName.Substring($Folder.TrimEnd('\','/').Length).TrimStart('\','/').Replace('\','/') } else { '' }
            if ($relative -eq '' -or $relative -notin $expected) { throw 'Unrecognized file in owned version; refusing deletion or activation.' }
        }
    }
    return $manifest
}
function Set-Current([string]$Id) {
    Assert-OwnedRoot
    $temporary=Join-Path $root ('.current-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        @{package_id=$Id} | ConvertTo-Json | Set-Content -LiteralPath $temporary -Encoding utf8
        # Move-Item -Force instead of the 3-arg [IO.File]::Move overload,
        # which Windows PowerShell 5.1 (.NET Framework) does not provide.
        Move-Item -LiteralPath $temporary -Destination (Join-Path $root 'current.json') -Force
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
}
if ($Mode -eq 'Install') {
    Assert-NoLinks $root
    if ((Test-Path -LiteralPath $root) -and !(Test-Path -LiteralPath (Join-Path $root '.attackmap-development-install'))) { throw 'Choose a new empty installation path; existing user directories are refused.' }
    $sourceManifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'package-manifest.json') -Raw | ConvertFrom-Json
    Validate-Payload $PSScriptRoot $true | Out-Null
    $id=$sourceManifest.package_id
    if ($id -notmatch '^dev-[0-9]{14}-[a-f0-9]{8}$') { throw 'Invalid package identity.' }
    New-Item -ItemType Directory -Path (Join-Path $root 'versions') -Force | Out-Null
    'AttackMap development package ownership v1' | Set-Content -LiteralPath (Join-Path $root '.attackmap-development-install')
    $destination=Join-Path (Join-Path $root 'versions') $id
    if (Test-Path -LiteralPath $destination) { Validate-Payload $destination | Out-Null }
    else {
        $stage=Join-Path (Join-Path $root 'versions') ('.stage-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $stage | Out-Null
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'app') -Destination $stage -Recurse
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'package-manifest.json') -Destination $stage
        Validate-Payload $stage | Out-Null
        Move-Item -LiteralPath $stage -Destination $destination
    }
    Set-Current $id
    $engineNote = if ($sourceManifest.engine.bundled) { 'A verified frozen engine is bundled; an explicit saved engine path remains your choice.' } else { 'Select a compatible absolute engine Python path in the app.' }
    Write-Output "Installed $id. Launch: $destination/app/AttackMap.NativeSpike.exe. $engineNote"
} elseif ($Mode -eq 'Rollback') {
    Assert-OwnedRoot
    if ($Version -notmatch '^dev-[0-9]{14}-[a-f0-9]{8}$') { throw 'Specify an installed package ID with -Version.' }
    Validate-Payload (Join-Path (Join-Path $root 'versions') $Version) | Out-Null
    Set-Current $Version
    Write-Output "Selected retained version $Version. Settings and credentials unchanged."
} else {
    Assert-OwnedRoot
    $versions=Join-Path $root 'versions'
    $targets=@(Get-ChildItem -LiteralPath $versions -Directory -Force)
    foreach ($target in $targets) {
        if ($target.Name -notmatch '^dev-[0-9]{14}-[a-f0-9]{8}$') { throw 'Unrecognized staged/version directory; inspect it before uninstall.' }
        Validate-Payload $target.FullName | Out-Null
    }
    foreach ($target in $targets) {
        $resolved=[IO.Path]::GetFullPath($target.FullName)
        if (![IO.Path]::GetDirectoryName($resolved).Equals($versions,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe uninstall target.' }
        Remove-Item -LiteralPath $resolved -Recurse
    }
    foreach ($name in @('current.json','.attackmap-development-install')) {
        $path=Join-Path $root $name; Assert-NoLinks $path
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
    Write-Output 'Owned application versions removed. AppData settings, reports, action snapshots and credentials preserved. Empty installation folders may remain.'
}
'@
$deployment | Set-Content -LiteralPath (Join-Path $stage 'Install-AttackMap.ps1') -Encoding utf8
# Unsigned dev channel: plain .ps1 launch is blocked by the default
# Restricted execution policy. A batch wrapper is not subject to it, so it
# can bootstrap PowerShell with an explicit per-process Bypass policy.
$launcher = @'
@echo off
setlocal
set "SCRIPT=%~dp0Install-AttackMap.ps1"
where pwsh.exe >nul 2>nul
if %errorlevel%==0 (
  pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
)
echo.
pause
'@
$launcher | Set-Content -LiteralPath (Join-Path $stage 'Install-AttackMap.cmd') -Encoding ascii
$zip = Join-Path $output ($packageId + '.zip')
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
$digest = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$digest  $([IO.Path]::GetFileName($zip))" | Set-Content -LiteralPath ($zip + '.sha256') -Encoding ascii
Write-Output "Package: $zip"
Write-Output "SHA256: $digest"
Write-Output 'Install (unsigned dev channel): run Install-AttackMap.cmd from the extracted package (double-click or cmd), or: powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-AttackMap.ps1'
