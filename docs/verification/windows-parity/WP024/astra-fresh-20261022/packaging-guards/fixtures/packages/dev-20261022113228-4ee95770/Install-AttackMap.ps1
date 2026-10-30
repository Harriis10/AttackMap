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
function Validate-Payload([string]$Folder,[bool]$IncludeInstaller=$false,[switch]$TolerateExtras) {
    Assert-NoLinks $Folder
    $manifest=Get-Content -LiteralPath (Join-Path $Folder 'package-manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.package_id -notmatch '^dev-[0-9]{14}-[a-f0-9]{8}$') { throw 'Unsupported package manifest.' }
    $expected=@('package-manifest.json')
    if ($IncludeInstaller) { $expected += 'Install-AttackMap.ps1'; $expected += 'Install-AttackMap.cmd' }
    foreach ($file in $manifest.files) {
        if ($file.path -notmatch '^[A-Za-z0-9_./ -]+$' -or $file.path.Split('/') -contains '..' -or [IO.Path]::IsPathRooted($file.path)) { throw 'Unsafe package entry.' }
        $path=Join-Path (Join-Path $Folder 'app') $file.path
        Assert-NoLinks $path
        if (!(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -ne $file.size_bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.sha256) { throw "Package checksum mismatch for $($file.path); prior installation retained." }
        $expected += 'app/' + $file.path
    }
    $extras=@()
    foreach ($entry in Get-ChildItem -LiteralPath $Folder -Recurse -Force) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected package entry.' }
        # Relative-path resolution without [IO.Path]::GetRelativePath, which
        # Windows PowerShell 5.1 (.NET Framework) does not provide.
        if (!$entry.PSIsContainer) {
            $relative = if ($entry.FullName.StartsWith($Folder.TrimEnd('\','/'), [StringComparison]::OrdinalIgnoreCase)) { $entry.FullName.Substring($Folder.TrimEnd('\','/').Length).TrimStart('\','/').Replace('\','/') } else { '' }
            if ($relative -eq '' -or $relative -notin $expected) {
                if ($TolerateExtras) { $extras += $relative } else { throw "Unrecognized file in package folder: '$relative' (refusing deletion or activation)." }
            }
        }
    }
    if ($TolerateExtras -and $extras.Count -gt 0) { Write-Warning "Ignoring unrecognized file(s) in the package folder (not part of the verified payload): $($extras -join ', ')" }
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
    # The user's extracted folder is not owned storage: tolerate and report
    # unrecognized files (extraction artifacts, copies parked beside the
    # payload) while every expected file still has to checksum-match.
    Validate-Payload $PSScriptRoot $true -TolerateExtras | Out-Null
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
