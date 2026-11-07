#requires -Version 7.2
[CmdletBinding()]
param([string]$TestRoot=(Join-Path $PSScriptRoot ('../.pytest_cache/release-rollback-test-' + [Guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($TestRoot)
$publish=Join-Path $root 'published-fixture'
$packages=Join-Path $root 'packages'
$install=Join-Path $root 'rollback-install'
New-Item -ItemType Directory -Path $publish -Force | Out-Null
foreach ($name in @('AttackMap.NativeSpike.exe','coreclr.dll','Microsoft.UI.Xaml.dll')) { 'synthetic rollback fixture v1' | Set-Content -LiteralPath (Join-Path $publish $name) }
'{"runtimeOptions":{"includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"8.0.32"}]}}' | Set-Content -LiteralPath (Join-Path $publish 'AttackMap.NativeSpike.runtimeconfig.json')
# v1: package, install, and place a user file in the install root before any upgrade.
& (Join-Path $PSScriptRoot 'package_native_windows.ps1') -PublishDirectory $publish -OutputDirectory $packages
$first=Get-ChildItem -LiteralPath $packages -Directory | Select-Object -First 1
$installer=Join-Path $first.FullName 'Install-AttackMap.ps1'
& $installer -InstallRoot $install
$original=Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw
$userFile=Join-Path $install 'user-notes.txt'
'rollback procedure user data' | Set-Content -LiteralPath $userFile
# v2: changed payload, installed into the same root.
'synthetic rollback fixture v2' | Set-Content -LiteralPath (Join-Path $publish 'AttackMap.NativeSpike.exe')
& (Join-Path $PSScriptRoot 'package_native_windows.ps1') -PublishDirectory $publish -OutputDirectory $packages
$second=Get-ChildItem -LiteralPath $packages -Directory | Where-Object Name -ne $first.Name | Select-Object -First 1
& (Join-Path $second.FullName 'Install-AttackMap.ps1') -InstallRoot $install
$afterUpgrade=Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw
if ($afterUpgrade -eq $original) { throw 'Upgrade did not select the new version' }
if ($afterUpgrade -notmatch [regex]::Escape($second.Name)) { throw 'current.json does not point at v2 after upgrade' }
# Rollback to v1 using the installer's own mode; selection and user files must survive.
& $installer -Mode Rollback -InstallRoot $install -Version $first.Name
if ($original -ne (Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw)) { throw 'Rollback did not restore the v1 selection' }
if (!(Test-Path -LiteralPath $userFile)) { throw 'Rollback removed a user file in the install root' }
foreach ($kept in @($first.Name,$second.Name)) {
    if (!(Test-Path -LiteralPath (Join-Path (Join-Path $install 'versions') $kept))) { throw "Rollback removed retained version payload: $kept" }
}
$refused=$false
try { & $installer -Mode Rollback -InstallRoot $install -Version 'dev-00000000000000-00000000' } catch { $refused=$true }
if (!$refused) { throw 'Rollback accepted an unknown version ID' }
if ($original -ne (Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw)) { throw 'Refused rollback changed the current selection' }
# Uninstall after rollback: both versions removed, user files preserved.
& $installer -Mode Uninstall -InstallRoot $install
if (Test-Path -LiteralPath (Join-Path $install 'current.json')) { throw 'Uninstall left current.json behind' }
if (Test-Path -LiteralPath (Join-Path $install '.attackmap-development-install')) { throw 'Uninstall left the ownership marker behind' }
$remaining=Get-ChildItem -LiteralPath (Join-Path $install 'versions') -Directory -Force -ErrorAction SilentlyContinue
if ($remaining) { throw ('Uninstall left version payloads: ' + ($remaining.Name -join ', ')) }
if (!(Test-Path -LiteralPath $userFile)) { throw 'Uninstall removed a user file in the install root' }
$result=[ordered]@{
    passed=$true
    test_root=$root
    install_root=$install
    first_version=$first.Name
    second_version=$second.Name
    steps=@('package-v1','install-v1','user-file-created','install-v2','rollback-to-v1','rollback-unknown-refused','uninstall-after-rollback')
    user_file_preserved='user-notes.txt'
}
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'rollback-test-result.json') -Encoding utf8
Write-Output "Release rollback procedure passed: $root"
Write-Output "Result record: $(Join-Path $root 'rollback-test-result.json')"
Write-Output "Versions exercised: $($first.Name) -> $($second.Name) -> rollback $($first.Name)"
