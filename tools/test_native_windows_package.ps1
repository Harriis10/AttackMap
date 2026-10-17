#requires -Version 7.2
[CmdletBinding()]
param([string]$TestRoot=(Join-Path $PSScriptRoot ('../.pytest_cache/package-test-' + [Guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($TestRoot)
$publish=Join-Path $root 'published-fixture'
$packages=Join-Path $root 'packages'
$install=Join-Path $root 'isolated-install'
New-Item -ItemType Directory -Path $publish -Force | Out-Null
foreach ($name in @('AttackMap.NativeSpike.exe','coreclr.dll','Microsoft.UI.Xaml.dll')) { 'synthetic package fixture' | Set-Content -LiteralPath (Join-Path $publish $name) }
'{"runtimeOptions":{"includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"8.0.32"}]}}' | Set-Content -LiteralPath (Join-Path $publish 'AttackMap.NativeSpike.runtimeconfig.json')
'not distributed' | Set-Content -LiteralPath (Join-Path $publish 'scan-smoke.json')
& (Join-Path $PSScriptRoot 'package_native_windows.ps1') -PublishDirectory $publish -OutputDirectory $packages
$first=Get-ChildItem -LiteralPath $packages -Directory | Select-Object -First 1
$installer=Join-Path $first.FullName 'Install-AttackMap.ps1'
if (Test-Path -LiteralPath (Join-Path $first.FullName 'app/scan-smoke.json')) { throw 'Smoke data packaged' }
& $installer -InstallRoot $install
$original=Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw
& $installer -InstallRoot $install
if ($original -ne (Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw)) { throw 'Repeated install changed current' }
$packageExecutable=Join-Path $first.FullName 'app/AttackMap.NativeSpike.exe'
$packageBytes=[IO.File]::ReadAllBytes($packageExecutable)
'corrupt incoming payload' | Set-Content -LiteralPath $packageExecutable
$refused=$false
try { & $installer -InstallRoot $install } catch { $refused=$true }
if (!$refused -or $original -ne (Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw)) { throw 'Failed incoming package changed prior current' }
[IO.File]::WriteAllBytes($packageExecutable,$packageBytes)
$unowned=Join-Path $root 'unowned-directory'
New-Item -ItemType Directory -Path $unowned | Out-Null
$refused=$false
try { & $installer -InstallRoot $unowned } catch { $refused=$true }
if (!$refused) { throw 'Installer accepted unowned existing root' }
'second payload' | Set-Content -LiteralPath (Join-Path $publish 'AttackMap.NativeSpike.exe')
& (Join-Path $PSScriptRoot 'package_native_windows.ps1') -PublishDirectory $publish -OutputDirectory $packages
$second=Get-ChildItem -LiteralPath $packages -Directory | Where-Object Name -ne $first.Name | Select-Object -First 1
& (Join-Path $second.FullName 'Install-AttackMap.ps1') -InstallRoot $install
& $installer -Mode Rollback -InstallRoot $install -Version $first.Name
if ($original -ne (Get-Content -LiteralPath (Join-Path $install 'current.json') -Raw)) { throw 'Rollback failed' }
$target=Join-Path $install ('versions/' + $second.Name + '/app/AttackMap.NativeSpike.exe')
$bytes=[IO.File]::ReadAllBytes($target)
'tampered' | Set-Content -LiteralPath $target
$refused=$false
try { & $installer -Mode Uninstall -InstallRoot $install } catch { $refused=$true }
if (!$refused -or !(Test-Path -LiteralPath $target)) { throw 'Modified payload uninstall was not refused' }
[IO.File]::WriteAllBytes($target,$bytes)
$userFile=Join-Path $install 'user-notes.txt'
'preserve user notes' | Set-Content -LiteralPath $userFile
& $installer -Mode Uninstall -InstallRoot $install
if (!(Test-Path -LiteralPath $userFile)) { throw 'Uninstall removed user-owned root file' }
if (Test-Path -LiteralPath (Join-Path $install 'current.json')) { throw 'Uninstall left current selector' }
Write-Output "Packaging fixture install/repeat/upgrade/rollback/tamper/uninstall passed: $root"
$refused=$false
try { & (Join-Path $PSScriptRoot 'package_native_windows.ps1') -PublishDirectory $publish -OutputDirectory (Join-Path $root 'invalid-engine-package') -EngineDirectory $publish } catch { $refused=$true }
if (!$refused) { throw 'Unverified frozen engine was accepted' }
Write-Output 'Unverified optional engine refusal passed.'
