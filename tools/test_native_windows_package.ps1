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
& (Join-Path $PSScriptRoot 'package_native_windows.ps1') -PublishDirectory $publish -OutputDirectory $packages -Profile ExternalEngine
$first=Get-ChildItem -LiteralPath $packages -Directory | Select-Object -First 1
$externalManifest=Get-Content -LiteralPath (Join-Path $first.FullName 'package-manifest.json') -Raw | ConvertFrom-Json
if ($externalManifest.engine.run_schema_range -ne 'unknown' -or @($externalManifest.engine.run_schema_versions).Count -ne 0) { throw 'External engine schema support was invented.' }
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
& (Join-Path $PSScriptRoot 'package_native_windows.ps1') -PublishDirectory $publish -OutputDirectory $packages -Profile ExternalEngine
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
Write-Output 'Unverified bundled engine refusal passed.'

# Required-profile and stale-freeze sentinels use synthetic source/proof only.
# No fixture executable is launched and no retained artifact is read or changed.
$builder=Join-Path $PSScriptRoot 'package_native_windows.ps1'
$python=Join-Path $PSScriptRoot '../.venv/Scripts/python.exe'
function Refuse-Package([hashtable]$Options,[string]$Diagnostic) {
    $refused=$false
    try { & $builder @Options } catch { $refused=$true; Write-Output "Expected refusal ($Diagnostic): $_" }
    if (!$refused) { throw "Missing refusal: $Diagnostic" }
    if (Test-Path -LiteralPath $Options.OutputDirectory) { throw "Refused package created output: $Diagnostic" }
}
Refuse-Package @{PublishDirectory=$publish;OutputDirectory=(Join-Path $root 'required-missing')} 'required engine absent'
$fixtureSource=Join-Path $root 'source'
$engine=Join-Path $root 'frozen'
New-Item -ItemType Directory -Path (Join-Path $fixtureSource 'src'),$engine -Force | Out-Null
'source sentinel' | Set-Content -LiteralPath (Join-Path $fixtureSource 'src/sentinel.py')
'[project]' | Set-Content -LiteralPath (Join-Path $fixtureSource 'pyproject.toml')
'synthetic frozen executable; never execute' | Set-Content -LiteralPath (Join-Path $engine 'attackmap.exe')
'frozen sentinel' | Set-Content -LiteralPath (Join-Path $engine 'sentinel.txt')
$lockPath=Join-Path $root 'fixture-release-lock.json'
$lockWriter=@'
import hashlib,importlib.util,json,pathlib,sys
s=importlib.util.spec_from_file_location('lock',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
lock=m.release_inputs(pathlib.Path(sys.argv[2]))
lock['toolchain']={key:{'version':'synthetic-test-identity'} for key in ('python','pyinstaller','dotnet_sdk')}
pathlib.Path(sys.argv[3]).write_text(json.dumps(lock,indent=2),encoding='utf-8')
'@
& $python -c $lockWriter (Join-Path $PSScriptRoot 'generate_release_lock.py') $fixtureSource $lockPath
if ($LASTEXITCODE -ne 0) { throw 'Synthetic release lock failed.' }
$lock=Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$proof=@{
    version='synthetic fixture; not runtime acceptance';exe_sha256=(Get-FileHash (Join-Path $engine 'attackmap.exe')).Hash
    source_checksums_sha256=$lock.source_checksums_sha256;release_inputs_sha256=$lock.release_inputs_sha256
    analyzer_requirements_sha256=$lock.analyzer_requirements_sha256;release_lock_sha256=(Get-FileHash $lockPath).Hash
    checks=@{modules_discovered=19;native_broker_commands_present=$true;scan_atomic_current_ready=$true;frozen_compare_action_ready=$true}
    capabilities=@{desktop=@{schema_versions=@('1.0','1.2','1.4')}}
    scan=@{exit_code=0;terminal=@{state='completed';artifact_readiness='ready'}}
    action=@{exit_code=0;terminal=@{state='completed'}}
    limitations=@('Synthetic test fixture; no executable or scan was run')
    payload_files=@(Get-ChildItem -LiteralPath $engine -File | ForEach-Object { @{path=$_.Name;size_bytes=$_.Length;sha256=(Get-FileHash $_.FullName).Hash} })
}
$proof | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $engine 'engine-verification.json') -Encoding utf8
$options=@{PublishDirectory=$publish;OutputDirectory=(Join-Path $root 'bundled-packages');EngineDirectory=$engine;ReleaseLockPath=$lockPath;SourceRoot=$fixtureSource;PythonExecutable=$python}
'changed source' | Add-Content -LiteralPath (Join-Path $fixtureSource 'src/sentinel.py')
Refuse-Package $options 'stale source'
'source sentinel' | Set-Content -LiteralPath (Join-Path $fixtureSource 'src/sentinel.py')
$sentinel=Join-Path $engine 'sentinel.txt'
$sentinelBytes=[IO.File]::ReadAllBytes($sentinel)
'tampered frozen sentinel' | Set-Content -LiteralPath $sentinel
Refuse-Package $options 'tampered frozen sentinel'
[IO.File]::WriteAllBytes($sentinel,$sentinelBytes)
Remove-Item -LiteralPath $sentinel
Refuse-Package $options 'missing frozen sentinel'
[IO.File]::WriteAllBytes($sentinel,$sentinelBytes)
'extra' | Set-Content -LiteralPath (Join-Path $engine 'extra.txt')
Refuse-Package $options 'extra frozen sentinel'
Remove-Item -LiteralPath (Join-Path $engine 'extra.txt')
& $builder @options
$bundled=Get-ChildItem -LiteralPath $options.OutputDirectory -Directory | Select-Object -First 1
$bundledManifest=Get-Content -LiteralPath (Join-Path $bundled.FullName 'package-manifest.json') -Raw | ConvertFrom-Json
if (($bundledManifest.engine.run_schema_versions -join ',') -ne '1.0,1.2,1.4' -or $bundledManifest.engine.run_schema_range -ne '1.0,1.2,1.4') { throw 'Package lost exact frozen capability schema versions or invented gaps.' }
$proof.Remove('capabilities')
$proof | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $engine 'engine-verification.json') -Encoding utf8
$legacyOptions=$options.Clone();$legacyOptions.OutputDirectory=Join-Path $root 'legacy-proof-packages'
& $builder @legacyOptions
$legacyPackage=Get-ChildItem -LiteralPath $legacyOptions.OutputDirectory -Directory | Select-Object -First 1
$legacyManifest=Get-Content -LiteralPath (Join-Path $legacyPackage.FullName 'package-manifest.json') -Raw | ConvertFrom-Json
if ($legacyManifest.engine.run_schema_range -ne 'unknown' -or @($legacyManifest.engine.run_schema_versions).Count -ne 0) { throw 'Legacy frozen proof invented schema capabilities.' }
$ps51=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$ps51Install=Join-Path $root 'ps51-install'
& $ps51 -NoProfile -ExecutionPolicy Bypass -File (Join-Path $bundled.FullName 'Install-AttackMap.ps1') -InstallRoot $ps51Install
if ($LASTEXITCODE -ne 0) { throw 'Windows PowerShell 5.1 isolated install failed.' }
$priorNonInteractive=$env:ATTACKMAP_INSTALL_NONINTERACTIVE
try {
    $env:ATTACKMAP_INSTALL_NONINTERACTIVE='1'
    & (Join-Path $bundled.FullName 'Install-AttackMap.cmd') -InstallRoot $ps51Install
    if ($LASTEXITCODE -ne 0) { throw 'Noninteractive launcher success failed.' }
    & (Join-Path $bundled.FullName 'Install-AttackMap.cmd') -Mode Rollback -InstallRoot $ps51Install -Version invalid
    if ($LASTEXITCODE -eq 0) { throw 'Launcher lost installer failure exit code.' }
} finally { $env:ATTACKMAP_INSTALL_NONINTERACTIVE=$priorNonInteractive }
$zip=Join-Path $options.OutputDirectory ($bundled.Name + '.zip')
@{scope='Synthetic required-profile/package/PS5.1 fixture only; no bundled scan or model call';package_id=$bundled.Name;zip_sha256=(Get-FileHash $zip).Hash.ToLowerInvariant();zip=$zip;ps51_install=$ps51Install;required_missing_refused=$true;stale_source_refused=$true;tamper_refused=$true;ps51_installed=$true;launcher_exit_propagation=$true} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'package-smoke.json') -Encoding utf8
Write-Output 'Required engine, stale-source, frozen sentinel, PS5.1 and noninteractive exit-code checks passed.'
