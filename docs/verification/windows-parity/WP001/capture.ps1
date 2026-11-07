# Read-only package/source/installation baseline. Writes only beside this script.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../../../..')).Path
$out=$PSScriptRoot
function Hash([string]$Path) { if(Test-Path -LiteralPath $Path -PathType Leaf){ (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() } }
function Probe([string]$Exe,[string[]]$Arguments,[string]$Name) {
    $stdout=Join-Path $out ($Name+'.stdout.txt'); $stderr=Join-Path $out ($Name+'.stderr.txt')
    $process=Start-Process -FilePath $Exe -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [ordered]@{executable=$Exe;arguments=$Arguments;exit_code=$process.ExitCode;stdout_file=[IO.Path]::GetFileName($stdout);stderr_file=[IO.Path]::GetFileName($stderr);stdout_sha256=(Hash $stdout)}
}
$packageRoot=Join-Path $repo 'desktop/windows/artifacts/development-packages'
$selected='dev-20261019192050-b678aee2'
$latest='dev-20261019201436-7d3584c4'
$installer=Join-Path $packageRoot ($selected+'/Install-AttackMap.ps1')
# Parse existing installer and load only its two read-only validation functions.
# Never dot-source the installer, whose top level performs installation.
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer parse failed'}
foreach($name in @('Assert-NoLinks','Validate-Payload')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if(!$node){throw "Missing existing validation function $name"}
    Invoke-Expression $node.Extent.Text
}
$validation=@()
foreach($id in @($selected,$latest)) {
    $folder=Join-Path $packageRoot $id
    Write-Output ('Validating '+$id); $manifest=Validate-Payload $folder $true
    $zip=$folder+'.zip'; $zipHash=Hash $zip
    $sidecar=(Get-Content -LiteralPath ($zip+'.sha256') -Raw).Trim().Split(' ')[0].ToLowerInvariant()
    if($zipHash -ne $sidecar){throw "ZIP checksum mismatch $id"}
    $validation += [ordered]@{role=$(if($id -eq $selected){'audit_candidate_and_default_installed_selection'}else{'newer_retained_candidate'});package_id=$id;manifest_sha256=(Hash (Join-Path $folder 'package-manifest.json'));payload_validation='PASS existing audit-candidate installer Validate-Payload; strict extras rejection';warnings=@();file_count=$manifest.files.Count;zip_sha256=$zipHash;zip_sidecar_match=$true;engine=$manifest.engine;exe_sha256=(Hash (Join-Path $folder $manifest.engine.executable));installer_sha256=(Hash (Join-Path $folder 'Install-AttackMap.ps1'))}
}
$installRoot=Join-Path $env:LOCALAPPDATA 'Programs/AttackMapDevelopment'
$currentPath=Join-Path $installRoot 'current.json'
$installed=[ordered]@{root=$installRoot;selection_status='not_found';runtime_launch_not_performed=$true;custom_roots_not_enumerated=$true}
if(Test-Path -LiteralPath $currentPath){
    $current=Get-Content -LiteralPath $currentPath -Raw | ConvertFrom-Json
    if($current.package_id -notmatch '^dev-[0-9]{14}-[a-f0-9]{8}$'){throw 'Unsafe installed selection'}
    $installedFolder=Join-Path $installRoot ('versions/'+$current.package_id)
    $im=Validate-Payload $installedFolder $false
    $installed.selection_status='selection_and_payload_verified'
    $installed.package_id=$current.package_id
    $installed.current_json_sha256=Hash $currentPath
    $installed.manifest_sha256=Hash (Join-Path $installedFolder 'package-manifest.json')
    $installed.engine_sha256=Hash (Join-Path $installedFolder $im.engine.executable)
}
$exe=Join-Path $packageRoot ($selected+'/app/engine/attackmap.exe')
$version=Probe $exe @('--version') 'packaged-version'
$modules=Probe $exe @('modules','--json') 'packaged-modules'
if($version.exit_code -ne 0 -or $modules.exit_code -ne 0){throw 'Packaged engine probe failed'}
$moduleData=Get-Content (Join-Path $out 'packaged-modules.stdout.txt') -Raw | ConvertFrom-Json
$dirty=@(git -C $repo status --porcelain=v1 --untracked-files=normal)
git -C $repo diff -- tools/package_native_windows.ps1 | Set-Content (Join-Path $out 'preserved-package-script.diff.txt') -Encoding utf8
$evidence=@('docs/windows-m3-acceptance.md','desktop/windows/verification/retained-m3/README.md','desktop/windows/verification/retained-m3/relocation-manifest.json','desktop/windows/artifacts/development-packages/dev-20261015190038-5667bbbf/package-manifest.json') | ForEach-Object { [ordered]@{path=$_;exists=(Test-Path (Join-Path $repo $_));sha256=(Hash (Join-Path $repo $_))} }
$result=[ordered]@{schema_version=1;captured_utc=[DateTime]::UtcNow.ToString('o');source=[ordered]@{head=(git -C $repo rev-parse HEAD).Trim();branch=(git -C $repo branch --show-current).Trim();version_file='pyproject.toml';version_file_sha256=(Hash (Join-Path $repo 'pyproject.toml'));dirty_status=$dirty;package_script_sha256=(Hash (Join-Path $repo 'tools/package_native_windows.ps1'));package_script_diff_sha256=(Hash (Join-Path $out 'preserved-package-script.diff.txt'))};packages=$validation;installed=$installed;selected_engine=[ordered]@{version_probe=$version;modules_probe=$modules;module_count=@($moduleData).Count;version=(Get-Content (Join-Path $out 'packaged-version.stdout.txt') -Raw).Trim()};historical_evidence=$evidence;accepted_m3=[ordered]@{date='2026-10-15';package_id='dev-20261015190038-5667bbbf';scope='Accepted Windows functional beta with limitations on Windows 10 x64 development host';deferred_unverified=@('C19 participant study','C21/C25 manual workflow and UX','C24 manual accessibility including Narrator');windows_C26='removed by user decision; no replacement performance gate';exclusions=@('macOS completion','clean-machine compatibility','signed public release','all original prerequisites','automatic acceptance of newer binaries')};unsupported_claims=@('Newer candidate is accepted M3 binary','Checksums authenticate publisher or signed release','Manifest source digest proves current dirty checkout matches frozen source','Default installation proves all custom installation roots','This baseline proves scan, AI, GUI, clean-host or manual accessibility acceptance');scope='Read-only probes and hash validation only; no rebuild, installation, scan or model call'}
$versionSource=Join-Path $repo 'src/attackmap/__init__.py'
$result.source.version_source='src/attackmap/__init__.py'
$result.source.version_source_sha256=Hash $versionSource
$result.source.declared_version=([regex]::Match((Get-Content $versionSource -Raw),'__version__\s*=\s*"([^"]+)"')).Groups[1].Value
$relocation=Get-Content (Join-Path $repo 'desktop/windows/verification/retained-m3/relocation-manifest.json') -Raw | ConvertFrom-Json
$retainedChecks=@($relocation.files | ForEach-Object {
    $path=Join-Path $repo $_.retained
    $actual=Hash $path
    [ordered]@{path=$_.retained;exists=(Test-Path -LiteralPath $path);expected_sha256=$_.sha256;actual_sha256=$actual;match=($actual -eq $_.sha256)}
})
$result.historical_relocation_validation=$retainedChecks
$result | ConvertTo-Json -Depth 30 | Set-Content (Join-Path $out 'baseline.json') -Encoding utf8
if($result.selected_engine.module_count -ne $validation[0].engine.analyzer_count){throw 'Module count differs from manifest'}
if($installed.selection_status -eq 'selection_and_payload_verified' -and $installed.package_id -eq $selected -and $installed.engine_sha256 -ne $validation[0].exe_sha256){throw 'Installed engine mismatch'}
Write-Output "PASS source/package/installed baseline; selected engine modules: $($result.selected_engine.module_count)"


