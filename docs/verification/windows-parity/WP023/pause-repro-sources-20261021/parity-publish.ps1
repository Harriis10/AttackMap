param([Parameter(Mandatory=$true)][ValidatePattern('^[a-z]$')][string]$Suffix)
$ErrorActionPreference = 'Stop'
$env:DOTNET_ROOT = [IO.Path]::GetFullPath('.tools/dotnet')
$env:DOTNET_CLI_HOME = [IO.Path]::GetFullPath('.tools/dotnet-home')
$env:NUGET_PACKAGES = [IO.Path]::GetFullPath('.tools/nuget-packages')
$evidence = "docs/verification/windows-parity/RECONCILE-2026-10-21/integrated-$Suffix"
$publish = "desktop/windows/artifacts/integrated-20261021-$Suffix"
if ((Test-Path -LiteralPath $evidence) -or (Test-Path -LiteralPath $publish)) { throw 'Use a fresh publish and evidence directory.' }
& '.venv/Scripts/python.exe' '.tmp/native_build_fingerprint.py' before $evidence $publish
if ($LASTEXITCODE -ne 0) { throw 'Source capture failed.' }
& '.tools/dotnet/dotnet.exe' publish 'desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj' -c Release -r win-x64 --self-contained true --no-restore -p:UseSharedCompilation=false -o $publish *> (Join-Path $evidence 'build.log')
$buildExit = $LASTEXITCODE
if ($buildExit -ne 0) { Get-Content -LiteralPath (Join-Path $evidence 'build.log') -Tail 30; throw "Native publish failed: $buildExit" }
& '.venv/Scripts/python.exe' '.tmp/native_build_fingerprint.py' after $evidence $publish
if ($LASTEXITCODE -ne 0) { throw 'Source verification failed.' }
Get-Content -LiteralPath (Join-Path $evidence 'build.log') -Tail 8
