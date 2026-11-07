#Requires -Version 7.0
[CmdletBinding()]
param(
 [string]$Executable = (Join-Path $PSScriptRoot '../desktop/windows/artifacts/native-spike/AttackMap.NativeSpike.exe'),
 [string]$Report = (Join-Path $PSScriptRoot '../.pytest_cache/m3-desktop-reference/attackmap-report.json'),
 [string]$OutputDirectory = (Join-Path $PSScriptRoot '../.pytest_cache/native-performance'),
 [ValidateRange(1,30)][int]$Launches = 30,
 [switch]$Quick,
 [ValidateRange(30,3600)][int]$TimeoutSeconds = 1800
)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$Report = (Resolve-Path -LiteralPath $Report).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$hardware = [ordered]@{ capturedAt = [DateTimeOffset]::UtcNow; os = [Environment]::OSVersion.VersionString; logicalProcessors = [Environment]::ProcessorCount; qualifyingHardware = $false; source = 'CIM and Get-PhysicalDisk; failures remain unknown' }
try {
 $computer = Get-CimInstance Win32_ComputerSystem
 $processors = @(Get-CimInstance Win32_Processor)
 $os = Get-CimInstance Win32_OperatingSystem
 $disks = @(Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,Size)
 $hardware['computer'] = $computer | Select-Object Manufacturer,Model,TotalPhysicalMemory
 $hardware['processors'] = $processors | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors
 $hardware['operatingSystem'] = $os | Select-Object Caption,Version,BuildNumber
 $hardware['disks'] = $disks
 $cores = ($processors | Measure-Object NumberOfCores -Sum).Sum
 $hardware['qualifyingHardware'] = ([int]$os.BuildNumber -ge 22000 -and $cores -ge 4 -and $computer.TotalPhysicalMemory -ge 16GB -and @($disks | Where-Object MediaType -eq 'SSD').Count -gt 0)
} catch { $hardware['hardwareInspectionError'] = $_.Exception.GetType().Name }
$results = [Collections.Generic.List[object]]::new()
for ($index=0; $index -lt $Launches; $index++) {
 $trialPath = Join-Path $OutputDirectory ('launch-{0:D2}.json' -f $index)
 if (Test-Path -LiteralPath $trialPath) { throw "Refusing stale measurement path $trialPath; choose a fresh output directory." }
 $start = [Diagnostics.ProcessStartInfo]::new($Executable)
 $start.UseShellExecute = $false
 $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
 $start.CreateNoWindow = $true
 foreach($argument in @('--performance-smoke',$Report,$trialPath)) { $start.ArgumentList.Add($argument) }
 # Only first process runs the complete latency/cycle suite; others establish fresh launch samples.
 $full = ($index -eq 0 -and -not $Quick)
 $start.Environment['ATTACKMAP_PERF_LOAD_TRIALS'] = $(if($full){'30'}else{'1'})
 $start.Environment['ATTACKMAP_PERF_SAMPLES'] = $(if($full){'100'}else{'1'})
 $start.Environment['ATTACKMAP_PERF_CYCLES'] = $(if($full){'100'}else{'1'})
 $process = [Diagnostics.Process]::Start($start)
 if (-not $process.WaitForExit($TimeoutSeconds*1000)) {
  $process.CloseMainWindow() | Out-Null
  $closed = $process.WaitForExit(10000)
  throw "Native performance process $($process.Id) timed out; graceful close confirmed=$closed. No forced descendant termination attempted."
 }
 if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $trialPath)) { throw "Launch $index did not produce a successful measurement artifact." }
 $trial = Get-Content -LiteralPath $trialPath -Raw | ConvertFrom-Json
 $results.Add($trial)
 Write-Output "Measured native launch $($index+1)/$Launches; failures=$(@($trial.failures).Count)."
 $process.Dispose()
}
function Get-P95([double[]]$Values) {
 if($Values.Count -eq 0){return $null}
 $sorted = @($Values | Sort-Object)
 return $sorted[[int][Math]::Ceiling($sorted.Count*.95)-1]
}
function Compare-Target($Value,$Maximum) { if($null -eq $Value){return $null}; return $Value -le $Maximum }
$first = $results[0]
$startup = @($results | ForEach-Object processStartToLoadedMilliseconds)
$exactCounts = ($Launches -eq 30 -and -not $Quick -and $first.completeSamples -and @($results | Where-Object { @($_.failures).Count -gt 0 }).Count -eq 0)
$qualifying = ($hardware.qualifyingHardware -and @($results | Where-Object { -not $_.platformQualifying -or -not $_.referenceFixture }).Count -eq 0)
$summary = [ordered]@{
 harnessVersion='native-windows-performance/v1'; generatedAt=[DateTimeOffset]::UtcNow; executable=$Executable;
 executableSha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant(); report=$Report;
 hardware=$hardware; freshLaunchCount=$Launches; quickMode=[bool]$Quick; exactProtocolCounts=$exactCounts;
 qualifyingHost=$qualifying; acceptance='unaccepted: Loaded marker does not prove primary-action readiness; visual/accessibility/workflow gates remain separate';
 p95ProcessStartToLoadedMilliseconds=(Get-P95 $startup); p95ReportMilliseconds=$first.p95LoadMilliseconds;
 p95FilterMilliseconds=$first.p95FilterMilliseconds; p95DetailMilliseconds=$first.p95DetailMilliseconds;
 loadedUiWorkingSetBytes=$first.loadedWorkingSetBytes; loadedUiPrivateBytes=$first.loadedPrivateBytes;
 completedOpenCloseCycles=$first.completedCycles; retainedWorkingSetGrowthBytes=$first.retainedWorkingSetGrowthBytes; retainedPrivateGrowthBytes=$first.retainedPrivateGrowthBytes;
 targetComparisons=[ordered]@{ loadedMarkerWithin3Seconds=(Compare-Target (Get-P95 $startup) 3000); reportWithin2Seconds=(Compare-Target $first.p95LoadMilliseconds 2000); filterWithin150Milliseconds=(Compare-Target $first.p95FilterMilliseconds 150); detailWithin100Milliseconds=(Compare-Target $first.p95DetailMilliseconds 100); loadedUiMemoryWithin500MiB=($first.loadedWorkingSetBytes -le 500MB); retainedWorkingSetGrowthWithin50MiB=($null -ne $first.retainedWorkingSetGrowthBytes -and $first.retainedWorkingSetGrowthBytes -le 50MB) };
 trialArtifacts=@(0..($Launches-1) | ForEach-Object { 'launch-{0:D2}.json' -f $_ });
 limitations=@('Windows 10 evidence is provisional, irrespective of measured numbers.','No analysis worker is started; this native report-only probe has no web renderer.','Loaded timing uses process creation UTC to root Loaded probe entry; primary-action readiness is not certified.','Full load/filter/detail/cycle suite is in first process; other processes provide independent startup samples.','Retained-memory baseline/final are forced-GC-normalized; both working set and private bytes are retained.','A quick run is diagnostic and never protocol-complete.','SSD presence does not prove report/output storage uses that SSD; verify placement manually.')
}
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding utf8
$summary | ConvertTo-Json -Depth 4
