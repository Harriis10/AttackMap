#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NativeExe,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateRange(1,1000)][int]$Launches = 30
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'This probe requires Windows.' }
$native = (Get-Item -LiteralPath $NativeExe).FullName
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Use a fresh output directory; existing results are preserved.' }
New-Item -ItemType Directory -Path $output | Out-Null
$samples = [Collections.Generic.List[object]]::new()
for ($trial = 0; $trial -lt $Launches; $trial++) {
    $proof = Join-Path $output ('launch-{0:d3}.json' -f $trial)
    $start = [Diagnostics.ProcessStartInfo]::new($native)
    $start.UseShellExecute = $false
    $start.WorkingDirectory = Split-Path -Parent $native
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.CreateNoWindow = $true
    $start.ArgumentList.Add('--readiness-smoke')
    $start.ArgumentList.Add($proof)
    $process = [Diagnostics.Process]::Start($start)
    if (!$process.WaitForExit(30000)) {
        @{ status='incomplete_process_live'; pid=$process.Id; trial=$trial; noRestartOrKill=$true } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'incomplete.json')
        throw "Original PID $($process.Id) remains active; inspect it before any follow-up."
    }
    $exitCode = $process.ExitCode
    $process.Dispose()
    if ($exitCode -ne 0) { throw "Readiness process exited $exitCode; inspect $proof." }
    $sample = Get-Content -LiteralPath $proof -Raw | ConvertFrom-Json
    if (!$sample.passed -or $null -eq $sample.processStartToPrimaryResponseMilliseconds) {
        throw "Readiness assertion failed; inspect $proof."
    }
    $samples.Add($sample)
}
$times = @($samples | ForEach-Object { [double]$_.processStartToPrimaryResponseMilliseconds } | Sort-Object)
$p95 = $times[[int][Math]::Ceiling($times.Count * .95) - 1]
$computer = Get-CimInstance Win32_ComputerSystem
$cores = (Get-CimInstance Win32_Processor | Measure-Object NumberOfCores -Sum).Sum
@{
    scope='Fresh primary Start scan AutomationPeer response to missing repository; no OS-picker or manual acceptance'
    nativeExe=$native
    nativeDllSha256=(Get-FileHash -LiteralPath (Join-Path (Split-Path -Parent $native) 'AttackMap.NativeSpike.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    measuredUtc=[DateTime]::UtcNow.ToString('o')
    os=[Environment]::OSVersion.VersionString
    physicalCores=$cores
    ramBytes=$computer.TotalPhysicalMemory
    windows11=([Environment]::OSVersion.Version.Build -ge 22000)
    launches=$samples.Count
    exactLaunchCount=($samples.Count -eq 30)
    p95PrimaryResponseMilliseconds=$p95
    numericThreeSecondTargetMet=($p95 -le 3000)
    outputDirectory=$output
    acceptedC26=$false
    limitations=@('Missing-repository response only; no Choose repository OS picker.', 'Record storage placement, concurrent workloads and hardware qualification separately.', 'No report/interaction/memory or manual workflow acceptance from this probe.')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'readiness-summary.json')
Get-Content -LiteralPath (Join-Path $output 'readiness-summary.json')
