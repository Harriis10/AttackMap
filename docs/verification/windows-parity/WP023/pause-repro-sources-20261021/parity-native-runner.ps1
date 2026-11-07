param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [string[]]$ApplicationArguments = @(),
    [switch]$LeaveOpen,
    [int]$TimeoutSeconds = 180
)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Executable).Path
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
[IO.Directory]::CreateDirectory($evidence) | Out-Null
Add-Type @'
using System.Runtime.InteropServices;
public static class NativeComparisonErrorMode {
    [DllImport("kernel32.dll")] public static extern uint SetErrorMode(uint mode);
}
'@
$oldMode = [NativeComparisonErrorMode]::SetErrorMode(0x8003)
$process = $null
try {
    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.WorkingDirectory = Split-Path $exe
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Normal
    $start.Environment['DOTNET_ROOT'] = [IO.Path]::GetFullPath('.tools/dotnet')
    foreach ($argument in $ApplicationArguments) { $start.ArgumentList.Add($argument) }
    if (!$LeaveOpen) { $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true }
    $process = [Diagnostics.Process]::Start($start)
    $record = @{ pid=$process.Id; started_utc=$process.StartTime.ToUniversalTime().ToString('O'); executable=$exe; arguments=$ApplicationArguments; left_open=[bool]$LeaveOpen }
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'process-started.json')
    if ($LeaveOpen) {
        $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'process.json')
        Write-Output "Started user-visible native application PID $($process.Id)."
    } else {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = !$process.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) { $process.Kill($true); $process.WaitForExit(10000) | Out-Null }
        if (!$process.HasExited) { throw 'Owned application cleanup unverified.' }
        $stdout.WaitAsync([TimeSpan]::FromSeconds(10)).GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $evidence 'stdout.log')
        $stderr.WaitAsync([TimeSpan]::FromSeconds(10)).GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $evidence 'stderr.log')
        $record.exit_code=$process.ExitCode; $record.timed_out=$timedOut; $record.exited=$process.HasExited
        $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'process.json')
        if ($timedOut -or $process.ExitCode -ne 0) { throw 'Native application verification failed; inspect retained evidence.' }
        Write-Output 'Native application completed; inspect its manifest and images.'
    }
} finally {
    if ($null -ne $process) {
        if (!$LeaveOpen -and !$process.HasExited) { $process.Kill($true); $process.WaitForExit(10000) | Out-Null }
        $process.Dispose()
    }
    [NativeComparisonErrorMode]::SetErrorMode($oldMode) | Out-Null
}
