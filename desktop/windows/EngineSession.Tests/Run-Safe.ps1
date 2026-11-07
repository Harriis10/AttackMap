param(
    [Parameter(Mandatory=$true)][string]$Dotnet,
    [Parameter(Mandatory=$true)][string]$Broker,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [ValidateRange(30,600)][int]$SuiteTimeoutSeconds = 180
)
$ErrorActionPreference = 'Stop'
$Dotnet = (Resolve-Path -LiteralPath $Dotnet).Path
$Broker = (Resolve-Path -LiteralPath $Broker).Path
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
[IO.Directory]::CreateDirectory($evidence) | Out-Null
$testDll = Join-Path $PSScriptRoot 'bin/Release/net8.0/EngineSession.Tests.dll'
if (!(Test-Path -LiteralPath $testDll)) { throw 'Build EngineSession.Tests Release before running.' }
Add-Type @'
using System.Runtime.InteropServices;
public static class SessionTestErrorMode {
    [DllImport("kernel32.dll")] public static extern uint SetErrorMode(uint mode);
}
'@
$oldMode = [SessionTestErrorMode]::SetErrorMode(0x8003)
try {
    $runs = @()
    foreach ($testCase in @(
        @{ Name='missing-arguments'; Arguments=@(); Expected=2 },
        @{ Name='missing-broker'; Arguments=@((Join-Path $evidence 'does-not-exist.exe')); Expected=2 },
        @{ Name='session-suite'; Arguments=@($Broker, (Join-Path $evidence 'session-results-recovered.json')); Expected=0 }
    )) {
        $start = [Diagnostics.ProcessStartInfo]::new($Dotnet)
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.WorkingDirectory = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
        $start.Environment['DOTNET_ROOT'] = Split-Path $Dotnet
        $start.ArgumentList.Add($testDll)
        foreach ($argument in $testCase.Arguments) { $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::Start($start)
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timeoutSeconds = if ($testCase.Name -eq 'session-suite') { $SuiteTimeoutSeconds } else { 60 }
        $timedOut = !$process.WaitForExit($timeoutSeconds * 1000)
        if ($timedOut) {
            $process.Kill($true)
            if (!$process.WaitForExit(10000)) { throw "Timed out harness process did not exit: $($process.Id)" }
        }
        if (!$stdout.Wait(10000) -or !$stderr.Wait(10000)) { throw "Harness output pipes did not close: $($process.Id)" }
        $stdout.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $evidence ($testCase.Name + '.stdout.log'))
        $stderr.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $evidence ($testCase.Name + '.stderr.log'))
        $runs += @{ name=$testCase.Name; pid=$process.Id; exit_code=$process.ExitCode; expected_exit=$testCase.Expected; timed_out=$timedOut; timeout_seconds=$timeoutSeconds; exited=$process.HasExited }
        $runs | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidence 'harness-runs.json')
        Write-Output "$($testCase.Name): exit $($process.ExitCode), timeout $timedOut"
        if ($timedOut -or $process.ExitCode -ne $testCase.Expected) { throw "Harness case failed: $($testCase.Name)" }
        $process.Dispose()
    }
}
finally { [SessionTestErrorMode]::SetErrorMode($oldMode) | Out-Null }
