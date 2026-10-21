$ErrorActionPreference='Stop'
$proofRoot=[IO.Path]::GetFullPath('docs/verification/windows-parity/WP021/native-full-shell-l-frozen-20261021-04')
$started=Get-Content -LiteralPath (Join-Path $proofRoot 'process-started.json') -Raw | ConvertFrom-Json
$expectedExe=[IO.Path]::GetFullPath('desktop/windows/artifacts/integrated-20261021-l/AttackMap.NativeSpike.exe')
if ($started.executable -ne $expectedExe -or !$started.arguments.Contains('--parity-smoke')) { throw 'Not the owned verification instance.' }
$target=Get-Process -Id $started.pid -ErrorAction SilentlyContinue
$record=[ordered]@{reason='Weekly usage 50 percent pause; incomplete journey is not accepted';pid=$started.pid;already_exited=($null -eq $target);closed_gracefully=$null;forced=@();owned_descendants=@();owned_survivors=@()}
if ($null -ne $target) {
    if ($target.Path -ne $expectedExe -or [Math]::Abs(($target.StartTime.ToUniversalTime()-[DateTime]::Parse($started.started_utc).ToUniversalTime()).TotalSeconds) -gt 2) { throw 'Process identity changed; refusing stop.' }
    $snapshot=@(Get-CimInstance Win32_Process)
    $ids=[Collections.Generic.HashSet[uint32]]::new()
    [void]$ids.Add([uint32]$started.pid)
    do {
        $added=$false
        foreach($entry in $snapshot) {
            if($ids.Contains([uint32]$entry.ParentProcessId) -and $ids.Add([uint32]$entry.ProcessId)) {$added=$true}
        }
    } while($added)
    $owned=@($snapshot | Where-Object {$ids.Contains([uint32]$_.ProcessId)})
    $record.owned_descendants=@($owned | Select-Object ProcessId,ParentProcessId,CreationDate,ExecutablePath)
    $record.closed_gracefully=$target.CloseMainWindow()
    if(!$target.WaitForExit(10000)) {$target.Kill($true); [void]$target.WaitForExit(10000); $record.forced+=@($started.pid)}
    foreach($entry in $owned) {
        $live=Get-Process -Id $entry.ProcessId -ErrorAction SilentlyContinue
        if($null -ne $live -and [Math]::Abs(($live.StartTime.ToUniversalTime()-$entry.CreationDate.ToUniversalTime()).TotalSeconds) -lt 2) {
            $live.Kill($true); [void]$live.WaitForExit(10000); $record.forced+=@($entry.ProcessId)
        }
    }
    $record.owned_survivors=@(foreach($entry in $owned) {
        $live=Get-Process -Id $entry.ProcessId -ErrorAction SilentlyContinue
        if($null -ne $live -and [Math]::Abs(($live.StartTime.ToUniversalTime()-$entry.CreationDate.ToUniversalTime()).TotalSeconds) -lt 2) {$entry.ProcessId}
    })
}
$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $proofRoot 'pause-cleanup.json') -Encoding utf8
if($record.owned_survivors.Count) {throw 'Owned verification survivors remain.'}
$record | ConvertTo-Json -Depth 5
