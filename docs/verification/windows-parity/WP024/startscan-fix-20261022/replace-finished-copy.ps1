$ErrorActionPreference = 'Stop'
$finishedRoot = 'C:\Projects\FINISHED'
$currentDirectory = Join-Path $finishedRoot 'AttackMap-Windows-Portable-20261022'
$currentZip = Join-Path $finishedRoot 'AttackMap-Windows-Portable-20261022.zip'
$stagedDirectory = Join-Path $finishedRoot 'AttackMap-Windows-Portable-20261022-startscan-fix-staged'
$stagedZip = Join-Path $finishedRoot 'AttackMap-Windows-Portable-20261022-startscan-fix-staged.zip'
$backupDirectory = Join-Path $finishedRoot 'AttackMap-Windows-Portable-20261022-before-startscan-fix'
$backupZip = Join-Path $finishedRoot 'AttackMap-Windows-Portable-20261022-before-startscan-fix.zip'
$proofPath = [IO.Path]::GetFullPath('docs/verification/windows-parity/WP024/startscan-fix-20261022/replaced.json')
if (Test-Path -LiteralPath $proofPath) { throw 'Replacement proof already exists.' }
if ((Resolve-Path -LiteralPath $finishedRoot).Path -ne $finishedRoot) { throw 'Unexpected FINISHED root.' }
$ancestor = Get-Item -LiteralPath $finishedRoot
while ($null -ne $ancestor) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected FINISHED ancestor.' }
    $ancestor = $ancestor.Parent
}
foreach ($target in @($currentDirectory, $currentZip, $stagedDirectory, $stagedZip, $backupDirectory, $backupZip)) {
    $absolute = [IO.Path]::GetFullPath($target)
    if ((Split-Path -Parent $absolute) -ne $finishedRoot) { throw 'Replacement path escaped explicit FINISHED directory.' }
    if ((Test-Path -LiteralPath $target) -and ((Get-Item -LiteralPath $target).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Redirected replacement target.' }
}
if ((Test-Path -LiteralPath $backupDirectory) -or (Test-Path -LiteralPath $backupZip)) { throw 'Backup already exists; preserve it.' }
if (-not (Test-Path -LiteralPath $stagedDirectory) -or -not (Test-Path -LiteralPath $stagedZip)) { throw 'Verified staging is missing.' }
$currentExe = Join-Path $currentDirectory 'AttackMap.NativeSpike.exe'
if ((Get-FileHash -LiteralPath $currentExe -Algorithm SHA256).Hash -ne '8E205A86743FF6A16DBB705C4AAD6E59B4635DB91F3C8A62804C9C1F88EFA118') { throw 'Unexpected installed executable; preserve current copy.' }
if ((Get-FileHash -LiteralPath $stagedZip -Algorithm SHA256).Hash -ne '79A14E259707F89C12A2327798AF7365E2DA0DA85AAAAC78AE3DD8E143EF80DD') { throw 'Staged ZIP changed.' }
$oldApplications = @(Get-Process -Name 'AttackMap.NativeSpike' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $currentExe })
$closedPids = @($oldApplications | ForEach-Object { $_.Id })
foreach ($application in $oldApplications) {
    Stop-Process -Id $application.Id -Force -ErrorAction Stop
    if (-not $application.WaitForExit(10000)) { throw 'Old portable process did not exit.' }
}
Move-Item -LiteralPath $currentDirectory -Destination $backupDirectory
Move-Item -LiteralPath $stagedDirectory -Destination $currentDirectory
Move-Item -LiteralPath $currentZip -Destination $backupZip
Move-Item -LiteralPath $stagedZip -Destination $currentZip
$result = [ordered]@{
    replaced = $true
    destination = $currentDirectory
    zip = $currentZip
    backup_directory = $backupDirectory
    backup_zip = $backupZip
    closed_old_portable_pids = $closedPids
    native_exe_sha256 = (Get-FileHash -LiteralPath (Join-Path $currentDirectory 'AttackMap.NativeSpike.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    zip_sha256 = (Get-FileHash -LiteralPath $currentZip -Algorithm SHA256).Hash.ToLowerInvariant()
    unrelated_applications_stopped = $false
    lm_studio_stopped = $false
}
$result | ConvertTo-Json | Set-Content -LiteralPath $proofPath -Encoding utf8
$result | ConvertTo-Json
