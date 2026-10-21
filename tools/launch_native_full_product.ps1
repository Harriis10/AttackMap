#requires -Version 5.1
[CmdletBinding()]
param([string]$BuildDirectory, [switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = 'desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj'
$configPath = Join-Path $workspace 'desktop/windows/full-product-launch.json'

function Assert-LocalUnredirected([string]$Path) {
    if (!$Path -or $Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[\x00-\x1f]' -or $Path.Substring(2).Contains(':')) { throw 'Choose an absolute local full-product build directory.' }
    foreach ($part in $Path.Replace('/','\').Split('\')) { if ($part -in @('.','..') -or $part.EndsWith(' ') -or $part.EndsWith('.')) { throw 'Path aliases are unsupported.' } }
    $full = [IO.Path]::GetFullPath($Path)
    $entry = Get-Item -LiteralPath $full -Force
    while ($null -ne $entry) {
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected launcher paths are unsupported.' }
        if ($entry -is [IO.FileInfo]) { $entry = $entry.Directory } else { $entry = $entry.Parent }
    }
    return $full
}

try {
    $configFile = Get-Item -LiteralPath $configPath
    if ($configFile.Length -gt 8192) { throw 'Full-product launch configuration exceeds its limit.' }
    $null = Assert-LocalUnredirected $configFile.FullName
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ($config.schema_version -ne 1 -or $config.project -cne $project -or !(Test-Path -LiteralPath (Join-Path $workspace $project) -PathType Leaf)) { throw 'Full-product project identity is invalid.' }
    $explicit = ![string]::IsNullOrWhiteSpace($BuildDirectory)
    if (!$explicit) {
        if (!$config.directory -or $config.exe_sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $config.dll_sha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'No verified full-product build is selected. The release owner must set full-product-launch.json, or pass an explicit full-product build directory.' }
        $BuildDirectory = [string]$config.directory
    }
    $directory = (Assert-LocalUnredirected $BuildDirectory).TrimEnd('\','/')
    if (!(Test-Path -LiteralPath $directory -PathType Container)) { throw 'Full-product directory is unavailable.' }
    $allowed = @((Join-Path $workspace 'artifacts'), (Join-Path $workspace 'desktop/windows/artifacts'))
    if (!($allowed | Where-Object { $directory.StartsWith($_.TrimEnd('\','/') + '\', [StringComparison]::OrdinalIgnoreCase) })) { throw 'Choose a full-product build beneath this workspace artifacts directory.' }
    if ($directory -match '(?i)(^|[\\/])WP[0-9]+Preview([\\/]|$)') { throw 'A component preview is not the full product.' }
    foreach ($required in @('AttackMap.NativeSpike.exe','AttackMap.NativeSpike.dll','AttackMap.NativeSpike.runtimeconfig.json','AttackMap.NativeSpike.deps.json','coreclr.dll','Microsoft.UI.Xaml.dll')) {
        $file = Join-Path $directory $required
        if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "Full-product runtime file missing: $required" }
        $null = Assert-LocalUnredirected $file
    }
    $depsPath = Join-Path $directory 'AttackMap.NativeSpike.deps.json'
    if ((Get-Item -LiteralPath $depsPath).Length -gt 8MB) { throw 'Full-product dependency metadata exceeds its limit.' }
    $deps = Get-Content -LiteralPath $depsPath -Raw | ConvertFrom-Json
    $entries = @($deps.libraries.PSObject.Properties | Where-Object { $_.Name -cmatch '^AttackMap\.NativeSpike/[^/]+$' -and $_.Value.type -ceq 'project' })
    if ($entries.Count -ne 1) { throw 'Selected payload is not the full AttackMap.NativeSpike project.' }
    $name = $entries[0].Name
    $runtimeProject = @($deps.targets.PSObject.Properties | ForEach-Object { $_.Value.PSObject.Properties | Where-Object { $_.Name -ceq $name } })
    if (!($runtimeProject | Where-Object { $_.Value.runtime.PSObject.Properties.Name -ccontains 'AttackMap.NativeSpike.dll' })) { throw 'Full-product runtime assembly identity is missing.' }
    $exe = Join-Path $directory 'AttackMap.NativeSpike.exe'
    $exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $dllHash = (Get-FileHash -LiteralPath (Join-Path $directory 'AttackMap.NativeSpike.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    if (!$explicit -and ($exeHash -ne $config.exe_sha256 -or $dllHash -ne $config.dll_sha256)) { throw 'Selected full-product bytes changed. The release owner must reverify and explicitly update both fingerprints.' }
    $selection = [ordered]@{ project=$project; directory=$directory; executable=$exe; exe_sha256=$exeHash; dll_sha256=$dllHash; selection=if($explicit){'explicit directory'}else{'exact configured build'}; validated=$true; launched=$false }
    if ($ValidateOnly) { $selection | ConvertTo-Json -Depth 4; exit 0 }
    Write-Output ("Opening full AttackMap product: " + $exe + " (DLL SHA256 " + $dllHash + ")")
    Start-Process -FilePath $exe -WorkingDirectory $directory | Out-Null
    exit 0
}
catch {
    Write-Error -Message ("AttackMap full-product launcher: " + $_.Exception.Message) -ErrorAction Continue
    exit 1
}
