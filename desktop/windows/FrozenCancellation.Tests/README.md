# Frozen cancellation probe

Standalone Windows console harness links the production `EngineSession` and contracts without changing them. Run from the repository root with an absolute verified frozen `attackmap.exe`, a fresh absolute proof path, cycle count (1–50), and synthetic Python file count (32–4000):

```powershell
$env:DOTNET_CLI_HOME = Join-Path (Get-Location) '.pytest_cache/dotnet-home'
$env:NUGET_PACKAGES = Join-Path (Get-Location) '.pytest_cache/nuget-packages'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
.pytest_cache/dotnet/dotnet.exe run --project desktop/windows/FrozenCancellation.Tests/FrozenCancellation.Tests.csproj --configuration Release -- C:\absolute\attackmap.exe C:\absolute\fresh-proof.json 50 2000
```

The bounded fixture stays in a unique owned TEMP directory. AI/CVE are disabled and only the installed `python` analyzer is selected. Before cancellation, UTF-8 CIM snapshots identify the direct owned broker and its actual `desktop-worker --engine --request` descendant. The staged request must match the original run/repository identity. Image/creation identities are checked while acquiring retained process handles; all observed owned handles must exit. The harness uses production Cancel/Disconnect only, with no termination hooks.

API return latency and observed process-tree exit latency are separate measurements. Natural completion before identity proof is explicitly unsampled and stops the campaign without retries. After the sequential campaign, twenty barrier-synchronized calls on one session must produce one request/start and nineteen rejections.

This is ordinary backend cancellation evidence, not UI acknowledgement, stubborn-descendant containment, Narrator, reference-machine performance, or final-package acceptance. Descendants created after the identity snapshot are outside direct handle observation; production verified cleanup is also required.
