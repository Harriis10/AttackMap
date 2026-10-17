# Windows desktop development

Windows M3 is accepted as a functional beta with documented limitations. The
WinUI shell uses the shared Python engine for analysis, supervision and report
publication. Remaining manual UX/accessibility and participant validation is in
M4; see the [acceptance ledger](../../docs/windows-m3-acceptance.md).

## Current build

The retained package is `artifacts/development-packages/dev-20261015190038-5667bbbf.zip`.
Its extracted application is in the adjacent directory under
`app/AttackMap.NativeSpike.exe`, with the frozen engine in `app/engine`.
Do not write QA output into this immutable package or overwrite it with a publish.
Installation and rollback are described in
[Windows development package](../../docs/windows-development-package.md).

## Toolchain and build

Use .NET 8, Windows App SDK 2.4.0, compatible Visual Studio XAML build tools,
and Windows SDK 10.0.19041 or newer. The local SDK and restored NuGet packages
were retained during cleanup, outside disposable pytest output:

```powershell
$env:DOTNET_CLI_HOME = "$PWD/.tools/dotnet-home"
$env:NUGET_PACKAGES = "$PWD/.tools/nuget-packages"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$dotnet = "$PWD/.tools/dotnet/dotnet.exe"
& ./.venv/Scripts/python.exe desktop/windows/generate_fixture.py
& $dotnet publish desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj -c Release -p:Platform=x64 --self-contained true -o desktop/windows/artifacts/native-spike
```

On another machine, use its installed .NET 8 SDK and normal NuGet cache instead.
The fixture generator creates synthetic UI data; it does not analyze a repository.
`bin/`, `obj/` and `artifacts/native-spike/` are disposable build outputs. Restore
will recreate project assets after cleanup. Packaging uses
`tools/package_native_windows.ps1`; bundle a frozen engine only with matching
engine verification metadata as specified in the package guide.

## Focused tests

Keep tests that exercise real production behavior, including those using small
fixtures or fake brokers to inject faults. They do not prove an HTTP model call.

- Python tests under `tests/`: core analysis, evidence/citations, budgets,
  cancellation, atomic publication, privacy, comparison and suppression.
- `EngineProtocol.Tests`, `EngineSession.Tests`, `NativeFaultComposition.Tests`:
  protocol and lifecycle handling, including invalid and reordered events.
- `ReportAdapter.Tests`, `SelectedArtifacts.Tests`, `SourceLocation.Tests`,
  `C23ReportComposition.Tests`: report integrity, exact selected-run export,
  source changes and uncertainty.
- `ReportExport.Tests`: rendered review export — HTML conversion with escaping
  and the severity palette, verified Markdown read, and a real local
  headless-browser PDF print with candidate fallback.
- Remaining focused native projects cover settings, credentials, launch,
  rendering adapters and window state. `ControlledFakeBroker` and
  `NativeFaultBroker` are fault-injection fixtures, not production analyzers.

For example, from the root with the toolchain environment above:

```powershell
& ./.venv/Scripts/python.exe -m pytest tests/test_narrative_citations.py -q
& $dotnet run --project desktop/windows/SelectedArtifacts.Tests
```

Use the smallest relevant set while changing code. Run broad verification at a
stable checkpoint, not after every small edit. Keep runtime output under
`.pytest_cache/`; remove completed disposable runs instead of accumulating copies
of the application runtime and Python environments.

## Real local-model integration

Target `C:\tmp\juice-shop`; write output outside that repository. Use only
`http://127.0.0.1:1234/v1` and `cyberstag-security-26b-a4b-v1` unless the user
requests another provider. AI and CVE lookup are optional and off by default.
Personal settings and credentials must stay separate from test settings.

The latest completed real integration evidence is retained in
[verification/retained-m3](verification/retained-m3/README.md). It includes the
actual report generation, AI Markdown/metadata, broker transcript, final build
proofs and final content screenshots. The relocation manifest maps original
historical paths to exact-byte retained copies. Old preview runtimes and repeated
QA outputs were removed on 2026-10-16. Do not infer a fresh verification run from
those historical artifacts.

A successful build, fake-broker check or internal UI assertion does not establish
visual appearance, keyboard usability or Narrator behavior. GUI changes require
a visible preview and actual visual review; remaining beta manual checks are
tracked in M4.
