# WP023 startup gate regression

Scope: opt-in compiled `--startup-smoke` only. Whole WP023 stays IN_PROGRESS.

The provider editor returns a nonnull disabled `ProviderConfiguration`. The old
gate rejected that valid AI-off state by testing `options.Provider == null`.
Root changed only that term to `options.Provider?.EnableAi != true` in shared
`MainWindow.xaml.cs`. `patch-review.json` retains both snippets and their hashes;
the subagent did not write shared shell code.

The existing settings hook reaches an enabled-AI negative without changing the
product restore flow: `--startup-smoke <settings-path>` injects a local settings
store, `RestoreLocalSettings` applies `EffectiveOptions`, `ApplyScanOptions`
passes its nonnull Provider to the editor, and `ReadScanOptions` reads that editor.
`RestoreProviderSettings` and personal `provider.json` are not needed.

`run_startup_regression.py` runs four independent native processes with fresh
allowlisted profiles: absent settings, explicit disabled provider object, enabled
AI negative, and enabled CVE negative. The two negative cases must report
`passed:false` while their restored enable flag is true. All four must exit zero,
preserve the injected settings, report no automatic scan, and have cumulative Job
`TotalProcesses == 1`. The app is assigned while suspended, so this count also
includes descendants that already exited. Scan and provider dispatch require a
descendant broker; a count of one proves none of those broker routes dispatched.
This is process accounting, not packet-level monitoring.

Root must supply a fresh native publish built from the captured patched source
with the matching frozen engine present at `engine/attackmap.exe` beside it. The
runner checks that path and never creates, repackages, replaces or launches the
engine itself. It refuses an existing output directory. Run from repository root:

```powershell
& .venv\Scripts\python.exe -B docs\verification\windows-parity\ROADMAP-NEXT-20261023\startup\run_startup_regression.py --native '<fresh-native-directory>\AttackMap.NativeSpike.exe' --output docs\verification\windows-parity\ROADMAP-NEXT-20261023\startup\runtime-01
```

The fresh native path must replace the explicit placeholder above. Root owns the
native publish/runtime slot. No runtime execution was performed by this subagent
when this runner was prepared. Native/DLL/engine identities are recorded before
and after execution; root's captured-source/build proof provides the complete
source-to-payload binding.

Focused pure consumer verification: `.tools/dotnet/dotnet.exe run --project
desktop/windows/NativeAiOptions.Tests/NativeAiOptions.Tests.csproj
--artifacts-path docs/verification/windows-parity/ROADMAP-NEXT-20261023/startup/native-ai-options-build
--no-launch-profile -p:NuGetAudit=false -p:UseSharedCompilation=false
-p:RestoreIgnoreFailedSources=true` exited 0 and reported 121 offline
settings/capability/secret checks PASS, zero engine/provider dispatches. This does
not prove the compiled startup gate; the runtime runner is the intended gate.

No normal personal-profile startup, manual visual/accessibility, clean-host,
signing, package acceptance, full WP023 or macOS acceptance is claimed.
# Integrator result after agent handoff

Root's final source03 native build passed all **four compiled startup scenarios**.
Cumulative Windows Job accounting records exactly one process per case and owned
cleanup, with no broker dispatch. The complete staged native+retained-engine
payload (799 files) stayed unchanged. See [actual runtime proof](runtime-03/summary.json),
[root integrity proof](../checkpoint-integrity.json) and [final handoff](../FINAL-HANDOFF.md).
The earlier agent preparation below does not itself claim this later runtime.

