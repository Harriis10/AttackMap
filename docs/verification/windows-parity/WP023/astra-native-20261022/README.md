# WP023 native regression checkpoint — Astra/high, 2026-10-22

Initial source: `258adf66a9ec3c5a691868ae67c3a73b08b92c4a`; tracked tree clean at inventory time.
Authority: current `docs/README.md`, Windows parity roadmap, WP023 TODO/backlog,
and `RESUME-2026-10-22/astra-high/README.md`. This is scoped checkpoint evidence,
not WP023 completion or GUI/provider/release acceptance.

## Actual result

**PASS: 26 consumer suites / 1,134 explicit assertions, plus all 31 controlled
cases across 3 process suites (9 + 8 + 14).** Executed after explicit integrator
GO, from 11:07:19 to 11:11:15 UTC on 2026-10-22. All 61 command invocations
returned zero, none timed out, and every owned Windows Job was empty before
close. Cumulative command duration was 234.822 seconds. All 31 builds used
existing assets; no restore, download or installation was needed.

`summary.json` records 29 completed suites and zero changes across all 1,082
input hashes. `suite-results.json` stores actual count lines and controlled
proof identities; `commands.json` stores command arrays, PIDs, timestamps,
durations, exit codes and stdout/stderr hashes. `compiled-payloads.json` binds
155 compiled files (including DLLs/runtime metadata), and staged broker hashes
are separately retained. `.NET SDK 8.0.426` was used (see `dotnet-version.stdout.txt`).

NativeOptions has 63 checks versus the historical 54; the other 25 console
counts are unchanged. Historical outcomes were not reused. The 31 controlled
cases all appear as passing in fresh proof JSON with no fault-composition gaps.

The execution source identity includes the already-present WP017 runner/test
review changes and root documentation changes; HEAD alone is not claimed as a
clean snapshot. `source-identity.json` records the exact tracked status, and the
before/after manifests prove that all scoped source/test/tool inputs remained
unchanged throughout execution. No implementation or canonical documentation
was changed by this agent. The build/test slot was returned to root immediately
after successful completion.

## Inventory and execution

`plan.json` classifies all 34 current `desktop/windows/*.Tests` projects and
contains exact command arrays and process-local environment overrides.
`inputs-prepared.json` hashes tracked native, engine, test, tool and installer
inputs before execution permission. Execution captures separate before/after
identities, command logs, exit codes, elapsed times, actual assertion/case counts,
binary and broker hashes, and owned Windows Job cleanup results.

Preparation (no dotnet, test, GUI, provider or engine launch):

```powershell
.venv/Scripts/python.exe docs/verification/windows-parity/WP023/astra-native-20261022/run-checkpoint.py
```

Execution, **only after integrator releases the native build/test slot**:

```powershell
.venv/Scripts/python.exe docs/verification/windows-parity/WP023/astra-native-20261022/run-checkpoint.py --run
```

Each project uses the repository `.tools/dotnet/dotnet.exe`,
`.tools/dotnet-home` and `.tools/nuget-packages`. Build uses `--no-restore`,
`-p:NuGetAudit=false`, `-p:UseSharedCompilation=false`, `-nodeReuse:false`;
there is no SDK/package installation. If assets are absent, an explicit restore
uses only this evidence directory's empty local feed and existing package cache.
Each command has its own Windows Job; suspended startup precedes assignment.
Timeout and nonempty-job conditions fail the checkpoint. Error mode `0x8003` is
process-local and restored; machine error-reporting settings are untouched.
The runner never deletes files. Existing test programs may clean their own
temporary fixtures. `TEMP`/`TMP` are isolated under this evidence directory.

## Preserved coverage

The 26 console consumer projects exactly preserve the names from
`../native-consumers-20261021-j-b/aggregate.json` (historical 1,125 checks).
They cover launch guards, protocol, scan/AI/provider options, overview,
report sections, risk paths, inventory, diagram policy, progress/timing,
finding/source context, artifact identity/export preparation, report composition,
suppression/history, fleet/watch, AI artifacts and window placement.
New counts come from actual stdout; historical counts are not substituted.

Controlled process coverage preserves all cases from the preceding checkpoint:

| Project | Cases | Scope |
| --- | ---: | --- |
| EngineSession.Tests | 9 | schema/order, identity, cleanup/readmission, exclusivity, cancellation/disconnect/exit races, ignored EOF |
| DesktopActionRunner.Tests | 8 | result identity/hash, exclusivity, credential isolation, cancellation, cleanup timeout/admission latch |
| NativeFaultComposition.Tests | 14 | worker/action malformed/oversized/missing data, nonzero completed exit, previous-report retention in test host |

Both fake brokers are built from current sources, copied with their complete
sidecars into new evidence directories and exposed as `attackmap.exe`, preserving
the production launch guard. No guard, timing limit or assertion is relaxed.
Proof JSON must contain every expected passing case and no recorded gap.

## Separate integration gates

All remaining test projects are explicitly classified, not counted as passes:

| Project | Requirement outside this consumer run |
| --- | --- |
| FrozenRunner.Tests | Fresh source-bound frozen engine; actual scanner/export/action integration |
| FrozenCancellation.Tests | Fresh frozen engine and runtime slot; original defaults 50 cycles and 2,000 files retained |
| ProtectedProviderStore.Tests | Frozen/source integration and actual isolated Windows DPAPI storage |
| ProviderRoundtrip.Tests | Actual Python provider configuration/action processes with isolated settings |
| ReportExport.Tests | Installed Edge/Chrome headless browser PDF export; separate browser-process execution |

Production WinUI builds and component Preview projects are not consumer console
tests. Full native journeys, screenshots and visual review, five live LM Studio
modes, frozen engine integration, manual accessibility, clean host, signing and
release approval remain independent gates owned by the integrator.

## Code inspection

CodeGraph was queried first. It returned production symbols but did not surface
the top-level test programs requested by file name; those uncovered programs and
project XML were inspected directly. Current controlled tests explicitly preserve
the original cleanup deadlines. The prior controlled checkpoint's guarded broker
staging recipe was inspected and retained. Existing retained evidence was not edited.

Preparation and execution manifests are separate. Read the actual execution
summary together with its command/proof logs; prepared commands are not passes.
