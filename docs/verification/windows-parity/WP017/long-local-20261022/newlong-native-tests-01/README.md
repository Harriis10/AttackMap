# Focused new local-budget native console checkpoint

2026-10-23. Root granted the explicit console build slot after applying the reviewed
patch set and ending all owned live Jobs. No product/test source was edited by
this checkpoint. New `run_checkpoint.py` owns only the focused build and console
test process trees through the primary harness's Windows Job launcher.

Result: **build PASS, 0 warnings/errors; 117 offline assertions PASS**. Both child
processes exited0 without timeout and verified owned Job cleanup. Build PID1084
took10.459440s; test PID2516 took1.576054s. Source/test before/after SHA256 maps
are preserved as `inputs-before.json` / `inputs-after.json`; `changed_inputs=[]`.
`summary.json` pins logs, process proofs and built executable. No GUI, full WinUI
publish, frozen engine, HTTP/provider or model execution occurred.

Exact owner command from repository root:

```powershell
./.venv/Scripts/python.exe -B docs/verification/windows-parity/WP017/long-local-20261022/newlong-native-tests-01/run_checkpoint.py
```

The owner used the authorized elevated execution context for the known Windows
temporary-directory ACL constraint. It ran repository `.tools/dotnet/dotnet.exe
build` on `desktop/windows/NativeAiOptions.Tests/NativeAiOptions.Tests.csproj`
with `--no-restore -p:NuGetAudit=false -p:UseSharedCompilation=false
-nodeReuse:false`, then the built `NativeAiOptions.Tests.exe`.
DOTNET_ROOT and DOTNET_ROOT_X64 point at `.tools/dotnet`; DOTNET_CLI_HOME at
`.tools/dotnet-home`; NUGET_PACKAGES at `.tools/nuget-packages`. Task TEMP/TMP
were new checkpoint-owned `temp/`. Exact argv/environment and bounds are saved
in `plan.json` and per-command `started.json` / `process.json`.

The console's own terminal line is:

```text
PASS 117 WP015 offline settings/capability/secret checks; zero engine/provider dispatches
```

The initial owner invocation failed before import/build/test because its own
repository calculation used parents[5] rather than parents[6] at this extra
directory depth (`ModuleNotFoundError: No module named
'run_wp017_native_modes'`). Root was notified before correction. Only the new
evidence runner was corrected; that first invocation created no source snapshots,
native process or test output. The successful invocation above is the first
actual build/test in this checkpoint. The earlier tool output retains the import
failure; this paragraph records it rather than pretending it was a test failure.

Coverage includes unchanged defaults/wire bytes, old3600 and new7200 allowance
triplets, exact serialization and shared call/token/jury settings, QA10800 bound,
local endpoint boundary matrix, malformed arguments, saved local preference
round-trip and remote-switch rejection. It is offline validation of the linked
native models; `ProviderSettingsView.cs` was hash-tracked but the WinUI control
and its longer label were not compiled or visually accepted by this console
project. No evidence here repairs or closes the prior Triage teardown failure,
five-mode live completion, accessibility, WP017 or release gates.
