# Isolated Windows profile follow-up — 2026-10-22

Status: read-only proposal, pending the native lane's .NET 8 known-folder probe and root edit lease. No runner/product edit, test, application, install or provider execution was performed for this proposal.

Root reports that the actual installer passed and the installed native smoke stopped before capability broker startup with `Engine request path must be absolute`; owned processes were cleaned up. Therefore the earlier package/preflight pass remains byte/source consistency evidence only. It did not prove successful native startup under the supplied environment.

## Observed harness mismatch

CodeGraph confirms `tools/run_wp017_native_modes.py:235-249` sets USERPROFILE to `<evidence>/profile`, APPDATA to `<evidence>/profile/Roaming` and LOCALAPPDATA to `<evidence>/profile/Local`, creating those directories. This does not create the normal `<USERPROFILE>/AppData/{Roaming,Local}` hierarchy. Existing `test_child_environment_drops_provider_python_proxy_and_qa_overrides` checks allowlisting, PATH and APPDATA containment; it never calls Windows known-folder resolution and therefore cannot detect this failure.

The root/native lane is testing whether Windows known-folder resolution under this exact environment expands the configured USERPROFILE hierarchy and returns empty when the standard directory is absent. Do not treat this causal explanation as confirmed until that probe reports the actual paths/HRESULTs. Overriding LOCALAPPDATA by itself is not proof of what .NET `Environment.GetFolderPath` returns.

## Minimal proposed patch after confirmation

Change only the two directory names in `child_environment` to `profile/AppData/Roaming` and `profile/AppData/Local`. Keep USERPROFILE at `profile`, TEMP/TMP at `temp`, the environment allowlist, system-only PATH and owned-job launch unchanged. Existing `mkdir(parents=True)` will create the required hierarchy before launch. Do not weaken the engine absolute-path guard or alter `DesktopActionRunner` to hide a bad test profile.

## Regression that exercises the failure

Add one Windows-only owned child-process test to `tests/test_wp017_native_runner.py` beside `OwnedProcessTests`. Create a fresh output directory, obtain the actual `child_environment`, and launch a short Python child through the existing `runner.launch` and Windows Job. The child calls the Windows `SHGetKnownFolderPath` API with normal flags for both LocalAppData and RoamingAppData, then frees each returned allocation through `CoTaskMemFree`.

Assert successful HRESULT, nonempty absolute returned paths, exact equality to the child's LOCALAPPDATA/APPDATA, existence, and containment under the isolated USERPROFILE and fresh evidence root. Emit the resolved values in the retained stdout log and require successful process exit plus verified owned-job cleanup. This is an OS integration check of the boundary used by .NET, rather than an assertion that merely repeats directory literals. The native lane's .NET 8 probe remains the direct runtime corroboration. No product executable, GUI or provider is needed for this focused regression.

For causal validation, first run that new test against the unchanged mapping and preserve its failure, then apply the two directory-name changes and run the focused environment/job test selection once. Run other runner tests only if the change or a failure warrants it. Keep all prior failed install/native evidence intact; repeat real native qualification in a new evidence root after focused validation and root approval.

## Boundaries

The runner is harness code, excluded from the current release input manifest according to root's verified inventory. Recompute package identity/source lock after the harness edit to confirm the same product bytes remain qualified; no rebuild is justified solely by this harness correction. A successful known-folder probe is evidence for the tested host and child environment, not general clean-host acceptance. The separate normal-startup/human GUI acceptance remains open.
