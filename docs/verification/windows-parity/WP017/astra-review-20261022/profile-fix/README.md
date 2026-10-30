# Windows profile layout regression — 2026-10-22

The native installed smoke exposed a harness defect: USERPROFILE pointed at a fresh `profile`, but the harness created `profile/Local` and `profile/Roaming`. Actual Windows known-folder resolution could not find the expected `profile/AppData` hierarchy.

Only the APPDATA/LOCALAPPDATA directory strings in `tools/run_wp017_native_modes.py` were changed to `profile/AppData/Roaming` and `profile/AppData/Local`. Product engine/native code and its absolute-path guard were not changed. A new Windows-only test launches an owned Python child through the real Windows Job harness and calls SHGetKnownFolderPath for LocalAppData and RoamingAppData with normal flags. The test checks HRESULT, existing absolute paths, equality with the exported environment, containment within the task-owned profile/output and verified process cleanup.

Red command, before changing the runner:

```powershell
.venv\Scripts\python.exe -B -m pytest tests/test_wp017_native_runner.py::OwnedProcessTests::test_child_known_folders_resolve_inside_isolated_profile -q -s -p no:cacheprovider --junitxml docs/verification/windows-parity/WP017/astra-review-20261022/profile-fix/red.xml
```

Result: exit 1, both known-folder subtests failed with HRESULT -2147024893 (`0x80070003`, path not found) and empty paths. The probe child itself exited 0 and its owned job cleanup was verified. Full stdout/stderr and test assertions are retained in `red.log`; `red-exit.txt` preserves the test process exit.

Green command, after the two-path fix:

```powershell
.venv\Scripts\python.exe -B -m pytest tests/test_wp017_native_runner.py -q -s -p no:cacheprovider --junitxml docs/verification/windows-parity/WP017/astra-review-20261022/profile-fix/green.xml
```

Result: exit 0, **30 passed and 25 subtests passed in 3.63 seconds**. Both known-folder HRESULTs were 0 and their existing paths exactly matched the redirected environment. Full test output including actual known-folder paths and owned process proof is retained in `green.log`. The tests used approved execution outside the restrictive sandbox because the existing TemporaryDirectory ACL behavior prevents these Windows tests there.

`result.json` records final harness/test hashes and the subsequent read-only source/package recheck. The complete current release source digests still match the existing lock; the runner is excluded from release inputs. The same pinned RequiredBundled package passed all 821 inventory checks. `git diff --check` passed for the edited runner/test files.

No actual product application, provider, build or installation was launched for this fix. All owned test processes exited and the slot was released immediately after the focused tests. The actual installed smoke must be repeated with a new evidence root. This establishes the two tested known folders on this host; it does not assert that Windows GetFolderPath(UserProfile) is redirected or prove human GUI/clean-host acceptance. Earlier failed evidence remains intact.
