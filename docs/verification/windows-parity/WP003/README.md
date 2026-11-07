# WP003 — capabilities and raw request preflight

Changes share CLI schema-1 capability generation and installed module records with read-only `capabilities` / `preflight` desktop actions. CLI flags come from actual Typer registration; desktop request/provider fields come from typed contracts. Desktop explicitly advertises single-repository `none` / `review` with the API backend, distinct from broader CLI modes.

Executable content hashes bind capability identity. Source execution additionally binds relevant source files; installed analyzer inventory contributes a digest. A changed expected identity returns `engine_changed`, requiring rediscovery. This is cache invalidation, not publisher authentication. Preflight performs no fallback command launch, installation, repository scan, provider check, or model call.

Parent granted a narrow additional lease on `desktop_worker.py` solely for validating raw request data before `RunRequest` parsing, repository checks and dispatch. Both supported run schemas 1.0/1.1 remain accepted. Unknown envelope metadata retains existing additive behavior; unknown scan/provider options and reserved unwired top-level feature names fail with a generic input-free error. No run-contract models or fixtures changed.

Focused command:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_desktop_capabilities.py tests/test_capabilities.py tests/test_desktop_actions.py -q --basetemp=docs/verification/windows-parity/WP003/pytest-tmp -p no:cacheprovider
```

Initial attempt: 9 passed, 34 setup errors because the WP003 evidence parent directory had not yet been created. Second run with the parent present and a distinct `pytest-tmp-retry` reached sandbox `PermissionError [WinError 5]` in temporary-directory access and final cleanup (`cleanup_dead_symlinks` / `os.scandir`), exit 1. Raw output is `pytest-retry.log`. No ACL changes were attempted. Root was asked to run the focused tests with approved execution and another unique temporary directory, adding existing desktop-worker/run-contract regressions. Until that run completes, full test acceptance is pending.

Frozen-action coverage toggles the existing `sys.frozen` transport branch under tests. It is not a newly built or installed frozen executable. The retained packages were preserved; they predate this implementation. Native UI consumption belongs to subsequent parity tasks. No live AI/provider result is claimed.

The first approved root regression run reported **71 passed, 16 failed**. All 16 failures were the new rejection tests expecting exit 1, while the existing invalid-request contract returns exit 2. Assertions were corrected to preserve that product exit behavior. Dispatch mocks explicitly assert that `serve`, `run_scan`, and provider execution were never called. Final rerun result is recorded below when available.

Final approved run: **87 passed in 245.42 seconds**, exit 0. Command included `tests/test_desktop_capabilities.py`, `tests/test_capabilities.py`, `tests/test_desktop_actions.py`, `tests/test_desktop_worker.py`, and `tests/test_run_contract.py`, using `--basetemp=docs/verification/windows-parity/WP003/pytest-tmp-approved-fixed -p no:cacheprovider --tb=short`. Raw output: `pytest-final.log`; machine-readable summary and source hashes: `verification.json`. Python syntax and changed-file whitespace checks also passed.
