# WP023 broad Python checkpoint — 2026-10-22

**PASS for the executed full default Python suite:** 4423 passed, 7 skipped,
20 subtests passed, 1 warning, zero failures/errors; pytest exit 0.
Pytest reports 853.25 seconds; the outer process duration is 855.22 seconds.
This is a Python checkpoint, not completion of WP023 or K5.

## Command and identity

```powershell
./.venv/Scripts/python.exe -m pytest tests -q --basetemp C:\Projects\INPROGRESS\AttackMap\.tmp-wp023-astra-python-20261022-02 --junitxml C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP023\astra-python-20261022\unrestricted-attempt-02\pytest-junit.xml
```

- Base HEAD: `258adf66a9ec3c5a691868ae67c3a73b08b92c4a`.
- Python 3.13.15, pytest 9.1.1, Windows 10 build 19045, existing `.venv`.
- Started 10:51:39 UTC; completed 11:05:54 UTC. No test selection filter,
  timing threshold override, new skip, or fixture/source edit was used by this agent.
- The existing venv has OpenAI/Anthropic SDKs and `httpx2`; no dependency
  bootstrap/install or live provider request was added to this run.
- `unrestricted-attempt-02/runtime.json` records Python executable SHA-256,
  installed package versions and relevant pytest environment values.
- `source-before.json` / `source-after.json` record hashes of tracked source,
  tests, installer, tools and configuration inputs. All `src/` hashes stayed
  unchanged. **The complete inventory did change:** concurrent approved edits
  touched `tests/test_wp017_native_runner.py` and `tools/run_wp017_native_modes.py`.
  The subsequent reviewer-owned focused tests validated this delta: **39 passed
  plus 23 subtests, exit 0, 3.43 s**, with hashes matching the broad run's final
  inventory. Evidence: [WP017 focused result](../../WP017/astra-review-20261022/focused-result.json).
  This broad run alone is not a claim that the final two files were tested as an
  immutable snapshot; the combined evidence is broad baseline plus focused delta.
- The pytest and wrapper processes exited; PID 23268, 6716, 29904 and 25416 were
  absent in the post-completion process check. Heavy-test slot was released to
  the reviewer for the focused delta, then the native checkpoint.

## Original scan-limit cases

All seven `tests/test_scan_limits.py` cases passed. Six contain timing assertions;
the seventh checks the environment override. Thresholds and fixture sizes were
unchanged. JUnit times below include test setup/call/teardown, not an independently
instrumented scanner-only duration; passing each original assertion proves its
internal threshold was satisfied.

| Case | Original assertion | JUnit seconds |
| --- | --- | ---: |
| Oversized file | scan < 5 s | 0.086 |
| Long word | scan < 5 s | 1.846 |
| Router assignment | scan < 5 s | 2.247 |
| Blueprint | scan < 5 s | 1.830 |
| GraphQL field | scan < 5 s | 2.201 |
| File-size environment override | no timing assertion | 0.018 |
| 6000 route matches | scan < 25 s; all 6000 routes | 8.011 |

## Seven tests not executed

These are existing test-owned skip gates, preserved without modification:

1. Two PHP plugin integration tests: `attackmap_analyzer_php_web` is not installed.
2. One live hostile-repository CLI test: requires explicit `ATTACKMAP_LIVE_CLI_TESTS=1`
   and authenticated Claude CLI. It was not enabled or replaced with a remote provider.
3. One cancellation-under-load stress test: requires `ATTACKMAP_STRESS_TESTS=1`
   and its approximately 5000-file fixture. This opt-in campaign was not run.
4. Two unreadable-file tests: Unix `chmod 000` semantics are not enforced on Windows.
5. One export symlink test: Windows symlink creation privileges unavailable.

Exact node names, skip messages and durations are in `junit-summary.json`.
JUnit counts 4450 testcase elements including the 20 passing subtests; the ordinary
pytest summary is 4423 passed plus 7 skipped. The single warning is the deliberate
duplicate ZIP member in `test_sealed_malformed_input_is_rejected[duplicate]`.

## Retained sandbox attempt

The files directly in this directory named `command.json`, `result.json`,
`runtime.json`, `source-before.json`, `source-after.json`, and `pytest-*.log`
belong to the **first, aborted restricted-token attempt**, not the passing run.
It was stopped after 79.42 seconds because pytest's private basetemp ACL admitted
OWNER RIGHTS/SYSTEM/Administrators but denied the restricted execution token:
even listing that newly created directory returned `PermissionError: WinError 5`.
Only the verified owned pytest PID 32508 was terminated; its wrapper recorded
exit 4294967295 and unchanged source hashes. No directory or foreign process was
deleted. `sandbox-process.json` and `sandbox-basetemp-acl.json` retain diagnosis.

Automatic approval allowed repeating the complete suite outside the restricted
sandbox with a new basetemp. The entire passing attempt is under
`unrestricted-attempt-02/`, including separate full stdout/stderr, JUnit,
command, elapsed time, runtime and before/after source identity.

## Remaining gates

No additional full regression is required solely because this run passed; the
recorded runner delta received focused tests. Native consumer, source/frozen/native
journeys, fresh same-source package, five completed live LM Studio modes, visual
review, manual accessibility, clean host, signing, macOS and human beta evidence
remain separate gates. No such gate was executed or claimed here.

No code, fixture, test, canonical roadmap or tracker was edited by this agent.
`summary.json` is the machine-readable handoff and `evidence-sha256.json` binds
the evidence files.
