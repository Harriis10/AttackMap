# WP043 chained window-enumeration failure evidence — 2026-10-31

This is a bounded harness diagnostic correction. It does not change native rendering, accepted-frame safety, or WP043/release acceptance. No new live capture was run.

## Reviewed defect and correction

`WindowEnumerationError` is a `FrameSafetyError`/`RuntimeError` subtype. `_require_safe` wraps it while qualifying the owned window, and a post-grab qualification failure is wrapped again after recording the discarded frame. The run-level serializer previously checked only the outer exception, losing structured EnumWindows diagnostics on these paths.

The serializer now follows explicit exception causes and reads API, stage, Win32 error, HWND and original callback cause from the first `WindowEnumerationError`. The outer failure type/message and discarded-frame handling remain intact. The enumeration implementation still rejects partial lists.

The focused regression injects a callback enumeration failure inside the real `_require_safe`, before and after the first grab. Both subcases require failed status, zero accepted captures, expected discarded-frame count, complete structured fields, and the same error fields in persisted `evidence.json`.

## Verification attempted and blocker

Exact targeted command, executed from the repository through `cmd.exe`:

```text
C:\Projects\INPROGRESS\AttackMap\.venv\Scripts\python.exe -m pytest tests/test_wp043_live_capture.py -q
```

Observed exit code: 1. Pytest summary: `64 failed, 28 passed, 2 warnings, 2 subtests passed in 19.65s`. This is not a passing suite or acceptance.

Both new regression subcases fail during setup, before harness execution: `make_args` cannot write `AttackMap.NativeSpike.exe` inside the Python-created temporary directory (`PermissionError: [Errno 13] Permission denied`). Cleanup also reports WinError 5. The suite reports the same filesystem denial across existing temporary-file tests and cache-write warnings. Representative new-test path: `C:\Users\PRECIS~1\AppData\Local\Temp\tmpimo2e63d\AttackMap.NativeSpike.exe` (post-grab subcase). No assertion bypass or alternate fake implementation was used.

PowerShell execution attempts produced no output and were stopped; the command above used `cmd.exe` and completed. Node child-process execution was also unavailable (`spawn EPERM`). The focused regression must be rerun successfully in a host context that permits its ordinary temporary-file writes before any live capture is attempted.

## Explicit-cause cycle correction and verification

Follow-up review found that legal self-referential or mutually referential `__cause__` chains could leave the serializer looping before cleanup and evidence persistence. Error serialization is now in `_error_details`; it tracks exception identities and visits each explicit cause at most once. It does not inspect `__context__`. The original outer type/message remain the reported failure, and ordinary wrapper chains still retain the first `WindowEnumerationError` API, stage, Win32 error, HWND, and callback cause.

Two added tests require no temporary files. They cover self/mutual cause cycles and an unrelated explicit-cause chain, all with an enumeration error in context that must be ignored, plus an ordinary two-wrapper enumeration chain with complete structured fields.

The exact full targeted command above was rerun through `cmd.exe`: exit code 1; `64 failed, 30 passed, 2 warnings, 5 subtests passed in 18.65s`. The temporary-filesystem blocker remains: a representative failure is `PermissionError: [Errno 13] Permission denied: 'C:\Users\PRECIS~1\AppData\Local\Temp\tmphn69itst\AttackMap.NativeSpike.exe'`; cleanup reports WinError 5 and pytest cache writes are also denied. This is not a passing suite.

The new in-memory serializer regressions were then run separately:

```text
C:\Projects\INPROGRESS\AttackMap\.venv\Scripts\python.exe -m pytest tests/test_wp043_live_capture.py -q -k error_details
```

Observed exit code: 0; `2 passed, 74 deselected, 1 warning, 3 subtests passed in 0.19s`. The warning is the denied pytest cache write. No live capture was run; the full focused suite must pass before one is attempted. Native rendering, WP043 and release acceptance remain unchanged.

## Test-fixture executable and no-cache full-suite retry

Review confirmed that `FakeBackend.launch` never executes `command[0]` and only
reads the supplied report at `command[2]`. Production `_strict_file` requires an
existing regular file and the harness hashes it; it does not require an `.exe`
suffix. The test helper now uses its own existing source file as the inert
executable input rather than writing a dummy `.exe`. The report remains a real
JSON file in the temporary directory. The existing executable-identity assertion
now requires that exact source path and SHA-256 instead of only a 64-character
hash. Production validation, capture artifacts and accepted-frame gates are
unchanged.

The full requested suite was run through `cmd.exe` with the pytest cache disabled:

```text
C:\Projects\INPROGRESS\AttackMap\.venv\Scripts\python.exe -m pytest tests/test_wp043_live_capture.py -q -p no:cacheprovider
```

Observed exit code: 1; `64 failed, 30 passed, 5 subtests passed in 26.13s`.
The first fixture write now fails at `make_args` line 316 while creating
`C:\Users\PRECIS~1\AppData\Local\Temp\tmpe0bm3fg9\attackmap-report.json`:
`PermissionError: [Errno 13] Permission denied`. Temporary-directory cleanup also
fails with WinError 5. The before/after-grab enumeration regression subcases reach
the same report-write failure before calling `run`; the exact source-path/hash
assertion consequently did not execute. The failure therefore persists for
ordinary temporary files after removing dummy executable creation. Cache warnings
were absent in this no-cache run. This is not a passing suite and does not close
the host filesystem blocker. No assertions were bypassed and no new live capture
was attempted.
