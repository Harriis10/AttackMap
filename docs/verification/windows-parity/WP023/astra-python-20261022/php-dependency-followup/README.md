# PHP dependency follow-up — 2 PASS

Executed after root GO and completion of the native heavy-test slot:
**2 passed in 1.25 s, exit 0**. The outer process took 2.28 s, from 11:12:05
to 11:12:07 UTC on 2026-10-22. Current source hashes were identical before and
after execution. The process completed and the slot was released immediately
to root for native publish/freeze. This supplements the two dependency skips in
the broad Python run without changing its historical result or the remaining
five skips.

Exact cases:

```text
tests/test_analyzers.py::test_discover_installed_analyzers_includes_php_web_when_installed
tests/test_analyzers.py::test_analyze_repository_uses_installed_php_web_analyzer_for_php_routes
```

Executed command, from the repository root in the approved execution context:

```powershell
./.venv/Scripts/python.exe docs/verification/windows-parity/WP023/astra-python-20261022/php-dependency-followup/run_followup.py
```

The wrapper uses the exact subprocess argument array saved in `preparation.json`:
the existing `.venv` Python, `sys.path.insert(0, .../.tools/wp024-freeze-venv/Lib/site-packages)`,
then `pytest.main()` with the two node IDs, `-q`, a fresh basetemp and JUnit output.
Separate stdout/stderr, JUnit, timestamps, elapsed time, exit code and before/after
source hashes are retained here. `preparation.json` deliberately retains its
historical PREPARED status; `result.json` and `followup-summary.json` record actual
execution. No installation, test patch or provider request was part of this command.

Read-only preflight confirmed all **15 external analyzer distributions** are
installed in the existing freeze venv. `attackmap-analyzer-php-web` version 0.1.0
imports from that environment and its installed direct-URL wheel SHA-256 matches
the existing local wheel archive. The core import remains this repository's
`src/attackmap/__init__.py`. Full metadata, entry points, PHP module hashes and
wheel identity are saved in `preparation.json`.

This confirms source-core discovery and PHP route analysis with the existing
dependency environment's installed PHP plugin. It does not prove execution through
a frozen package executable. A fresh frozen package has separate runtime validation.
The other Windows permission and opt-in stress/CLI skip gates remain explicit and
were not bypassed here. No further tests or code changes were performed.
