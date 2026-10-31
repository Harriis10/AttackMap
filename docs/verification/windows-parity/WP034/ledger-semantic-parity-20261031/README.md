# WP034 — semantic serial/parallel ledger parity — 2026-10-31

Owner: `/root/ledger_parity_fix`; integrator: `/root`. Base commit:
`4ea5e49ade229fc0432d68ce0f7e99bcf87b545d` with pre-existing dirty work preserved.
This closes only the three fleet parity assertions. **WP034 remains IN_PROGRESS;
C35 memory/default/load and the other whole-task gates remain open.**

## Cause and correction

`test_fleet_real_workers_match_serial[all/json/markdown]` compared raw `ScanResult`
data from separate scans. Ledger 1.1 deliberately records monotonic detect and
analysis durations and lifecycle elapsed times. Those clocks differ across real
serial and worker executions.

The new [captured-baseline audit](baseline-projection-audit.json) reads all six
repo/format pairs from this run's actual immutable report generations. Every pair
contains exactly **45 raw differences: 9 `detect_duration_ms`, 3
`analysis_duration_ms`, 33 lifecycle `elapsed_ms`**. After the narrow projection,
each complete scan has **0 semantic differences**. The suggested earlier
`ledger-parity-audit-20261031/README.md` was absent; it was not treated as evidence.
The retained admission audit was read as a reference and remains unchanged.

Only `tests/test_fleet_parallelism.py` changes. `_scan_semantics` deep-copies the
entire scan and normalizes numeric values only at these three ledger paths.
Before normalization it rejects nonnumeric, negative and nonfinite clock values,
and checks nondecreasing lifecycle elapsed times separately for every analyzer.
Equal times are valid. Missing/`None` durations and absent/`None` ledgers retain
their distinct representations. All event records, their original order and every
other scan/ledger field remain part of exact dictionary equality.

Focused negative checks retain sensitivity to analyzer name/version/origin,
implementation/hash, package/entry point, provenance, selection/applicability,
execution/start/mode, skip/error/counts, completion status, lifecycle state/order,
and ordinary scan data. A timing-shaped provenance field is not normalized.
Missing/unknown clocks, invalid numeric values, reversed lifecycle times and
nonmutation are covered. Cardinality assertions also prevent `zip` from silently
accepting a missing child result.

Production ledger/worker/report behavior is unchanged. The pre-existing WP035 CLI
isolation hunk is preserved, recorded by `wp035_hunk_unchanged: true` in the
[completion record](completion.json). No shared TODO/backlog/index file changed.

## Executed verification

| Run | Result | Evidence |
| --- | --- | --- |
| Original three real-worker cases before the test correction | **3 FAIL, 0 errors/skips**, 21.16 s | [JUnit](baseline.xml), [transcript](baseline.txt) |
| Full parallelism file plus both analyzer ledger suites | **94 PASS, 0 failures/errors/skips**, 33.63 s | [JUnit](focused.xml), [transcript](focused.txt) |
| Eight-file relevant fleet regression | **175 PASS, 1 SKIP, 0 failures/errors**, 71.71 s | [JUnit](fleet-regression.xml), [transcript](fleet-regression.txt) |

Both passing runs execute **all three formerly red formats without deselection**.
These runs overlap; their counts must not be added. The single skip is
`test_unreadable_file_is_skipped_and_reported`: `chmod 000` is not enforced on
Windows or for root. Source identity is unchanged within each executed run.

Reproduce from the repository root with fresh, unused `--basetemp` paths:

```powershell
.venv/Scripts/python.exe docs/verification/windows-parity/WP034/ledger-semantic-parity-20261031/run_tests.py focused tests/test_fleet_parallelism.py tests/test_analyzer_run_ledger.py tests/test_pipeline_analyzer_ledger.py -q -p no:cacheprovider --tb=short --basetemp=artifacts/wp034-ledger-semantic-parity-20261031/focused-temp
.venv/Scripts/python.exe docs/verification/windows-parity/WP034/ledger-semantic-parity-20261031/run_tests.py fleet-regression tests/test_fleet_input_budget.py tests/test_fleet_admission.py tests/test_fleet_parallelism.py tests/test_fleet_publication.py tests/test_scan_service.py tests/test_resource_limit_events.py tests/test_unreadable_and_fleet_failures.py tests/test_desktop_fleet.py -q -p no:cacheprovider --tb=short --basetemp=artifacts/wp034-ledger-semantic-parity-20261031/fleet-regression-temp
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP034/ledger-semantic-parity-20261031/record_evidence.py
git diff --check -- tests/test_fleet_parallelism.py
```

Exact commands and interpreter are also retained in `*.command.json`. The runner
uses the existing host-only ACL workaround: inside the pytest process,
`os.mkdir(..., 0o700)` uses `0o777`, and TEMP/TMP/TMPDIR point to a task-owned
directory. Production orchestration, transports, data, assertions and child
process code are not replaced. New temporary directories were used for each run;
no earlier directory was reset or deleted.

## Handoff and limits

- Task: WP034 parity slice; owner: `/root/ledger_parity_fix`; lease released to root.
- Changed paths: `tests/test_fleet_parallelism.py` and this new evidence directory;
  task-owned runtime outputs are under `artifacts/wp034-ledger-semantic-parity-20261031`.
- [Owned patch](owned-change.patch) excludes the existing WP035 changes; SHA-256:
  `65a52c50984a6aa8237a1a926afc79f622da2cc5d7925663c3bef44675234338`.
- Final test-file SHA-256:
  `d81cc21c3674a24e09cff12a13d3be2f3d3d1928302703ccef813565f609223e`.
- [Completion record](completion.json) includes base/source identities, commands,
  run IDs, outcome counts, limitations and next action.
- `git diff --check -- tests/test_fleet_parallelism.py` passed.
- No live provider/LM Studio calls, Juice Shop qualification, C35 10k/50k/100k
  memory runs, native/UI review, frozen/package build, cross-platform or release
  acceptance occurred. Package ID: not applicable.
- Next: independent review, then root reconciles the shared planning documents.

The retained earlier failed/deselected results remain historically accurate and
are not rewritten. This evidence provides a narrowly validated semantic parity
comparison, with the full ledger retained, and makes no wider acceptance claim.
