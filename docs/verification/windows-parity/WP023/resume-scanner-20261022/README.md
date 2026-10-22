# WP023 scanner/taint resume evidence — 2026-10-22

Exclusive source lease: `src/attackmap/taint_flow.py`; new focused test `tests/test_taint_enclosing_index.py`. `scanner.py`, `test_scan_limits.py`, timing thresholds, existing fixtures, config scanner/index/pipeline/service/models were not changed by this worker.

Current behavior before repair: each Python sink called `_PyFlow._enclosing`, linearly scanning all function intervals. The preserved 6000-route profile identified this as the dominant Python taint cost. The smallest repair builds a sweep-line interval index once and uses binary search per query. It preserves inclusive endpoints, greatest starting line, original-order tie choice, decorator starts, nesting, overlapping intervals and no-match behavior. Function intervals remain unchanged for callers that enumerate them. O(F log F) construction and O(log F) lookup replace O(F) per query; O(F) extra storage. This does not discard signals or reduce scan coverage.

Before canonical promotion, preserved prototype tests completed **5 passed in10.05s**, including actual6000 routes and6000 external calls (`prototype.xml`, `prototype-6000.json`). Its embedded output label predates this run and mentions concurrent native QA; that label is inherited text, not an assertion about this run. Actual wall8.160s/CPU7.750s for its scan. The original test automatically created a previously untracked old-dated JSON; it was copied here and only that newly generated file removed afterward.

`differential_6000.py` imports current canonical source and applies only the prototype method in memory after the reference run. Both runs scan the unchanged preserved actual6000 input. Entire `ScanResult.model_dump(mode='json')` equals, including all output fields, with identical SHA256 `9a0ad9b5a6c511651e4abe695513c12a136d132ec254e8da8b48be1df18fa19f`. Baseline10.478s wall/10.375s CPU, indexed7.829s wall/7.781s CPU. This is a bounded single-fixture comparison, not a qualified broad performance campaign. `differential-6000.json` preserves the record.

After promotion the exact focused command was:

```powershell
.venv/Scripts/python.exe -Xutf8 -m pytest tests/test_taint_enclosing_index.py tests/test_taint_flow.py tests/test_taint_guard_safety.py tests/test_scan_limits.py tests/test_resource_budgets.py::test_time_budget_check_overhead_is_negligible -q --tb=short -p no:cacheprovider --basetemp .tmp/wp023-resume-scanner-approved-20261022 --junitxml docs/verification/windows-parity/WP023/resume-scanner-20261022/focused-approved.xml
```

**275 passed in25.19s, exit0** (`focused-approved.xml`, `focused-approved.log`). New differential coverage checks250 deterministic random interval collections at every relevant integer line, endpoints/ties/invalid intervals, nested decorated async functions, and complete scan-output equality against the original linear lookup for all11 Python taint-flow fixtures. Existing flow and guard suites preserve sanitizer/negative findings checks across languages.

All seven preserved timing cases passed with their existing assertions. JUnit case durations (include fixture/setup accounting and are not exact internal assertion stopwatches): long_word2.328s, router_assign2.604s, blueprint1.328s, graphql_field1.527s (each original5s assertion); actual6000 many_matches6.707s (original25s); taint flow4.317s (original20s); budget check case0.025s (original1000ns average assertion unchanged). Passing these cases now does not prove the previously observed slowdowns were all caused by the interval lookup. Long-line and budget cases were untouched. The original failed broad checkpoint is retained and no new broad gate is claimed.

The first sandbox invocation used the same suite with `.tmp/wp023-resume-scanner-20261022` and `focused.xml`. It failed in tmp_path setup and pytest teardown with `PermissionError: [WinError 5]` at `cleanup_dead_symlinks -> root.iterdir -> os.scandir(basetemp)`. Terminal exit1; pytest crashed before summary/JUnit, so there is no valid terminal pass/error count or XML for that attempt. Fresh escalated basetemp fixed the environmental access failure. No assertion or test selection changed to obtain a pass.

## Independent review and canonical reproduction

Ultra review identified that the original `differential_6000.py` assumes the
pre-promotion linear source. Running it after promotion would compare two
indexed implementations. Its retained result above was produced before
promotion; do not reuse its timing labels for later runs.

The integrator added `verify_canonical_6000.py`, explicitly installs the old
linear lookup for the reference run, restores the current indexed lookup for
the second run and restores it again in `finally`. A fresh execution passed:
`canonical-6000.json`, all 6000 routes and external calls in each result,
identical full ScanResult SHA256 `9a0ad9b5a6c511651e4abe695513c12a136d132ec254e8da8b48be1df18fa19f`.
All source Python and fixture byte hashes were identical before/after.
Reference 8.349 s, indexed 7.335 s on this one fixture; this remains a bounded
comparison, not a broad performance or C35 qualification.

`git diff --check` for owned changes passed. All owned exec sessions returned terminal results. A final elevated read-only Win32_Process inventory matched no Python process with the owned pytest/differential/prototype command lines. No model, build, GUI, package, stress campaign, automation or background continuation was launched. No unrelated process was stopped.
