# WP034 — preserve legacy positional ScanRequest calls — 2026-10-31

The opt-in `fleet_input_byte_budget` field had been inserted before the
pre-existing final `deployment_aliases` field. A valid pre-budget positional
constructor call therefore bound its alias declarations to the byte budget,
and `execute_scan_request` rejected it with `Fleet input byte budget must be a
positive integer` before dispatch.

The correction appends the new option after all 55 legacy fields. Zero-based
position 54 remains `deployment_aliases`; position 55 is the optional input
budget. The default remains `None`. Quota validation, allocation, child
environment propagation, scanner behavior and resource-policy defaults are
unchanged by this correction.

`test_legacy_positional_request_keeps_final_deployment_aliases` reconstructs
the old argument list by omitting the new field from the dataclass fields and
passing a nonempty `DeploymentAliases` value as the final positional argument.
It calls the real public validation/dispatch function, verifies successful
dispatch, alias object identity and the absent budget. The fleet implementation
is stubbed in this constructor regression; the relevant suite separately retains
`test_fleet_deployment_aliases_resolve_observed_links` and real subprocess/scanner
quota checks.

## Executed verification

- [RED JUnit](red.xml) / [text](red.txt): **1 FAIL, 1.83 s** before moving the
  production field, with the exact positive-integer configuration error above.
- [Focused JUnit](focused.xml) / [text](focused.txt): **25 PASS, 10.47 s** after
  the correction, covering the full WP034 input-budget suite and the new
  positional compatibility regression.
- [Relevant regression JUnit](regression.xml) / [text](regression.txt): **93 PASS,
  3 FAIL, 1 SKIP, 131.70 s** in the unfiltered seven-file suite below. All three
  failures are the retained `test_fleet_real_workers_match_serial[all/json/markdown]`
  raw `analyzer_run_ledger` equality assertions. No cases are deselected. The
  legacy positional regression and the existing observed-link alias test pass.
  The skip is `test_unreadable_file_is_skipped_and_reported`: `chmod 000` is not
  enforced on Windows or for root.
- [Completion record](completion.json): source identity, actual signature tail,
  parsed JUnit outcomes and the retained baseline ledger-difference count.

The first ordinary RED attempt failed during pytest temporary-directory setup
with `PermissionError: [WinError 5]`. It is retained separately as
[non-counted temp-ACL output](noncounted-red-temp-acl.txt); it is not a product
reproduction or a passing/failing compatibility test. Subsequent runs used an
elevated local pytest process and a fresh, uniquely named base directory for
each run. No old temporary tree was reset or deleted.

Run from the repository root:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_fleet_input_budget.py::test_legacy_positional_request_keeps_final_deployment_aliases -q -p no:cacheprovider --tb=short --basetemp=C:/Projects/INPROGRESS/AttackMap/.tmp/wp034-compat-red-elevated-20261031-17bc --junitxml=docs/verification/windows-parity/WP034/agent-compat-fix-20261031/red.xml
.venv/Scripts/python.exe -m pytest tests/test_fleet_input_budget.py -q -p no:cacheprovider --tb=short --basetemp=C:/Projects/INPROGRESS/AttackMap/.tmp/wp034-compat-focused-20261031-a391 --junitxml=docs/verification/windows-parity/WP034/agent-compat-fix-20261031/focused.xml
.venv/Scripts/python.exe -m pytest tests/test_fleet_input_budget.py tests/test_fleet_admission.py tests/test_fleet_parallelism.py tests/test_fleet_publication.py tests/test_scan_service.py tests/test_resource_limit_events.py tests/test_unreadable_and_fleet_failures.py -q -p no:cacheprovider --tb=short --basetemp=C:/Projects/INPROGRESS/AttackMap/.tmp/wp034-compat-regression-20261031-b7e4 --junitxml=docs/verification/windows-parity/WP034/agent-compat-fix-20261031/regression.xml
git diff --check -- src/attackmap/scan_service.py
git diff --no-index --check -- NUL tests/test_fleet_input_budget.py
```

The tracked diff check returns 0. The new-file `--no-index --check` reports no
whitespace errors; its exit 1 indicates a difference from `NUL`.

## Retained evidence and limitations

The original [agent-admission regression](../agent-admission-20261031/README.md)
remains **90 PASS, 3 FAIL, 1 SKIP**. Its three ordinary serial/parallel raw-ledger
equality failures are not waived by this compatibility repair. Its later bounded
result remains 92 PASS, 1 SKIP with those three cases explicitly deselected.

Factual count correction: the retained
[baseline-ledger-differences.json](../agent-admission-20261031/baseline-ledger-differences.json)
contains **45 entries**, not the original README's 44: 9 `detect_duration_ms`,
3 `analysis_duration_ms` and 33 lifecycle `elapsed_ms` differences. This note
corrects the count without rewriting the retained execution evidence.

This patch provides no WP034/C35 memory-peak, finite-default, sustained-load,
native/UI, frozen-package, cross-platform or release qualification. No provider
calls were made. Common roadmap/TODO/backlog documents and corpus release work
are outside this corrective slice.

Changed production file: `src/attackmap/scan_service.py` (field order only within
the existing WP034 source changes). Changed focused test file:
`tests/test_fleet_input_budget.py`. All new corrective evidence is in this folder.
