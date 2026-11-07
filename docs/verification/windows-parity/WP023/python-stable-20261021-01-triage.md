# Stable Python checkpoint 20261021-01 — failed, inputs unchanged

One authorized broad invocation used project `.venv/Scripts/python.exe -Xutf8 -m pytest -q tests --tb=short --basetemp C:/Projects/INPROGRESS/AttackMap/.tmp/wp023-stable-20261021-01/pytest --junitxml C:/Projects/INPROGRESS/AttackMap/docs/verification/windows-parity/WP023/python-stable-20261021-01.xml`.

Actual terminal: **4164 passed, 12 failed, 7 skipped, 1 warning; 5110.46 seconds; exit 1**. This is not a passing broad gate. Exact602-file inventory covers src/, tests/ including fixtures, and pyproject.toml, excluding bytecode caches. Before/after digest both `dd9ae910a54cc478d5c9504e184448ee962539cbb483fd135c6f101bb8769b0c`; every inventoried file is unchanged. Native-only UI files changed concurrently after packaging freeze; these are outside this inventory and some Python contract checks may inspect them. C10k campaign used an isolated sealed snapshot. Concurrent work means timing assertions are real failures under this load, not proof of a regression cause or a qualified performance baseline.

Raw evidence: python-stable-20261021-01.log, .xml, -inputs.json, -outcomes.json. The latter retains every exact failure traceback and skip reason. No source/test patches, threshold changes, retries, or provider/model launches occurred during this run. ATTACKMAP_LIVE_CLI_TESTS and ATTACKMAP_STRESS_TESTS were absent and explicitly removed from child environment. Freeze57-distribution environment was not changed.

Four fixture/configuration failures requiring focused corrections:

- test_desktop_reference sidecar/rerun and refusal-to-overwrite tests: mandated workspace-local .tmp basetemp violates generator's intentional workspace-only .pytest_cache destination policy before tested behavior is reached. Fix fixture destination outside workspace or deliberate allowed cache child, preserve guard and overwrite checks. No generator policy change.
- test_scanned_coverage unreadable scan_files case: test injects Path.read_text failure but scanner now uses RepoIndex bounded binary descriptor capture. The injected denial never occurs. Inject actual Path.open descriptor denial and assert injection happened; preserve empty accepted coverage assertion. Config case passed through its original text seam. This does not yet prove an actual inaccessible file was wrongly admitted.
- test_secrets_deep non-git directory: workspace-local .tmp is inside the parent Git checkout, so rev-parse correctly succeeds. Use an owned external non-checkout directory and assert actual rev-parse rejection before testing limitation. Do not modify git discovery semantics or strip repository data.

Eight load-sensitive timing failures, all real failed assertions pending one serialized unchanged-threshold retry authorized by root:

- actual installer entry analyze --help exceeded30s subprocess timeout.
- budget check average5627.674ns exceeds1000ns assertion.
- longline variants long_word16.64s, router_assign20.95s, blueprint10.54s, graphql_field10.18s exceed5s.
- many matches70.21s exceeds25s.
- taint flow29.35s exceeds20s.

Do not simply weaken these limits or call them harmless. Root must coordinate native-idle retry, compare failures, and investigate any reproducible issue. No passing broad result is inferred from focused repairs.

Seven skips: two optional php-web import tests (not installed in project .venv); live hostile CLI opt-in disabled;5000-file stress opt-in disabled; two chmod000 tests unsupported Windows/root semantics; symlink export case lacks Windows symlink privileges. Expected warning is intentionally duplicated ZIP member negative fixture.

## Approved fixture-only follow-up

After preserving the original failed evidence, root approved edits only to tests/test_desktop_reference.py, tests/test_scanned_coverage.py and tests/test_secrets_deep.py. Two generator tests now use owned tempfile.TemporaryDirectory destinations asserted outside real WORKSPACE; the real workspace-policy rejection test is unchanged. Read-denial injection now targets Path.open and asserts at least one denied call for each scanner. The non-Git test uses an owned external directory and first verifies actual hardened rev-parse rejection. No production code, threshold or skip policy changed.

Focused command: `.venv/Scripts/python.exe -Xutf8 -m pytest tests/test_desktop_reference.py tests/test_scanned_coverage.py::test_unreadable_file_is_not_enumerated tests/test_secrets_deep.py::test_history_on_a_non_git_directory -q --tb=short --basetemp .tmp/wp023-fixture-fixes-20261021-01 --junitxml docs/verification/windows-parity/WP023/python-fixture-fixes-20261021-01.xml` — **10 passed in23.63s**. Focused diff whitespace check passed, line-ending warnings only. This repairs the four fixture failures; it does not replace the failed broad checkpoint or resolve the eight timing failures.

Changed test hashes: desktop_reference A71861A0E62B1CBD3B55856C7EA76A89BFF71F7F1F8293E14F8BEE0FD9DD8427; scanned_coverage3A9D2B316E2549BCB6EB85F8C0B563DCB48EDBDDD8D9ECCE0131AE8256797731; secrets_deep D1ED206680A44BC6E60778F4A086A7BDEAB0773D8D6183A6B209804D3CB21958.
