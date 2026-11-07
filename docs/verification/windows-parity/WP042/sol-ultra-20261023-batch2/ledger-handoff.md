# WP042 batch 2 — per-run analyzer ledger

Owner: `/root/analyzer_catalog`, GPT-6.1 Sol / ultra. Active-plan scope is the first per-run selection/execution ledger; whole WP042, packaging, native visual acceptance, and live-provider acceptance remain open. The shared dirty checkout was preserved; no commit/reset/cleanup or package installation was performed.

## Behavior and API

The old pipeline selected analyzers once and then called `analyze_repository` with that list, causing a second `detect()` pass. A stateful detector could therefore appear selected without being executed. Detect exceptions also collapsed to the same false result as ordinary unmatched detection.

`resolve_analyzer_run(root, analyzers=None, *, index=None, profile_id=None, opt_in_matches=None)` now returns an `AnalyzerRunPlan` bound to the resolved repository root and the exact `RepoIndex` capture object. `analyze_repository(..., run_plan=plan)` claims that plan once and executes its selected instances without detecting again. With no explicit index it uses the plan's captured index. Wrong roots, different capture objects, reuse, and simultaneous plan/instance arguments are rejected before execution.

The pipeline keeps the existing `resolve_run_analyzers` list API and supplies an optional plan observer. Normal direct `analyze_repository(root, analyzers=...)` calls create a fresh plan, retaining explicit/default selection, opt-in gating, `(priority, name)` execution/merge order, and legacy selected-analyzer list behavior. It never caches a prior run's detector result. A deadline before analysis records selected-but-skipped decisions and consumes the plan.

`AnalyzeOptions.analyzer_profile_id` associates the validated caller selection with the ledger; root owns CLI/service/native validation and schema 1.5 transport. The report stores `scan.analyzer_run_ledger`; `run-manifest.json` adds the same `analyzer_run_ledger` payload. Existing `analyzers` lists remain selected metadata and do not assert successful analysis. Legacy scans without a ledger retain `null`/unknown semantics.

## Ledger schema 1.0

`AnalyzerRunLedger` is a typed model in `analyzer_run_ledger.py`:

- `scope`: `analyzer_selection_and_execution`.
- `inventory_scope`: `registered_candidates` for Automatic, `supplied_candidates` for an explicit instance list.
- `selection_mode`, optional `profile_id`, `resolution_complete`, `execution_complete`, and `entries`.
- Entry selection/applicability/execution are separate: `selected|skipped`, `not_evaluated|applicable|unmatched|detect_error`, and `not_started|succeeded|failed|skipped`.
- Skip reasons distinguish `unmatched`, `detect_error`, `opt_in`, and `pipeline_deadline`. Safe errors contain only stage and a bounded exception type.
- `analysis_started` is true after an observed in-process call or successful isolated result, false before invocation/captured-input rejection, and unknown for a failed isolated host request whose plugin invocation cannot be proven.

`execution_complete` means recorded terminal analyzer decisions/outcomes, including skips and failures; it does not claim successful or complete repository coverage. Detect errors are explicit in the ledger; legacy `analyzer_errors` continues to represent analysis/host failures. Missing/load/initialization/metadata discovery errors remain in the separate catalog rather than being invented as registered run candidates. A legacy missing/non-callable detector retains the existing default-applicable policy.

Success is recorded only after a usable result and provenance stamping have completed. Strict analysis failures leave subsequent entries `not_started`, preserve the original exception, and do not mark the ledger complete. Supplied duplicate names retain the legacy multiple-invocation behavior and can produce repeated ledger rows; consumers must not silently deduplicate outcomes.

## Implementation provenance

`analyzer_run_identity(instance)` captures the actual implementation class/module and bounded class-source-file digest, never a same-name catalog winner. Normal plugin loading retains its exact entry-point object privately so the run can observe package/version/pin metadata without another discovery or load. Unavailable discovery context remains unknown/supplied; it is not borrowed by name. Caller-defined subclasses retain their own supplied provenance even though the pre-existing isolation policy uses `isinstance`.

The serialized identity omits absolute source paths, source text, URLs, and raw exception messages. Declared pins remain separate from observed installed metadata; content verification is false. A class-file hash is not the full imported dependency closure. Undeclared analyzer metadata versions are null, while explicitly declared default-looking versions are retained. Package metadata version remains a separate observation.

## Verification

Final focused command after the last version-null correction:

```powershell
& .\.venv\Scripts\python.exe -B -m pytest tests/test_analyzer_run_ledger.py tests/test_pipeline_analyzer_ledger.py -q -p no:cacheprovider --basetemp=.tmp/wp042-ledger-20261023-batch2/pytest-05 --junitxml=docs/verification/windows-parity/WP042/sol-ultra-20261023-batch2/ledger-tests-final.xml
```

Result: **22 passed**, exit 0, `1.90 s`. Tests cover flaky detectors/one invocation, explicit/Automatic/opt-in/unmatched/detect-error decisions, strict and ordinary failures, sibling merge precedence, same-root different-capture and cross-root rejection, repeat-run ownership, legacy list behavior, isolated success/timeout/captured-input rejection, actual entry-point provenance without rediscovery, colliding supplied names, supplied subclasses, declared/undeclared versions, deadline skips, and report/manifest parity.

A broader focused regression checkpoint before the final small identity/version corrections passed **194 tests, 2 skipped** in `25.39 s`. Its command included the two ledger files plus analyzer/catalog/profile/order/privacy, pipeline, skip-dir, diagnostics, CLI comparison, whole-scan AI allowance, and desktop AI suites. The two skips require an installed PHP plugin absent from this source interpreter. It did not run the whole-checkout workflow self-scan or contact a real provider. Root owns final integrated verification after the frozen source checkpoint.

Evidence: `ledger-tests-final.xml`, `ledger-regression-tests.xml`, and `ledger-source-hashes.json`. Scoped tracked `git diff --check` passed. Final released analyzer source SHA-256 is `50e28db09f7b8efb08c7f667f7475b2ad531b12d212eb857af9c88e325d2188b`; other exact source/test hashes are in the JSON file.

No actual model calls, package/frozen build, source-vs-frozen scan comparison, or native visual acceptance was performed by this agent for batch 2.
