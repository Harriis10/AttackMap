# Detailed analyzer ledger and progress handoff — 2026-10-23

Source released to root after the focused final suite: **49 PASS in22.86s**.
`ledger-source-hashes.json` records the released bytes of analyzers.py,
analyzer_run_ledger.py, pipeline.py and both focused test files.

## Additive contract

`AnalyzerRunLedger.schema_version` accepts persisted1.0 and1.1; newly created
ledgers default to1.1. Existing selection, applicability, execution, actual
implementation identity, profile and inventory scope fields remain intact.
New entry fields:

- `detect_duration_ms`: nullable finite nonnegative elapsed wall time around
  the one detector call.
- `analysis_duration_ms`: nullable finite nonnegative elapsed wall time around
  the analysis request, result coercion/copy and provenance stamping. Isolated
  mode includes parent host wait/overhead; it is not child CPU time.
- `signal_counts`: nullable object with exactly `routes`, `external_calls`,
  `databases`, `auth_hints`, `secret_hints`, each a nonnegative integer. Counts
  come from the successful per-analyzer extraction before core merging. A
  failed/pending/skipped analyzer has unknown counts, not five invented zeros.
- `lifecycle_events`: at most16 ordered events. Each contains `stage`
  (`detect`, `selection`, `analysis`), `state` (`started`, `requested`,
  `applicable`, `unmatched`, `detect_error`, `selected`, `skipped`, `succeeded`,
  `failed`), relative `elapsed_ms` from plan creation, nullable sanitized
  `error_type`. No wall timestamps, exception messages or source paths.

An isolated host request emits `analysis/requested`. A host failure leaves
`analysis_started:null` because actual child entry is unknown; a successful
usable result establishes true. Captured-input failure emits failed with
`analysis_started:false` and no analysis duration, because the host was never
requested. Strict failures record error/event/duration before rethrowing;
pending siblings remain not_started and the ledger is incomplete. A pipeline
deadline preserves selected but unexecuted state and records the skip without
an analysis duration. Provenance stamping failures are now inside the guarded
per-analyzer failure path.

Both resolvers accept optional keyword `progress`. Detection start/outcome,
selection/skip reason, analysis start/request and final outcome are emitted
through existing safe `progress.stage` labels. Pipeline creates the sink before
selection and stops its spinner on selection/analysis exceptions or a deadline
before scan. Selection remains once per capture and no detect is repeated.
The existing progress protocol is unchanged; final structured lifecycle records
live in the identical report/manifest ledger. Legacy analyzer lists still mean
selected, never succeeded.

## Verification

```powershell
.venv/Scripts/python.exe -B -m pytest tests/test_analyzer_run_ledger.py tests/test_pipeline_analyzer_ledger.py tests/test_single_pass.py tests/test_progress.py tests/test_pipeline.py -q --basetemp=.tmp/wp039-python-20261023/ledger-live-stable-20261023 --junitxml=docs/verification/windows-parity/WP039/sol-ultra-20261023-python/ledger-live-stable.xml
```

Final result49 PASS,22.86s. Earlier detailed-ledger checkpoint28 PASS3.21s;
affected isolation/privacy/order/single-pass/progress checkpoint36 PASS11.40s.
These overlap and must not be added into a total. Initial scoped pytest was
blocked by sandbox WinError5 on its task-specific basetemp, then the authorized
targeted suite passed outside that temp restriction. The first live-extension
suite had48PASS/1failure because the new test fake omitted the existing begin
hook; adding the missing fake hooks produced the final49PASS. That intermediate
failure was a test-fixture defect, not a product failure or blanket retry.

Checks cover one-shot flaky detect, opt-in/unmatched/detect errors, success vs
analysis failure, strict pending siblings, isolated unknown start, captured
input failure, extracted counts before merge, deterministic monotonic timing,
bounded/sanitized lifecycle, legacy1.0 loading, provenance failure, stage order
and privacy, sink availability during selection and cleanup on failure.

Native/root integration was reviewed read-only: the consumer accepts1.0/1.1,
the exact fields/states/nulls and finite timings; it labels analysis/host wait
and keeps report observations separate from current inventory. Source tests do
not prove a fresh frozen/native candidate, visible appearance, provider calls,
package/SBOM, manual accessibility or whole-task WP042 acceptance. Root owns
those integration gates. No provider call, venv/pin mutation, native GUI build,
fleet edit, Git commit or cleanup was performed in this ledger slice. Subsequent
captured native console verification is documented separately in
`native-discovery-handoff.md`.
