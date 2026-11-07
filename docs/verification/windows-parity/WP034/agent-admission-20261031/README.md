# WP034 — finite fleet input quotas — 2026-10-31

This bounded source slice follows the active Windows-parity WP034 task after
the WP033 campaign. It adds an opt-in aggregate captured-input budget to the
existing fleet coordinator; it does not close WP034/C35 or release acceptance.
No provider calls were made and no product defaults were changed.

## Behavior and accounting invariants

`ScanRequest.fleet_input_byte_budget=B` requires a strict positive integer.
The public API rejects a single-repository request with this fleet-only option.
For `N` repositories, input-order fixed quotas are `B // N`, with an extra byte
for the first `B % N` repositories. Their sum is exactly `B`. They are held for
the whole request, with no redistribution after completion, failure or cancel.
The effective child cap also preserves any stricter positive inherited
`ATTACKMAP_INDEX_BYTE_BUDGET`. Each child receives a separate environment copy;
the parent environment is never changed. No CLI/native/protocol option is added.

A zero quota is a `fleet_input_capacity` failed row and starts no child. A
successful child's raw JSON must contain an integer, non-negative snapshot
`total_size` within its effective cap and exactly matching integer
`index_config.index_byte_budget`. Missing/coercible/excess/mismatched metadata
is `fleet_input_budget_unverified`, not a successful retained result. These
checks establish internal worker-result consistency, not authenticity or an
OS memory boundary.

Existing `index_bytes` file-skip events and limitations remain in successful
children; fleet architecture keeps partial repository status. The manifest's
new `fleet_resource_admission.input_bytes.capture_status` is `partial` when
any requested child fails/is not admitted or a successful child emits an
`index_bytes` skip, otherwise `within_quotas`. This status describes this input
policy only. Global diagnostic coverage remains unchanged: its accepted-path
enumeration status is distinct from source omissions and language/rule coverage.
`verified_captured_bytes` sums only successful bound snapshots and can be less
than allocated quotas; failed child capture/peak cost is not included in it.

The existing `FleetMemoryPolicy` continues to own live/retained-result logical
reservations, cleanup quarantine and bounded payload policy. Input quotas do not
replace that policy or establish a working-set cap.

## Verification

- [RED JUnit](red.xml) / [text](red.txt): **11 FAIL, 1 PASS** before implementation;
  failures identify the absent opt-in API and the ordinary no-option control
  passes. Earlier non-elevated setup attempts were blocked by Windows temp ACLs
  and are not counted as useful reproduction.
- [Focused JUnit](focused.xml) / [text](focused.txt): **40 PASS** at the production
  scanner checkpoint. Two additional raw-metadata counterexamples were added
  afterward and are included in the final regression below.
- [Exploratory scanner JUnit](scanner.xml) / [text](scanner.txt): **14 PASS,
  2 FAIL** due to an incorrect test expectation that global fleet coverage is
  partial. Inspection confirmed the existing accepted-path diagnostic semantics;
  the final checks assert policy status, child skip events/limitations and
  partial fleet-architecture coverage instead. No global coverage schema changed.
- [Full relevant regression](regression.xml) / [text](regression.txt): **90 PASS,
  3 FAIL, 1 SKIP, 159.51 s**. All three failures are the existing ordinary
  `test_fleet_real_workers_match_serial[all/json/markdown]` raw analyzer-ledger
  equality assertion; the new opt-in policy is not active in those cases.
- [HEAD scan-service baseline](baseline.xml) / [text](baseline.txt) reproduces
  the same `[all]` failure in **13.32 s**, loading HEAD `scan_service.py` only
  in memory without rewriting the checkout. All other current source/plugins
  remain present, so this is not a clean-checkout qualification. The
  [44 exact ledger differences](baseline-ledger-differences.json) are solely
  `detect_duration_ms`, `analysis_duration_ms` and lifecycle `elapsed_ms`
  telemetry. [Identity](baseline-identity.json) and
  [reproducer](baseline_ledger_probe.py) preserve the comparison. No unrelated
  ledger implementation/test normalization was changed in this WP034 slice.
- [Final bounded regression](final.xml) / [text](final.txt): **92 PASS, 1 SKIP,
  3 explicitly deselected ledger cases, 56.72 s**, including all final tests.
  The skip is `test_unreadable_file_is_skipped_and_reported`: `chmod 000 is not
  enforced on Windows or for root`. Deselection does not turn the full
  regression into a pass; its three failures remain an open test gate.
- Retained actual scanner metadata: [32-byte policy](production-budget-32.json)
  and [1-byte policy](production-budget-1.json); [runtime, source hashes and
  final JUnit summary](completion.json). [Collector](collect_evidence.py) reads
  only this slice's disposable test outputs.

The tests cover exact quota sums/remainders including zero allocations, typed
non-admission with successful siblings, invalid-budget rejection before launch,
strict raw metadata checking, child-only environment propagation, the stricter
inherited cap, ordinary no-option compatibility and existing memory admission.

Actual production scanner integration uses two physical tiny Python repositories
and one supervised worker at a time. With `B=32`, both quotas are 16 bytes,
each captures one 13-byte file and emits one explicit `index_bytes` skip:
26 successful captured bytes in total. With `B=1`, repository A preserves a
zero-file partial snapshot under its 1-byte cap, while B receives typed
`fleet_input_capacity` without launch. A separate two-worker subprocess test
runs real production `RepoIndex` capture and JSON interchange, capturing 8 bytes
under quotas 6/5 with both skip events retained. These are small scanner and
lifecycle checks, not a memory or performance qualification campaign.

Run from repository root (fresh isolated `--basetemp`; this host required an
elevated test process because ordinary Windows temp ACLs denied pytest access):

```powershell
.venv/Scripts/python.exe -m pytest tests/test_fleet_input_budget.py tests/test_fleet_admission.py tests/test_fleet_parallelism.py tests/test_fleet_publication.py tests/test_scan_service.py tests/test_resource_limit_events.py tests/test_unreadable_and_fleet_failures.py -q -p no:cacheprovider --tb=short --basetemp=C:/tmp/wp034-input-regression-20261031 --junitxml=docs/verification/windows-parity/WP034/agent-admission-20261031/regression.xml
.venv/Scripts/python.exe docs/verification/windows-parity/WP034/agent-admission-20261031/baseline_ledger_probe.py
.venv/Scripts/python.exe -m pytest tests/test_fleet_input_budget.py tests/test_fleet_admission.py tests/test_fleet_parallelism.py tests/test_fleet_publication.py tests/test_scan_service.py tests/test_resource_limit_events.py tests/test_unreadable_and_fleet_failures.py -q -p no:cacheprovider --tb=short -k 'not test_fleet_real_workers_match_serial' --basetemp=C:/tmp/wp034-input-final-20261031 --junitxml=docs/verification/windows-parity/WP034/agent-admission-20261031/final.xml
.venv/Scripts/python.exe docs/verification/windows-parity/WP034/agent-admission-20261031/collect_evidence.py
git diff --check -- src/attackmap/scan_service.py docs/resource-limits.md
git diff --no-index --check -- NUL tests/test_fleet_input_budget.py
```

## Remaining gates

- No finite default was selected or qualified. The single-repository aggregate
  default remains uncapped; the new fleet cap is an explicit core API option.
- Captured source bytes do not bound read buffers, decoded strings, analyzer
  signals, model/graph memory or retained parent results. Memory estimates and
  the existing opt-in logical reservation policy are not OS memory enforcement.
- Current-scope same-engine/reference-host 10k/50k/100k scan/merge peaks, declared
  byte/signal/graph counts, a peak below 2 GiB or a reviewed measured default
  change, sustained cancellation-under-load and fleet memory qualification
  remain open. No benchmark acceptance is inferred from these tiny fixtures.
- No native/UI, frozen package, cross-platform or release acceptance was run.
  The WP043 rendering gate remains unchanged.
- The ordinary fleet serial/parallel raw-ledger equality regression remains
  unresolved as recorded above; its baseline reproduction does not waive it.

Changed source: `src/attackmap/scan_service.py`; focused tests:
`tests/test_fleet_input_budget.py`; contract documentation:
`docs/resource-limits.md`. Main roadmap/TODO/backlog and common handoff are left
to the root agent.
