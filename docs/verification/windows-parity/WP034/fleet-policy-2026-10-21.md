# WP034 fleet policy partial checkpoint — 2026-10-21

Scope: `scan_service.py`, additive `fleet_admission.py`, dedicated focused tests,
and current checkpoint in `docs/resource-limits.md`. No index/scanner/safe_fs,
analyzer, execution supervisor, pipeline, native or wire schema changes in this
slice. WP034 remains PARTIAL; current10k stopped before scan/merge and supplies
no working-memory acceptance.

## Implemented behavior

* Forward configured fleet hard timeout in both progress-callback branches.
* Optional core-only `ScanRequest.fleet_memory_policy`; defaults remain functional
  count-only/in-process serial with explicit memory qualification unknown in the
  additive run-manifest admission diagnostic. No invented numeric default.
* Immutable caller-supplied estimates per fleet repo ID; atomic reserve before
  submit; live+retained charge plus explicit parent/parse/link headroom; successful
  child transfers to retained-parent charge atomically. Unknown estimates/capacity
  fail explicitly and preserve successful siblings. A serialized result limit
  bounds both success and failure payload reads under this opt-in policy.
* Only verified supervised tree completion releases a running reservation.
  Unknown cleanup retains charge, stops current admission and quarantines future
  fleet requests in the process until a late verified callback releases ownership.
  Cancellation before dispatch and executor rejection refund only never-launched
  reservations. Duplicate/racing settlement cannot double-refund.
* Existing fleet `failed` rows carry typed `error_type`; existing terminal states
  and ResourceLimitEvent categories are unchanged. Logical reservations are not OS
  enforcement, observed process memory or proof of the estimates' correctness.

API: `FleetMemoryPolicy(total_bytes, parent_bytes, parse_bytes, linking_bytes,
estimates={repo_id: FleetMemoryEstimate(live_bytes, retained_bytes,
result_bytes_limit, evidence_id)})`. Reviewed current-scope measurement evidence is
the caller's prerequisite. No CLI/native option or environment policy was invented.
Explicit opt-in runs supervised children even with concurrency1; ordinary serial
mode remains unchanged. Separate fleet requests do not share physical-memory
reservations. A process-local outstanding-cleanup guard prevents a new fleet from
bypassing a known uncertain owned child.

## Verification actually run

1. Initial focused orchestration checkpoint: `test_fleet_admission.py`,
   `test_fleet_parallelism.py`, `test_desktop_fleet.py`, `test_scan_service.py`:
   **86 PASS in308.10s**. Subsequent changes added cleanup-race/lifecycle cases and
   richer admission diagnostics; no full regression matrix was repeated.
2. Final current-source focused check:

   `.venv/Scripts/python.exe -m pytest tests/test_fleet_admission.py docs/verification/windows-parity/WP029/test_ci_contract_evidence.py -q --tb=short -p no:cacheprovider --basetemp .tmp-wp034-fleet-final-20261021`

   **30 PASS in67.16s**:20fleet policy/lifecycle cases and10CI-helper cases. Fleet
   cases include actual small Windows supervised sibling JSON writers, a cancelled
   sleeping child and a hard-timeout child. No scanner/fullscan, UI, AI/provider,
   corpus evaluation or benchmark was run. Unknown-cleanup and callback races use
   injected supervisory seams; they are not proof that every OS failure is covered.
3. `py_compile` of both production modules and the CI helper PASS; scoped diff
   whitespace check PASS. Focused tests used approved escalation because restricted
   Windows temporary-directory ACLs prevent reliable fixture creation.

No measured-working-set claim follows from these tests. Test reservation numbers
are deliberately synthetic and labeled as such, not proposed product defaults.

## Still open

Current working scan/merge10k/50k/100k memory, source/graph declarations and a measured
finite aggregate default belong to the index workstream. Parent parse/link and
retained-result memory estimates need real qualification, as do physical fleet
sibling memory, cancellation under scan load and any enabled default policy.
Cooperative stage deadlines do not stop an in-flight hang; hard timeout is a
separate supervised worker mechanism with cleanup uncertainty preserved. WP035
pre-resume OS memory enforcement remains separate. No source/analyzer/graph
coverage was reduced to obtain a passing test or chart.
