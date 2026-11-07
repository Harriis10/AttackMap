# WP023 independent interval-index review — 2026-10-22

Verdict: no blocking implementation finding in the reviewed interval-index patch. The lookup preserves the original result for arbitrary integer interval collections under the current immutable-after-construction `_PyFlow.funcs` lifecycle. The initial non-blocking evidence reproducibility concern was resolved during review by a new explicit canonical comparison. There are no open findings from this review. This review does not close WP023 or a performance/release gate.

Owner: `/root/ultra_taint_review`. Base: `18fc9b2ae711bf0b39d93c996ae2ab220cc9a82d`. Authority: current `AGENTS.md`, `docs/README.md`, Windows parity roadmap/TODO/backlog and the 2026-10-22 resume supplement. Only this review document was written. CodeGraph was consulted before source lookup; the current Git diff and direct current source/test/hash checks confirmed the reviewed content despite the integrator's earlier frozen-index warning.

## Findings, by priority

- **Resolved P2 — retained 6000-route harness did not explicitly restore the linear reference.** `resume-scanner-20261022/differential_6000.py:16-29` labels its first iteration `linear` but uses the imported current `_PyFlow` unchanged. Only the second iteration installs a prototype lookup. After canonical promotion, a rerun would compare two indexed implementations, and the second also constructs the index twice. This did not disprove the recorded pre-promotion comparison or reveal a runtime defect in the patch. The integrator preserved that historical evidence and added `verify_canonical_6000.py`, which explicitly installs the removed linear loop and then restores the captured current canonical lookup, including a `finally` restoration. Inspected `canonical-6000.json` records successful complete output equality and unchanged source/fixture bytes. Use the new harness for future comparisons. The permanent fixture differential in `tests/test_taint_enclosing_index.py:76-81` also explicitly installs the original linear algorithm and is unaffected.

## Implementation reasoning

| Concern | Current source and result |
| --- | --- |
| Inclusive endpoints and gaps | `taint_flow.py:255-265` schedules each end at `end + 1` and expires entries only when `end < line`. Every potential winner change therefore has an event; before the first segment and after the terminal `None` segment the binary lookup returns no match. Single-point intervals remain eligible for their one line. |
| Greatest start and first eligible tie | `taint_flow.py:252-265` uses the heap key `(-start, ordinal, end, node)`. The root has the greatest start and earliest original ordinal among unexpired intervals. Expired earlier ties are removed until the next eligible tie reaches the root. Unique ordinals prevent heap comparisons from reaching AST objects. |
| Arbitrary input order and crossing overlaps | Sorting event coordinates, rather than relying on `ast.walk` order or proper nesting, handles disjoint, nested, crossing and equal-start intervals. Lazy removal of expired non-root entries cannot hide a better eligible root; each entry is pushed once and popped at most once. |
| Negative starts and reversed intervals | `taint_flow.py:253-254` excludes `start <= -1`, exactly matching the original `best_start = -1` sentinel; `start > end` could never satisfy the original containment check. Zero starts remain accepted. Empty collections return empty tuples and no match. |
| Identity and provenance | `taint_flow.py:266-270` retains the original AST references and compresses consecutive equal winners using identity. Neither intervals nor nodes are rewritten. Repeated references to the same node can safely share a segment because the lookup returns only that object. `id(fn)` caches, decorators, source coordinates, `enclosing_name` and `enclosing_fn` retain their semantics. |
| Construction lifecycle | `taint_flow.py:279-285` builds the index after all original intervals have been appended. Current production consumers only enumerate/read `funcs` (`taint_into_name` at line 728); no post-construction mutation was found in `src/attackmap` or tests. Future mutation would need an index rebuild, but it is outside the present private lifecycle. |
| Complexity and scope | At most two event coordinates per function, one heap insertion/removal per function, and at most one segment per event give O(F log F) construction, O(F) additional storage and O(log F) lookup. The patch does not cap, drop or shorten any function, sink, evidence chain or scan. No threshold/default/fixture change appears in this source diff. |

## Evidence checked without rerunning workloads

- Reviewed `git diff -- src/attackmap/taint_flow.py` and all 81 lines of the new test. Its reference at lines 15-21 is the removed linear loop verbatim. Identity comparisons cover endpoints, ties, invalid intervals, 250 seeded shuffled interval collections, decorated async/nested/sibling boundaries, and full scan outputs for all 11 Python taint fixtures.
- Parsed `resume-scanner-20261022/focused-approved.xml`: 275 tests, 0 errors, 0 failures, 0 skips, suite time 25.125 seconds. The log/README reports pytest's 25.19-second terminal total. This review inspected retained worker results; it did not execute those tests independently.
- Inspected historical `differential-6000.json`: both recorded outputs contain 6000 routes and 6000 external calls; full `ScanResult` equality is recorded with identical SHA256 `9a0ad9b5a6c511651e4abe695513c12a136d132ec254e8da8b48be1df18fa19f`. Recorded wall times are 10.4784783 seconds linear and 7.8287092 seconds indexed. Its rerun caveat is resolved by the new comparison below.
- Inspected the integrator's new `verify_canonical_6000.py` and `canonical-6000.json`: explicit original linear lookup versus captured current canonical index, both with 6000 routes and 6000 external calls, complete output equality and the same result SHA256. Recorded wall times are 8.3485086 and 7.3351843 seconds. The harness records hashes for every Python source under `src/attackmap` and every fixture file, asserts that both maps remain unchanged, restores the current lookup in `finally`, and refuses to overwrite retained output. It uses the current constructor in both modes, so these timings compare lookup modes in that constructor, rather than reproducing an entire old engine. This is bounded correctness evidence with a local timing observation, not a broad performance claim. The integrator executed it; this reviewer inspected its retained code and result without launching a workload.
- Current source SHA256 is `AF4E1BB6341ABC26F400AA1CDA9D789749A7E38CB28EAE99793762FE010944D2`; new test SHA256 is `DB3A6259E2E7FBA4636C802975D85E8B32F6F72850EE5CBFD870DF40F66DC32A`. Both match the worker's `source-hashes.json`.
- `git diff --name-only -- tests/test_scan_limits.py tests/test_resource_budgets.py` produced no changes. Their retained timing results are scoped test evidence; neither the single 6000-route comparison nor this static review is a broad performance campaign.

## Handoff

- `task_id`: WP023 interval-index independent review.
- `owner`: `/root/ultra_taint_review`.
- `base_commit`: `18fc9b2ae711bf0b39d93c996ae2ab220cc9a82d`.
- `final_commit_or_diff_hash`: uncommitted review document; reviewed source/test hashes recorded above; no source patch authored.
- `paths_changed`: `docs/verification/windows-parity/WP023/ultra-review-20261022.md` only.
- `leases_released`: review-document lease released on delivery; no source lease held.
- `tests_executed`: none; read-only source, diff, hash, XML and JSON inspection.
- `tests_not_executed`: regression, profiling, build, UI, model and independent dynamic counterexample execution.
- `live_provider_calls`: 0.
- `manual_checks`: static algorithm proof and current caller/test/evidence review; no GUI review.
- `package_id`: not applicable.
- `run_ids`: `resume-scanner-20261022` worker evidence and the integrator's `canonical-6000.json`; no reviewer workload run.
- `evidence`: source diff; current source/test hashes; focused-approved XML; historical differential and new canonical JSON/harness; this document.
- `limitations`: static review plus retained focused results; no broad gate, qualified performance claim, packaged/native acceptance or independent rerun.
- `next_action`: integrator may accept the focused implementation after its normal integration checks; use the new explicit canonical harness for future comparisons and preserve original evidence.
