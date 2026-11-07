# WP032 independent ownership-index review — 2026-10-22

Verdict: **no actionable findings or implementation blockers** in the sealed canonical-equivalent topology index. The reviewed patch preserves the existing consumer differences, including explicit empty owners and order-sensitive threat ownership. The ambiguity-policy candidate remains held. This bounded review does not close WP032, C28 or a release gate.

Owner: `/root/ultra_taint_review`. Base: `18fc9b2ae711bf0b39d93c996ae2ab220cc9a82d`. Authority: current `AGENTS.md`, documentation index, Windows parity roadmap/TODO and the 2026-10-22 resume supplement. The review owns this document only; no source/test files were edited and no workloads were launched.

## Semantics reviewed

| Concern | Current source and conclusion |
| --- | --- |
| Topology name order and deduplication | `src/attackmap/topology.py:253-267` consumes the unchanged auth → service → edge family stream. Its per-file ordered dictionary retains each distinct lowercased nonempty name in first-seen order. This is the same normalized-name deduplication the removed `_services_in_file` loop performed; it does not import threat modeling's distinct raw-hint deduplication policy. |
| First owner and exact file keys | `topology.py:114-115` and `270-276` use the first indexed name, exactly matching the removed first-nonempty assignment. File strings remain raw dictionary keys; slash/backslash and case variants are not merged. `_services_in_file` retains its list return shape. |
| Empty, whitespace and Unicode | `topology.py:264-266` ignores only the empty name. Whitespace-only names remain truthy ownership values until the unchanged rendering code strips them; they are not replaced with a layout owner. `.lower()` remains `.lower()`, so `Straße` and `STRASSE` stay distinct normalized names. No `.strip()` or `.casefold()` was added to ownership collection. |
| Role attachment, rendering and graph order | `topology.py:133-139` reuses the same per-file name sequence for each role. Every conflicting nonempty name still receives the role, in the same order. Node/edge recording and layout fallback are unchanged, preserving rendered normalization, first useful role, node order, files_seen order, edge deduplication, edge evidence and all existing layout nodes. |
| Threat raw deduplication and empty markers | `src/attackmap/threat_model.py:260-267` still deduplicates exact raw `(payload, file)` pairs before `331-340` lowercases and overwrites owners. Thus `alpha, beta, alpha` selects `beta`; `alpha, empty, alpha` leaves the empty marker. Empty remains an explicit map entry and prevents map-level layout fallback. The file is byte-for-byte unchanged. |
| Consumer family boundaries | Topology continues to consider auth/service/edge hints. Threat ownership continues to consider auth/service hints only. The new index is local to topology; it is not shared into threat modeling or scoring. |
| Work and storage | Building the per-file index once removes the full hint-stream rescan previously performed for every role hint. The remaining role/name associations still run. The index requires storage proportional to distinct file/name associations. The deterministic pass-count test supports this structural claim; no runtime-speed or memory qualification is inferred. |

The explicit empty-owner counterexample in `resume-r10b-20261022/compatibility.json` remains a valid reason to hold the older ambiguity-policy candidate: it changed inferred-layout/elsewhere-in-repo evidence at approximately 0.50 service-chain confidence into unsupported file-local ownership at 0.80. The new patch does not make that change. The consumers' existing disagreements are deliberately preserved pending an explicit policy decision.

## Evidence inspected

- CodeGraph was consulted before source lookup. Reviewed the current Git diff, the sealed `ultra-owner-20261022/canonical.patch`, the complete 107-line new `tests/test_wp032_service_owner.py`, the comparison harness, manifest, XML and relevant original compatibility outputs. Current source/test hashes match the manifest.
- The sealed baseline topology's Git object is `354e7b8a783d9ef36eb2468bbd009e6e88e73582`, matching `HEAD:src/attackmap/topology.py`. Its preserved byte hash is `28dcf0de5ad989c8732b66cefbc907864788d7863031ae14e7cb432b498c3fd3`.
- Current topology SHA256: `7ed254df6018b69bc59cb7530ee3189ccc83b7af94518ba0135a5915b69b312a`. Current and baseline threat-model SHA256 both equal `49a08f1a0d3ff348b97b62c0dc44897ab7f4232b177117c967192557cb7cb31f`. New test SHA256: `717b52696efd6ae05c8c7146c9d1422080066248a0001adf2b9905beb8ef9083`.
- Parsed focused XML: **132 tests, 0 failures, 0 errors, 0 skips**, suite time 1.242 seconds; retained terminal log reports **132 passed in 1.29s**. These are the owner's executed canonical results, inspected without a reviewer rerun. The earlier 103-test candidate run is separate evidence and is not treated as canonical acceptance.
- `compatibility_check.py` loads separate baseline/current modules, deep-copies each input for each consumer run, and compares complete maps, per-file service lists, graph dataclasses, service/ATProto chains, generated findings and attack paths. Equality compares the actual nested structures before JSON storage; graph, evidence and other list orders remain part of the comparison.
- Retained comparison: **346 / 346 complete consumer outputs equal**, no differences, aggregate input hashes unchanged. The matrix covers three hint families, 18 name sequences, HTTP/env/queue calls, slash/backslash file keys, mixed families, separate sinks and absent layout. The negative control independently loads the rejected candidate and asserts detection of its empty-owner regression. This is a meaningful check against accidentally comparing the same implementation twice.
- `golden-before.json` SHA256 is `6fce537fa372707e30713a8ad444ebe1c0e27f594f5c67c24c175d284b9174ae`. All six artifact hashes listed in the manifest matched their current bytes. Sealed patch SHA256 is `e28ce6cd0eb259432c32f8fd485900d3219d1c89b92ad7c9fa5ba42c414b12ad`; its contents match the reviewed two-file patch. `git diff --check` for topology/threat source passed.

The differential establishes bounded equivalence of these complete consumer outputs on constructed inputs. It is not a complete real-repository ScanResult or pipeline differential, a broad regression, a performance campaign, an ambiguity-policy fix, or proof of all remaining C28 criteria. No timing limits, scan scope or fixtures were weakened by the reviewed patch.

## Handoff

- `task_id`: WP032 canonical-equivalent ownership-index independent review.
- `owner`: `/root/ultra_taint_review`.
- `base_commit`: `18fc9b2ae711bf0b39d93c996ae2ab220cc9a82d`.
- `final_commit_or_diff_hash`: reviewed sealed canonical patch `e28ce6cd0eb259432c32f8fd485900d3219d1c89b92ad7c9fa5ba42c414b12ad`; review document remains uncommitted.
- `paths_changed`: `docs/verification/windows-parity/WP032/ultra-owner-review-20261022.md` only.
- `leases_released`: review-document lease released on delivery; no source/test lease held.
- `tests_executed`: none by this reviewer; read-only source/diff/hash/XML/JSON inspection.
- `tests_not_executed`: regression, dynamic counterexample, profiling, build, UI, model and package workloads.
- `live_provider_calls`: 0.
- `manual_checks`: independent static equivalence reasoning, comparison strategy and artifact identity checks; no GUI review.
- `package_id`: not applicable.
- `run_ids`: owner's `ultra-owner-20261022` evidence; original `resume-r10b-20261022` compatibility evidence as historical negative context.
- `evidence`: current source diff, canonical patch, owner manifest/README, focused XML/log, compatibility harness/result and complete baseline golden.
- `limitations`: constructed-input consumer equivalence plus retained focused tests; no independent workload rerun, pipeline acceptance or C28 closure.
- `next_action`: integrator may accept the focused index after its normal integration checks. Keep the older ambiguity-policy candidate held and retain its counterexamples for a separately reviewed policy decision.
