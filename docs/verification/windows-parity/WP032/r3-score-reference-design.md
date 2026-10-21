# R3 producer-owned score reference — separate design, not implemented

Do not infer score ownership from equal numbers, tier labels, co-location, or UI
selection. Current producer `threat_model.py:1608–1613` chooses one
ExploitabilityScore per sink-kind aggregate and retains only score/tier; current
presentation cannot recover that producer decision reliably.

Proposed additive lease, separate from R1/R2:

- models.py: optional producer score ID/source-route-file on ExploitabilityScore;
  optional exact `exploitability_score_ref` on Finding. Legacy absent refs remain
  absent. Review schema/additive consumer fixtures before naming final fields.
- exploitability.py: emit ID at `_score_chain`, derived from the canonical typed
  taint-chain identity `(route_method,route_path,route_file,sink_kind,sink_file,
  sink_line)` used by merge.py. Do not derive from display prose, score, factor
  order, or normalized taint observation ID (the latter currently omits
  route_file in its identity). Scope ID resolution to selected repository/report
  generation; it is not global authenticity or runtime proof.
- threat_model.py: attach the exact selected producer score ID alongside existing
  numeric score/tier, without changing score policy. Resolve equal-score ties
  deterministically using full producer identity if needed.
- finding_presentation.py/report.py: resolve only the exact ref within supplied
  producer scores; reject duplicate/missing/stale refs as unavailable. Keep
  explicit candidate-only value matches separate if legacy context needs them;
  do not mark their contributions finding-owned/supplied.

Focused tests: identical score/tier on unrelated sink kinds; clamped 100 scores
with distinct raw factors; same path/sink with different route_file; identical
relative paths in two repo generations; exact positive ref; absent legacy ref;
unknown/duplicate ref; score/ref disagreement; factor permutation; unchanged
numeric ranking and legacy import behavior. Prove model→fusion→report propagation
with fixture artifacts, then run the smallest affected model/report/score suites.
No scoring, schema, producer, presentation or test source changes are authorized
by this design document itself. R1/R2 candidate does not implement any of this.
