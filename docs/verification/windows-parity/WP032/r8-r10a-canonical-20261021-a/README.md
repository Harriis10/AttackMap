# R8 unknown auth / R10a host labels

Approved narrow canonical slice: `crossrepo.py`, `topology.py`, and new `test_wp032_unknown_auth_topology.py`. No observation-ID migration, shared-file ownership change, schema, provider or GUI work.

Previously, a missing route auth entry defaulted to false and could classify an unread/unknown repository as omitting authentication. The cohort now retains missing entries as unknown. A repository enters either enforcement/omission group and the eligible denominator only when every relevant route has a known auth signal. Known true+unknown and known false+unknown both remain unknown. A complete two-enforcing/one-omitting cohort still produces the same speculative anomaly, independent of additional unknown repositories and input order. No runtime authentication claim is added.

Previously, topology split the first DNS label at its first hyphen, collapsing `auth-api` and `auth-worker` to `auth`. It now preserves the complete first label. Existing localhost aliases remain unchanged, and `http-call` remains a naming heuristic rather than an observed contract link.

`focused-run.json` / XML preserve **104 passes**, no assertion/setup failures. This includes existing crossrepo/topology, the R1/R2 reference-binding regressions, and 37 new controls (including all 24 repository order permutations). The topology docstring was corrected during that run to remove the stale claim that it mirrors the analyzer; this comment-only input drift is explicitly recorded rather than hidden. `topology-stable-run.json` separately records the targeted final-byte check of all topology tests and the seven hostname controls. No broad suite was repeated.

Limit: a present false auth signal is still the existing producer's heuristic result; this slice does not fix upstream file-read provenance or shared-handler ownership. Those require the separately scoped R5/R10b work.
