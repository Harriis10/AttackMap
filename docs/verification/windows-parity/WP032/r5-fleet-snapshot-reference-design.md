# R5 fleet source-basis preservation — separate design, not implemented

Current finalize reads deployment aliases and auth markers after child analysis.
`pipeline.py:1024` clears the thread pin; separate workers never install their
captured indexes in the parent. `scan_service.py:751,756` may therefore combine
captured typed routes/calls with newer live config/handler bytes. A child report's
snapshot verification is not verification of these later parent reads.

Proposed bounded slice, coordinated with WP033/WP035 owners:

1. Compute per-repository deployment declarations and route-auth facts while
   that child's captured index is available. Use explicit matching index/scope;
   missing capture must produce unknown/limitation, never a live fallback.
   The current `captured_index` is local to run_scan (pipeline.py:401), not a
   returned state field. Compute the bounded facts there before clearing the
   pin, or explicitly thread that index to a narrow producer while it is alive;
   do not assume a nonexistent state.index/state.captured_index API. Parallel
   mode must compute the same facts in the child before interchange.
2. Introduce a bounded internal `FleetEvidenceBasis` payload containing child
   repo/generation/snapshot identity, declaration keys with exact relative source
   identities/hash basis, and route-auth facts keyed by file/method/case-sensitive
   path with known/unknown status. Include no raw source bytes or credentials.
   Hash basis must match the actual captured index; do not label normalized-text
   hashes as raw-byte hashes. No namespace/service owner may be guessed.
3. Carry this additive internal payload through `_run_single` fleet_result
   serialization (scan_service.py:252–260), `_load_repo_scan:398`, and
   FleetRepoResult. Extend the existing reserved result-byte limit and explicit
   max-record bounds; reject over-budget payloads without silently dropping
   references or importing arbitrary files. Do not retain every child RepoIndex
   or raw snapshot in fleet parent memory as a workaround.
4. Parent validates repo, child generation, snapshot, declaration/route shape and
   bounds, then merges captured facts only. CLI declaration precedence remains
   explicit; its origins must remain CLI, not inherit a discarded config origin.
   Unknown auth cannot prove an omitted control. Missing legacy basis must be
   surfaced as unavailable for dependent reasoning rather than re-read live.

Exact file lease proposal: new bounded evidence-basis module + scan_service.py
interchange/finalize + additive FleetRepoResult field in fleet.py; pipeline/state
access only if needed for explicit index lifetime. Add focused owned fixture
tests first; coordinate all fields and byte ceilings with the current transport
owner before editing. No core/schema changes are made by this design document.

Acceptance fixtures: edit/delete/add config after child capture; change handler
auth after child returns; all child completion permutations; serial/parallel
parity; two same-basename roots; changed repo/generation/snapshot payload;
unknown/partial capture; malformed/oversized facts; cancellation; CLI override
origin; unchanged source complete positive control. Dependent links/risks must
either reflect the captured old basis or explicitly remain unavailable, never
upgrade to observed from newer live bytes. No real scan, provider call, TLS/mTLS
observation or runtime control claim is required for these controlled fixtures.
