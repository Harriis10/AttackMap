<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Resource limits (C35 / AM049)

## WP034 bounded aggregate-input policy — 2026-10-31

Core API fleet callers may explicitly set `ScanRequest.fleet_input_byte_budget`
to a positive integer. The default remains `None`: ordinary serial/count-only
fleets retain their existing behavior, and the single-repository aggregate
default remains uncapped. No new qualified numeric default is claimed. A public
single-repository request rejects this fleet-only option instead of ignoring it.
There is no CLI, wire-protocol or native setting for the option in this slice.

For `B` bytes across `N` requested repository IDs, the coordinator reserves
`B // N` bytes per repository and one additional byte for the first `B % N`
repositories in input order. The quotas sum to `B`; scheduling and completion
order cannot change them. Quotas remain reserved for the whole run, including
failure and cancellation. Unused capacity is not transferred between siblings.
A zero-byte quota produces the typed `fleet_input_capacity` failed row without
dispatch; successful siblings remain available. Invalid budgets fail before
dispatch. Opting in uses supervised children even with a worker count of one.

Each child receives its quota through its own copied environment, without any
parent/global environment mutation. A positive inherited
`ATTACKMAP_INDEX_BYTE_BUDGET` remains an additional ceiling: the effective child
limit is the smaller of that ceiling and its fleet quota. Existing capture gates
continue to emit `ResourceLimitEvent(category="index_bytes")`, limitations and
partial fleet-architecture repository status for skipped files. The parent
requires the returned snapshot's `index_byte_budget` to match the effective
limit and its `total_size` to fit that limit; an absent, mismatched or excessive
snapshot produces `fleet_input_budget_unverified` and is not retained as success.
This is consistency checking of the owned worker result, not authentication of
an untrusted analyzer or proof of actual physical memory use.

`run-manifest.json` adds `fleet_resource_admission.input_bytes` only when opted
in. It records `total_bytes`, `allocated_bytes`, `repository_quotas`, and
`verified_captured_bytes` (successful bound snapshot totals only). Its explicit
`capture_status` is `partial` if any requested child fails/is not admitted or
any successful child emits an `index_bytes` skip; otherwise it is `within_quotas`.
`within_quotas` describes this policy only, never language/rule/runtime coverage.
Existing fleet diagnostic coverage remains scoped to accepted-path enumeration;
child byte-limit events and limitations carry the skipped-source evidence.

Input-byte quotas compose with the existing opt-in `FleetMemoryPolicy`; they
do not replace live/retained-result reservations or enforce an OS memory limit.
Capture read buffers, decoded text, analyzer signals, models, graphs and parent
retention can exceed captured input bytes. This bounded policy does not close
WP034/C35, qualify 10k/50k/100k scans, prove a peak below 2 GiB, or qualify a
native/package/release build. [Reproduction, tests and limits](verification/windows-parity/WP034/agent-admission-20261031/README.md).

## WP034 implementation checkpoint — 2026-10-21

The following describes the current narrow fleet-policy patch. Measurements below
this section are retained historical evidence, not qualification of the present
source. WP034 remains **PARTIAL**. The current21-module10k run took about1072s,
including1068s in analyzer selection, and exceeded the default600s stage budget
before scan/merge. It provides no working scan/merge peak or <2GiB acceptance.
The512MiB aggregate input default remains a proposal owned by the index workstream;
input bytes alone do not bound signal/model/graph memory. No source/analyzer/graph
coverage was reduced by the fleet patch.

Ordinary fleets retain their existing count-limited behavior. The additive
`fleet_resource_admission` entry in `run-manifest.json` labels count-only and
in-process serial execution as memory qualification **unknown**. No fabricated
per-child2GiB estimate or default failure of unconfigured fleets is introduced.

Core API callers may explicitly supply `ScanRequest.fleet_memory_policy`, a
`FleetMemoryPolicy` from `attackmap.fleet_admission`. This is an opt-in logical
admission policy, **not OS enforcement or proof of peak memory**. The caller must
provide positive total, parent, parse and linking headroom budgets, and a
`FleetMemoryEstimate` per stable fleet repository ID. Each estimate contains
live-child bytes, retained-result bytes, serialized-result byte limit and the
identity of reviewed measurement evidence. A string identity records the caller's
claim; the ledger does not authenticate or independently validate measurements.
There is no presently qualified numeric default. The wire protocol and native
settings do not expose this experimental policy.

Under this policy, the coordinator atomically reserves live plus retained-result
bytes **before** submitting a child. Fixed parent/parse/linking headroom is charged
throughout. A successful, verified child exit atomically drops the live charge
and keeps the retained-result charge through fleet linking/publication. Siblings
wait when active workers can free capacity; if retained results alone prevent a
later child from fitting, that child fails explicitly rather than losing source
coverage silently. The returned manifest records requested estimates, peak
logical reservations and remaining retained charges. It does not report these
as observed working set or physical memory limits. Separate fleet requests do
not share a physical-memory reservation pool.

Missing estimates produce `fleet_memory_unknown`; insufficient capacity produces
`fleet_memory_capacity`; cancellation before dispatch produces
`fleet_admission_cancelled`; a result exceeding its configured serialized limit
produces `fleet_result_bytes`; unverified tree termination produces
`fleet_cleanup_unknown`. These names live in existing fleet failed rows as
`error_type`, with ordinary failed/partial fleet behavior and preserved successful
siblings. Existing `ResourceLimitEvent` categories describe source file/index
skips only; no incompatible category was inserted into that schema. Both success
and failure result JSON reads are bounded under the opt-in policy. Bounded JSON
bytes do not themselves establish a bound on parsed model memory; that must be
included in reviewed parse/retention estimates.

Cancellation acknowledgement, process leader exit and Future completion never
prove cleanup. The supervisor's verified entire-tree completion is the release
condition. An uncertain child keeps its full reservation; a process-local
quarantine prevents later fleet requests from bypassing its outstanding cleanup.
A late verified supervisor callback releases the quarantined charge. Repeated
callbacks cannot double-refund. The current fleet stops further admission after
uncertainty even if cleanup later completes; already successful siblings remain.
In-process serial mode remains unchanged unless the caller explicitly opts into
the policy, which uses supervised children even at concurrency1.

`fleet_timeout_seconds` now reaches the supervised child with or without a
progress callback. This is a hard worker elapsed timeout, including startup and
publication, followed by verified cleanup; it is distinct from the cooperative
stage budget. The stage budget starts before capture, allows the current stage
to finish and marks skipped later optional stages partial. A stage boundary
check cannot prevent an in-flight hang. Under opt-in memory policy, failed cleanup
after cancellation/timeout is surfaced after15s cleanup grace as uncertainty,
never as verified termination; owned supervision and reservation remain until
verification. Default count-only mode retains the prior wait-for-cleanup behavior.

Qualification still requires like-for-like current-scope10k/50k/100k working
measurements, signal/graph counts and source identities, measured finite aggregate
and per-child defaults, parent parse/link/retention cost, actual sibling and
cancel-under-load evidence. Small subprocess tests exercise OS lifecycle and
policy plumbing only, not scanner memory acceptance or an OS memory cap.

AttackMap publishes finite default budgets so a huge repository ends as an
**explicit partial analysis** instead of an unbounded run. Every exceeded limit
produces either explicit partial coverage or a typed failure; no truncated
result is ever represented as complete.

## Budget table

| Budget | Default | Override | On breach |
| --- | --- | --- | --- |
| Accepted text per run (aggregate bytes) | **no aggregate cap today** (see honesty note below) | `ATTACKMAP_INDEX_BYTE_BUDGET=<bytes>` | Files exceeding the remaining budget are skipped one by one; a `ResourceLimitEvent` (`repo_index` / `index_bytes`) and a limitation record it. Not all later files are claimed skipped. |
| Accepted bytes per file | 2,000,000 | `ATTACKMAP_MAX_FILE_BYTES=<bytes>` | File skipped; `ResourceLimitEvent` (`repo_index` / `file_bytes`) with the observed stat size. |
| File count per run | 100,000 | `ATTACKMAP_INDEX_FILE_LIMIT=<n>` (0 disables); `RepoIndex.build(max_files=n)` (added 2026-10-17 by the index owner) | Files beyond the cap are skipped; one aggregate limitation line plus a structured `ResourceLimitEvent` (`repo_index` / `index_files`, `observed_files`) and a partial scope. Never a silent drop. |
| Graph edges | 1,000,000 | `ATTACKMAP_MAX_GRAPH_EDGES=<n>` or `build_graph(scan, max_edges=n)` | Edge insertion stops at the ceiling; the built subgraph stays usable and carries `graph.graph["edge_budget_exceeded"]` plus a `scan.limitations` entry naming the PARTIAL scope. |
| Deterministic elapsed time | 600 s (10 min) | `--time-budget-seconds <n>` (CLI) or `ATTACKMAP_TIME_BUDGET_SECONDS=<n>` (env; CLI flag publishes the env var so fleet workers inherit it) or `AnalyzeOptions.time_budget_seconds` (SDK) | The in-flight stage runs to completion; later optional stages are skipped; the run ends **COMPLETED** with `error_type="time_budget_exceeded"` in `analyzer_errors`, a limitation saying ANALYSIS IS PARTIAL, `time_budget.exceeded=true` in `run-manifest.json`, and `coverage.status="partial"` in the diagnostic context. |
| AI usage (per repo, whole scan) | 8 provider calls / 32,000 output tokens / 600 s | `--ai-max-calls`, `--ai-output-tokens`, `--ai-timeout-seconds` | No provider attempt starts past the allowance (`docs/ai-budgets.md`). Fleet AI features are rejected outright. |
| Worker concurrency (fleet) | 1 (serial); `--max-workers`/request `max_workers` | capped by `ATTACKMAP_FLEET_MAX_WORKERS` | Never more workers than repositories; invalid cap is a typed configuration error. |
| Desktop/fleet worker supervision | 600 s subprocess timeout | fleet/desktop supervision config | Worker is terminated and recorded as failed, not left running. |

### Honesty note: the 512 MiB accepted-text default

The C35 engineering target is a 512 MiB default aggregate accepted-text budget.
**Today's shipped default is no aggregate cap** (`ATTACKMAP_INDEX_BYTE_BUDGET`
unset = unlimited aggregate; the 2 MB per-file and 100,000-file caps do apply).
The aggregate budget machinery, events, and scopes already exist in
`src/attackmap/index.py` and are fully override-driven; flipping the default
from "unset" to 512 MiB is a one-line change in `index.py`, which is owned by
the parallel AM049 workstream (which added the file-count cap on 2026-10-17)
and was intentionally not duplicated here. Until that lands, treat 512 MiB as
a **target**, not a shipped default.

## Deadline semantics (what "elapsed time" bounds)

The deterministic budget is checked at stage boundaries
(`scan_and_merge` start; `secrets_history` / `cve` / `suppress` / `baseline` /
`pr_comment` / `llm` / `hunt` / `remediate` / `triage` starts). An in-flight
stage always runs to completion — so the worst case is one stage's own
duration beyond the ceiling, never an unbounded hang, and never a mid-stage
kill that would corrupt publication. `translate` and `publish` always run so a
breached run still emits its reports plus the partial marker. The check is a
single `perf_counter` read per boundary: measured 273 ns per check (100,000
checks timed), i.e. ~3 µs per run at ~10 checks — negligible by construction.

## Tonight's measurements (2026-10-17)

Produced by `tools/measure_stress.py` against a fixture from
`tools/gen_stress_repo.py` (deterministic template, ~687 bytes/file, one Flask
route + subprocess sink + secret-hint per file). Fixtures are generated into a
temp directory at run time and never committed.

### Host context

- Windows 10 19045 x64, AMD64, 8 logical CPUs, 64 GiB total RAM
- Python 3.13.15, in-process engine run (the measuring process is the engine)
- Peak memory method: `ctypes GetProcessMemoryInfo` → `PeakWorkingSetSize`
  (process-lifetime peak; with `--repeat 3` it is the max across runs).
  Stdlib only — no new dependencies.

### 10,000-file fixture (measured 2026-10-17)

Fixture: 10,000 files, 6,867 KiB (7,012,230 bytes) declared and verified on
disk (~687 bytes/file); generation took 5.9 s. 3 measurement runs, each a full
engine scan (auto analyzer set, `files_scanned=10000`, 1 high finding each);
all three completed inside the 600 s default budget with `exceeded=false`.

| Stage | p50 ms | p95 ms | samples |
| --- | --- | --- | --- |
| request_validation | 0 | 0 | 3 |
| select_analyzers | 3,173 | 3,978 | 3 |
| scan_and_merge | 115,197 | 191,621 | 3 |
| translate | 20,214 | 20,256 | 3 |
| suppress | 10,358 | 10,570 | 3 |
| publish | 11,847 | 11,876 | 3 |
| Whole run (wall) | 165,948 | 243,289 | 3 |

- **Peak resident memory: 903,299,072 bytes = 861.5 MiB — below the 2 GiB
  threshold** (a single deterministic worker, in-process). Working set after
  each run: ~252-264 MiB.
- Deadline-check overhead: **273 ns per check** (100,000 checks measured);
  a run performs ~10 checks → ~3 µs total, negligible by construction.
- Caveat, stated honestly: run 1 (200 s scan) was slower than runs 2-3
  (~115 s) on the same fixture — first-run warmup on this host. p95 with 3
  samples is effectively the max; treat it as an upper bound, not a stable
  percentile.
- At the measured rates the 600 s default bounds roughly 40,000-50,000 files
  of this shape on this host; larger inputs will breach and end COMPLETED
  with explicit partial coverage (proven by the cancellation-under-load test).
- These numbers describe **this fixture on this host only**. No universal
  repositories-per-second claim is made or implied.

### 50,000-file fixture (measured 2026-10-19 overnight)

Fixture: 50,000 files, 35,372,230 bytes (~33.7 MiB, ~687 bytes/file). 3 full
engine runs on the **current 9-analyzer engine** (post-AM052 — note the 10k
reference above was measured on the pre-wave 4-analyzer engine, so the series
is not a like-for-like scaling curve; a fresh 10k on the current engine is a
recorded follow-up). All runs scanned all 50,000 files (`files_scanned=50000`,
1 high finding each).

| Stage | p50 ms | p95 ms | samples |
| --- | --- | --- | --- |
| request_validation | 0 | 0 | 3 |
| select_analyzers | 62,887 | 81,045 | 3 |
| scan_and_merge | 564,427 | 1,004,332 | 3 |
| translate | 56,457 | 56,793 | 3 |
| suppress | — skipped — | — | budget expired before this stage |
| publish | 91,972 | 94,405 | 3 |
| Whole run (wall) | 827,328 | 1,287,345 | 3 |

- **The 600 s default time budget EXPIRED in every run** (`exceeded=true`,
  before the `suppress` stage): the run ends COMPLETED with explicit partial
  coverage — visible budget exhaustion demonstrated at scale, not only in unit
  tests.
- **Peak resident memory: 5,166.0 MiB (5.05 GiB) — ABOVE the 2 GiB
  threshold.** The peak is transient (mid-run, inside `scan_and_merge`): the
  working set after each run settles at ~1,265-1,272 MiB.
- Deadline-check overhead: 295.1 ns per check.

### 100,000-file fixture (measured 2026-10-19 overnight)

Fixture: 100,000 files, 70,822,230 bytes (~67.5 MiB). 3 full engine runs; all
scanned all 100,000 files — the 100,000-file index cap did **not** trigger
(exactly 100,000 accepted, none skipped), 1 high finding each.

| Stage | p50 ms | p95 ms | samples |
| --- | --- | --- | --- |
| request_validation | 0 | 0 | 3 |
| select_analyzers | 126,286 | 126,643 | 3 |
| scan_and_merge | 1,131,806 | 1,981,384 | 3 |
| translate | 114,234 | 116,229 | 3 |
| suppress | — skipped — | — | budget expired before this stage |
| publish | 187,805 | 189,751 | 3 |
| Whole run (wall) | 1,663,514 | 2,497,808 | 3 |

- Time budget 600 s expired in every run (same explicit partial-coverage
  outcome; wall p50 27.7 min).
- **Peak resident memory: 10,279.3 MiB (10.04 GiB) — 5x ABOVE the 2 GiB
  threshold.** Working set after each run: ~2,465-2,477 MiB. The mid-run spike
  lives in `scan_and_merge`, which holds per-file signal state for the whole
  repository before merge/publish can release it.
- Deadline-check overhead: 265.3 ns per check.

### What the 50k/100k numbers mean for C35

Stated plainly: **the C35 peak-memory criterion (`< 2 GiB`) is NOT met at
50,000 or 100,000 files on this host.** The 10,000-file measurement passes
(861.5 MiB, pre-wave engine). The honest reading:

1. Coverage stays complete even when the time budget expires (all files
   scanned; the skip list is empty) — degradation is visible and typed, never
   silent.
2. The memory excess is a transient peak inside `scan_and_merge`, not the
   steady-state footprint (1.3 GiB / 2.5 GiB after the run). Any fix should
   target per-file signal lifetime during the scan loop (streaming merge or
   chunked release), not the published models.
3. Until a fix or a documented memory budget/degradation policy for very
   large repositories lands, large-repo peak memory remains an **open
   criterion gap** — recorded, not waived.

## Reproducing

Exact commands used for tonight's numbers (from the repo root):

```bash
# 10k measurement (fixture generated into a temp dir, 3 repeats)
.venv/Scripts/python.exe tools/measure_stress.py --count 10000 --repeat 3 \
  --json-out C:/tmp/attackmap-stress10k.json

# 50k / 100k measurements (2026-10-19 overnight; ~45 min / ~2 h on this host)
.venv/Scripts/python.exe tools/measure_stress.py --count 50000 --repeat 3 \
  --json-out C:/tmp/am-c35/measure-50k.json
.venv/Scripts/python.exe tools/measure_stress.py --count 100000 --repeat 3 \
  --json-out C:/tmp/am-c35/measure-100k.json

# cancellation-under-load proof (opt-in; measured 125.5 s for the 5,000-file
# fixture with a 1-second budget — bounded by one scan stage, not a hang)
ATTACKMAP_STRESS_TESTS=1 .venv/Scripts/python.exe -m pytest \
  tests/test_resource_budgets.py -q

# standalone fixture generation (50k/100k supported; never commit fixtures)
.venv/Scripts/python.exe tools/gen_stress_repo.py --count 50000 --output "$TEMP/stress50k"
.venv/Scripts/python.exe tools/gen_stress_repo.py --count 100000 --output "$TEMP/stress100k"
```

## Known gaps vs the C35 criterion

1. **Peak memory exceeds 2 GiB at 50k/100k files** (5.05 GiB / 10.04 GiB,
   measured 2026-10-19): open engineering work — streaming/chunked signal
   release inside `scan_and_merge`, or a documented memory budget with
   explicit degradation for very large repositories. Recorded, not waived.
2. The 10k passing reference (861.5 MiB) was measured on the pre-AM052
   4-analyzer engine; a fresh 10k run on the current 9-analyzer engine is a
   follow-up so the series is comparable.
3. The 512 MiB accepted-text default is not a shipped default yet (see honesty
   note above); the 100,000-file-count default shipped on 2026-10-17 via the
   index owner's parallel change.
4. Peak memory is measured for a single-repo, single-worker, in-process run.
   Fleet-wide memory admission (capping total worker memory across
   subprocesses) is not implemented.
5. Numbers qualify this host only; a reference-host qualification pass (or a
   documented default reduction) remains open until repeated on the pinned
   reference machine.
6. The graph edge breach is reported via `graph.graph` attributes and
   `scan.limitations`; a typed `ResourceLimitEvent` producer for the graph
   would require extending the `producer`/`category` Literals in
   `models.py` (owned elsewhere; the index owner extended them for
   `index_files` on 2026-10-17, the same route a future `graph.edges`
   producer would take).
