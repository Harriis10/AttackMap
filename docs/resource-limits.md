# Resource limits (C35 / AM049)

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

### 50,000 / 100,000-file fixtures

`tools/gen_stress_repo.py --count 50000|100000` is supported and generation is
deterministic, but full engine measurements at those sizes were **not** run
tonight — the 10,000-file scan takes ~4 minutes per run on this host, and the
50k/100k runs need a longer measurement window. This is a stated gap, not an
extrapolated number.

## Reproducing

Exact commands used for tonight's numbers (from the repo root):

```bash
# 10k measurement (fixture generated into a temp dir, 3 repeats)
.venv/Scripts/python.exe tools/measure_stress.py --count 10000 --repeat 3 \
  --json-out C:/tmp/attackmap-stress10k.json

# cancellation-under-load proof (opt-in; measured 125.5 s for the 5,000-file
# fixture with a 1-second budget — bounded by one scan stage, not a hang)
ATTACKMAP_STRESS_TESTS=1 .venv/Scripts/python.exe -m pytest \
  tests/test_resource_budgets.py -q

# standalone fixture generation (50k/100k supported; never commit fixtures)
.venv/Scripts/python.exe tools/gen_stress_repo.py --count 50000 --output "$TEMP/stress50k"
.venv/Scripts/python.exe tools/gen_stress_repo.py --count 100000 --output "$TEMP/stress100k"
```

## Known gaps vs the C35 criterion

1. 50,000- and 100,000-file measurements not yet recorded (tooling supports
   them; awaiting a longer window).
2. The 512 MiB accepted-text default is not a shipped default yet (see honesty
   note above); the 100,000-file-count default shipped on 2026-10-17 via the
   index owner's parallel change.
3. Peak memory is measured for a single-repo, single-worker, in-process run.
   Fleet-wide memory admission (capping total worker memory across
   subprocesses) is not implemented.
4. Numbers qualify this host only; a reference-host qualification pass (or a
   documented default reduction) remains open until repeated on the pinned
   reference machine.
5. The graph edge breach is reported via `graph.graph` attributes and
   `scan.limitations`; a typed `ResourceLimitEvent` producer for the graph
   would require extending the `producer`/`category` Literals in
   `models.py` (owned elsewhere; the index owner extended them for
   `index_files` on 2026-10-17, the same route a future `graph.edges`
   producer would take).
