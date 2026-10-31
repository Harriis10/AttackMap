<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Detection benchmark (`attackmap bench`)

The **1.0 precision gate** ([#197](https://github.com/mlaify/AttackMap/issues/197)).
Where `review_eval` grades LLM *review text*, this scores AttackMap's *findings*
against a hand-labeled corpus of ground-truth vulnerabilities and reports
**precision / recall / F1 per detector class**. Every future detector change
should report its delta here.

## Running it

```bash
attackmap bench                         # prints the per-class table
attackmap bench --output reports        # + benchmark-results.{md,json}
attackmap bench --fail-under 0.9        # CI gate: exit non-zero if any scored class drops below 0.9
```

Run from a repo checkout — the manifest ships in `evals/`, not the installed
wheel. Point `--benchmark` at a different manifest to score your own corpus.

## Methodology

- **Ground truth is labeled independently of the tool.** Each case in
  [`evals/benchmark/benchmark.json`](../evals/benchmark/benchmark.json) lists the
  genuine, exploitable weaknesses in a repo — read from the source, not derived
  from what AttackMap emits — so the score is not circular.
- **Only precise detector classes are scored.** `injection`, `bola`,
  `unauth_state_change`, `webhook_exposure`, `crypto`. Architectural / advisory
  findings (e.g. "public routes sit near sensitive data", secret-env
  *references*, admin-route groupings) make no precise claim and are **out of
  scope** — they never count as false positives. (`cve` is not scored by the
  default runner: it is offline+deterministic and does not query OSV, so a CVE
  label would only ever record a false negative — CVE benchmarking needs a
  recorded-OSV fixture, tracked as future work.)
- **Matching.** A finding is mapped to a canonical class from its tags/title, and
  matched to a label when the class agrees and its evidence cites the same
  **repository-relative** file, confirmed by an **exact route + method** match
  (`/orders` never matches `/orders/search`) or — when the finding cites no
  route — a line within a small window.
- **Metrics.** *Recall* = labels matched by ≥1 finding ÷ total labels; *precision*
  = scored findings that matched ≥1 label ÷ all scored findings. A grouped finding
  that legitimately cites several true routes helps recall without a precision
  penalty.

## Baseline (v0.4.28, example-app corpus)

| Detector class | Precision | Recall | Notes |
|---|---|---|---|
| `webhook_exposure` | 100% | 100% | Public unverified webhook detected. |
| `unauth_state_change` | 100% | 40% | Per-route detection is solid; **recall gap** — admin/internal-prefixed state-changing routes are absorbed by the admin-route grouping and not flagged individually. |
| `bola` | 100% | 50% | **Recall gap** — misses an id-addressed Flask read route. |
| `injection` | — | 0% | **Recall gap** — same-file f-string / concatenated SQL in `orders-api-demo` is not yet caught by the taint pass. |

**Precision is 100% across every scored class** — AttackMap's precise findings on
this corpus are all true positives. The value of the baseline is the honest
**recall gaps**, which are exactly the targets the [road to 1.0](https://github.com/mlaify/AttackMap/issues/209)
epics attack: injection depth, unauthenticated admin/internal routes, and broader
BOLA coverage. The corpus grows as new labeled cases (known-vuln and known-clean)
are added; the standing invariant enforced by tests is **precision = 100%** on the
curated set — a regression that introduces a false positive fails CI.

## v0.6.0 — intra-procedural taint flows (#239)

The taint pass now traces a request value through local assignments to the
sink (`u = request.args["u"]` → `requests.get(u)`), binds sanitizers to that
flow, and raises a dedicated SQL-injection / path-traversal finding only when a
flow is traced. A new labelled case, `express-docs-demo`
(`evals/benchmark/cases/`), adds two-line JS path-traversal and SSRF routes plus
their known-clean twins (basename-reduced path, fixed-host URL).

| Detector class | Precision before → after | Recall before → after |
|---|---|---|
| `injection` | — → 100% | 0% → 100% (0/5 → 5/5) |
| `bola` | 100% → 100% | 50% → 50% |
| `unauth_state_change` | 100% → 100% | 40% → 40% |
| `webhook_exposure` | 100% → 100% | 100% → 100% |

"Before" is v0.5.0 scored against the same (extended) corpus. The full run
history lives in [`evals/benchmark/HISTORY.md`](../evals/benchmark/HISTORY.md).

## M0 scoped-evidence check (2026-10-15, source 1.5.1 working tree)

The AM003 integration removes repository-wide datastore/outbound hints from
route facts. On the existing four-repository, 13-label corpus, the measured
results are:

| Detector class | Precision | Recall | Matched labels |
| --- | --- | --- | --- |
| `injection` | 100% | 100% | 5/5 |
| `bola` | 100% | 50% | 1/2 |
| `unauth_state_change` | 100% | 40% | 2/5 |
| `webhook_exposure` | Not defined (no predictions) | 0% | 0/1 |

The webhook recall drop from 100% to 0% is an explicit limitation. The billing
fixture performs fixed-target, parameterized operations that the current taint
chains do not link to its webhook. The previous finding borrowed repository
context as route reachability. Restoring coverage requires evidence of the
handler's actual operations (AM012/AM013 and AM038), without restoring global
hint propagation. The original labels and fixtures remain unchanged. These
small-corpus results do not establish general detector quality or pass C27.

Reproduce with `python -m attackmap bench --output reports/m0-benchmark`.

## AM037 — versioned evaluation corpus (`attackmap evaluate`, C27)

`src/attackmap/evaluation.py` adds the C27 evaluation infrastructure on top of
`bench`: a **versioned corpus manifest** (schema + corpus version, frozen split
seed) whose cases carry an explicit expectation — `positive`, `negative`
(a near-twin that is genuinely not vulnerable), or `clean` (a whole repository
expected to produce no scored-family findings) — each with a one-line rationale
justified from the fixture source; a **repository-level split** with a seeded,
deterministic ≥20% holdout recorded per side; per-family
**TP/FP/FN, precision, recall, Wilson 95% intervals, sample counts, and an
`experimental` flag** below 30 positive and 30 negative labeled cases; and a
report (JSON + markdown) that always lists every advertised family.

The **matching unit** is the labeled expectation: a case matches when a
same-family finding cites its repository-relative file with exact route +
method (line-window fallback when the finding cites no route) — the same
semantics `bench` uses, with findings deduplicated by stable `finding_id`
first. This is stricter than bench's finding-level precision: a grouped
finding that over-cites a labeled-clean twin counts as an FP here.

The shipped seed corpus (`fixtures/evaluation/corpus.json`, v0.1.0) holds
**28 expectations over 10 repositories: 17 positive, 9 negative, 2 clean** —
far below the C27 targets (30 repos, 300 positive, 300 negative, 10 clean);
every family, including the unpopulated `crypto` family, is reported as
experimental with the gap stated. Seed run highlights (deterministic,
offline): injection 6/6 positives matched with no negative violated; both
clean repos are currently violated (a Flask session-gate write is flagged
unauthenticated, and a fixed-host `axios.post` is flagged SSRF) — honest
false-positive signal the small bench corpus cannot express.

```bash
attackmap evaluate                                # print the report
attackmap evaluate --corpus fixtures/evaluation/corpus.json --output reports/eval
```

## WP030 bounded source increment — 2026-10-31

The active WP030 work adds a separate frozen corpus at
[`fixtures/evaluation/increment-20261031/corpus.json`](../fixtures/evaluation/increment-20261031/corpus.json):
27 machine-authored source-justified expectations (16 positive, 10 negative,
one synthetic clean) over two immutable upstream training-app source slices
(DVWA GPL-3.0-or-later and Juice Shop MIT) and an authored clean catalog.
Exact Git objects, immutable source URLs, file/line hashes, license evidence,
explicit repository membership and a JSON schema are included. The original
v0.2.0 corpus now has 46 expectations / 13 identities; its labels and split
remain unchanged. The new manifest is separate so adding data does not
silently reshuffle that baseline.

The new actual offline CLI result is TP=0 / FP=0 / FN=16; ten explicit
negatives are unviolated and the clean label passes. Precision is undefined,
not 100%, and zero matched positives is a coverage gap. All families remain
experimental. Source-slice dependencies are incomplete, both upstreams are
intentionally vulnerable training applications, Juice Shop was a known
integration target, and independent human review remains pending.

The arithmetic union is 73 expectations / 16 logical source identities
(41 positive / 29 negative / three clean); this is not a merged evaluation,
production-diversity acceptance or C27 completion. See the
[source/provenance and freeze description](../fixtures/evaluation/increment-20261031/README.md)
and [integrity audit, raw reports, tests and limitations](verification/windows-parity/WP030/agent-20261031/README.md).

```powershell
.\.venv\Scripts\python.exe -B -m attackmap evaluate --corpus fixtures/evaluation/increment-20261031/corpus.json --output artifacts/wp030-evaluation
```
