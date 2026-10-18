# Delivery efficiency — C37 evidence (AM051)

Status page for [roadmap criterion C37](roadmap-2026-2028.md#c37-delivery-efficiency).
It separates what is machine-verified today from what still requires human
work, and states exactly how the remaining evidence will be recorded.

**Criterion (quoted from the roadmap).** "A new contributor can build the core
and run its focused suite within 30 minutes, and a supported desktop developer
can run the respective fixture-backed app within 90 minutes, excluding
prerequisite tool downloads. Three contributors unfamiliar with the relevant
component each complete the written setup without undocumented steps. Contract
changes run both client fixture suites in CI before release." Proof includes
onboarding trial records, maintained architecture/contract docs, release-build
dependency manifests, CI links, and flaky-test tracking over eight weeks.

**Method.** Everything marked *fresh* below was executed on 2026-10-18
(2026-10-18T06:37–06:49Z per the JSON records) on Windows 10 19045 x64 with
the repository's existing `.venv` (Python 3.13.15), working tree at commit
`dbf72d8` plus the AM051 files added by this change (and unrelated concurrent
edits to `src/attackmap/` owned by another task; see the subset note). No
network calls were made for these measurements (see the install-stage
honesty note). The full test suite was not rerun for this page.

## What is machine-verified now

### 1. Contributor setup path with measured timings (fresh)

[`scripts/verify_setup.py`](../scripts/verify_setup.py) walks the C37 core
setup path stage by stage and writes a JSON timing record to
`.pytest_cache/setup-verification/`. Fresh measurements from this session:

| Flow | Stages measured | Result | Record |
| --- | --- | --- | --- |
| Existing `.venv` (`--skip-install`) | python-check, focused suite | 177 passed; 3.17 s measured stage time (first run) / 6.16 s (second run; suite 2.08–3.03 s) | `verify-setup-20261018T063747Z.json`, `verify-setup-20261018T063805Z.json` |
| Fresh venv in a temp directory (`--fresh --venv <temp> --skip-install --skip-suite`) | venv-create, python-check | 14.57 s measured stage time (venv creation 14.50 s) | temp record, not retained |
| Existing `.venv`, final subset (`--skip-install`) | python-check, focused suite | 81 passed; 4.63 s measured stage time (suite 3.04 s) | `verify-setup-20261018T064850Z.json` |

Subset note: the first two rows used `tests/test_taxonomy.py` as the fifth
subset file; mid-session, a parallel in-flight edit to
`src/attackmap/index.py` (by another task owner; `models.py` not yet updated)
broke that file's scanner-dependent tests — a code-state issue, not a setup
issue. The fifth file was switched to `tests/test_finding_identity.py`
(24 passed) so the verifier stays independent of in-progress feature work;
the earlier green records are retained above as measured.

Honesty notes:

- The **install stage was not measured locally**: `pip install -e ".[dev]"`
  in the existing `.venv` requires build isolation (the venv has no
  `setuptools`), which downloads from PyPI; network installs were out of
  scope for this session. The verifier's normal flow does include the real
  install step, and the
  [client contract fixtures](../.github/workflows/client-contract-fixtures.yml)
  CI workflow runs `verify_setup.py --fresh` on a clean runner, so the job
  log becomes machine-measured install-time evidence once it has run. No CI
  numbers are claimed before a real run exists.
- Timings cover only executed stages; prerequisite tool downloads (Python,
  git, .NET SDK, NuGet packages) are excluded per the criterion wording.
- Measured total (6–20 s) is far inside the 30-minute budget, but this is a
  maintainer host with a warm cache, not a new-contributor trial; the
  qualifying measurement is the human trial below.

### 2. Contract-relevant CI (configuration fresh, execution pending first run)

- The existing [CI matrix](../.github/workflows/ci.yml) already runs the
  full pytest suite — which includes both client fixture suites — on every
  push and pull request to `main`, across Ubuntu/macOS/Windows × Python
  3.11–3.13 plus Node 22.
- New: [client-contract-fixtures.yml](../.github/workflows/client-contract-fixtures.yml)
  adds an explicit, named job that runs both client fixture suites
  (`tests/test_run_contract.py` over the `fixtures/run-contract/` golden and
  fault corpora, plus `tests/test_ui_contract_adapter.py`,
  `tests/test_desktop_workflow_fixtures.py`, `tests/test_desktop_reference.py`)
  whenever contract-relevant paths change (contract models and schemas, the
  fixture corpora and their tests, the desktop workflow fixtures, the
  reference generator, the contract doc). It also runs the fresh-venv
  `verify_setup.py` flow and uploads the timing record.
- The YAML was validated locally with `yaml.safe_load` (including that the
  push/pull_request path filters are identical). It has **not yet executed
  on GitHub** — a real run link must be attached here after the first
  contract-relevant change lands; until then this is configured-but-unrun,
  not proven.

### 3. Flaky-test tracking scaffold (fresh, two-run proof)

[`tools/flaky_tracker.py`](../tools/flaky_tracker.py) records per-run pytest
outcomes (`pytest -q -rA --tb=no` console output, or an optional
`pytest-json-report` JSON when that plugin happens to be installed; no new
dependencies) into an append-only JSONL log at
`.pytest_cache/flaky-log.jsonl` and prints a per-test runs/failures summary.
Fresh proof of aggregation this session:

- Two real focused runs recorded: `tests/test_run_contract.py` (33 passed,
  1.66 s) and `tests/test_run_contract.py` +
  `tests/test_ui_contract_adapter.py` (40 passed, 1.88 s); the summary
  correctly shows the 33 shared tests at 2 runs / 0 failures and the 7
  adapter-only tests at 1 run.
- The failure-aggregation path was exercised only with **synthetic** pytest
  output written to a temp log (1 failed + 1 passed run → the tool flags
  `test_shared_golden_messages[path3]` as a flaky candidate). That was parser
  verification, not a real flaky test; no real failure occurred.

**Zero weeks of the eight-week window have elapsed.** No flakiness trend,
median change lead time, or fix-record is claimed.

### 4. Maintained docs and manifests (existing, re-read)

- Architecture/contract docs: [`run-contract.md`](run-contract.md),
  [`desktop-workflow-fixtures.md`](desktop-workflow-fixtures.md),
  [`desktop-reference-fixture.md`](desktop-reference-fixture.md).
- Release-build dependency manifests exist:
  [`tools/generate_release_lock.py`](../tools/generate_release_lock.py) and
  [`tools/generate_release_sbom.py`](../tools/generate_release_sbom.py), plus
  the pinned analyzer set in `pyproject.toml`'s `all` extra. These were read,
  not regenerated, for this page.
- Desktop recipe: [project_notes/HANDOFF.md](project_notes/HANDOFF.md) §8 and
  [desktop/windows/README.md](../desktop/windows/README.md) (retained M3
  toolchain; not re-timed for this page).

## What remains (not claimed as done)

### Three-contributor onboarding trials (human)

Three contributors unfamiliar with the relevant component (two for core, one
for the Windows desktop app, or as availability allows) must each follow
[CONTRIBUTING.md](../CONTRIBUTING.md) end to end on a machine they control,
without asking maintainers. Each trial is recorded as a file under
`.pytest_cache/onboarding-trials/` (JSON, never committed with personal data
beyond a stated alias) using exactly these fields:

```json
{
  "trial_id": "onboarding-YYYYMMDD-<alias>",
  "date": "",
  "participant_alias": "",
  "component": "core | windows-desktop",
  "machine": {"os": "", "arch": "", "python": "", "preexisting_tools": ""},
  "followed_doc": "CONTRIBUTING.md (commit sha)",
  "stage_elapsed_minutes": {"clone": 0, "venv": 0, "install": 0, "focused_suite": 0, "total": 0},
  "desktop_only": {"fixture_generator": 0, "dotnet_publish": 0, "app_launch_and_smoke": 0},
  "undocumented_steps_encountered": [],
  "within_budget": "30min core | 90min desktop | exceeded",
  "verdict": "pass | pass-with-notes | fail",
  "notes": ""
}
```

A trial passes only if the participant reports no undocumented steps and the
total (excluding prerequisite tool downloads) fits the 30-minute (core) or
90-minute (desktop) budget. Until three passing records exist, the criterion's
onboarding clause is **open**.

### Eight-week flaky/metrics window (process)

Weekly, for eight consecutive weeks starting from a recorded start date:
run the focused suites (and any broad checkpoint runs), `record` their
outputs with `tools/flaky_tracker.py`, snapshot `summary` output into this
directory as `flaky-week-<n>.txt`, and log median change lead time manually
(issue-open to merge, per merged PR) in `flaky-week-<n>.txt`. The window has
not started; the start date, the week files and any conclusions will be added
here when they actually exist. Fix repeated causes before adding
infrastructure to improve an unmeasured metric.

### Cross-repository CI gap

The separate macOS repository (`mlaify/AttackMap-mac`) carries its own native
client suite, which **cannot be executed from this repository's CI**. The
"both client fixture suites in CI" clause is covered here only by the
repo-local proxy described above. When the macOS repo runs its contract
suite in its own CI, link those runs here; until then this remains a stated
gap.

## Change log for this page

| Date | Change |
| --- | --- |
| 2026-10-18 | Page created for AM051: setup verifier + fresh timings, contract CI workflow (validated, not yet run), flaky tracker scaffold + two-run proof; focused-subset fifth file switched from `test_taxonomy.py` to `test_finding_identity.py` after an unrelated in-flight `src/attackmap/index.py` edit broke scanner-dependent tests; human portions left open with recording templates. |
