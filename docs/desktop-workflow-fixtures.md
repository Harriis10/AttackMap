# Desktop workflow golden corpus v1

`fixtures/desktop-workflows` is a small shared, deterministic C21/C23 corpus for
future native comparison, suppression, evidence and selected-run export tests.
No repository was analyzed. All source paths, scan coverage claims, findings,
evidence conflicts and recommendations are explicitly synthetic scenario data.
Evidence basis remains `unknown`; no fixture claims observed controls, verified
runtime reachability or exploitation. Severity is a seeded filter value.

| File | Purpose |
| --- | --- |
| `previous.json` | Complete previous scenario with findings A, B, C, D |
| `current.json` | Complete current scenario: A reworded, D persisted, E new, B resolved, C suppressed |
| `partial-coverage.json` | A and E present, C suppressed; D missing because coverage excludes its source |
| `suppressed.json` | Previous scenario with only C moved to reasoned suppression |
| `expected.json` | Stable IDs, expected comparison sets, edge-case IDs and byte SHA-256 values |
| `suppressions.yaml` | ID selector for C with a mandatory synthetic acceptance reason |
| `sources/source-before.txt` | Fixed source snapshot associated with A |
| `sources/source-changed.txt` | Different live-source stand-in requiring a source-changed warning |

The reports use the canonical saved-report shape and validate against current
`Finding`/`ScanResult` models. Their IDs are calculated with the core stable
rule/entity identity API. The same rule emits distinct explicit synthetic entity
keys A–E; A retains its ID despite title rewording. No file/rule renames are
inferred. `fixture.version`, `fixture.run_id` and the fixed timestamp identify the
seeded scenario. These are golden test metadata, not a published artifact
generation or a run-integrity claim.

Complete previous/current comparison must produce:

- New: E.
- Persisted: A and D.
- Resolved: B.
- Newly suppressed: C, with its reason retained.

Previous/suppressed comparison has A, B and D persisted and only C newly
suppressed; C must not be labelled resolved. Removing the selector restores C
without changing its semantic identity. The tests use core suppression and diff
APIs; the native client must not introduce alternative matching or scoring.

C23 evidence cases include conflicting synthetic auth statements on A, missing
location on E, a 321-character non-ASCII virtual location on D, unsupported
language/truncated coverage in the partial scenario, and a changed live source
whose bytes differ from A's stored snapshot SHA-256. Long paths are virtual
report data rather than host files, so the fixture does not depend on Windows
long-path settings. A source-open flow must warn that the live source differs
before presenting it as the scanned snapshot. The fixture and hash tests provide
the inputs and expected warning, not proof that the UI implements that warning.

## Coverage-aware comparison

In the partial scenario, B is included in synthetic scanned coverage and can
be resolved. D is explicitly unsupported and omitted under truncated coverage;
D is presented as **resolution uncertain due to changed coverage**.

The new core `compare_report_files` API supplies explicit source coverage to
`diff_findings`. The previous strict expected-failure test now passes through
that API. Missing files, unknown enumeration, analyzer failures and missing
structured baseline locations cannot prove resolution. A numeric file count is
never substituted for enumerated coverage. Native views and exports consume the
same versioned semantic result and reasons.

Legacy direct `diff_findings` calls without a coverage context retain their
historical behavior for compatibility. Callers implementing report history must
use `attackmap.comparison.compare_report_files` or pass `ComparisonCoverage`
explicitly. Source coverage is not a claim of detector-version parity or verified
runtime remediation; comparison notes state this limitation.

C21 still requires independent Windows/macOS end-to-end recordings for all ten
workflows, native commands/dialogs, persistence and migration behavior. This
corpus supports those future checks but does not establish either platform's
workflow, accessibility, export or performance acceptance.

Run the focused corpus checks with:

```powershell
.venv\Scripts\python.exe -m pytest tests/test_desktop_workflow_fixtures.py -q -rx
```
