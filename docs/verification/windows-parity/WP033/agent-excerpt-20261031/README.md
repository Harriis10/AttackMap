# WP033 — excerpt raw-snapshot binding — 2026-10-31

Scoped source correction only. WP033 remains **IN_PROGRESS**. This work does not
claim native/frozen/package/release acceptance, C34 performance, whole-task
completion, or a change to the FAILED WP043 rendering gate.

## Reproduction and correction

The existing campaign evidence
`artifacts/wp033-mutation-campaign-20261031/phases-final/phase-excerpt-transient-open-gap.json`
records a transient A → B → A sequence: indexing captures A, source excerpt
capture reads live B, and publication after restore labels the tree `verified`
while incorrectly attaching B's raw SHA to A's snapshot id.

The focused regression in this directory reproduced that failure before the
product change: **7 FAIL / 1 PASS**, no errors. The same eight tests now pass.

Two product files changed:

- `src/attackmap/citations.py`: when the exact repository has an active index,
  excerpt capture uses only `sources_by_rel[relative].raw`. An absent captured
  file never falls back to the live tree. The existing byte cap, raw SHA,
  UTF-8 replacement decoding, redaction, and span identity remain in use.
  A different repository's pin does not affect a direct capture.
- `src/attackmap/artifact_manifest.py`: `captured_under_snapshot_id` is granted
  only when the excerpt's path and raw SHA match `ScanSnapshot.raw_files`.
  An unbound source remains visible without a snapshot id. Publication adds
  `source_capture_verification`, marks the run `incomplete`, and changes a
  would-be `verified` state to `unverified` with the affected paths. Existing
  `drifted` state and changed/deleted/added lists remain intact. A legacy
  snapshot without raw hashes cannot prove exact excerpt-byte provenance.

No change was made to index, scanner, incremental cache, pipeline, scan service,
the concurrent campaign's tests, schemas, packages, or native application.
Existing dirty work was preserved.

## Executed verification

Working directory: `C:\Projects\INPROGRESS\AttackMap`; executable:
`.venv/Scripts/python.exe`; Python 3.13.15 on Windows. Test data and reports live
under `artifacts/wp033-excerpt-20261031`, outside analyzed fixture repositories.

All commands below used `-q -p no:cacheprovider` and task-specific `--basetemp`.
The initial ordinary test attempts failed at temporary-directory setup because
the restricted process could not access the new directory; they are not
functional regression evidence. The completed runs used the approved elevated
execution path with the same checkout and interpreter. No model/provider,
network, GUI, installer, or product package was used.

| Run | Result | Evidence |
| --- | --- | --- |
| New focused tests before fix | 7 FAIL, 1 PASS, 0 errors | `before-regression-elevated.xml` |
| New focused tests after fix | 8 PASS | `focused-after.xml` |
| Focused plus existing citations/artifact/snapshot/incremental/CLI | 194 PASS, 0 FAIL/SKIP/errors; 40.76 s | `focused-regression.xml` |
| Direct narrative/publication/schema consumers | 97 PASS, 0 FAIL/SKIP/errors; 29.88 s | `publication-citation-consumers.xml` |

The 194 count includes the eight new tests; these counts must not be added to
the separate eight-test run. The only warning in the 194 run is the intentional
duplicate ZIP member in the malformed snapshot transport negative test.

Exact completed commands, with evidence paths relative to the working directory:

```powershell
.venv/Scripts/python.exe -m pytest docs/verification/windows-parity/WP033/agent-excerpt-20261031/test_excerpt_snapshot.py -q -p no:cacheprovider --junitxml=artifacts/wp033-excerpt-20261031/before-regression-elevated.xml --basetemp=artifacts/wp033-excerpt-20261031/before-regression-elevated-temp
.venv/Scripts/python.exe -m pytest docs/verification/windows-parity/WP033/agent-excerpt-20261031/test_excerpt_snapshot.py -q -p no:cacheprovider --junitxml=artifacts/wp033-excerpt-20261031/focused-after.xml --basetemp=artifacts/wp033-excerpt-20261031/focused-after-temp
.venv/Scripts/python.exe -m pytest docs/verification/windows-parity/WP033/agent-excerpt-20261031/test_excerpt_snapshot.py tests/test_citations.py tests/test_artifact_manifest.py tests/test_snapshot_consistency.py tests/test_snapshot_inputs.py tests/test_snapshot_transport.py tests/test_incremental.py tests/test_cli_incremental.py -q -p no:cacheprovider --junitxml=artifacts/wp033-excerpt-20261031/focused-regression.xml --basetemp=artifacts/wp033-excerpt-20261031/focused-regression-temp
.venv/Scripts/python.exe -m pytest tests/test_narrative_citations.py tests/test_artifact_publisher.py tests/test_artifact_schemas.py -q -p no:cacheprovider --junitxml=artifacts/wp033-excerpt-20261031/publication-citation-consumers.xml --basetemp=artifacts/wp033-excerpt-20261031/publication-citation-consumers-temp
git diff --check -- src/attackmap/citations.py src/attackmap/artifact_manifest.py
```

`git diff --check` passed. [Machine-readable summary and source/evidence hashes](summary.json)
bind these results to the source files and the saved product patch. The retained
temporary reports include the normal pinned A capture and the rejected unpinned
B capture after restore.

## Boundaries and next integration gate

This is deterministic source/owned-filesystem evidence. It does not establish
atomic repository capture, provider/claim support, final product or native
round-trip equivalence, release qualification, or C34 performance. The existing
pin ownership/threading contract is reused; no new snapshot API was introduced.
Legacy snapshot metadata with excerpts but no raw SHA now publishes incomplete,
as exact byte binding cannot be recovered from normalized text hashes.

The campaign owner can now replace the known-gap expectation with a strict
raw-A transient-revert regression and rerun its independent mutation phases
against this product diff. Root integration review remains required.
