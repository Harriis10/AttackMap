# R3 owned prototype: exact score producer references

Review only; **not applied to canonical source**. `candidate.patch` contains four production files, the existing presentation test adjustment, and one new focused test file. `candidate-files/` preserves exact candidate bytes. Patch SHA256: `b5794bf15ccdf323dfa6d9b97cd83ee62a9847535ba35891363f6ba0398247a8`. `review-manifest.json` records every baseline/candidate hash, confirms all canonical destinations still match their baselines, and confirms the owned `report.py` is unchanged. Patch applicability has not been run during the concurrent timing lease.

The score producer adds an optional `ExploitabilityScore.producer_reference`; fusion copies that exact producer into optional `Finding.exploitability_reference`. A present reference has required scope, a versioned SHA256 identity, declared repository root/snapshot, and full typed chain identity including route method/path/**route_file**, sink kind/file/line. Both optional fields default to `None`. Existing numeric score, tier, factor policy, ordering, and tie selection remain unchanged.

Presentation resolves only one exact producer in the selected scan context, with exact typed source chain, numeric/tier agreement and factor integrity. Equal numbers, colocated files, legacy imports, missing scope and ambiguous duplicate references cannot supply factor contributions. Explicit statuses explain why resolution is unavailable. A resolved reference identifies the selected modeled producer; it does not authenticate a publisher or prove runtime behavior.

## Captured basis source trace

The existing pipeline captures `RepoIndex.build(repo_path)` (`pipeline.py:407`) and supplies it to `analyze_repository` (`449-457`). `analyzers.py:836` runs repository passes against that index; `scanner.py:1004-1005` stamps the merged scan's `scan_snapshot` from `index.snapshot.identity()`. The pipeline passes the resulting scan to `translate_recon` (`pipeline.py:520`). Its auth-filtered model copy (`recon_to_analysis.py:109`) preserves root/snapshot; `generate_findings` (`128-132`) reaches `threat_model.py:1608` and `score_exploitability(scan, ...)`.

The candidate consumes this passed `ScanResult.root` and `scan_snapshot.snapshot_id`. It neither resolves live paths nor reconstructs a snapshot from current files. Without an absolute declared root and valid captured snapshot identifier, the producer is typed `unverified` and cannot supply owned decomposition. The captured-basis test creates a real owned RepoIndex snapshot once, then prohibits both `Path.resolve` and another `RepoIndex.build` during scoring.

## Verification actually run

- `focused-run.json` / `focused.xml`: **83 passed**, exit 0; existing exploitability, finding presentation, ranking factors, finding identity plus new references. Includes equal numbers with different chains/repositories/snapshots, exact duplicates, number/tier disagreement, legacy import, full route-file identity and factor corruption.
- `captured-basis-run.json` / `captured-basis.xml`: **1 additional test passed**, exit 0. This incremental run followed addition of the captured-basis test; it is not a single 84-test run.
- `baseline-numeric.json` and `candidate-numeric.json`: three synthetic producer scores and two fused findings preserve the existing numeric/factor fields exactly.
- `fixture-compatibility-baseline.json` and `fixture-compatibility-candidate.json` are byte-identical: **29 model rows across 10 retained JSON files** import with identical existing fields. No fixtures were rewritten. Each run records command, imported package path and/or input hashes separately in its artifacts.
- Recorded canonical production inputs were unchanged before/after both test runs. No provider, GUI, real-repository scan, broad suite or benchmark was run for this prototype.

## Serialization impact and limits

Ordinary fresh `model_dump` adds null `producer_reference` / `exploitability_reference` fields when absent; byte-for-byte JSON goldens and fresh report checksums can therefore change even when old values do not. Existing fixtures remain immutable. The exact reviewed import set is:

- `fixtures/desktop-workflows/current.json`
- `fixtures/desktop-workflows/expected.json`
- `fixtures/desktop-workflows/partial-coverage.json`
- `fixtures/desktop-workflows/previous.json`
- `fixtures/desktop-workflows/suppressed.json`
- `fixtures/desktop-parity/report-empty.json`
- `fixtures/desktop-parity/report-expectations.json`
- `fixtures/desktop-parity/report-missing-sections.json`
- `fixtures/desktop-parity/report-nonempty-legacy.json`
- `fixtures/desktop-parity/report-partial-legacy.json`

Scope compares declared captured context; imported snapshot identity authenticity still belongs to the surrounding artifact contract. Identical repository/content snapshots deliberately share producer identity; this adds no publication generation identifier. No `report.py`, frozen shared fixture, native consumer, observation-ID migration or schema version change is included. Native/runtime compatibility and broader contract acceptance remain unverified. Canonical promotion requires root review and a new lease.
