# Desktop reference fixture v1

`tools/generate_desktop_reference.py` creates the versioned C20/C26 load fixture.
It uses only the Python standard library, runs no analyzer and accesses no
repository content or network service. Every finding title and evidence entry
is labelled `SYNTHETIC`; findings and observations carry an `unknown` evidence
basis. Severity values exercise filtering only. They are not security judgments.
The scan records zero files scanned and explicitly disclaims runtime evidence.

Generate the full fixture from the repository root:

```powershell
.venv\Scripts\python.exe tools/generate_desktop_reference.py --output .pytest_cache/m3-desktop-reference
```

The default profile is exactly:

| Item | Count or size |
| --- | ---: |
| Findings | 10,000 |
| Unique synthetic finding IDs | 10,000 |
| Normalized observations in `scan.signals` | 50,000 |
| Unique synthetic observation IDs | 50,000 |
| Report bytes, including final LF | 20,971,520 (20 MiB) |
| High / medium / low filter rows | 3,334 / 3,333 / 3,333 |
| Findings with unknown evidence basis | 10,000 |
| Files actually scanned | 0 |

The report uses the canonical saved-report object shape (`scan`, `findings`,
`attack_surfaces`, `attack_paths`, `suppressed_findings`, `exploitability`). It is
not a versioned run envelope. Observations are actual serialized normalized
Signal records, not repeated evidence strings or a claimed source-file count.
They appear only in `scan.signals`, preventing double-counting typed hints.
Finding entity keys and IDs belong to this synthetic fixture, not real detector
output. Current native adapters can open the canonical report directly; rendering
or inventory support for every field is a separate adapter acceptance question.

An explicitly labelled `fixture.padding` ASCII string fills the remaining bytes
to exactly 20 MiB. Padding tests transport/parser pressure and contributes no
observations or security evidence. JSON ordering, compact separators, ASCII
escaping and LF termination are fixed. There are no timestamps, random values,
absolute machine paths or engine-build-dependent serialized defaults.

Outputs are:

- `attackmap-report.json`: the reference report.
- `desktop-reference-manifest.json`: version, expected counts, exact byte size,
  severity counts and report SHA-256; acceptance is explicitly `unmeasured`.
- `attackmap-report.sha256`: independently usable checksum line.

Generated output inside this workspace is restricted to `.pytest_cache`.
An explicit external output directory is also accepted. A different existing
file is never overwritten; identical regeneration is permitted. Small tests use
`--findings`, `--observations` and `--report-bytes`; an undersized target fails.

On 2026-10-15 the full default report was generated and independently reread.
Every finding validated against `Finding` and every observation against
`ScanResult.signals`; actual counts, uniqueness, size and checksum matched:

```text
612d12c9b56bfa98ccb7061e81b67120bc738759e9731737ab1fe9d1ada658ba  attackmap-report.json
```

Seven small generator tests verify deterministic bytes, canonical model shapes,
metadata/hash agreement, idempotent generation, overwrite refusal, destination
restriction and invalid counts/size handling. The full 20 MiB fixture is generated
once for measurement rather than included in every unit test run or committed.

## Measurement contract and limits

C20 requires each platform slice to open a real fixture, render 10,000 virtualized
findings, support keyboard/screen-reader navigation, launch/cancel a controlled
worker and produce an installable development package. The time boxes are at most
10 engineer-days on Windows and five on macOS. This synthetic fixture supplies
the load corpus, not those interaction, package or architecture-decision proofs.
Keep real analysis-report acceptance separate from synthetic stress acceptance.

C26 targets p95 app-ready at most three seconds, report-ready at most two seconds,
filtering at most 150 ms and selection-to-detail at most 100 ms. App-ready means
the primary action responds; report-ready means the list and first detail are
usable. Record 30 fresh-process launches and 30 load trials; interactions use
10 warmups followed by 100 samples. Combined UI memory must be at most 500 MiB
after loading, excluding the analysis worker and including owned renderer
processes. After 100 open/close cycles, retained memory may grow by at most
50 MiB over the warmed baseline.

Measure on Windows 11 with at least four CPU cores, SSD and 16 GiB RAM, and on an
Apple M1-or-better Mac with 16 GiB RAM. Record exact hardware, OS, app and engine
builds, fixture version and checksum. Generation, schema validation and checksum
verification establish corpus reproducibility only. They establish none of the
desktop latency, virtualization, memory, accessibility or acceptance targets.
