# Frozen local evaluation increment — 2026-10-31

This separate manifest adds **27 source-justified expectations** over three
source-slice identities: **16 positive, 10 negative, one synthetic clean**.
It preserves the original `../corpus.json` v0.2.0 labels and split unchanged.
All new labels are machine-authored and **await independent human review**.

| Snapshot | Immutable source revision | License | P / N / clean |
| --- | --- | --- | ---: |
| `repos/dvwa` | `d45ba3c4e7efa7f023f25f58ab4af9912c887057` | GPL-3.0-or-later | 10 / 4 / 0 |
| `repos/juice-shop` | `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4` | MIT | 6 / 6 / 0 |
| `repos/clean-catalog` | Authored synthetic fixture, pinned by file hashes | MIT | 0 / 0 / 1 |

The two upstream snapshots are **intentionally vulnerable training apps**,
not production repositories. They contain selected, unmodified Git blobs,
not complete runnable applications. The DVWA files retain their GPL license;
they are separate source fixture data, not relicensed as AttackMap MIT code.
Upstream license text and notices are included alongside both snapshots.
`provenance.json` pins each source URL, revision, Git blob ID, file SHA-256,
license evidence and acquisition method. No source repository was modified.

`freeze.json` pins the manifest, provenance and unchanged original manifest.
With seed `20261011` and requested holdout fraction `0.5`, DVWA is tuning;
Juice Shop and the synthetic clean catalog are holdout (2/3 repositories,
13/27 expectations). Same-upstream near twins stay together. The seed was
not selected from evaluation results. Juice Shop was already a local
integration target: this is a frozen split for future regression work,
not an unseen blind benchmark. The clean catalog shares project authorship
with historical synthetic fixtures; its isolation does not establish
independent real-world lineage.

Each non-clean label has primary and supporting source-line SHA-256 anchors
over the nonempty trimmed UTF-8 line. This avoids duplicating published key
material in metadata. Rationale is written from source, not detector output.
The harness's existing broad `injection` bucket explicitly includes open
redirect, SQL and command injection (`src/attackmap/bench.py`); the redirect
labels do not claim SQL injection. The constant-query negatives label a
different SQL operation in a file that also contains a vulnerable operation.
They are not claims that the entire upstream file or repository is clean.

Reproduce from the AttackMap checkout root:

```powershell
.\.venv\Scripts\python.exe -B docs/verification/windows-parity/WP030/agent-20261031/audit_increment.py
.\.venv\Scripts\python.exe -B -m attackmap evaluate --corpus fixtures/evaluation/increment-20261031/corpus.json --output artifacts/wp030-evaluation
```

The source acquisition script refuses to overwrite this frozen directory.
Do not edit labels, membership or source to make detector results pass.
Versioned human adjudication and detector work belong to subsequent slices.
See [the bounded evidence and results](../../../docs/verification/windows-parity/WP030/agent-20261031/README.md).
