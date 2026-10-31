# WP030 — frozen, provenance-backed source increment — 2026-10-31

The bounded deliverable is a portable, frozen source-slice corpus with
fail-closed integrity checks and actual offline CLI evaluation.
**WP030 remains IN_PROGRESS; C27 is not accepted.** No detector, scoring,
core runtime, release package or original label was changed.

## New corpus and provenance

The [separate increment](../../../../../fixtures/evaluation/increment-20261031/README.md)
contains 27 expectations over three source identities: **16 positive,
10 negative and one synthetic clean repository**. Fourteen expectations
belong to the DVWA source slice, 12 to Juice Shop, one to an authored
read-only Flask catalog. It includes 26 inventoried files, including licenses.

DVWA revision `d45ba3c4e7efa7f023f25f58ab4af9912c887057` is
GPL-3.0-or-later, established by its README and included COPYING text.
Juice Shop revision `e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4` is MIT,
with included license and retained file notices. Exact Git objects were read
from clean tracked local checkouts, without network acquisition or source
edits. Each copied file has an immutable GitHub revision URL, SHA-256 and
Git blob ID in the [provenance ledger](../../../../../fixtures/evaluation/increment-20261031/provenance.json).
GPL data is kept separately with its original license, not relicensed as MIT.

These are intentionally vulnerable training applications and **selected
source slices**, not independently reviewed production repositories.
Missing application dependencies limit the meaning of source-slice results.
No claim of general production diversity or full-application coverage follows.

## Freeze and independent technical inspection

The original 46-case, 13-identity v0.2.0 corpus, seed and membership remain
unchanged. The increment is evaluated separately to avoid reshuffling that
baseline. The new seed is `20261011`, holdout fraction `0.5`: DVWA is tuning;
Juice Shop and the synthetic clean catalog are holdout, 2/3 identities and
13/27 expectations. Same-upstream near twins cannot cross sides. Juice Shop
was a prior integration target, so this is a prospective regression freeze,
not evidence of an unseen blind test. The new synthetic fixture shares
AttackMap authorship with older fixtures; separate paths do not make it
independently sourced production data.

The coordinator independently inspected the DVWA escaped-but-unquoted SQL
positive versus bound-integer negative, and Juice Shop basket ownership
positive versus middleware-bound address ownership negative. That technical
agent review also caught two blank crypto anchors; their source-line positions
were corrected **before the first increment evaluation**, and all anchors now
pin hashes of nonempty lines. See [preflight correction record](preflight-corrections.json).
This was agent review of selected labels, **not independent human review**.
Every new label remains `pending_independent_human_review`.

The broad harness `injection` family already explicitly includes `open redirect`
in `bench.py`; redirect labels use that existing taxonomy. The negative
constant-query labels concern distinct operations, not entire vulnerable files.
The freeze records integrity and execution order; it is not an independently
attested historical timestamp.

## Integrity audit and meaningful mutation checks

[audit_increment.py](audit_increment.py) validates the
[JSON schema](../../../../../fixtures/evaluation/increment-20261031/bundle.schema.json),
manifest/provenance/baseline hashes, exact file inventory, source bytes and Git
blob hashes, revision URLs and license evidence, primary/supporting line anchors,
source-to-case mapping, physical path aliases, unique entities and source lineage
membership. It rejects exact or whitespace-normalized cross-split code copies
and copies of baseline code. Hash comparisons cannot prove absence of semantic
template similarity or undisclosed common ancestry.

The [audit report](corpus-audit.json) is PASS. Nine focused tests exercise
source tampering, extra uninventoried source, stale anchors, relabeling, seed
changes, false license claims, physical aliases, inconsistent case mappings,
duplicate entities, forged human-review status, path traversal, one upstream
masquerading as two repository IDs, and cross-split copied code even after
its new source hash/blob inventory is internally consistent.

The focused shared run has **36 PASS** (27 existing evaluator tests + nine
new corpus audit tests), [JUnit](focused-tests-qualified.xml), 9.82 seconds.
After moving the path-escape assertion into its intended test, the final nine
increment tests were rerun; see [final increment JUnit](increment-tests-final.xml).
The earlier 34-test run preceded the final two leakage mutations and is not
added to 36. An initial restricted run failed because Windows denied the pytest
temporary-directory access; [its JUnit](focused-tests.xml) is retained and is
not counted as a pass. The subsequent approved runs used distinct temp paths.

## Actual offline evaluation

Both source-checkout CLI commands completed with exit 0 and **zero scan errors**:

- [New increment raw JSON](evaluation-increment/evaluation-report.json) and
  [report](evaluation-increment/evaluation-report.md): **TP 0, FP 0, FN 16**;
  all ten explicit negatives respected and the clean label passed.
- [Unchanged baseline raw JSON](evaluation-baseline/evaluation-report.json) and
  [report](evaluation-baseline/evaluation-report.md): 46 expectations / 13 identities,
  original membership retained. Existing weaknesses and the clean-node injection
  violation remain visible.

The new increment's precision is **undefined**, not 100%: no labeled positive
was matched. A clean pass and unviolated negatives do not establish useful
detection coverage. The evaluator scores labeled entities and does not count
unlabeled findings as false positives. The additional
[scan inventory](source-slice-scan-inventory.json) confirms 13 PHP source files,
eight TS source files and one clean Python source file were actually scanned.
Juice Shop emitted two scored-family findings at other, unlabeled entities;
their [raw evidence](scored-finding-evidence.json) is retained without adjudicating
those entities or adding labels after scoring. DVWA emitted no scored-family
finding. The 16 missed source-backed expectations remain unchanged for future
WP031 work; this result is a coverage gap, not detector acceptance.

The [execution record](evaluation-execution.json) records exact commands,
elapsed times and before/after hashes of the dataset inputs and all core Python
source files. They did not change during the two evaluations. Provider calls:
**0**. No LM Studio, GUI, frozen-build, native rendering or release claim is made.

## Honest remaining C27 gap

The arithmetic union of the old corpus and new source slices is **73
expectations / 16 logical identities: 41 positive, 29 negative, three clean**.
This arithmetic is not a merged benchmark, not a shared frozen split and not
16 accepted independently reviewed production repositories. The arithmetic
distance to 30 / 300 / 300 / 10 is 14 identities / 259 positives / 271 negatives /
seven clean. Reviewed production eligibility remains unproven. All advertised
families remain experimental; crypto lacks new negative labels, webhook is
unsampled in the increment, and no mature-family threshold is met.

The next step is independent human adjudication and genuinely production-relevant
independent source acquisition with license/revision evidence, then a versioned
freeze before WP031 tuning. Neither large label counts copied from templates nor
agent source review can replace that gate.

## Reproduce

From the repository root, using a fresh pytest temp path:

```powershell
.\.venv\Scripts\python.exe -B docs/verification/windows-parity/WP030/agent-20261031/audit_increment.py
.\.venv\Scripts\python.exe -B -m pytest tests/test_evaluation.py tests/test_evaluation_increment.py -q -p no:cacheprovider --basetemp artifacts/wp030-recheck-temp
.\.venv\Scripts\python.exe -B -m attackmap evaluate --corpus fixtures/evaluation/increment-20261031/corpus.json --output artifacts/wp030-recheck-increment
.\.venv\Scripts\python.exe -B -m attackmap evaluate --corpus fixtures/evaluation/corpus.json --output artifacts/wp030-recheck-baseline
```
