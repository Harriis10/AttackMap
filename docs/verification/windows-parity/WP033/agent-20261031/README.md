# WP033 — deterministic source mutation campaign, 2026-10-31

**Navazující excerpt checkpoint:** po samostatné produktové opravě jsou phase
testy aktualizované na běžné regression kontroly bez XFAIL. Čerstvý společný
phase/excerpt/citations/artifact/snapshot běh má **128 PASS, 0 SKIP/XFAIL/FAIL**
(6.02 s). Pinned capture musí zachovat raw A; explicitní unpinned capture B
po obnovení souboru A musí zůstat unverified/incomplete bez falešné snapshot
vazby. [Nová evidence](../../../../../artifacts/wp033-mutation-campaign-20261031/excerpt-followup/summary.json)
· [JUnit](../../../../../artifacts/wp033-mutation-campaign-20261031/excerpt-followup/combined.xml).
Původní 100-sequence běh níže nebyl tímto follow-upem zopakován; integrátor
provádí vlastní ověření nové společné source sady. WP033 zůstává IN_PROGRESS.

**Původní bounded výsledek před excerpt opravou: 100/100 independent generated sequences PASS, 300 mutation
steps, 600 full/incremental comparisons, 1,200 actual deterministic analysis
runs.** A separate focused regression has **67 PASS + 1 strict XFAIL**. The
expected failure reproduces an excerpt/snapshot binding gap; it is not a
passing acceptance case. These immutable records describe the pre-fix source;
the current phase regression no longer has an expected failure.

No product source file was edited by this slice. The pre-existing dirty
`incremental.py`, `test_incremental.py`, roadmap documents and other agents'
changes were retained. CodeGraph was consulted before code exploration;
several file-name queries returned unrelated symbols, so uncovered code was
read directly. No provider, network model call, GUI, package, release or C34
performance qualification was run.

## Executed source campaign

The new [campaign test](../../../../../tests/test_wp033_mutation_campaign.py)
runs explicit Python-web, JavaScript-web and Config built-in analyzers through
`analyze_repository`, its whole-repository passes, and `translate_recon`.
Each seed `2026103100`–`2026103199` has its own physical repository and cache.
It performs cold, warm, three deterministic generated mutations, then a final
warm checkpoint. The first mutation is stratified over all nine families;
two distinct remaining families are selected with that sequence's seeded RNG.
If a sequence deletes the spare file before its later rename, the rename
operation recreates that spare first; this is one documented composite
mutation checkpoint, not an additional separately counted sequence or scan.

Every checkpoint compares the complete serialized scan except the
wall-clock analyzer run ledger, actual generated findings and fingerprints,
attack surfaces/paths, and complete normalized signals including observation
IDs and origins. Equality is checked directly, then matching hashes and
counts are retained. Every comparison produces six actual findings and
11–24 normalized observations; empty results cannot satisfy the test.

Two hundred warm checkpoints require **zero** fresh extractor calls while
the full reference must still execute extraction. Cold results require the
same extractor call list as the full reference. Upgrade, policy and corrupt
cache cases require measurable misses. Dependency/config changes must also
produce their new dependency/database observation; renamed/deleted paths
must disappear from coverage and provenance.

| Mutation family | Steps |
| --- | ---: |
| edit | 29 |
| add | 33 |
| rename | 36 |
| delete | 32 |
| dependency | 38 |
| config | 32 |
| source-role policy | 27 |
| built-in analyzer identity/version | 33 |
| cache corruption | 40 |

Corruption is split into truncated JSON (11), foreign schema (11), invalid
checksum (12), and structurally invalid payload with a valid checksum (6).
This tests accidental corruption, not an attacker recomputing a valid
checksum over a valid forged payload; the cache remains trusted local state.

**Upgrade boundary:** the campaign changes physical bytes in a disposable
copy of the actual extractor identity inputs and changes the real declared
Python-web producer version. It proves source-byte invalidation and updated
provenance with full recomputation. It does not execute a changed extractor
implementation or install an external plugin. The separate prior frozen
A/B proof is not repeated or counted as part of these 100 source sequences.

## Four mutation phases and the corrected excerpt regression

The new [phase tests](../../../../../tests/test_wp033_mutation_phases.py)
schedule mutations with deterministic hooks rather than timing races:

| Phase | Observed result |
| --- | --- |
| Capture | Change immediately after `_read_capture_bytes` returns the original bytes; findings/provenance/coverage stay pinned, publication is explicitly incomplete. |
| Detection | Change immediately after the Python analyzer returns; later passes retain the original snapshot and publication is incomplete. |
| Publication | Change immediately after `scan.json` is written; manifest detects drift and marks snapshot incomplete. |
| Excerpt, after capture | Captured span stays immutable, citation validation uses the retained span, persistent live drift marks publication incomplete. |
| Excerpt, before capture | Pinned capture retains original raw A and verified source binding; persistent live drift still marks the run incomplete. |
| Excerpt, transient change then restore, pinned | Capture retains raw A and the original excerpt; after restoration the matching source binding may verify. |
| Excerpt, transient change then restore, unpinned | Capture records raw B; after restoration to raw A, publication must mark source binding unverified/incomplete and omit `captured_under_snapshot_id`. |

All seven phase cases are now ordinary passing regressions. The transient
case explicitly tests both pinned and unpinned capture; it retains the
original raw A/B mismatch and restoration scenario rather than removing
the counterexample or weakening it to current-tree equality.

The historical pre-fix [raw-SHA counterexample](../../../../../artifacts/wp033-mutation-campaign-20261031/final/phases/phase-excerpt-transient-open-gap.json)
records original captured raw SHA
`00551a200179220096d4063b3ace4707348ac9662f6d7bbb7f0526d06dba9769`
and live excerpt raw SHA
`7fc56372b8d43b0f9d8b66fb0f321e06684530487e39f33049a32f2a160a86e0`.
The manifest stamps the latter under snapshot
`3880fa037f1ce9f0929ceaec57b45620d9723394294c6fa5d508255810db93f7`
while reporting verified. This was a real content mismatch: the tests compare
captured **raw** bytes from `RepoIndex.sources`, not CRLF raw hashes against
the snapshot's normalized text hashes.

## Preserved pre-fix diagnosis and follow-up boundary

No `citations.py`, `review_prompts.py`, `hunt_harness.py`, `pipeline.py` or
`artifact_manifest.py` edit is authorized by this subagent's lease.

The path observed before the independently implemented product fix was:

1. `hunt_harness.run_majority_verify` (lines 609–618) creates a context via
   `review_prompts.build_citation_context` when no explicit/scoped context exists.
2. `review_prompts.build_citation_context` (569–574) calls
   `citations.capture_source_spans` with root/locations, without the run index.
   `_code_excerpts` (577–586) has the same standalone fallback.
3. `citations.capture_source_spans` (94–145) opens the live path (125–132)
   and hashes raw bytes. `SourceSpan.metadata` (88–91) contains raw source
   and excerpt hashes, but no proven analyzed snapshot binding.
4. `hunt_harness.run_majority_verify` (618) preserves `captured.metadata()`;
   the pipeline persists `citation_context` in hunt metadata (867, 906).
5. `artifact_manifest.write_artifact_manifest` (297) invokes
   `_snapshot_publication_block` (151–191). It verifies the **current tree**
   (170–171), then `_captured_sources` (124–148) unconditionally labels each
   metadata source with the report's snapshot ID (146–147). No excerpt-to-
   analyzed-byte check occurs, so a transient change followed by restoration
   is invisible to this gate.

A proposed explicit API follow-up would thread the captured run index into
excerpt construction, validate repository and snapshot identity, and use
`index.sources_by_rel[rel].raw` with existing size/redaction bounds. When a
captured index is supplied, missing input must not silently fall back to the
live tree. Preserve standalone live capture as an explicit separate API mode.
Metadata should carry a binding established at capture; publication should
verify it instead of inventing `captured_under_snapshot_id`. Preserve raw
source hashes, and use the corresponding normalized-text hash when comparing
against `scan_snapshot.files`. Missing or mismatched binding must be explicit
incomplete/unknown, even if the working tree was restored. This needs a
separately coordinated citations/report lease and caller threading; this slice
does not claim to have implemented that explicit threading.

The subsequent collaborator's bounded fix now resolves the active pinned
index in `capture_source_spans` and reads captured raw bytes without live
fallback for absent captured input. Snapshot identity carries exact raw
hashes, and publication compares excerpt hashes against those raw hashes
before assigning `captured_under_snapshot_id`; unbound sources mark the run
unverified/incomplete even after a transient source change is reverted.
This follow-up edited only the phase tests and this agent's documentation
and evidence. It does not claim explicit API/native threading acceptance.

## Fresh follow-up command and result

```powershell
$env:PYTHONPATH = Join-Path $PWD 'src'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:ATTACKMAP_WP033_EVIDENCE_DIR = Join-Path $PWD 'artifacts/wp033-mutation-campaign-20261031/excerpt-followup/phases'
& ./.venv/Scripts/python.exe -m pytest tests/test_wp033_mutation_phases.py docs/verification/windows-parity/WP033/agent-excerpt-20261031/test_excerpt_snapshot.py tests/test_citations.py tests/test_artifact_manifest.py tests/test_snapshot_consistency.py -q --basetemp artifacts/wp033-mutation-campaign-20261031/excerpt-followup-temp -p no:cacheprovider --junitxml artifacts/wp033-mutation-campaign-20261031/excerpt-followup/combined.xml
# 128 passed in 6.02 s; fresh elevated temp, no skip/xfail/failure
```

This includes 7 phase cases and the collaborator's 8 excerpt cases, plus
existing citations, artifact-manifest and snapshot-consistency tests. The
collaborator's test file and all product files were read but not edited by
this follow-up. Its [summary](../../../../../artifacts/wp033-mutation-campaign-20261031/excerpt-followup/summary.json)
records exact source hashes, JUnit counts and the new phase records. Prior
pre-fix evidence is retained unchanged. The original `audit_campaign.py` is
preserved as that checkpoint's historical runner; do not rerun it into the
original evidence directory after source changes, because it also writes a
current source manifest. It does not qualify the updated excerpt behavior.

## Historical pre-fix commands, results and evidence

From `C:/Projects/INPROGRESS/AttackMap`, the successful final commands were:

```powershell
$env:PYTHONPATH = Join-Path $PWD 'src'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:ATTACKMAP_WP033_EVIDENCE_DIR = Join-Path $PWD 'artifacts/wp033-mutation-campaign-20261031/final/sequences'
& ./.venv/Scripts/python.exe -m pytest tests/test_wp033_mutation_campaign.py -q --basetemp artifacts/wp033-mutation-campaign-20261031/final-temp -p no:cacheprovider --junitxml artifacts/wp033-mutation-campaign-20261031/final/campaign.xml
# 100 passed in 140.53 s

$env:ATTACKMAP_WP033_EVIDENCE_DIR = Join-Path $PWD 'artifacts/wp033-mutation-campaign-20261031/final/phases'
& ./.venv/Scripts/python.exe -m pytest tests/test_wp033_mutation_phases.py tests/test_incremental.py tests/test_snapshot_consistency.py tests/test_snapshot_inputs.py tests/test_cli_incremental.py -q -rx --basetemp artifacts/wp033-mutation-campaign-20261031/regression-temp -p no:cacheprovider --junitxml artifacts/wp033-mutation-campaign-20261031/final/regression.xml
# 67 passed, 1 xfailed in 39.84 s

& ./.venv/Scripts/python.exe docs/verification/windows-parity/WP033/agent-20261031/audit_campaign.py
# validates all 100 records, all 600 comparisons, all families/modes, the exact gap and both JUnit files
```

The focused regression contains 21 existing incremental, 21 snapshot
consistency, 14 snapshot-input and 6 CLI tests, plus 5 passing phase tests
and the one expected failing excerpt test. Campaign and regression do not
share test cases; their total is **167 PASS + 1 strict XFAIL**.

Earlier attempts are not included in that passing result: two non-elevated
probe runs failed before useful execution because pytest temporary-directory
creation/ACLs were unusable in the restricted Windows process. A three-seed
elevated probe passed (5.62 s). The first phase run had 4 PASS, 1 FAIL and
1 XFAIL because a new test compared CRLF raw SHA to normalized text SHA;
the fixture comparison was corrected to captured raw bytes. The final
regression above re-executed the corrected tests and exact gap condition.
No product defect was fixed as part of that test correction.

Evidence:

- [Summary and explicit limitations](../../../../../artifacts/wp033-mutation-campaign-20261031/final/summary.json)
- [Campaign JUnit](../../../../../artifacts/wp033-mutation-campaign-20261031/final/campaign.xml)
- [Focused regression JUnit](../../../../../artifacts/wp033-mutation-campaign-20261031/final/regression.xml)
- [100 sequence records](../../../../../artifacts/wp033-mutation-campaign-20261031/final/sequences/)
- [Phase records](../../../../../artifacts/wp033-mutation-campaign-20261031/final/phases/)
- [Post-run source SHA manifest](../../../../../artifacts/wp033-mutation-campaign-20261031/final/source-sha256.json)
- [Evidence SHA manifest](../../../../../artifacts/wp033-mutation-campaign-20261031/final/evidence-sha256.json)
- [Evidence validator](audit_campaign.py)

The source manifest records current post-run bytes; it is not a source-bound
product package attestation. Every sequence recorded the same actual baseline
engine identity. C34 performance needs its separate 20 repetitions per mode
on a documented reference platform; the test durations here are not such a
measurement. External plugin upgrade, final frozen/native round-trip,
clean-host/unsupported-OS and release gates remain open.
