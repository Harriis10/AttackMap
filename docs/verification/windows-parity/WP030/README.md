# WP030 wave 0 corpus audit — 2026-10-20

WP030 remains IN_PROGRESS. This audit preserves every existing label and source fixture. It inventories the current seed and runs the existing evaluator; it does not establish independent human review, production diversity, or C27 acceptance.

## Reproduce

From the repository root:

```powershell
.\.venv\Scripts\python.exe docs/verification/windows-parity/WP030/audit_corpus.py
.\.venv\Scripts\python.exe -m attackmap evaluate --output docs/verification/windows-parity/WP030/evaluation
.\.venv\Scripts\python.exe -m pytest tests/test_evaluation.py -q
```

`corpus-audit.json` records the manifest hash, exact source-file hashes, counts, duplicate checks, missing-source checks, provenance-field inventory, and repository split. `evaluation/` contains the actual offline engine evaluation report, including case-level outcomes and Wilson intervals. No live model calls or external downloads are involved. System Python lacks the project's installed dependencies; use the project virtual environment.

## Inventory and gaps

The current v0.2.0 manifest contains 46 expectations across 13 repository identities: 25 positive, 19 negative, and 2 clean. C27 still needs at least 17 more repositories, 275 positive labels, 281 negative labels, and 8 clean repositories. Adding synthetic near twins alone does not establish production diversity.

| Family | Positive | Negative | Missing to 30/30 |
| --- | ---: | ---: | --- |
| injection | 9 | 7 | 21 / 23 |
| unauth_state_change | 8 | 6 | 22 / 24 |
| bola | 4 | 4 | 26 / 26 |
| webhook_exposure | 3 | 1 | 27 / 29 |
| crypto | 1 | 1 | 29 / 29 |

Every family remains experimental. The deterministic split has 9 tuning repositories (27 expectations) and 4 holdout repositories (19 expectations): auth-gate-pair, flask-admin-demo, php-omeka-app, python-service-app. The holdout ratio is 4/13 = 30.77%, and no repository identity crosses the split. Both clean repositories are on the tuning side; crypto has no holdout cases; webhook holdout has no negative cases. A seeded split is not evidence that labels or source lineages were isolated before all prior tuning. Freeze a reviewed, expanded membership manifest before further detector tuning; changing the seed to improve metrics is not acceptable.

All paths point to checked-in examples, benchmark cases, or fixtures. Per-case source URL/revision, license, reviewer, and review date fields are absent. The manifest explicitly states v0.2 labels await C27 human review. Repository-level licensing alone does not prove the provenance of any future external sample. Hash-based duplicate checks detect exact copies only; template/lineage overlap needs manual review.

## Actual current evaluation

The raw reports are authoritative for this invocation. Tuning injection has TP=6, FP=1, FN=0: the existing clean-node-demo label is violated by an SSRF finding. Holdout injection has TP=0, FP=0, FN=3, all in php-omeka-app. Tuning also misses one BOLA, one crypto, and one unauthenticated-state-change positive. These are observations against unchanged labels, not grounds to rename labels. They are candidate reproductions for WP031 after the required independent review and corpus freeze. No mature-family precision/recall claim follows from these sample sizes.

## Next bounded corpus slice

1. Review the 46 existing expectations from their source anchors with a human reviewer independent of detector output. Record reviewer identity/date, agreed label, rationale, disputed status, and source revision in a separate review ledger. Preserve disputed expectations until adjudicated; do not silently replace them with passing examples.
2. Select a small production-relevant slice covering Node/ATProto, PHP/Laminas/Omeka S, and Python service handlers, prioritizing authenticated object ownership, unauthenticated state changes, and verified versus unverified webhooks. Record immutable upstream revision, file hash, source URL, SPDX/license evidence and redistribution decision before importing anything. External acquisition is not performed by this audit.
3. Include at least one reviewed clean repository in the new holdout and positive/negative crypto and webhook examples there. Use independent repositories/lineages for holdout; keep safe/unsafe variants from one origin on the same side. Freeze explicit repository membership and source hashes before tuning, retaining the existing seed manifest as a baseline.
4. Publish the reviewed slice even when it is below 30/300/300/10, report the remaining numerical gaps, run schema/source/lineage/duplicate audit and actual evaluation, and compare case-level TP/FP/FN against this baseline. Do not manufacture 600 labels by copying the same template or treat a reviewer-free automated pass as human review.

No product code, detector, scoring file, fixture, retained evidence, or tracker was edited for this slice.

## Focused verification limitation

The inventory script completed successfully, including source existence and disjoint holdout assertions. Actual `attackmap evaluate` completed and wrote both raw reports. This agent's sandboxed pytest attempts encountered Windows temp-directory access denial; the workspace-basetemp retry also raised `PermissionError: [WinError 5]` during pytest temporary-directory cleanup (see `pytest.log`). Those attempts are not test passes. The coordinator independently reports a successful 43-test run with approved execution and a unique temp directory; its evidence belongs to WP001/coordinator verification rather than this local pytest log.
