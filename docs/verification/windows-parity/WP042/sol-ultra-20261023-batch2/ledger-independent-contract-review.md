# Independent schema 1.5/profile transport review

Reviewer: `/root/analyzer_catalog`, GPT-6.1 Sol / ultra. CodeGraph-first read-only review covered root changes in `run_contract.py`, `desktop_capabilities.py`, `scan_service.py`, and `cli.py`, plus the native `AnalyzerSelectionModel.SetRunLedger` consumer.

One P2 error-typing issue was found and resolved: profile availability used declared metadata names, then instance lookup used runtime analyzer names. A valid-looking supplied candidate with `metadata.name='php-web'` and `name='different-runtime-name'` caused an uncaught `KeyError` instead of a typed unavailable-profile result. Root added explicit mismatch rejection and a regression. Independent in-memory recheck used the real PHP profile, one mismatched candidate, mocked output-directory creation, and a scan-dispatch trap; it now returns:

- service: `ScanRequestError`;
- CLI helper: `BadParameter`;
- safe message: `Analyzer runtime names do not match their declared metadata; profile unavailable.`

No scan, installation, or fallback occurred. The original source-only reproduction returned `KeyError 'php-web'` before the correction.

Schema 1.5 keeps profile identity qualified and rejects old-schema profile fields and mixed explicit modules/profile selection. The reviewed service carries profile identity into `AnalyzeOptions`, resolves an explicit profile once without plugin reloading, and leaves Automatic discovery to the pipeline. The CLI applies trusted-only policy before profile discovery. Capability preflight checks declared profile availability and exact expansion against its engine inventory. These observations are code/contract review, not a provider or desktop runtime test.

Native ledger parsing agrees with the producer's selection/applicability/execution fields, requires success evidence, separates report observations from current installed inventory, and keeps absent/malformed ledgers unknown. A valid-duplicate-name edge was reported to the native owner: direct legacy APIs may deliberately execute multiple same-name instances, so repeated ledger rows must not be deduplicated or rejected merely by name. The native owner is addressing that separate file under its lease. Root owns final native test and visual verification.

No remaining blocking root profile-transport issue was found after the typed mismatch correction. Final package/source freezing and integrated proof remain with root.
