# Actual batch2 source/frozen discovery

`verify_catalogs.py` completed all assertions through `verify_batch.run`, using eight separately bounded Windows Job Object launches. Every command exited 0 and recorded verified cleanup of its owned process tree. Commands were `modules --catalog-json`, `modules --json`, `modules --profiles-json`, and `capabilities` in each runtime.

| Observation | Source `.venv` | Fresh batch2 frozen engine |
| --- | ---: | ---: |
| Effective modules | 9 | 21 |
| Catalog candidates | 9 | 24 |
| Official plugin candidates/packages | 0 | 15 |
| Shadowed plugin candidates | 0 | 3 |
| Available profiles | 2 | 4 |
| Schema 1.5/profile option advertised | yes | yes |

The frozen collision names are `omeka-s`, `php-laminas`, and `php-web`. All four frozen profiles are available: `automatic@1.0`, `node-atproto@1.0`, `php-laminas-omeka@1.0`, and `python@1.0`. The source interpreter supplies only Automatic and PHP because the required Node/Python plugin distributions are absent there.

Executable: `.tmp/wp042-sol-ultra-20261023-batch2/engine-final/dist/attackmap/attackmap.exe`. Its SHA-256 matched the fresh build proof before and after the probes: `487e2f368bcb5323341fc96c9b2a2597cc97d431a4c5377790b60dd9bf7b445c`.

All **121 core build origins** point into that freeze's captured `source/src` and match current source bytes. The proof includes `attackmap.analyzer_run_ledger`, the catalog/profiles, registry, pipeline, models, and run contract. Actual frozen catalog class-source locations point into its own `_internal/attackmap` bundle, and runtime identity is `Frozen`; source identity is `Python`. The source and frozen identities remain separate.

All 15 frozen plugins report installed wheel provenance with Git pin status `unverified`; the declared lock is not promoted to verified installed Git source. Every candidate keeps `content_verified=false`.

Evidence: `catalog-verification.json`, `catalog-runtime-origin-check.json`, eight raw `source-*.json`/`frozen-*.json` discovery payloads, and per-command `catalog-probe-*` folders with exact commands, raw stdout/stderr, process records, and ownership/cleanup proof. Module, catalog, profile, capability, and engine-identity data agree within each runtime.

These are actual executable discovery probes. No repository scan, provider response, native visual review, package acceptance, or release approval is asserted by this evidence.
