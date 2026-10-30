# WP042 analyzer catalog source slice

Base: `507bddacd72a246a136ca2d46faad2aa661806c1`. Agent: `/root/analyzer_catalog`, GPT-6.1 Sol / ultra. This is a scoped source implementation and deterministic verification, not whole-task acceptance.

## Behavior and integration API

The existing registry loads entry points in entry-point name order, keeps the first registered analyzer for each name with built-ins first, and sorts effective execution metadata by `(priority, name)`. These defaults and existing no-argument public discovery return types are preserved.

`attackmap.analyzer_catalog.get_analyzer_catalog()` performs one discovery pass and returns `AnalyzerCatalogSnapshot`:

- `.analyzers`: tuple of effective instances in `(priority, name)` order.
- `.metadata`: tuple of normalized metadata in the same order.
- `.to_dict()`: independent JSON-safe payload with schema `1`, scope `installed_discovery`, effective order, policy, all discovered candidates, enumeration errors, and undiscovered official package names.

The payload retains built-in/plugin collisions and identifies the winning candidate. It distinguishes trusted-policy skips and load, initialization, analyzer-metadata, and contract errors. Exception messages are omitted. Origin, package/version, entry point, implementation class/module, and observed class-definition source-file SHA-256 are available where observed. Source hashing is limited to regular `.py` files up to 4 MiB; unavailable frozen source produces no invented digest.

Declared official lock entries and installed `direct_url.json` evidence are separate. A wheel path/hash or directory containing a commit string does not verify the Git pin. Exact Git repository/commit comparison is labeled as installed VCS metadata, and `content_verified` remains false. URLs omit embedded credentials, query strings, and fragments. Class-source hashes do not prove the full imported dependency closure.

Root owns CLI/capabilities identity binding, profiles, and the envelope. This slice does not evaluate `detect()`, execute analysis, install packages, or call a provider. Absence from the entry-point inventory is labeled undiscovered and does not assert that a distribution is uninstalled.

## Changed files

- `src/attackmap/analyzers.py`: optional catalog observer through discovery and registry; existing normal paths retain their calls/return types.
- `src/attackmap/analyzer_catalog.py`: snapshot, candidate/provenance collection, and bounded class-source observations.
- `tests/test_analyzer_catalog.py`: collisions for all three PHP names, plugin precedence before priority, one-pass loading/order, third-party/trusted policy, named errors, provenance limitations, credential omission, unavailable/source-change cases, and legacy entry-point mappings.

## Verification

Final focused command (PowerShell, elevated sandbox access only to allow isolated pytest temporary files):

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/test_analyzer_catalog.py tests/test_analyzers.py tests/test_analyzer_order.py tests/test_supply_chain.py tests/test_analyzer_log_privacy.py tests/test_analyzer_metadata_schema.py -q -k 'not self_scan_reports_nothing_for_our_action' -o cache_dir=.tmp/wp042-catalog-20261023/cache-05 --basetemp=.tmp/wp042-catalog-20261023/pytest-05 --junitxml=docs/verification/windows-parity/WP042/sol-ultra-20261023/catalog-tests.xml
```

Result: **88 passed, 2 skipped, 1 deselected**, exit `0`, pytest time `4.45 s`. The skips require an installed PHP plugin, which this source interpreter does not have. JUnit is retained as `catalog-tests.xml`.

The exact deselected test is the pre-existing whole-checkout workflow self-scan. The prior broader invocation stalled there after the relevant tests had progressed and was interrupted; it is not reported as PASS. Initial sandbox invocations also encountered denied temp/cache creation and are not acceptance evidence. Two initial catalog privacy assertions were corrected to check exact exception payloads because ordinary built-in descriptions legitimately contain the word `secret`.

A direct source-interpreter discovery smoke observed nine effective built-ins in the expected run order, with no external analyzer package discovery. `git diff --check` passed for the scoped tracked source. Root will bind final integration hashes after CLI/capability integration.

## Remaining gates

Source/frozen inventory comparison, a new packaged bundle inventory/SBOM, selected executable identity, native UI provenance/reasons, actual scan coverage, live-provider tests, and whole WP042 acceptance remain with the active plan. The existing frozen candidate does not gain this source implementation until rebuilt and verified. Runtime detect/selected/executed/failed ledgers are outside this slice.
