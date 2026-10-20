<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](../docs/README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Updated Analyzer Metadata (Canonical Model)

AttackMap now uses one canonical `AnalyzerMetadata` model across built-in and plugin analyzers.

Canonical model location:
- [`src/attackmap/analyzer_contracts.py`](/Volumes/Dev/repos/GitHub/mlaify/attackmap/AttackMap/src/attackmap/analyzer_contracts.py)

## Canonical fields
- `name`
- `display_name`
- `version`
- `description`
- `scope`
- `targets`
- `languages`
- `priority`
- `experimental`
- `enabled_by_default`

Derived property:
- `ecosystems` (ordered, deduplicated, lowercase tuple from `languages + targets`)

## Runtime behavior
- Built-in analyzers now instantiate this richer canonical metadata model directly.
- Plugin metadata is normalized into the canonical model during analyzer load/validation.
- Registry and metadata access paths now use canonical normalization.

## Backward compatibility
- Legacy metadata construction using `ecosystems=...` is still accepted.
  - In compatibility mode, `ecosystems` is mapped into `languages` when `languages` and `targets` are omitted.
- Existing imports from `attackmap.analyzers` remain valid.
- Existing analyzer discovery and merge behavior is unchanged.

## SDK import path
Preferred import path for plugin/analyzer repos:
- `from attackmap.sdk.contracts import AnalyzerMetadata`

`AnalyzerMetadata` from SDK maps to the same canonical model.
