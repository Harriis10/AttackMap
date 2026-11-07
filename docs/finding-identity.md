<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Finding identity and legacy references

Findings with an explicit `rule_id` use a versioned semantic ID. JSON includes
`identity_scheme` (`rule-aggregate/v2`, `rule-entity/v2`, or `legacy-title/v1`)
and preserves the optional detector-owned `entity_id`.

The 16-hex ID is the first 16 hex characters of SHA-256 over the UTF-8 string
`attackmap-finding/v2\0rule-aggregate\0` plus the exact rule ID. When an entity
key exists, append `\0entity\0` plus that exact key before hashing. Titles,
recommendations, severity, confidence and the changing set of locations do not
replace identity. No hash key includes evidence prose or recommendation text.

Most rules aggregate one issue type across a repository; their entity key is
unset. Per-entity rules must supply `entity_id`. The core vulnerable-dependency
rule emits one finding per `(ecosystem, package, version)` and derives an opaque
`dependency/v1:` key followed by the full SHA-256 hex digest of that tuple as an
ASCII JSON array without separator whitespace. Source metadata is not copied
into the entity key, so credential-bearing version strings cannot leak there. Different packages,
ecosystems and versions stay distinct despite sharing a rule ID. Repository
selection remains external to finding IDs: compare baselines within one repo.

Individual locations retain their existing rule/file/normalized-source/occurrence
fingerprints. A new location is a new instance of an existing aggregate. File
renames are not guessed: a changed path produces a new instance. Rule renames
remain new/resolved findings; there is no inferred rename map.

Collision policy: a baseline, active set, or suppressed set containing multiple
records with one semantic ID is rejected by the diff with an explicit
`Ambiguous finding identity` error. No record is silently overwritten. Detectors
must aggregate instances or provide distinct stable entity keys. This guard also
catches truncated-hash collisions; it does not replace the entity model.

Existing baseline JSON is migrated on read from its recorded rule and entity,
even if its stored `id` used the old title hash. Old core dependency records can
recover their entity only from the exact historical emitter grammar
`Vulnerable dependency: name@version (ecosystem)` under that rule. This is a
specific compatibility decoder, not title similarity. Records without a rule,
or old dependency records whose entity cannot be recovered, are retained with
legacy title identity and a visible diff note for review. Plugins need explicit
rule/entity keys for prose-independent identity.

Passing a string to `finding_id(title)` explicitly retains the legacy API; new
callers pass the complete finding or its serialized mapping. Existing YAML `id:`
selectors remain accepted for an unchanged title and emit a replacement notice.
A legacy title ID that would match multiple semantic identities cannot suppress
any of them without an explicit alias. Unmatched selectors remain in the file
and produce `matched no findings` notices.

To migrate a reference after a title edit, use recorded baseline semantics:

```python
from attackmap.finding_identity import legacy_id_aliases
from attackmap.suppress import SuppressionSet

migration = legacy_id_aliases(old_report["findings"])
suppression_set = SuppressionSet(selectors, id_aliases=migration.aliases)
# Show migration.notices for unmappable/ambiguous records; review them manually.
```

This explicit adapter does not rewrite files or discover historical scans.
Persist the reviewed replacement ID in the selector. Rule/path and inline
suppression behavior is unchanged. JSON, triage and AI context use the same
semantic IDs. SARIF uses stable rule/entity scope plus its existing per-instance
protocol. Existing fingerprinted location IDs and rule-less SARIF fallback IDs
are unchanged; explicit-rule repository-level SARIF results undergo a one-time
identity migration because their old fingerprint included the title. Existing
Code Scanning dismissals for that fallback scope may require review.
