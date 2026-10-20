<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Finding detail context

New JSON report findings, including suppressed findings, carry a precomputed
`context` object with `context_version: "1.0"`. Consumers can display this
without invoking Python for each selected finding. Older reports have no such
object and must retain an explicit unknown fallback.

The context contains the stable finding ID, static heuristic claim, supplied
severity/confidence and numeric scores, recommendation, suppression state,
structured locations and source-quality policy, and uncertainty notes.
Numeric point contributions are not supplied by Finding; they remain unknown.
Non-test source paths are unclassified, never presumed production or runtime.

Normalized observations at exactly the same full relative file and line are
bounded candidate cross-references, not detector-owned support. Basename,
nearby line and prose matching do not create links. Structured conflicts remain
visible. An index is built once per report; at most eight candidates are emitted
per finding in stable observation-ID order.

Repository controls and attack paths currently have no stable finding-ID
association. Their linkage therefore remains unknown even if source paths
coincide. A Finding's own `code_flows` may be presented as a detector-owned
static data-flow trace; it does not establish a trust-boundary crossing or
runtime exploitability. This is a useful detail contract, not completion of
missing detector-owned control/trust associations.
