<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Exact AI references (C14 prerequisite)

`attackmap.citations` distinguishes mechanical reference validity from claim
support. A valid reference means that a complete, case-sensitive token resolves
to a producer-issued evidence record or a captured source span. It does **not**
establish that the cited material supports a model's conclusion. Every validation
result therefore retains `claim_support: not_assessed`.

The allowlist is constructed only from explicit IDs in recognized producer
evidence arrays (`surface`, `finding`, `path`, `taint`, `exploit`, and `anomaly`).
Hypothesis text and arbitrary nested payload fields cannot extend it. Duplicate
or malformed IDs are rejected. A source ID is content addressed and binds a
canonical repository-relative path, exact captured line range, full captured
file SHA-256, and redacted excerpt SHA-256. Exact full `path:anchor` and
`path:start-end` aliases resolve to that same stored span. Basenames, bare file
paths, case variants, substring IDs, URLs containing an ID, invented line ranges,
and invisible suffixes do not resolve.

Source capture reads each selected file once, applies byte/location/line bounds,
and redacts before retaining excerpt text. Validation uses the retained span and
hashes, never whatever currently happens to be at a live filesystem location.
Changing a file after capture does not rewrite the model's original evidence.
Source references that cannot be captured remain unavailable. A structured ID
can be valid while having no captured source; that is not a valid source-span
reference. Traversal, absolute paths, symlinks and junctions inside the repository
are excluded from capture.

Hunt generation, critic and skeptic passes now share one captured source and
producer-evidence context. Skeptic prompts include its exact source metadata and
redacted excerpts. CONFIRMED/REFUTED model votes require a valid captured-source
reference; missing excerpts no longer disable validation. Standalone skeptic and
verify prompt rendering also captures explicit source metadata. The consensus
result exposes `citation_context` for report adapters. A model's narrative outside
this parsed jury-verdict path is not automatically semantically validated.

These file captures are not an atomic snapshot of an entire repository and do
not solve the separate AM047 consistent-analysis-snapshot work. Hashes establish
content identity, not authenticity. Runtime/deployment behavior and semantic
claim support still require engineering review. Fake/golden tests exercise prompt/hunt
integration, mutated files/models after capture, unavailable evidence, and exact
references. Complete C14 acceptance still includes broader model-output and
claim-support evaluation beyond mechanical reference identity.

## Narrative review references

Narrative review output is checked against producer IDs in the exact selected, sanitized prompt, including loopback prompt truncation. Duplicate IDs, malformed aliases such as `find:2`, and omitted evidence do not validate a citation. The original model prose is retained below an explicit status notice; the atomic output persists `reference_validation` beside provider metadata.

File/line references are classified separately. The narrative prompt currently supplies no captured snapshot spans, so detected source references remain individually unresolved and unvalidated, even when producer IDs resolve. This check never reads current source files to manufacture snapshot support. Reference checks do not assess whether the evidence supports the claim and cannot promote model text to deterministic findings.

## Claim support is a closed set, separate from reference validity (2026-10-17)

Reference validity never establishes that evidence supports a claim. `attackmap.citations.assess_claim_support`
records one of exactly two states per claim: `supported_by_cited_evidence`, only when a cited captured span
itself contains an identifier, route, or secret-kind that the claim's own text names (a deterministic
token-presence check; review/assessment vocabulary like "confirmed" or "supported_by_cited_evidence" is
structurally excluded from the extracted terms, so hostile analyzed files cannot talk the check into the
supported state), or `not_assessed`, which is the honest state for everything else — including valid
references whose spans name nothing the claim names. No state ever asserts a claim is false.

Consumers: hunt/skeptic consensus items and their reports carry per-item `claim_support`; narrative review
`reference_validation` persists one closed-set entry per cited claim (honestly `not_assessed`, because the
narrative prompt supplies no captured spans); deterministic defensive-review JSON weaknesses/recommendations
carry the same per-claim fields computed from the finding's own evidence text. `review_eval` rejects proof
verbs ("proves", "confirms", …) attached to citations in either order. Limits: token presence is not semantic
entailment, and a hostile file that prints a claim's identifier can still earn the token-level state; both
limits are stated in report/limitations text.
