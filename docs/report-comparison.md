<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Shared saved-report comparison

`attackmap.comparison.compare_report_files(baseline, current)` reads each selected
canonical report once, limits each input to 64 MiB, records its SHA-256 and
returns a JSON-serializable result. `compare_reports` is the in-memory equivalent.
The core validates report shapes and rejects different repository roots. Native
clients select paths and present this result; they do not perform their own
finding matching, resolution decisions or scoring.

The result has `comparison_version: "1.0"`, exact baseline/current report paths,
repository identities and input checksums, `counts`, `changes`, and `notes`.
Change groups are `new`, `persisted`, `resolved`, `newly_suppressed`,
`resolution_uncertain` and `new_instances`. Rows retain source finding fields,
evidence labels and suppression reasons. Missing evidence classification stays
`unknown`. Uncertain rows add `resolution_reason`; instance rows add
`new_instance_locations`. The instance count counts locations rather than rows.

Stable rule/entity IDs own matching, including the documented legacy baseline
adapter. Suppression is distinct from resolution. Only a missing baseline
finding whose structured source files all appear in current `scan.scanned_files`
can enter `resolved`. Missing or malformed enumeration, analyzer failures,
omitted source files and absent structured baseline locations instead produce
`resolution_uncertain`. `files_scanned` never proves source coverage. Existing
coverage limitations remain visible in notes; neither source enumeration nor
resolution classification proves detector-version parity or runtime remediation.

The lower-level `diff_findings(..., current_coverage=ComparisonCoverage(...))`
enables the same classification and optional Markdown section. Calls without
that keyword preserve legacy behavior and count keys. New history integrations
must use the comparison service or explicitly supply coverage; an old direct
call does not establish C23 coverage honesty.

The CLI `analyze --baseline` path now supplies the same coverage context. Its
console summary, `attackmap-diff.md` and optional PR Markdown distinguish
`resolution uncertain` from `resolved`. Every coverage-aware comparison states
that analyzer/config version parity is unknown and source-covered disappearances
are not verified fixes. New-high and newly-suppressed gates retain their existing
policy; uncertainty does not silently become a claimed resolution.

`HistoryComparisonView.cs` is a native selection/presentation control. It has a
`CurrentReportPath` property, `OwnerWindowHandle` for the native baseline picker,
and an `Action<ComparisonRequest>` event carrying baseline/current paths. The
host owns execution and calls `SetBusy`, `SetResult(JsonElement)` or `SetError`.
The control rejects a result for different selected paths or an unsupported
comparison version. It contains no subprocess, detector or scoring logic.

Golden coverage comparisons, legacy shapes, incomplete analyses, missing
locations, source count counterexamples, exact-path/checksum provenance, new
instances and repository mismatch are covered by focused core tests. Native
picker, keyboard, screen reader and complete end-to-end acceptance still require
platform execution; a compiled control alone does not establish those claims.
