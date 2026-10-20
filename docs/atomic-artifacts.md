<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Atomic report generations

`attackmap.artifact_publisher` is the shared filesystem boundary. Render reports
into `generation_dir(base, run_id)` using a unique run ID. Finish the existing
`artifact-manifest.json` before calling `publish_generation(base, run_id)`.
The publisher checks all six section files, report and timing structure, schema
version, manifest identity, required files, and every listed SHA-256 against
file bytes. It refuses symlinks, junctions, traversal, and Windows reserved names.
Callers must not mutate a generation after publication or reuse a published ID.
Directory allocation rejects an existing artifact manifest; publication rejects
an already prepared generation, including prior results no longer current.

`current-generation.json` is authoritative. Its single atomic replacement selects
an entire generation and binds its artifact manifest checksum. Read through
`current_generation(base)`; it returns no current result if any required artifact
or checksum is corrupt. Previous generation directories remain available.
Read a pointer once per operation and use that returned directory throughout.
The producer must serialize publication for a shared output base.

Cancellation or errors before pointer replacement preserve the previous result.
Call `write_diagnostic(base, run_id, state="failed" | "cancelled", error=...)`
to record `diagnostics/<run_id>/terminal-diagnostic.json` separately; this never marks artifacts ready
or switches current. Callers must redact diagnostic errors before saving them.
A cancellation racing after the commit observes a completed publication.

The finalized `run-manifest.json` includes the `publication` stage in milliseconds.
It measures validation and preparation before the final manifest/pointer writes;
the atomic replace itself cannot be included without rewriting committed data.
This is elapsed preparation timing, not a claim of filesystem durability or
complete power-loss recovery. Pointer data is flushed before replacement.

Existing flat CLI filenames are supported through
`export_compatibility(base, generation)`. This explicit export copies only known
generated reports, refuses user-owned destination files, and writes its manifest
last. Artifact metadata and run timing are exported for every format; JSON or
Markdown selection filters the other flat report files. The flat compatibility
view is nonauthoritative and may be incomplete if
export is interrupted; a failure here does not invalidate the committed result.
Consumers needing consistent results must use the current pointer. Arbitrary
files in the output base remain scan inputs; a pointer is excluded as generated
only when its complete generation validates.

Fleet uses the same manifest with `generation_profile: fleet`.
`write_fleet_manifest` binds published child generation directories and their
manifest hashes. Publishing verifies the fleet summary and each bound child;
the child count must match the summary. A corrupt child invalidates fleet reads.

Fleet compatibility export also recreates `base/<repo_id>/<known-report-file>`
from only the child generations bound by the published parent manifest. It never
copies arbitrary directories or unlisted files. All parent and child destinations
are checked for user-file collisions before any file replacement. Child exports
complete before the parent compatibility manifest is replaced. Repeated exports
recognize prior generated files by positive manifest checksums; changed user
files, symlinks, and destinations belonging to immutable generations are refused.
This compatibility tree remains nonauthoritative and can be partial on an I/O
failure; the current parent generation and its bound children remain readable.

Tests inject errors/cancellation at all defined publication checkpoints, truncated
writes and replace failure, corrupt files, invalid names, redirected files, and
compatibility collisions. These focused Windows checks do not establish the full
C10 interruption/process-exit matrix or independent macOS acceptance.

## Analysis timestamps

The additive `scan_timing` object in `run-manifest.json` uses schema `1.0`,
clock `engine_utc` and scope `analysis_pipeline_before_publication`. Its
`started_at` and `finished_at` are engine-recorded UTC ISO timestamps;
`outcome` is `completed`, `failed` or `cancelled` when terminal timing is
available. The scope includes the analysis pipeline and optional analysis
stages, and ends before generation validation and pointer publication.
It is not an elapsed-duration replacement or a publication-completion time.

A policy failure can retain a completed analysis outcome. Likewise, a later
publication failure can have completed analysis timing and a failed terminal
diagnostic; these describe different stages. Failure diagnostics can carry the
same timing object without publishing a successful generation. A missing
terminal timestamp remains unknown, and fleet-parent aggregate timing is not
inferred from its children.

Native consumers read timing only from the captured generation's manifest-listed,
hash-verified run manifest. Missing, malformed or unsupported timing, non-UTC
timestamps and reversed intervals display an unavailable label. Legacy imports
never inherit adjacent metadata. Client request time and artifact-manifest
creation time remain separate concepts; neither substitutes for analysis time.
The immutable earlier preview packages predate this additive implementation.

Persistent failure timing is best-effort after run state exists and the output
is writable. Failures before that point cannot supply an analysis interval.
The later C15 context addition also writes best-effort diagnostics for failures
inside non-atomic pipeline execution, allowing a supervising broker to retain
known inner stages and coverage. This does not finalize a generation or change
the current pointer. Earlier timing-only preview packages predate that behavior.

## Structured diagnostic context (integration candidate)

The C15 addition uses an independently versioned `diagnostic_context` object
with `context_version: "1.0"` while retaining existing terminal diagnostic
fields. It contains stage outcomes and measured durations, declared analyzer
metadata, accepted-path counts, producer-issued resource events and bounded
fleet child context. Missing information is explicitly `unknown` or
`not_started`; partial reporting is distinct from complete reporting for a
named scope. This integration is still under focused verification and is not
present in the preceding immutable preview packages.

Coverage describes accepted-path enumeration only, not language/rule/runtime
coverage or completeness of analysis. Resource reporting covers only its listed
instrumented byte-limit scopes. Events come from the actual file-size and index
budget checks, never from parsing limitation prose. A skipped index-budget
candidate does not imply all later files are skipped: a smaller later file may
still fit. Legacy analyzers keep unknown reporting; known events survive a merge
with them and do not become a claim that every analyzer enforced the same limit.

Diagnostic projection excludes source excerpts, raw repository paths and raw
requested analyzer names. Later broker records preserve already known typed
context instead of replacing it with an empty fallback. Output stays bounded
and storage remains best-effort without replacing the original execution error
or current valid generation. Focused tests and schema validation must establish
these behaviors; the mere presence of these fields does not accept C15.

