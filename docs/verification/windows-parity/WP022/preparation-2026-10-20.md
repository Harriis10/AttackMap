# WP022 bounded selected-export/SARIF preparation — non-DONE

New `ExportPrep/SelectedExportWorkspace.cs` and `SelectedSarifProjection.cs` plus isolated `SelectedExportPrep.Tests` prepare read-only selection validation and callbacks. Existing `ExportSelection`, `SelectedArtifacts`, exporters, shell/pickers, shared project/resources and trackers remain unchanged. No PDF/render/clipboard/open/reveal/save operation is executed by the new production helper.

## Exact selection and safe intent boundary

The workspace requires a verified captured generation and reuses `SelectedArtifacts.List`/`ReadText` for manifest/report binding, bounded bytes, artifact membership and selected source reparse/final-path checks. It never follows a mutable current-generation pointer. JSON/MD/HTML/PDF/SARIF and save/open/reveal/copy intents carry workspace epoch, generation, report hash and manifest hash. Replacing/cancelling selection invalidates older callbacks; failed-save acknowledgement invalidates retry intents without writing anything.

Save preflight rejects traversal, URL/UNC/mapped-network paths, alternate streams/trailing aliases, source files/immutable generation directories, directories, and existing reparse ancestors. A colliding destination requires explicit overwrite approval and exact captured destination hash; a destination appearing/changing after the picker is rejected. Content identical to a selected artifact is rejected conservatively to avoid source aliasing. Destination fingerprints are stream-bounded to64MiB. These are preflight guards, not authorization tokens: root must revalidate immediately before its actual atomic write and enforce target/handle safety during the write, including races after callback validation. This helper performs no write and cannot guarantee a separately implemented writer's transaction behavior.

PDF dependency probing examines only configured existing local `.exe` paths and never executes/downloads/installs anything or accesses a URL/network drive. Results are typed `Unavailable` or `PresentUnverified`; presence is not a successful PDF render. PDF intents require a still-present local dependency plus verified selected Markdown. The test executable used for presence probing is inert fixture text and is never launched.

This new helper requires verified generations. Existing legacy JSON-only export remains a separate unchanged path; root must preserve its disclosure/behavior when wiring the new helper.

## Deterministic SARIF projection

The derived SARIF2.1.0 document preserves canonical active-finding order/IDs, rule IDs, original severity/confidence/evidence basis and explicit relative structured source locations. High/medium/low translate to SARIF error/warning/note; unknown values use none while original labels remain in properties. No confidence-derived security-severity, new score, title-derived identity, prose-derived path, chain or line1 is invented. Findings lacking locations remain locationless. Duplicate titles with different IDs stay separate. Unicode relative paths become percent-encoded inert URIs; absolute/traversal/malformed locations are omitted with partial notification.

Free-form evidence/secret values are deliberately excluded from this standalone safe projection. Supplied evidence count/basis remain in properties with `evidenceTextWithheld=true`; original canonical evidence remains in the hash-bound JSON artifact. No raw source JSON is embedded. Structured source IDs/order and source report SHA/generation remain traceable. Limits are 64MiB input/depth64,10000 finding rows,256 locations per row and10000 total locations; omissions/caps are explicit. Coverage completeness stays unknown; source limitation/analyzer-error counts and resource reporting are preserved as metadata, not converted into safety claims. `invocations.executionSuccessful` describes projection processing only, never scan/runtime/provider success.

Root should prefer copying an already manifest-listed canonical core SARIF artifact where present; this new safe derived projection is not a claim to replace all existing core SARIF features or suppressed-result export. No schema/taxonomy/evidence inference is added.

## Verification and remaining evidence

With `.tools/dotnet/dotnet.exe` and workspace DOTNET_CLI_HOME/NUGET_PACKAGES:

- Initial test catch failed to include InvalidDataException during expected collision rejection; corrected before acceptance.
- `run --project desktop/windows/SelectedExportPrep.Tests/SelectedExportPrep.Tests.csproj --no-restore`: final PASS43 checks, exit0. Compiled test DLL timestamp is later than the final helper source (includes mapped-network path guard).

Actual synthetic filesystem tests exercised selected manifest/report tampering, malicious manifest traversal, duplicate title/different ID, no location/file-only no invented line, malformed/large JSON, explicit bounds/partial, raw secret exclusion, collision/overwrite fingerprint change, cancel/save failure, unsafe paths, real file/directory symbolic-link/reparse rejection, long Unicode destination and long Unicode **selected source** replay. They preserve fixture source originals. No permissions were weakened and no symlink case was silently skipped. Assertions cover SARIF structure/version and deterministic bytes; the complete external SARIF JSON Schema was not fetched or validated.

Root wiring and closure gates:

1. Initialize/select from the exact host `ExportSelection` for the displayed historical generation; preserve WP013 selected identity. Do not rebuild selection from current pointer during asynchronous save/picker work.
2. Present format availability, immutable selection disclosure and typed PDF dependency status. Keep legacy JSON export separate; only offer MD/HTML/PDF when selected verified Markdown exists.
3. On explicit user action, `Request(format, operation, destination, overwriteApproved, pdf)` yields a callback intent; cancelled picker returns null. Revalidate `Validate(intent)` and destination identity just before dispatch. A false result requires reselection/new preview, not fallback to a newer report or another destination.
4. Root's existing JSON/MD exporter or local renderers own safe atomic destination writes. New SARIF bytes come from `ReadSarif`, which checks selection again after reading/projection. Recheck intent after awaited work and before publishing bytes. Prefer exact bound existing SARIF artifacts where supported. Never overwrite sources or an immutable generation.
5. Open/reveal/copy handlers must target the captured artifact/derived payload for that generation only. If a requested derived format has no saved artifact to reveal/open, report unavailable or require an explicit save; do not open a stale/newer similarly named file. No handler is invoked in this preparation.
6. Use existing error/cancel recovery and call `SaveFailed()` for failed saves. Prove destination collisions, actual picker cancellation, save-denied errors, renderer absence and real exports preserve source/destination semantics; do not infer this from callback-only tests.
7. Finish WP013 host identity integration, real shell dialogs/export/open/reveal/copy journey, SARIF consumer/schema validation and actual HTML/PDF visual output evidence. WP022 remains non-DONE; no shell picker or actual PDF visual acceptance is claimed.
