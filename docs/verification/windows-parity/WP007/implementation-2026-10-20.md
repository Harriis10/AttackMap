# WP007 typed report sections

New `ReportSections.cs` and `ReportSectionAdapter.cs` provide independent read-only section projections; existing findings import and structure adapters remain compatible and unchanged. Shell composition belongs to later view/integration tasks.

The loader enforces 64 MiB and JSON depth 64, checks caller-supplied expected SHA-256 against exact read bytes, rejects run envelopes, and preserves caller generation identity without claiming manifest verification. Sections distinguish missing, malformed, present-empty and partial; 10000-row cap retains supplied total and original source indices. Scores/order/IDs remain core supplied; absent IDs remain null. Cloned source rows retain unknown additive fields and provenance after JSON document disposal. Secret projection exposes only identity/name/kind/location, with no raw value or evidence payload. Resource limit events/scopes/reporting and scan limitations are retained.

Typed projections cover paths, exploitability, attack surface/routes, dependencies, secret hints and suppressed findings; explicit evidence rows preserve vulnerability/workflow/taint/analyzer records without inventing schema fields. Analyzer inventory is unavailable when absent; empty analyzer errors do not imply successful analyzer execution. Fleet uses actual `fleet_summary_json` index `repos`/`cross_repo_links` through `ReadFleet`, separate from single-repo reports; candidate resolution remains source supplied and is never promoted.

Verification uses `.tools/dotnet/dotnet.exe`, `DOTNET_CLI_HOME=.tools/dotnet-home`, `NUGET_PACKAGES=.tools/nuget-packages`:

- `run --project desktop/windows/ReportSections.Tests/ReportSections.Tests.csproj --no-restore`: PASS 98 checks (golden complete/partial/empty/missing section rows/count/order, IDs/scores, secret exclusion, malformed/oversized, hash mismatch, same-name fleet identity/candidate/failure/generation).
- `run --project desktop/windows/ReportAdapter.Tests/ReportAdapter.Tests.csproj --no-restore`: PASS 71 existing checks.
- `run --project desktop/windows/C23ReportComposition.Tests/C23ReportComposition.Tests.csproj --ignore-failed-sources`: PASS 17 existing composition checks (no-restore initially lacked project.assets.json; normal restore resolved it).

Default PATH `dotnet` has no SDK; explicit bundled SDK succeeds. No native visual/accessibility, live provider, full fleet dispatch/publication or Swift acceptance performed. Fleet test payload is explicitly synthetic and follows current source index shape; it is not a frozen WP002 fleet dispatch schema. Integration must pass a verified selected-generation hash/context and preserve the partial notices in UI.
