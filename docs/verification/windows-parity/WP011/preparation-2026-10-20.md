# WP011 bounded preparation — no closure

WP008/WP009 remain manual-pending. This slice prepares independent overview content only; it does not close WP011 or wire navigation into MainWindow. Existing `OverviewAdapter.cs` already belongs to saved-report import, so the new implementation is `Overview/ParityOverviewAdapter.cs` plus `Overview/OverviewView.cs`. No shared adapter/model/resource/project, prior views, trackers or shell files changed.

The new loader hashes and parses one bounded report read, then supplies those same bytes to WP007 projections. Counts use section supplied totals; absent/malformed totals are null/unknown, never zero. Core ranked risks/path order and values remain unchanged. Overview shows at most 32 risk/path rows with explicit cap notice and partial status, retaining source totals. Actions and strengths require actual `defensive_review_json.recommendations`/`strengths`; legacy prose does not create them. Their original source indices/order, supplied statement/action, priority, confidence and evidence basis remain visible. Malformed lists and structured review are distinct from missing and empty. No raw source/secret/evidence fields are retained by this model.

Current core `review_json.py` emits `linked_finding` as a **title**, not an ID. This preparation intentionally does not make that title navigable. Callbacks arise only from explicit finding_id/path_id/inventory_id or supplied path IDs; absent IDs remain unlinked. Links include generation and report SHA-256. The model rejects stale generation/hash and identities not issued by this overview. Legacy imports with no generation issue no links. The control rechecks its current overview before raising a callback, and performs no host navigation.

Verification with `.tools/dotnet/dotnet.exe` and workspace DOTNET_CLI_HOME/NUGET_PACKAGES:

- Initial `run --project desktop/windows/ParityOverview.Tests/ParityOverview.Tests.csproj --ignore-failed-sources -p:NuGetAudit=false`: PASS 16 checks. Final `--no-restore` repeat after additional malformed-review/unissued-identity tests: PASS 18 checks, exit 0.
- `build desktop/windows/ParityOverview.Tests/Preview/Overview.Preview.csproj --ignore-failed-sources -p:NuGetAudit=false`: PASS, zero warnings/errors, 3m28s. Preview DLL timestamp is later than final adapter source.

Tests cover source counts/order/scores, unknown versus zero, missing structured review, empty and partial report, explicit action/strength projection, long text, raw secret exclusion, hash mismatch, stale generation/hash, malformed list/row preservation and explicit identity rules. No scanner, provider, CVE or analyzer execution is implied.

Standalone preview is under `desktop/windows/ParityOverview.Tests/Preview/`, default light/1280x900 with `--dark` and `--small` switches. It consumes the real new control and maintained synthetic legacy report. No preview is launched in this slice. Computer Use initialization previously timed out twice; visual/keyboard evidence remains pending, with no screenshots/acceptance claimed.

Root integration additions after dependency/manual gates:

1. Add `OverviewView` to shell navigation using the verified selected-generation report path/hash and generation; call `ParityOverviewAdapter.Load` then `SetOverview`.
2. Subscribe `NavigationRequested` **before** rendering; revalidate callback generation/hash against current host selection and route only exact IDs through existing finding/path/inventory navigation. Unknown/unissued/stale IDs produce a recoverable message.
3. Save/restore host view selection around drill-down and return; cancel/discard asynchronous older-generation loads before updating the view.
4. Preserve section caps/partial/unknown notices. Do not reinterpret a legacy title as an ID or regenerate scoring in the UI.
5. Perform actual scan → overview → risk/source → return journey, keyboard focus/selection, both themes/two sizes and screenshot review before any WP011 acceptance.
