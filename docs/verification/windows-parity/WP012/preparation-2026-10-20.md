# WP012 bounded suppression preparation — no closure

WP005 option binding is still active. This slice adds only `Suppression/SuppressionWorkspaceModel.cs`, `SuppressionWorkspacePanel.cs`, isolated tests/preview and this evidence. Existing `SuppressionPanel.cs` owns reason/governance/full plan/receipt UI and remains unchanged. No baseline file is read, written or hashed by the new model; no scanner or action broker runs in these tests.

The retained list consumes WP007 suppressed source indices/IDs/order and count, showing title, reason, origin/suppressed_by and expiry/expires only. Missing values remain unknown; missing/empty/malformed/partial section states retain source notices. Extra raw secret/value/evidence fields are excluded. Selecting a retained row is read-only; its title never becomes a suppression identity. The action finding ID must be explicitly bound by the host and is displayed separately.

Baseline selection is an explicit canonical local absolute path plus host-supplied SHA-256, independent of no-suppress for the next scan. Missing/unverified hash blocks preview/apply. Relative paths, traversal, UNC/URLs, control characters, alternate streams, reserved devices and trailing alias characters are rejected before intent creation. Validation does not imply the file exists, is a regular nonredirected file or belongs to the selected repo; host/core must prove those facts.

Selection tickets and per-action context revisions reject stale asynchronous picker and preview results. Previews bind exact baseline path/hash, finding ID, generation and report hash; apply requires an accepted applicable preview, while undo requires the current opaque receipt. Host-reported apply completion updates the expected baseline hash and enables undo; undo invalidates hash until refreshed. Retained report rows never change after these acknowledgements. A new scan is always required to refresh scan results.

## Proven current core limitation

`suppression_actions.py::_target` permits only `.attackmap-suppress.yaml` or `.attackmap-suppress.yml` inside the repository and rejects redirected paths. It does not accept arbitrary selected external baseline destinations. **Do not map a selected external baseline intent silently onto the default repo file.** Root must keep such write actions disabled or implement/review an explicit scoped action-contract extension. Scan baseline selection and suppression-file editing are distinct integrations. Plans/receipts remain host-owned snapshots, not authorization tokens.

## Verification

Using `.tools/dotnet/dotnet.exe` with workspace DOTNET_CLI_HOME/NUGET_PACKAGES:

- Initial `run --project desktop/windows/SuppressionWorkspace.Tests/SuppressionWorkspace.Tests.csproj --ignore-failed-sources -p:NuGetAudit=false`: PASS 26 checks; expanded repeat PASS 31.
- Final `run ... --no-restore`: PASS 33 checks (result-plan path/hash mismatch rejection included).
- Initial standalone preview build: PASS, zero warnings/errors, 3m55s. Final `build ... --no-restore -p:NuGetAudit=false` after explicit verified-plan binding: PASS, zero warnings/errors, 1m44s.

Checks cover exact source identity/reason/order/count, unknown origin/expiry, missing/empty/malformed/partial, long text, raw secret exclusion, no-suppress independence, explicit action finding, unsafe paths, missing hash, busy duplicate requests, stale selection/action responses, changed baseline/generation, apply/undo receipt progression and unchanged retained rows. These are synthetic intent-state tests, not actual file apply/undo or rescan evidence.

## Root integration API and remaining gates

1. Create `SuppressionWorkspaceModel` from the verified selected `ReportSections`; subscribe panel callbacks before `SetModel(model)`.
2. `ChooseBaselineRequested(ticket)` opens the native picker. Host verifies intended local regular nonredirected file, computes exact hash, and calls `CompleteBaselineSelection(ticket,path,hash)`; discard false/stale results. Call `Refresh()` after host changes. Picker cancellation makes no file changes. `ClearBaselineRequested` and `NoSuppressChanged(bool)` must bind WP005 options independently, without automatically scanning.
3. Bind the selected **real active finding** with `SetFinding(exactId)`; retain/validate full original record in the existing action service. Never recover IDs by title or list position.
4. `ActionRequested(SuppressionIntent)` is callback-only. Revalidate current host generation/report hash and selected baseline file hash before dispatch. Map only supported exact target paths to existing broker preview/apply/undo, reusing existing governance/identity review and full plan/receipt behavior. If unsupported, reject clearly and reset with `Reject(intent)`; never fall back to another file.
5. For a valid preview, derive actual plan target/hash and call `AcceptPreview(intent, verifiedPlanBaseline, opaquePreviewId, canApply)`. Model rejects path/hash/context mismatches. Host registry retains full plan and receipt; opaque IDs in this model contain no plan contents. Revalidate broker `can_apply`, exact target/context, source identity and file hash again before writes.
6. After confirmed broker success only: `AcceptApplied(intent, opaqueReceiptId, postApplyHash)` or `AcceptUndone(intent)`. A false/stale acknowledgement must not mutate a newer displayed selection. Handle uncertain broker outcomes using existing recovery/receipt logic; do not present the selected report as rescanned.
7. `SetReport(next)` invalidates baseline/preview/receipts and old asynchronous tickets; rebind only after host verifies selection. Preserve actual recovery receipts in the existing broker service independently.

Standalone host under `SuppressionWorkspace.Tests/Preview/` supports light/dark and 1280x900/900x700 (`--dark`, `--small`). No preview was launched. Visual/keyboard/Narrator acceptance remains pending because Computer Use previously failed initialization. WP012 remains non-DONE until WP005 binding, supported explicit write-target integration, real temporary baseline preview→apply→undo→rescan, and native visual/keyboard evidence are complete. No Juice Shop writes are authorized by this preparation.
