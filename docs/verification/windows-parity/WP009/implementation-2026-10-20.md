# WP009 native inventory

`Inventory/InventoryViewModel.cs` and `InventoryView.cs` add a standalone native inventory control built on the accepted WP007 read-only report sections. No shell/shared-adapter/model files were changed. Integration and host visual/keyboard acceptance remain pending.

Nine groups retain independent source counts/order: attack surface, routes, dependencies, CVE/vulnerabilities, secrets, CI workflows, data flows, analyzers and analyzer errors. Missing, empty, malformed/partial and filtered states are explicit. Severity/confidence/evidence/name filters retain source totals and clear only selections hidden by filters. Section changes preserve filter input. Generation and report limitations/resource-limit reporting remain visible. No sorting, scoring or cross-section association is inferred.

Details render explicit scalar allowlisted fields as labeled text, rather than raw JSON. Secret rows consume only WP007 safe metadata; no raw secret/value/match/evidence payload exists in the inventory model. Source callbacks contain only supplied file/line or explicit sink_file/sink_line, and require host validation before opening. No file is opened by this control. CVE empty data never implies lookup enabled/completed or absence of vulnerabilities. Missing analyzer inventory, explicit not_used/not_applicable states and separately supplied failures remain distinguishable; an empty error list does not establish successful coverage.

Verification uses `.tools/dotnet/dotnet.exe` with workspace DOTNET_CLI_HOME/NUGET_PACKAGES:

- `run --project desktop/windows/Inventory.Tests/Inventory.Tests.csproj --ignore-failed-sources -p:NuGetAudit=false`: initial PASS 62 checks. Final `--no-restore` repeat: PASS 64 checks, including global partial/limit notices and final source-location projection.
- `build desktop/windows/Inventory.Tests/Preview/Inventory.Preview.csproj --ignore-failed-sources -p:NuGetAudit=false`: PASS, zero warnings/errors, 2m55s. Preview DLL timestamp is later than final view-model source.

The test suite compares every frozen report fixture's source count/order across eight supplied section groups, and tests missing analyzers, explicit analyzer states/failures, dependency IDs/order, filters, selection, long text, secret exclusion and global partial/limit notices. It does not prove a real CVE lookup, analyzer run or native visual acceptance.

Standalone screenshot-ready host is under `desktop/windows/Inventory.Tests/Preview/`; default light 1280x900, switches `--dark` and `--small` (900x700). It loads only the maintained synthetic legacy report and makes no scan/provider calls. It has not been launched in this task. Computer Use was unavailable in the prior WP008 turn (two initialization timeouts); no screenshots or keyboard/Narrator PASS are claimed. Required host review: visit every group, inspect a selected row, zero-match/clear filters, keyboard focus/selection, source callbacks, both themes/two sizes and long-text wrapping. Keep WP009 IMPLEMENTED/MANUAL_PENDING until that review and shell wiring are complete.
