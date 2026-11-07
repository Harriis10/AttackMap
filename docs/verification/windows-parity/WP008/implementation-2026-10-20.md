# WP008 risk and path workspace

Implementation is source/model verified; native visual/keyboard acceptance and shell integration remain pending.

`RiskPathsViewModel` preserves core-supplied exploitability and path order and scores, with independent route, sink, confidence and supplied classification filters. Detail exposes supplied steps, impact, score factors, evidence, limitations and uncertainty. No title/route similarity creates evidence or finding associations. Source and finding actions exist only for explicit structured `file`/`line`, `locations`, `finding_id`/`finding_ids`; host must validate sources and navigate the selected generation before opening them. Legacy fixture paths lack explicit source/finding IDs/classification/confidence; these remain unknown and the supplied chain text remains inspectable.

`RiskPathsView` is an independently loadable native UserControl. ListView provides native selection and focus behavior; TextBoxes and ComboBox expose filter labels. Candidate/speculative/observed/unknown are explicit filter options, not runtime conclusions. Empty, missing, malformed/partial and filtered rows retain section notices and source totals. Selected detail clears when filtering hides the selected row. The control emits callbacks rather than opening arbitrary paths itself; unconnected source/finding buttons are disabled. It is not wired into MainWindow.

Verification with `.tools/dotnet/dotnet.exe` and workspace DOTNET_CLI_HOME/NUGET_PACKAGES:

- `run --project desktop/windows/RiskPaths.Tests/RiskPaths.Tests.csproj --ignore-failed-sources`: PASS 17 model checks (golden order/count, core scores/factors, route/sink/confidence/classification filters, chain detail, no invented links, selected generation, empty/missing/filtered and selection clearing).
- `build desktop/windows/RiskPaths.Tests/Preview/RiskPaths.Preview.csproj --ignore-failed-sources -p:NuGetAudit=false`: initial preview build succeeded with zero warnings/errors.
- Final `build ... --no-restore -p:NuGetAudit=false`: PASS, zero warnings/errors, 2m53s. Built DLL timestamp is later than final RiskPathsView source; includes resource initialization and preserved list selection when rebinding after filters. A prior rebuild hit apphost file locking because the owned preview was launched prematurely; PID 28392 was stopped and verified absent before the successful rebuild. No preview process remains running.
- Final repeated model command with `--no-restore`: PASS 17 checks.

Preview host: `desktop/windows/RiskPaths.Tests/Preview/`. Run its built `RiskPaths.Preview.exe` for the maintained synthetic legacy report. Switches `--dark` and `--small` select dark theme and 900x700; default light/1280x900. This host consumes the actual control and model without production-shell edits. It does not scan or contact providers.

Actual visual acceptance is **not performed**: Computer Use `@oai/sky` initialization timed out twice and reset the JS kernel (30-second then 60-second cap). No screenshot, Narrator or keyboard-selection PASS is claimed. Next host review: capture all four theme/size combinations; Tab through filters/list/detail links; arrow-select rows, inspect chain, filter to zero and clear, then confirm focus/scrolling and no truncation. WP008 must stay IMPLEMENTED/acceptance pending until those checks and shell integration complete.
