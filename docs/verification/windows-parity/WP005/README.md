# WP005 native options/settings component handoff

Status: COMPONENT_READY / MANUAL_PENDING. Root shell integration and actual visual/keyboard acceptance remain outstanding. This is component evidence, not full WP005/K2 acceptance.

Implemented NativeScanOptions additive seven WP004 fields, validation and conditional schema 1.2 serialization; requests retain exact default schema 1.1 bytes otherwise. LocalSettings preserves schema 1, unknown JSON and disabled provider preferences, refuses corrupt/future settings overwrite, and retains an exact first-write backup. EngineCapabilities consumes schema 1, exposes supported run schemas/options/analyzers and disabled reasons, binds cache identity to executable SHA256, and invalidates on engine changes. Bundled engine resolution remains the default; explicit advanced paths retain existing launch/self-executable guards. No download or startup network/process probing was added.

The standalone WP005Preview project links only component files. Shared MainWindow, EngineProtocol, projects/resources and trackers were not edited. Exact root integration additions are in root-integration.md, including capability action/preflight ordering and preservation of unknown settings.

## Verification observed

With DOTNET_CLI_HOME=$PWD/.tools/dotnet-home and NUGET_PACKAGES=$PWD/.tools/nuget-packages:

- `.tools/dotnet/dotnet.exe run --project desktop/windows/NativeOptions.Tests/NativeOptions.Tests.csproj -c Release`: 54 checks passed. Final captured no-build output is model-tests.log. Covers seven sentinel fields, exact old wire bytes, ranges/paths/conflicts, migration/reopen/reset, corrupt/duplicate/future JSON preservation, unknown settings/provider preservation, capability versions/unsupported modes/modules and same-path/path-switch identity invalidation. No engine/provider process.
- `.tools/dotnet/dotnet.exe run --project desktop/windows/ReportAdapter.Tests/ReportAdapter.Tests.csproj -c Release`: 71 checks passed (observed command output).
- `.tools/dotnet/dotnet.exe run --project desktop/windows/EngineLaunchSpec.Tests/EngineLaunchSpec.Tests.csproj -c Release`: 24 checks passed (observed command output).
- `.tools/dotnet/dotnet.exe build desktop/windows/WP005Preview/WP005Preview.csproj -c Release --no-restore -p:NuGetAudit=false`: final diagnostic build passed, zero warnings/errors; preview-diagnostic-build.log. Earlier successful preview-build.log retained.
- `git diff --check -- desktop/windows/AttackMap.NativeSpike/NativeScanOptions.cs desktop/windows/AttackMap.NativeSpike/LocalSettings.cs`: passed; line-ending advisory only.

## Isolated preview evidence and limitations

First bounded attempt PID 8944 produced no PNG and was terminated/verified exited; preview/process.json preserves that result. One authorized diagnostic attempt then launched the same exact standalone executable with isolated root `preview-diagnostic`, `--capture --close`, and repository DOTNET_ROOT. It produced preview-0.png (supported synthetic capabilities), preview-1.png (old-engine disabled extended options), startup.log and preview-result.json. Automated native-control journey saved/reopened all seven sentinels, emitted schema 1.2 and rejected unsupported values while retaining them. No engine/provider calls or user settings were involved. Screenshot artifacts were captured; actual visual review is root-owned and has not been claimed here. Native keyboard, real picker interaction, Narrator, and composed application acceptance remain pending.

Diagnostic PID 25640 was still alive at the 30-second bound, so its exact executable path was checked before terminating that owned PID. Original process handle verified exited. Window handle was zero at final observation; this does not prove a visible top-level window remained. RenderTargetBitmap captured the loaded actual native control tree; it is not a desktop screenshot. Exact timestamps, executable path/hash and managed DLL hash are in preview-diagnostic/process.json. No further launch attempts were made.

No live provider, analyzer scan, installed application or personal settings acceptance is claimed. Root must integrate the documented shell seam, inspect both PNGs and complete actual interaction acceptance before closing WP005/K2.

## Root visual review and replacement capture

Root rejected the first captured pair: transparent background made labels unreadable, long paths clipped, and the second capture lost context. Those original artifacts are retained as failed evidence. Corrected only the isolated preview: explicit opaque white background/light theme and black text, wrapping baseline/suppression/engine paths, and fresh loaded control trees for each state. The replacement build passed with zero warnings/errors (preview-theme-build.log).

The one authorized replacement capture produced `preview-themed/preview-0.png` and `preview-themed/preview-1.png`. Exact launch invocation was `Start-Process -FilePath <absolute WP005Preview.exe> -ArgumentList @(<absolute preview-themed root>, '--capture', '--close') -PassThru -WindowStyle Normal`, with repository DOTNET_ROOT. PID 33128 naturally exited within its 45-second bound; original handle verified exited, no forced termination. `preview-themed/process.json` records exact paths, SHA256s and UTC lifecycle. `preview-result.json` again records save/reopen and unsupported-request rejection with no engine/provider calls. Root visual inspection of the replacement pair is pending; no visual PASS or manual interaction acceptance is claimed.

## Final footer layout correction

Root found the themed supported/unsupported pair readable but the left help paragraph below Model clipped at the action row. Moved that full startup/network paragraph into the existing automatically sized footer above actions and made the left options ScrollViewer vertical scrollbar explicit with bottom padding. Shared layout applies to both capability states; previous unsupported capture retained by root instruction. No unrelated tests were rerun.

`preview-layout-build.log`: build PASS, zero warnings/errors. One supported capture at the same 1160x960 window size is `preview-layout/preview-0.png`; run used the preceding command with additional `--supported-only`. PID 14448 naturally exited within its 45-second bound (21.4 seconds); original process handle verified exited, no forced cleanup. Exact managed DLL hash and path/lifecycle are in preview-layout/process.json. Root visual review is pending. Keyboard/Narrator/two-size/dark-theme acceptance remains pending regardless.

## Final supported viewport correction and terminal handoff

Root accepted full footer help visibility but found Model partly clipped. Returned the empty engine field to its normal single-line height and reduced left option spacing from 8 to 4, reserving additional viewport room while retaining explicit scrolling and bottom padding. Baseline/suppression path wrapping remains intact. Final build passed with zero warnings/errors (preview-final-build.log); no tests were rerun. One supported capture at the same size is preview-final/preview-0.png; prior unsupported image remains preview-themed/preview-1.png. PID 23792 naturally exited after 16.9 seconds within its 45-second bound, original process handle verified exited, no forced cleanup. Exact executable path/DLL hash/lifecycle are in preview-final/process.json.

Terminal status: MANUAL_PENDING, as instructed by root. Latest screenshot visual inspection, composed shell integration and keyboard/Narrator/dark-theme/two-size acceptance are not claimed. All prior regression/model results remain as recorded; no engine/provider calls or personal settings access occurred.
