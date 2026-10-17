# Windows desktop technology spike

Status: **WinUI 3 implementation candidate; C20 acceptance open**, 2026-10-15.
The Windows beta work uses native presentation with the existing Python engine.
Windows C26 performance qualification, including the Windows 11 host requirement,
was removed from Windows M3 by user decision on 2026-10-15. Earlier performance
requirements in the historical bootstrap section are superseded.
The original bootstrap evidence below is historical; the current implementation
and rollback decision are recorded in the final section. Neither section accepts
unverified C19, macOS, accessibility or reference-host requirements.

## Original bootstrap behavior and smallest change

CodeGraph inspection and the platform inventory establish the current Windows
Python/pywebview host and CLI subprocess boundary. Existing web report surfaces
include overview/findings/exploitability/paths/surface/diagrams/reviews, inventories,
history/diff and fleet. Run states include idle/running/cancelling and three terminal
states. The smallest isolated experiment adds desktop/windows only, leaves that
production path intact, and tests native list/control feasibility with synthetic
data before adapting production reports.

## Evidence collected

| Check | Actual result |
| --- | --- |
| OS | Environment.OSVersion: Windows NT 10.0.19045.0; inventory identifies Windows 10 AMD64; not the C26 Windows 11 host |
| dotnet --info | Host 9.0.21 x64; **no .NET SDKs**; runtimes 6–9 present |
| Workspace-local SDK | Official Microsoft dotnet-install.ps1 installed .NET SDK 8.0.426 in .pytest_cache/dotnet with -NoPath; global tools unchanged |
| Visual Studio discovery | vswhere found Community 2026 18.10.12217.157 and BuildTools 2017; initial PATH/2022-only check missed the current installation |
| Windows Kits include directories | 10.0.19041.0 and 10.0.26100.0 present; this alone does not prove complete build tools |
| Native source | Six NavigationView destinations plus Settings, bounded ListView/ItemsStackPanel, fixture loading/filter/detail |
| python desktop/windows/generate_fixture.py | 10,000 rows; 3,540,175 bytes; SHA256 1cc6947d341248fe595f9abead14179d4947b11a7a9a05bee558023928916c34 |
| dotnet build desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj -p:Platform=x64 | Exit 1: No .NET SDKs were found. Compilation and NuGet restore never began |
| Local SDK build, same project and -p:Platform=x64 | Exit 0, 0 warnings/errors, elapsed 00:01:11.45 including restore; not startup latency |
| Local SDK publish -c Release -p:Platform=x64 --self-contained true -o desktop/windows/artifacts/native-spike | Exit 0, development folder produced; clean-host installation unverified |
| Debug process liveness | Start-Process -WindowStyle Hidden; alive after 3 seconds, then explicitly stopped; not proof of rendered/interactable UI |
| Initial published runtime | Exited -1073741189 (0xC000027B); HRESULT 0x802B000A: Cannot locate resource from ms-appx:///MainWindow.xaml |
| Fixed published runtime | EnableMsixTooling=true emits AttackMap.NativeSpike.pri; process remains alive with window handle; --smoke root Loaded callback runs and exits 0 |
| Native fixture smoke | passed=true, loaded=10000, filtered=1, selected=synthetic-00042, shellDestinations=6; dispatched filter/selection events and detail recommendation checked |
| Narrator, startup, memory, package install | Unmeasured / not executed |

Pinned Windows App SDK 2.4.0 exists in the
[Microsoft NuGet package registry](https://www.nuget.org/packages/Microsoft.WindowsAppSDK/2.4.0).
The unpackaged/self-contained project choice follows the
[Microsoft deployment guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/unpackage-winui-app).
Restore and native compilation passed. SDK/bootstrapper downloads initially failed
inside the network sandbox; standard escalation allowed the official Microsoft SDK
and NuGet dependency downloads. No global SDK installation occurred. No external
AI call occurred. SDK installation's first-run CLI printed a development HTTPS
certificate setup message; no certificate trust command was run.

Development exception capture exposed the missing MainWindow resource URI. Compiled
XBF existed in obj but the published app lacked its PRI. SDK targets gate PRI
generation behind EnableMsixTooling; adding it while retaining WindowsPackageType=None
fixed packaging without changing the controls/templates. Initialization callbacks
are guarded until InitializeComponent completes. The subsequent native Loaded smoke
checks 10k fixture loading, filter/selection event dispatch and recommendation text.
This exceeds process liveness evidence but does not validate layout, keyboard or
Narrator. Native interactive inspection was unavailable. Prior spike-error.txt may
persist in ignored output and must not be mistaken for the passing smoke result.

## Decision gate and rollback

Continue the Windows spike within C20's total ten engineer-day ceiling; record
elapsed engineer time when resumed. Build prerequisites were obtained locally;
a named Windows 11 x64 interactive host remains required. Record exact tool and
resolved package dependency versions in a release lock before distribution. Current
restore assets are local build output, not a committed dependency lock.

Before selecting WinUI: open a real shared engine fixture, validate schema/freshness
and secrecy projection, prove virtualized 10k rendering and assistive navigation,
launch/cancel a controlled descendant worker, create and install a development
package, and collect startup/memory/packaging effort. Specify remaining platform
features, estimate migration based on that work, and compare retaining the current
host against the same native/accessibility gates. No generic web-shell replacement
is proposed. C19 interaction study and C21–C26 beta acceptance remain separate gates.

Planning estimate, not measured effort: one slice each for engine DTO/command
adapter, worker lifecycle/freshness, findings/triage, architecture/inventory,
reports/history, and settings/platform integration, followed by accessibility,
performance and packaging acceptance. Calendar estimates are deferred until the
first executable spike proves toolchain and lifecycle costs.

Rollback is straightforward while isolated: omit desktop/windows from release,
retain the current Python UI/installer and reuse the same engine artifacts. A later
pilot must store settings separately/versioned, preserve originals during import,
and keep the existing launcher available until native parity is accepted. No
production launcher, installer, CI or global tracker changed in this slice.

## Current Windows implementation decision and rollback

Use WinUI 3 for the Windows beta candidate and retain Python ownership of
analysis, scoring, provenance, artifact publication and worker supervision.
This records the implementation choice already exercised by the current native
build; it is not approval of the original cross-platform C20 gate.

The candidate now reads real canonical reports, preserves uncertainty, launches
source or frozen engine brokers, compares selected runs, supports reasoned
suppression and exact-run export, and projects supplied architecture/inventory
records. The native layer does not rescore findings. A corrected, self-contained
unsigned development package bundles the verified frozen engine; source and
packaged engine selection use explicit absolute paths rather than PATH probing.

Current evidence, with its scope limits:

- Real native-to-frozen Juice Shop execution: 18 findings, zero scan errors,
  validated artifacts (`native-installed-engine-composition-2026-10-15.json`).
- Session/action/fault process suites plus loaded MainWindow abnormal-exit
  composition reject completed-envelope/nonzero-exit publication and preserve
  the previous report (`native-fault-composition-exitguard-current.json`,
  `native-mainwindow-exitguard-runtime-2026-10-15.json`).
- A 10,000-finding/50,000-observation/20 MiB reference fixture and Windows 10
  diagnostic measurements exist. The optimized reprobe uses one launch and
  forced-GC baseline/final normalization; these remain optional diagnostics.
- Thirty-six actual content captures were reviewed. Their transparency and
  composition limitations prevent treating them as full visual acceptance
  (`native-nine-view-visual-review-2026-10-15.json`).
- Expanded audits inspect 188 control observations without QA name repair;
  this does not verify keyboard task completion or Narrator. Actual DPAPI save
  and production-loader roundtrip are separately verified using an isolated
  synthetic credential (`native-protected-provider-current.json`).

Verification files above are under `desktop/windows/verification`. The exact
remaining criteria and evidence aliases are in `docs/windows-m3-gate-status.json`.
The historical missing-toolchain and synthetic-only statements in the original
slice do not describe the current candidate. The ten-engineer-day time box has
no accepted effort record; automated wall time is not a substitute. C19 participant
outcomes, the macOS slice/decision and manual accessibility/appearance remain
open; Windows performance qualification is no longer required. No calendar migration estimate is asserted.

For rollback, keep the previously reviewed version and its engine binding in the
same owned installation. Use the reviewed extracted installer's `-Mode Rollback
-Version <installed-package-id> -InstallRoot <owned-root>` to change version
selection, then explicitly launch that version's executable. Payload integrity
checks still apply. Do not overwrite a newer payload or infer compatibility from
an unchanged product version string.

Reports, original imports, protected credentials and action recovery snapshots
remain outside the replaceable payload. Settings are versioned; unsupported data
must be preserved and reported, not silently rewritten by an older client. A
rollback is not proof that every schema downgrade works. If native workflow
acceptance fails, preserve reports and use the verified engine CLI for local
analysis/export while resolving the native defect. The older Python host remains
a recovery option only to the extent its own dependencies and workflows are
verified; it does not waive native M3 accessibility or usability requirements.
Do not promote the native launcher to a public release until its stated gates
pass. Public signing/distribution and the four-week beta are M4 work.
