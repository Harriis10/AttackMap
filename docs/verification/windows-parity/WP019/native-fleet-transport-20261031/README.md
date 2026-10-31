# WP019 / WP034 — native fleet typed transport, 2026-10-31

**Latest bounded execution:** [native fleet transport live-01](live01.md)
completed 9/9 checks, exit 0, reader/writer manifests verified and owned Job
cleanup/census clear. This uses one worker, two fixtures and a snapshot-bound
diagnostic frozen engine. The whole-current-source freeze gate failed on four
native QA files; it is not same-source release qualification. The prior
unbuilt-composition checkpoint below is retained history. Summary UI, ordinary
parallel CLI, named profiles, OS sandbox, production fleet and release remain open.

Status: bounded transport block implemented and focused checks pass. WP019, WP034, WP035 and release acceptance remain IN_PROGRESS / OPEN. The changed WinUI composition was not built or visually accepted.

## Before and resulting behavior

The native FleetSession previously sent only timeout_seconds and max_workers. The current native selection already had an installed analyzer profile/module model plus isolation, recall, analyzer strictness, CVE and suppression switches; these were dropped at fleet launch.

FleetScanOptions and NativeFleetRequest now carry the supported selection, with profile/modules exclusive, integer/path/identity validation, a per-repository soft budget below the whole-fleet allowance, and no provider credentials. MainWindow captures the selected supported flags, validates the installed selection, checks explicit fleet capabilities, and performs source/engine-identity-bound preflight before creating the worker request. FleetSession uses the same typed serializer and rejects disagreement between the transported and supervised timeout.

The strict Python FleetScanOptions accepts the qualified profile for schema 1.4, rejects unknown option fields and unknown profiles, and preserves it through the neutral request mapper to the service and child --analyzer-profile argument. Profile availability is checked by native discovery and preflight; execution retains existing offline profile resolution. No installation or analyzer substitution occurs. The published fleet schema was regenerated. New capabilities explicitly advertise fleet scan_options; old 1.4 documents retain existing supported defaults and module/isolation behavior but cannot authorize named profiles.

## Reachable and unavailable controls

- Reachable: selected available profile or explicit installed modules; analyzer isolation, recall, strict analyzers, CVE, no-suppress/strict-suppressions, per-child soft budget; existing total fleet allowance and 1–4 worker admission.
- Fleet AI, baseline/policy, custom suppressions and secret history remain excluded as the existing Fleet UI states. Provider configuration and credentials are not transported.
- Memory reservations and input-byte admission have no native controls and remain unavailable. The service-only WP034 opt-ins are not exposed or silently fabricated. Count admission is not an OS memory cap.
- Current .venv discovery: php-laminas-omeka@1.0 available; node-atproto@1.0 lacks node-service and atproto; python@1.0 lacks python. Availability is environment-specific. Focused preflight tests use explicit fixture metadata and do not claim these missing plugins are installed.

## Verification actually executed

- `.tools/dotnet/dotnet.exe run --project desktop/windows/FleetWorkspace.Tests/FleetWorkspace.Tests.csproj`: **73 FleetWorkspace/protocol/request checks PASS**. Covers typed serialized selections/defaults, worker/timeout limits, profile/module conflicts, bad paths, foreign identities and unsupported module syntax.
- `.tools/dotnet/dotnet.exe run --project desktop/windows/NativeOptions.Tests/NativeOptions.Tests.csproj`: **69 checks PASS**. Includes legacy fleet capability fallback, explicit profile advertisement, missing/unavailable analyzers and profile/modules conflict. No engine/provider process.
- `.venv/Scripts/python.exe -m pytest tests/test_desktop_fleet.py tests/test_fleet_schema_contract.py tests/test_desktop_capabilities.py -q -p no:cacheprovider --basetemp C:/Projects/INPROGRESS/AttackMap/native-fleet-transport-20261031-elevated-tmp3`: **89 PASS in 6.29 s**. Contract/service/argv seams; no real repo scan or LM Studio call. Run used approved normal folder access after restricted pytest mkdir(mode=0o700) returned WinError5. No ACL or test-source workaround.

## Native build and visual gate

The default host dotnet has no SDK; the repository .tools/dotnet/dotnet.exe provides SDK 8.0.426. A normal parallel build exited 1 with zero reported compiler errors; its diagnostic log is desktop/windows/artifacts/native-fleet-build-20261031.log. Serial attempts built GraphExplorer.Core and GraphExplorer.NativeView, then stopped producing output without creating the main native EXE. The last bounded attempt was:

```text
.tools/dotnet/dotnet.exe build desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj --no-restore -m:1 -p:UseSharedCompilation=false -p:Configuration=Debug -p:Platform=x64
```

That owned session was canceled and returned exit 1. A previous serial observation showed VBCSCompiler; the final no-shared attempt had no child compiler process at the last observation. This does not establish the root cause. No more build variants, host install, environment change or unrelated-process termination were performed.

No current candidate exists at desktop/windows/AttackMap.NativeSpike/bin/x64/Debug/net8.0-windows10.0.19041.0/win-x64/AttackMap.NativeSpike.exe. The added Fleet explanatory paragraph therefore has **no current-build visible preview or visual acceptance**. Full native composition, actual fleet scan, frozen/package integration, OS isolation/resource boundaries, C35 and release gates remain open.
