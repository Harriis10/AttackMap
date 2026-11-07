# Native fleet transport live-01 — bounded PASS

2026-10-31. Native transport only, **one worker and two synthetic fixtures**.
WP019/WP034/WP035 remain IN_PROGRESS; no same-source release claim.

## Actual run

[Raw native result](../../../../../artifacts/wp043-context-diagnostics-20261031/fleet-transport-live01/native-fleet-transport.json),
[actual preflight](../../../../../artifacts/wp043-context-diagnostics-20261031/fleet-transport-live01/preflight.json),
[runner and process census](../../../../../artifacts/wp043-context-diagnostics-20261031/hidden-fleet-transport01-launcher/README.md).
Diagnostic candidate: `native-candidate-fleet-transport/AttackMap.NativeSpike.exe`.
Coordinator session output records native build **exit 0, 0 warnings/errors,
1:14.59**, and **19 guard tests PASS**; no saved build/test log is claimed.

App PID 31576 exited 0; run `cf640f466f804fa5a6cf4025b180fc9e`, generation 1.
All **9/9 checks PASS**, failure null. Real supported preflight and persisted
worker request agree: `modules=[config]`, `isolated_analyzers=true`,
`time_budget_seconds=30`, `timeout_seconds=180`, `max_workers=1`.
Actual request SHA-256:
`e8b27cee2c58b670a7832880aab457b5c262472df6bce7c777e6c52ac3fb9a5e`.

Both children completed, and the runner independently rehashed actual manifest
bytes against the native terminal:

| Child | Manifest SHA-256 |
| --- | --- |
| reader | `d3faf85a9b1c747ebc242bceb22c05b2f5655dfe0c16a958156839e2971a8816` |
| writer | `84a4e92b11d02058fd1b7228b89a90c0203ac88fe2d738f26d41c6e34e8a137a` |

App, engine and both fixtures retained their initial hashes. `cleanupBlocked`
is false, owning Windows Job active processes reached **0** before close.
Pre/post WMIC census found no NativeSpike, and post census no `attackmap.exe`.
No model calls; stdout/stderr empty. Isolation selection and owned cleanup do
not establish OS sandbox enforcement.

## Frozen-engine identity and failed whole-source gate

Actual frozen engine SHA-256:
`38632471645e82c5f20a0e05a413763c4573bf0006b695d2f00668c34d47746c`.
[Freeze explanation](../../../../../.tmp/fleet-e2e-engine-20261031-01/README.md)
and [diagnostic build proof](../../../../../.tmp/fleet-e2e-engine-20261031-01/diagnostic-build-proof.json)
bind it to captured snapshot inputs. PyInstaller exited 0, but the wrapper's
**whole-current-source gate failed** because four native QA files changed during
freeze: `MainWindow.Workspaces.cs`, `MainWindow.FleetTransportSmoke.cs`,
`MainWindow.xaml.cs`, `Fleet/FleetTransportQaInputs.cs`. No engine/Python/schema
input changed; captured inputs remain unchanged. This does not constitute
whole-current-source or same-source native/engine release qualification.

## Open gates

PASS covers native transport/preflight/persisted request/terminal/cleanup for
this one-worker fixture run. It does not prove the ordinary parallel CLI path,
OS sandbox, named analyzer profiles, summary loading/UI/pixels, representative
production 16-repository fleet, resource/scale limits, manual or release gates.
