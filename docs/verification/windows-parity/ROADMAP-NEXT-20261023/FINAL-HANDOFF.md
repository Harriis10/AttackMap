# Final scoped roadmap handoff — 2026-10-23

User requested roadmap inspection followed by parallel implementation. Three
GPT-6.1 Sol ultra agents worked in disjoint scopes; root integrated shell changes,
reviewed evidence and completed actual native QA. No further task was started.

## Changes

- `fleet_resource_identity.py`: prepared strict declaration/qualified identity
  contract and pure undirected shared-resource projection. Matching requires
  scope, protocol, host, explicit port, namespace and resource, with independent
  source references. Ambiguous observations are quarantined; input is bounded.
  Public failures are sanitized. Windows path aliases and IPv4/mapped broadcast
  regressions found during independent review are fixed. Current extraction and
  pipeline do not call it; only coverage preparation metadata was added.
- `FleetGraphEvidenceNavigation.cs` / `FleetGraphPane.cs`: canonical relationship
  evidence picker, exact source/target repository labels, unknown refs and source
  line handling, qualified source requests and retained selection. Traversal,
  device/Windows alias roots and stale/forged requests are rejected. Evidence and
  graph are explicit alternative views of the same current model/viewport.
- `FleetView.cs`, `MainWindow.Workspaces.cs`, `MainWindow.FleetGraph.cs`: source
  event composition. Before live-file inspection, verify summary/index, target
  child manifest, transport identity, canonical root and snapshot. The existing
  SourceLocation inspector rejects redirection and checks the opened path.
  An explicit folder action repeats the guards. Closing returns to the same
  selection; inspection does not open an editor or prove captured-byte equality.
- `MainWindow.xaml.cs`: startup gate accepts a disabled nonnull provider
  configuration; enabled AI/CVE still fail the opt-in gate.
- `MainWindow.FleetEvidenceSmoke.cs`: actual current native fleet/source/back QA,
  both source sides and forged request checks; no fake provider or AI invocation.

## Verification and identity

Source: `.tmp/roadmap-next-20261023/source-03`, captured through the existing
release-input collector. Native output: `.tmp/roadmap-next-20261023/native-03`.
Complete build inputs/payload are in `native-publish-03/build-proof.json`.
Native DLL SHA-256:
`d1839c106c64ac7e115bcba223ebbc9b18d783d7fb9a427c2df2b3cc5b704bde`.

Runtime uses the retained frozen engine from fleet16 source02:
`80073cfe4ee39138fbca41978fecb7ff40e1674d744cbfdbe4e4b6c4829ddceb`.
This deliberately separates native/source preparation and scoped QA from a new
same-source frozen/package/release claim. No new portable package or Git commit
was created in this batch; the previous local checkpoint/ZIP is preserved.

Evidence:

- `focused-verification.json`: 104 pytest tests, 128 navigation assertions and
  the separate 121-option consumer result, with source/proof references.
- `nonhttp/version02/verification.json`: complete saved graph equality after
  removing only the new coverage metadata, not merely matching counts.
- `fleet-smoke-proof-04.json`: 94 actual native checks, all16 child manifests,
  exact transport/snapshot binding, two real source location inspections,
  same-selection return, native/vector/WebView context and cleanup.
- `fleet-runtime-binding-04.json`: complete native and retained engine payload
  hashes before/after, both unchanged.
- `startup/runtime-03/summary.json`: four actual compiled startup cases and
  cumulative Job counts of one app process, no descendant broker/provider.
- `visual-review-03.json`: preserved compact inline layout finding.
- `visual-review-04.json`: corrected inspector in both themes/two sizes and
  vector-return pixels. Two Light source dialogs were separately reviewed in
  runtime03; final same-dialog code receives two successful source checks.
- `process-cleanup.json`: all ten owned Jobs exited and cleanup verified.

Relevant commands (each output uses a fresh path):

```
.venv/Scripts/python.exe -m pytest tests/test_fleet_resource_identity.py tests/test_fleet_architecture.py -q -p no:cacheprovider --basetemp=.tmp/roadmap-next-20261023-nonhttp-v2-01 --junitxml=docs/verification/windows-parity/ROADMAP-NEXT-20261023/nonhttp/version02/tests-03.xml
.tools/dotnet/dotnet.exe run --project desktop/windows/FleetGraphNavigation.Tests/FleetGraphNavigation.Tests.csproj --configuration Release --no-restore -p:UseSharedCompilation=false
.venv/Scripts/python.exe -B docs/verification/windows-parity/ROADMAP-NEXT-20261023/verify.py capture --attempt 03
.venv/Scripts/python.exe -B docs/verification/windows-parity/ROADMAP-NEXT-20261023/verify.py publish --attempt 03
.venv/Scripts/python.exe -B docs/verification/windows-parity/ROADMAP-NEXT-20261023/verify.py smoke --attempt 03 --runtime-attempt 04
.venv/Scripts/python.exe -B docs/verification/windows-parity/ROADMAP-NEXT-20261023/startup/run_startup_regression.py --native C:\Projects\INPROGRESS\AttackMap\.tmp\roadmap-next-20261023\startup-native-03\AttackMap.NativeSpike.exe --output C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\ROADMAP-NEXT-20261023\startup\runtime-03
```

The first sandboxed native run failed temporary-directory cleanup ACL checks;
runtime02 failure is retained. Runtime03 repeats the same binaries with necessary
access and passes93 checks; final source03 fixes the visual finding and runtime04
passes94. No timeouts were mistaken for completion. No LM Studio calls occurred.

## Remaining roadmap work

- WP044: real extractor/adapter with qualified non-secret datastore declarations,
  child-snapshot binding and independently verified paired repositories; queue
  producer/consumer and RPC remain unanalysed. Do not join names/dialects.
- WP043/WP019: full partial/failure and finding/path/graph/source/export journeys,
  representative real16-repository qualification, hosted WebView2 pixels and
  offline clean-host distribution; graph/source workflow here is a scoped slice.
- Dense native Fit labels remain small; list/zoom/filter/full SVG are necessary.
  Compact inspector scrolls long facts. This is not a general readability claim.
- Source dialog Dark/OS interaction, keyboard/Narrator/200% text, Explorer/picker/
  clipboard manual paths and all other WP026 acceptance remain open.
- WP023/25/37: final fresh combined engine/native package, required regression,
  signing and clean Windows lifecycle; previous portable is unchanged.
- Independent human corpus review, studies/beta and macOS have separate gates.

All three whole WP tasks remain IN_PROGRESS. Active batch leases are released;
only the unrelated old app PID11020 remains. LM Studio and unrelated work were
not stopped. Runtime source capture and previous portable bytes are retained.
