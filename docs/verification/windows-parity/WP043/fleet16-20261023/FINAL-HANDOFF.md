# Combined fleet graph delivery — 23 October 2026

This scoped batch is delivered. Do not start another roadmap task from this
handoff. WP043/WP044 remain IN_PROGRESS for the explicit gates below.

- Portable: `C:\Projects\AttackMap-Windows-x64-fleet16-20261023.zip`,
  117,960,474 bytes. SHA-256
  `c4dd12211868b53cc022cb3dba71ee8eeb38f0327835eae7140a18a91e750467`.
  Adjacent `.sha256` file uses the delivered filename.
- Local code checkpoint: `f5247d07d7d856e15bda5e79944694a6d58745a1` on
  `codex/fleet16-checkpoint-20261023`. The shared checkout HEAD and index were
  preserved. The final evidence/helper correction may add a descendant commit;
  [Git proof](candidate/git-checkpoint.json) identifies the shipping checkpoint.
- Frozen engine: `80073cfe4ee39138fbca41978fecb7ff40e1674d744cbfdbe4e4b6c4829ddceb`.
  Native DLL: `e56d65fe527fd40ff86308151eeb636a62dc7c3c617f0b31c348b0e05c737774`.
- Captured source02: engine source digest
  `58c4973e1adf7ecb273d97fc6c54f82102a2214cf0531bc693d30695efeac4ae`;
  full release input digest
  `8002ba6eba080d0834f795b205b021366e8fafd776e04ecedd9485f39556c9f3`.
  Live shipping inputs still matched this capture at delivery.

## Performed verification

- 202 integrated Python tests (29 architecture tests included), 12 new production
  summary-binding tests, four release-lock checks; 330 native model/layout checks,
  98 fleet binding checks, 14 Node tests and 33 bounded host export checks.
  These suites have separate scopes, not one broad regression run.
- Actual source 16-fixture serial/parallel 1/2/4 parity; Juice Shop + 15 fixtures;
  integrated source broker2/16. Controlled source partial retained 15 child
  manifests plus one failed group, with restored fixture and empty job; that
  particular run had concurrent source drift and is not source-checkpoint proof.
- Final combined native/frozen pair: 75 actual Fleet workflow checks, 16 verified
  child manifests, exact root/transport/snapshot mapping, report opening/back,
  interrupted vector transition and current web acknowledgment. Both payloads
  matched their complete pre/post hashes; owned job cleanup verified.
- Separate frozen Juice Shop broker/compare, 21 effective analyzers, four profiles,
  24 candidates/three shadowed. Three report ledger copies match, schema1.1;
  candidate01/02 whole reports match after removing only those three ledgers.
- Two self-contained native publishes passed; final publish has no C# or PRI249
  warning. Actual final closure audit verifies 534 publish files and 263 captured
  inputs, local web assets, notices, MSAGL archive/content/DLL identity and fixture.
- RequiredBundled/SBOM verifies 796 payload files. Portable ZIP verifies all 803
  file entries and 178 directories against actual bytes. Actual isolated packaged
  native engine guard and bundled executable capabilities pass; payload unchanged.
  The original RequiredBundled stage/ZIP remain unchanged.

[Delivery](candidate/delivery.json), [portable proof](candidate/portable-final-proof.json),
[packaged runtime](candidate/portable-runtime-02-proof.json),
[final candidate](candidate/candidate02-summary.json).

The first portable attempt rejected the SDK's case-preserved
`Microsoft.ui.xaml.dll` spelling. The helper now compares required Windows runtime
names case-insensitively while still verifying exact paths, collision refusal and
file hashes. Seven refusal tests passed again and the actual archive passed.
Earlier failure logs and Git staging attempts remain preserved.

## Honest remaining gates and cleanup

Actual native client images were reviewed in Light/Dark at two sizes. The compact
toolbar exposes a graph area; dense native detail still needs zoom/filter/list or
full SVG. WebView2 composition pixels are omitted by the client capture and Sky OS
capture timed out, including foreground retry. Hosted web appearance, normal
startup with personal legacy settings, keyboard/Narrator/200% text and clean-host
distribution are not accepted by these checks. An unrelated older AttackMap
process was left running; isolated packaged guards did not read personal settings.

Non-HTTP producer/consumer/shared datastore/RPC joins remain unanalysed, and 16
real production repositories were unavailable. Tests used the user-authorized
generated roots and Juice Shop. Full source/evidence/back/export journeys,
signatures, release/manual/dependency gates and macOS remain open.

Technical continuation note: the older `--startup-smoke` assertion requires a
null Provider object, whereas current AI-off configuration uses a disabled
configuration object. It was not used as a passing gate here; the executed
isolated packaged engine guard has its own saved proof. Correct that old QA
assertion when that startup gate is next explicitly resumed.

Own preview/candidate windows and owned test/build jobs have exited. The temporary
browser tab was closed, viewport override reset and local HTTP server terminated.
No LM Studio/provider calls, installs, remote publication or user workload shutdown
were performed. Root's fleet lease is released; other owners' leases are preserved.
