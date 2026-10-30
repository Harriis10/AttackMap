# WP017 controlled provider faults — 2026-10-23

Prepared by `/root/ultra_provider_faults` for the root-owned GUI/build session.
The active WP017 task remains **IN_PROGRESS**. No native app, packaged engine,
LM Studio request, real model, full publish or visual review was executed by this
agent. These are negative fixture journeys, never live-mode success evidence.

## Frozen implementation and evidence

- `MainWindow.ProviderFaultSmoke.cs`: SHA256
  `23fe3b9aaa97f3890d66ad9a0ebb863baf844cfbecddcd4993c7f020545d23ab`.
- `provider_fault_fixture.py`: SHA256
  `f03b5331d3d815c6b4a941de536e217e8508e6cc06b43d39fa7f2010f0681440`.
- `test_provider_fault_fixture.py`: SHA256
  `666ea75c0a2dbbf3019d4268dff4c97ec35663abd616c172cbb8f0011189fb26`.
- `shared-hooks.patch`: four small, coordinated hooks; original apply check passed.
  Root owns application/reconciliation with the window-lifetime patch.
- [Exact 21-test output](unit-test-output.txt) and [exit/input record](unit-tests.json):
  exit 0; 21 tests in 6.629 seconds. Tests exercise actual owned fixture HTTP,
  socket/thread cleanup and synthetic negative-gate/provenance inputs. Synthetic
  native/process/build records test rejection behavior and prove no native run.

The native project uses SDK source globbing; no project-file addition is needed.
The live runner and `verify_wp017_live.py` are unchanged.

## Current behavior and the focused change

`RunSelectedRepository` already provides discovery → native preflight → actual
engine worker → canonical report import → selected generation/export binding.
The new partial calls that same method for an AI-off baseline and a single Review
fault scan over a new tiny Python/Flask/config fixture. It never scans Juice Shop
or changes an input repository. All generated reports are outside the fixture.

Ordinary child `LOCALAPPDATA`, `APPDATA` and `USERPROFILE` variables **do not prove
Windows known-folder isolation**. The earlier `native-fault-plan.md` normal-startup
profile assumption must not be reused. The explicit `--provider-fault-smoke`
constructor hook validates its whole configuration and replaces settings,
placement and recent-repository stores before initialization/restore. Its own
Loaded branch skips personal restore, and the existing smoke theme guard skips
theme loading. Capabilities and native preflight pass the existing `outputBase`
argument to `DesktopActionRunner` so neither writes to its personal known-folder
default. The scan receives an explicit owned output directory. Store constructors
only retain paths; they do not read settings.

Configuration is restricted to absolute fixed-drive paths without reparse points,
fresh output/state locations, a root-owned fixture and matching input hashes. The
endpoint must be exactly `http://127.0.0.1:PORT/v1` on a private non-1234 port.
The fixture exclusively binds `127.0.0.1:0`, never forwards traffic, and records
only request method/path/number/timestamp plus response status/bytes/hash. It does
not record request bodies, instructions, source snippets or authorization.

## Cases and required outcomes

| Case | Owned HTTP fixture | Required native/result evidence |
| --- | --- | --- |
| `unavailable` | One `POST /v1/responses`, HTTP 503 with the exact controlled error body. | Actual matched deterministic baseline and new verified generation, unavailable Review page and manifest, `model_output_available=false`, one reserved call with unknown output usage, identical deterministic findings, byte-matched selected JSON export. This is service unavailability, **not TCP connection refusal**. |
| `malformed` | One generation POST, HTTP 200 with exactly one byte, `{`. | Same negative outcomes as above; the body hash/byte count is independently checked against the malformed fixture constant. A status code alone cannot pass. |
| `pending-cancel` | Records one received POST, holds response, then releases a clearly labeled synthetic sentinel. | Native Cancel is requested only after the received nonce marker; native terminal cancelled, previous canonical/report/export/rows/revision preserved, no committed `current-generation.json` pointer, all owned processes and HTTP threads closed. |

The pending case's native 500 ms wait establishes a bounded post-cancel selection
check. It does **not** establish that the late HTTP response was received before
that check, or prove a stale callback was suppressed while the window remained
open. The controller separately records the late response attempt and inspects
the final publication pointer after app/HTTP cleanup. No ACK ordering or visual
acceptance is claimed.

TCP connection refusal and an exhausted-budget journey remain separate open
cases. A refused-port socket probe cannot count a native client's rejected TCP
attempt; this controller makes no such claim. The controlled 1-call/30-second
provider allowance and 120-second scan timeout belong only to these fixtures;
they do not change the real LM Studio mode budgets.

## Root-only execution

The CLI defaults to read-only preflight: no directory, socket, HTTP request or
process is started, including no import bytecode writes. `--run` is required for
every actual journey. Each run requires a new root under an existing parent.
Do not overlap GUI sessions. The existing Windows Job launcher assigns the app
while suspended and verifies owned descendants are gone before success.

For a newly approved complete package, use `--manifest-sha256` and, when required
by the package, `--release-lock`. That lane retains the existing full package
identity/source-lock checks. Do not weaken the live runner to accept a fixture.

For root's requested **current native source preview with the retained older
frozen engine**, use the separate explicit lane below. It requires current
native-build proof/source inventory/resolved inputs and bound EXE/DLL, plus
reviewed native/engine proof hashes, the engine EXE hash, every retained frozen
payload file, and its original release-lock hash. It does not assert a new
package, current engine source parity, release acceptance or real-model success.

The following inputs are concrete paths; the native build proof is created and
reviewed by root before preflight. The retained seed is read-only and hash-pinned
in the generated config; the scans use the new owned fixture instead.

```powershell
$faultRoot = 'C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\RESUME-2026-10-23-sol-ultra\provider-faults'
$faultScript = Join-Path $faultRoot 'provider_fault_fixture.py'
$faultApp = 'C:\Projects\INPROGRESS\AttackMap\desktop\windows\artifacts\sol-ultra-20261023-integration02\AttackMap.NativeSpike.exe'
$faultNativeProof = 'C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\RESUME-2026-10-23-sol-ultra\native-build02\native-build.json'
$faultEngine = 'C:\Projects\INPROGRESS\AttackMap\.tmp\wp024-sol-long-budget-20261023-02\dist\attackmap\attackmap.exe'
$faultEngineProof = 'C:\Projects\INPROGRESS\AttackMap\.tmp\wp024-sol-long-budget-20261023-02\build-proof.json'
$faultEnginePin = '574497f7c4ae3c8859edb5506c0538c8cba99dc70436f29857dbec6240aa81f5'
$faultSeed = 'C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP017\sol-long-local-20261023-remediate\remediate\reports\d2ee2327a28e468bae62ff0542d3e12f\attackmap-report.json'
# Pin these after reviewing the actual root-owned native build proof and retained engine proof.
$faultNativeProofPin = (Get-FileHash -LiteralPath $faultNativeProof -Algorithm SHA256).Hash.ToLowerInvariant()
$faultEngineProofPin = (Get-FileHash -LiteralPath $faultEngineProof -Algorithm SHA256).Hash.ToLowerInvariant()
$faultRunParent = Join-Path $faultRoot 'native-runs'
# Create this owned parent once, before the read-only preflight below.
New-Item -ItemType Directory -Path $faultRunParent -ErrorAction Stop
$faultArgs = @('--app', $faultApp, '--seed', $faultSeed, '--source-preview',
    '--native-build-proof', $faultNativeProof, '--native-build-proof-sha256', $faultNativeProofPin,
    '--engine', $faultEngine, '--engine-sha256', $faultEnginePin,
    '--engine-build-proof', $faultEngineProof, '--engine-build-proof-sha256', $faultEngineProofPin)
python -B $faultScript @faultArgs --case unavailable --output (Join-Path $faultRunParent 'source-preview-unavailable-01')
# Root's GUI lease and reviewed inputs are required for the explicit execution:
python -B $faultScript @faultArgs --case unavailable --output (Join-Path $faultRunParent 'source-preview-unavailable-01') --run
python -B $faultScript @faultArgs --case malformed --output (Join-Path $faultRunParent 'source-preview-malformed-01') --run
# Optional third journey after reviewing the two results:
python -B $faultScript @faultArgs --case pending-cancel --output (Join-Path $faultRunParent 'source-preview-pending-cancel-01') --run
```

The controller revalidates inputs immediately before output/socket creation and
after the journey. It never sets `ATTACKMAP_QA_HTTP_AUDIT_DIR/NONCE`. Fixture
requests and synthetic response sentinels must never be fed into the live gate.

A read-only preflight against `integration01` was correctly rejected after root
changed `MainWindow.Capture.cs` for the subsequent preview: the old proof had
`8004034c228c596d9eddf0378daa73391b4ec27febae559f7dc232343984f231`, while the
then-current file had `74e8e6b40a0d942f9b5a964a789926f113a3a434ca21617b007048bd34d43360`.
No output/socket/process/provider request was started by that preflight. Root's
subsequent native build02 replaces that input; commands above select it. Root
owns the actual GUI runs and their resulting acceptance records.

Before an actual PASS, require the fresh `summary.json`, a terminal native proof,
exact emitted provider settings and fixture POST/response correlation, matched
report/manifest/export hashes, unchanged package/source/seed/fixture identities,
an exited assigned Windows Job with verified cleanup, joined server and handler
threads, and closed owned connections. On a failure, retain the root and its
process/transport proofs. No summary is created for an incomplete journey.

Reproduce the focused fixture/gate tests (no app or engine execution):

```powershell
python -B C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\RESUME-2026-10-23-sol-ultra\provider-faults\test_provider_fault_fixture.py
```

Tests use fresh UUID directories with inherited workspace ACLs and verify each
cleanup target remains immediately beneath their own `test-temp` parent before
removal. An initial Python 3.13 `TemporaryDirectory` attempt failed because its
private DACL could not be reopened inside the Windows sandbox. No ACL/system
permission was changed; those failed scratch directories are ignored and no
runtime remained owned after the tests.
