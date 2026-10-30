# WP017 native fault gates and visible report review — read-only plan

Prepared 2026-10-22 while root owns the live LM Studio/native session. **Nothing
in this plan was executed.** No GUI, provider, build, test, server or process was
started and no product source/settings were changed. Wait until all five live
modes and their owned processes finish before taking the GUI/runtime slot.

Authority: active `docs/windows-parity-todo.md#wp017` and WP017 backlog entry.
WP017 requires provider-down/cancel/malformed evidence separately from five real
successful responses. AGENTS requires live integration against
`http://127.0.0.1:1234/v1`, model `cyberstag-security-26b-a4b-v1`; deterministic
fixtures/fake providers are permitted. A new loopback fixture below is therefore
**controlled fault integration**, never an LM Studio/model success. Do not stop,
reconfigure, restart, proxy or occupy the user's LM Studio port.

## Recommended order

1. Preserve completed live-mode artifacts and exact candidate/source identity.
2. Open a completed canonical report with the existing non-closing `--show-report`
   path and perform actual visible review after activation. This resolves the
   capture uncertainty without another model request.
3. Run the existing `--fault-smoke` once for the native previous-report/abnormal
   broker boundary: ten direct MainWindow checks, no HTTP or analyzer workload.
4. In separate fresh task profiles, run controlled connection refusal and malformed
   Responses API cases against an owned loopback fixture, using ordinary product
   controls. If needed, add one controlled pending-response cancellation case.
   Do not repeat all five expensive live modes merely to exercise these failures.

The existing Python/native unit evidence remains useful. The recent native
checkpoint already passed all 14 `NativeFaultComposition.Tests` cases; a new full
matrix is unnecessary. `tests/test_desktop_ai_modes.py` includes injected FakeSDK
dispatch, unavailable/fallback, shared-budget and stale-output checks. These are
in-process fixtures, with monkeypatched scanning and no HTTP; they do not supply
the proposed real native→frozen→loopback transport journey.

## Existing flags: capabilities and limits

| Path | What it actually exercises |
| --- | --- |
| `--fault-smoke BROKER PREVIOUS_JSON PROOF_JSON` | Hardcoded `modules: completed_exit7`, default AI-off options. Childless NativeFaultBroker emits completed/ready and exits 7. Ten MainWindow retention/cleanup/control checks. No provider error injection. |
| `--parity-smoke SEED OUT --engine ENGINE --native-scan --repository REPO --ai-mode MODE` | Applies a new default ProviderConfiguration, including the fixed LM Studio endpoint. No endpoint CLI argument exists; it also requires a completed model state for PASS. It is not a fault-state validator. |
| `tools/run_wp017_native_modes.py` | Live success harness pins the endpoint/model and requests `/models`; evidence validation rejects incomplete/malformed response observations. It must not be weakened or repurposed to call a fake response a live success. |
| `--show-report CANONICAL_JSON` | Ordinary startup and saved-generation import; window remains open. Root may inspect content and use actual provider/repository controls. |

**Answer about routing a fake endpoint without product changes:** the product
supports arbitrary literal-loopback HTTP ports through ProviderSettingsView and
ProviderConfiguration. Existing `child_environment` plus `launch` can launch the
normal product with a fresh isolated profile containing task-specific provider
configuration. Root then invokes the actual controls. The current automated parity
flag cannot select that endpoint; a fully automatic fault journey would require
a separately leased harness/UI driver change. Environment-only OPENAI_BASE_URL
injection is not a workaround: the launcher allowlist and native engine launch
scrub provider environment overrides, and the request carries explicit options.

The opt-in production HTTP audit is also pinned to the exact live endpoint.
`client_audit_options` rejects another base URL when its audit env is enabled.
For controlled fixtures, leave `ATTACKMAP_QA_HTTP_AUDIT_DIR/NONCE` unset and keep
separate fixture request counts/response hashes. Do not change the audit or the
live acceptance gate to accommodate the fixture.

## A. Safe existing path to leave a report open

Exact app argv, executed later through root's owned launcher:

```text
ABSOLUTE_CANDIDATE_APP --show-report ABSOLUTE_COMPLETED_CANONICAL_JSON
```

No smoke/capture/verify-startup flags should accompany it: they select different
startup handlers or automatic closure. `App.OnLaunched` constructs MainWindow and
calls `window.Activate()`. The normal `--show-report` handler only calls
`LoadReport`; it contains no automatic close and no scan/provider dispatch.

Use a **fresh corrected** `harness.child_environment(output)` profile. The known
folder issue has been fixed: owned `profile/AppData/Local` and `Roaming` exist.
All inspected normal-startup AttackMap settings paths use LocalApplicationData:
settings.json, provider.json, theme.json, window.json and recent-repositories.json
under `AttackMap/NativePreview`. Fresh isolation means these restore calls examine
only task-owned locations, not the user's settings. It is inaccurate to say the
normal branch skips restore; it restores defaults from the empty task profile.
The earlier probe showed SpecialFolder.UserProfile itself can still resolve the
real user profile; do not generalize environment isolation to every Windows API.

Illustrative exact Python launch sequence for root to place in its review owner
after binding the accepted package and report (not a new checked-in executable):

```python
from pathlib import Path
from tools import run_wp017_native_modes as h

app = h.local_path(APP_ABSOLUTE)
seed = h.local_path(CANONICAL_ABSOLUTE)
out = h.local_path(NEW_REVIEW_OUTPUT_ABSOLUTE)
before = h.package_identity(app, REVIEWED_MANIFEST_SHA256, RELEASE_LOCK_ABSOLUTE)
seed_before = h.record(seed)
out.mkdir()  # exclusive fresh root, existing parent
env = h.child_environment(out)
h.save(out / 'inputs.json', {'package': before, 'seed': seed_before})
# Keep this owner alive while root activates/reviews and explicitly closes the app.
# 1800 is only a bounded human-review session ceiling, not a model deadline.
h.launch([str(app), '--show-report', str(seed)], out, env, 1800)
assert h.package_identity(app, REVIEWED_MANIFEST_SHA256, RELEASE_LOCK_ABSOLUTE) == before
assert h.record(seed) == seed_before
```

Root must run that owner non-blockingly in its existing execution session, then
activate the identified app window and review it. The helper does not close the
app upon report load; it waits for user/root closure. On ceiling/failure its Job
cleans only owned processes and the run must not be called a successful review.
Review actual report identity, AI section/state, findings and layout; then close
the window and require the Job empty before releasing the slot. Do not start a
second GUI while a live parity journey still owns the session. Record screenshots
only after visible activation; repeated capture timeout is evidence to retain,
not a reason to interrupt the user's current LM generation.

## B. Existing controlled MainWindow fault command

Use the already staged, complete childless NativeFaultBroker runtime, checking its
source/checksum binding in the recent native checkpoint before use:

```text
C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP023\astra-native-20261022\staged-brokers\NativeFaultBroker\attackmap.exe
```

Exact argv:

```text
ABSOLUTE_CANDIDATE_APP --fault-smoke ABSOLUTE_STAGED_BROKER ABSOLUTE_PREVIOUS_CANONICAL_JSON ABSOLUTE_NEW_PROOF_JSON
```

Use the same `child_environment` and `launch` pattern, timeout 120 seconds, fresh
owned output, pinned candidate/seed/broker pre/post identity. The staged broker is
framework-dependent; supply the repository's absolute `.tools/dotnet` as
`DOTNET_ROOT` and `DOTNET_ROOT_X64` in this controlled child environment if required
by its apphost, as in the retained native checkpoint. This is a test broker, not
the bundled production engine. No new broker build is needed if its full runtime
and identity remain valid; if missing, stop and request a build slot.

Require proof `passed=true`, `error=null`, `callbacks=0`, exactly ten checks, all
true: abnormal exit rejected; no completed callback; displayed path/hash preserved;
rows/revision preserved; run/export selection preserved; previous presentation
identity preserved; failure and previous-report label visible; selected diagnostic
folder exists and is reported; cleanup/admission restored; reveal/retry controls
available. The fake creates no terminal diagnostic file. Explorer launch, retry
execution, provider failure and manual appearance are not covered by these checks.

NativeFaultBroker additionally supports malformed/oversized envelopes, missing or
malformed artifacts/manifests and no-terminal exit in its console test matrix.
Passing one of those binaries to `--fault-smoke` does not select another mode:
the MainWindow handler itself always requests `completed_exit7`.

## C. Controlled local-provider faults without touching LM Studio

The following fixture/controller is a **proposed small evidence-only helper**,
not an existing command or a file created in this task. Root may implement it in
a new leased evidence directory and independently review it before execution.
No product rebuild or candidate modification is required.

The fixture binds only `127.0.0.1` with port 0, records the actual allocated port,
and rejects 1234 defensively. It owns its socket/process and logs method/path,
request count, timestamps and response status/body hash; it never forwards traffic
and need not log source-bearing request bodies or authorization headers. All
requests must be constrained to its announced port. No proxy, DNS, hosts-file or
firewall changes are needed.

| Case | Deterministic local behavior | Required result |
| --- | --- | --- |
| connection-refused | Reserve an exclusive Windows TCP socket on 127.0.0.1:0 without listen, retain it for the case. No bind/close race with another process taking the port. | Test connection fails honestly; an explicit Review scan cannot report completed AI output. Confirm the attempted endpoint from the emitted request and connection refusal, not only zero server requests. |
| malformed JSON | Listen on its allocated port. `GET /v1/models` may return a valid list containing the fixture model. `POST /v1/responses` returns HTTP 200, application/json, Content-Length 1, body `{`, then closes the response. | Actual loopback HTTP request observed; malformed body cannot produce completed AI output. Model-list success alone must not hide generation failure. |
| valid JSON/no text | Same models response; Responses returns `{"id":"fixture-empty","model":"fixture-no-model","status":"completed","output":[]}`. | Semantic malformed/unusable response is unavailable, despite HTTP 200 and status completed. `_run_via_openai_sdk` explicitly rejects absent text. |
| pending response + cancel, optional | Accept one POST and signal a received marker, then hold its response on a controller event. No model is running. Root clicks Cancel after that marker, observes cleanup, then releases/stops its fixture. | Cancellation reaches terminal/verified cleanup, previous report remains selected, no later fixture response publishes a stale generation. This is controlled cancellation, not proof LM Studio stopped a real model computation. |

For each case allocate a fresh app/profile/output and owned small fixture repo.
Use a tiny Python/Flask source fixture with `python-web,config` analyzers; keep all
reports outside that repo. Capture one deterministic baseline on that same fixture
if findings byte invariance is part of the case. Do not rerun Juice Shop five
times or use its working tree for mutation. A fixture case that never dispatches
the intended provider request is incomplete, even if the GUI remains usable.

Two configuration methods require no product change:

1. Open the normal product via `--show-report`, select the owned fixture repository
   and bundled engine, use Settings to set the announced loopback endpoint, select
   OpenAI/API, Review, model `fixture-no-model`, and enable AI explicitly. Do not
   save credentials and do not modify the LM Studio endpoint in any personal profile.
2. Before launch only, create the following **new task-profile files** beneath
   `env['LOCALAPPDATA']/AttackMap/NativePreview`; normal startup restores them.
   This makes the configuration deterministic while root still invokes real UI
   actions. `--parity-smoke` would overwrite the provider selection, so do not use it.

`settings.json` template (absolute path values; isolated fixture only):

```json
{"SchemaVersion":1,"PythonPath":"ABSOLUTE_BUNDLED_ENGINE","RepositoryPath":"ABSOLUTE_OWNED_FIXTURE_REPOSITORY","Modules":"python-web,config"}
```

`provider.json` template (replace PORT with the allocated non-1234 port):

```json
{"schema_version":1,"configuration":{"enable_ai":true,"provider":"openai","endpoint":"http://127.0.0.1:PORT/v1","model":"fixture-no-model","max_calls":1,"timeout_seconds":30,"output_token_limit":32000,"mode":"review","speed":"standard","backend":"api"}}
```

The one-call/30-second allowance is an explicit **controlled fixture configuration**,
not a reduction of live-mode limits. Keep the live runner's 900-second AI allowance,
1200-second scan timeout and existing output/call budgets unchanged. Generation
uses the Responses API (`POST /v1/responses`), not chat/completions. SDK retries are
disabled; a fixture must count actual attempts rather than assume the setting.
Provider Test connection uses only GET models with at most ten seconds per its
existing code; it does not exercise malformed generation.

Exact app argv remains `APP --show-report PREVIOUS_CANONICAL`. The controller
keeps the fixture and app Job alive, root starts the scan once through actual UI,
waits for the intended fault/terminal and inspects Reports. There is no existing
CLI flag to automatically click Start with this custom provider. A direct frozen
`ENGINE desktop-worker --request REQUEST_JSON` can complement transport evidence
using a properly validated desktop request, but it does not prove native controls
or the native-to-engine request path. Do not substitute it silently.

Acceptance for provider faults differs from the abnormal-broker check: a provider
failure can still publish a valid deterministic analysis generation. Review/Hunt/
Remediate must be unavailable when no usable output exists; Triage may explicitly
fall back to deterministic output. Do not incorrectly require the previous static
report to remain selected after every AI failure. Require correct new generation
binding, deterministic findings invariance for matched inputs, explicit AI status,
`model_output_available=false`, no completed-response claim, honest unknown usage,
bounded actual attempts, no secret disclosure, and a verified owned-process exit.
For a cancelled scan, require previous-report preservation and no stale publish.

## D. What the capture failures do and do not establish

Root reported two external ComputerUse `FrameArrived` timeouts during Hunt and a
transparent in-process PNG. This plan preserves those reports without claiming
an independently reproduced GUI defect.

Source reasoning:

- `RunSelectedRepository` awaits discovery/preflight and `engine.Run`.
- `EngineSession.RunCore` launches a separate broker process, asynchronously reads
  stdout, and awaits `WaitForExitAsync`. The model HTTP call occurs in the worker,
  not as a synchronous HTTP wait on the WinUI thread. Long LM latency alone does
  not demonstrate a frozen UI.
- Some request serialization, protocol parsing, progress callbacks, UI binding
  and report import work runs on the captured UI context. Those are possible
  short stalls; source reading does not measure their duration or prove that one
  caused either reported timeout.
- Parity's `AI-mode.png` capture occurs **after** the awaited scan returns and the
  selected saved artifact is bound/exported. A transparent final PNG cannot be
  explained simply as capture waiting for the still-running model call.
- NativeCaptureProbe waits for two CompositionTarget rendering frames with a
  three-second ceiling, then calls RenderTargetBitmap. It validates nonzero
  dimensions and buffer length but never tests alpha/content visibility. Thus a
  fully transparent PNG can pass its structural checks. External FrameArrived
  capture is a different mechanism; neither failure proves the other's cause.

After all five modes, activate a normal retained `--show-report` window and inspect
its visible state before another screenshot attempt. Keep the same canonical hash,
candidate identity, monitor/viewport, theme and capture method in the record.
If external capture still fails while the visible app responds, report a capture
path limitation. If actual UI does not respond, preserve that separate observation
and obtain an explicit diagnostic lease. No product change or timeout reduction
is justified from the present source-only investigation.

## Handoff

Highest-value immediate actions after live completion: non-closing visible report
review, then the existing ten-check MainWindow broker fault. Controlled provider
faults need only an evidence-owned loopback fixture/controller plus normal UI,
not a product rebuild or an LM Studio shutdown. All fixture, transport, native
composition, real model and human accessibility results must remain separate.
No gate is accepted by this plan and no runtime remains owned by this agent.
