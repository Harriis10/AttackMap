# New-candidate GUI execution plan — 2026-10-22

Prepared by `/root/sol_gui_plan`, read-only except this document. No GUI, model,
provider probe, build, test broker or application was started. Root exclusively
owns the interactive Windows, LM Studio and package-test slots. This plan accepts
no WP017/WP023, K2/K4, accessibility or release gate.

Authority: `docs/README.md`, active TODO WP017/WP023 and backlog lock keys
`lmstudio`, `interactive_windows`, `package_test_slot`. CodeGraph was consulted
before code inspection. Current source was checked for both runner entry points,
package/source identity and saved-report inspection. Historical evidence below
supplies only the concrete remaining gaps.

## Entry gates and binding

Wait for the repaired source checkpoint, independent review, fresh RequiredBundled
candidate, reviewed package-manifest SHA256 and its matching release lock. Do not
reuse `dev-20261022113134-4de136c6` to claim repair acceptance. New live source-bound
evidence and old Review/Hunt successes must keep separate candidate identities.
Root decides whether new-candidate five-mode acceptance needs Review/Hunt reruns;
the old successes alone cannot establish same-source five-mode acceptance.

Before any launch, all previous owned Jobs must be empty; confirm no outstanding
root native/engine journey or pending LM generation. Preserve the user's LM Studio
process and personal settings. Use an actual interactive host; inability to obtain
window geometry/capture is a blocker to observation, not a successful visual gate.

Bind these values from root's reviewed candidate handoff, replacing every angle
placeholder. A SHA computed from an arbitrary package is not an independent
reviewed pin. Do not create the phase output directories before invoking runners.

```powershell
$taskPython = 'C:\Projects\INPROGRESS\AttackMap\.venv\Scripts\python.exe'
$taskGui = 'C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP023\astra-gui-20261022\run-gui-checkpoint.py'
$taskInspect = 'C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP017\astra-review-20261022\inspect_saved_report.py'
$taskApp = '<NEW_CANDIDATE_ABSOLUTE>\app\AttackMap.NativeSpike.exe'
$taskManifest = '<NEW_CANDIDATE_ABSOLUTE>\package-manifest.json'
$taskLock = '<NEW_SOURCE_MATCHED_RELEASE_LOCK_ABSOLUTE>'
$taskPin = '<REVIEWED_64_HEX_MANIFEST_SHA256>'
$taskSeed = '<COMPLETED_CANONICAL_GENERATION_ABSOLUTE>\attackmap-report.json'
$taskEvidence = 'C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP023\astra-gui-20261022'
$taskArgs = @('--app', $taskApp, '--release-lock', $taskLock,
 '--pinned-manifest', $taskManifest, '--manifest-sha256', $taskPin, '--seed', $taskSeed)
```

`package_identity` verifies every package byte, exact inventory and source lock
against current release inputs. The GUI runner also snapshots its own/helper
hashes and seed, then checks them before/after each launch. `--pinned-manifest`
must be precisely the selected app's sibling package manifest. Fresh output must
have an existing parent and must not overlap candidate, seed, lock directory or
`C:\tmp\juice-shop`. A stale lock/source or changed helper is a stop condition;
do not bypass identity checks or mutate the immutable package.

## Execution order

1. Complete root's sequential real-model work on the new candidate. No overlapping
   GUI journey. Hunt+verify, Remediate and Triage have no prior completed response;
   Hunt+verify's previous unavailable generation is a failure, not a seed for AI
   success review. Real mode argv belongs to `tools/run_wp017_native_modes.py`:
   `--app APP --seed SEED --output FRESH --mode MODE --manifest-sha256 PIN
   --release-lock LOCK --provider-timeout P --scan-timeout S --process-timeout H
   --run`, where MODE is exactly `review`, `hunt`, `hunt_verify`, `remediate` or
   `triage` and `P <= S < H`. Use `hunt_verify` for the user-facing Hunt+verify.
   Current bounds are P 1..3600, S 1..86400, H 1..7200 seconds. Root must choose
   the reviewed explicit long-local values; the 900/1200/1500 defaults are not
   silently adequate for the failed long response. Do not lower call/token/jury
   limits or relabel an HTTP models probe as completion. The exact endpoint/model
   remain `http://127.0.0.1:1234/v1` / `cyberstag-security-26b-a4b-v1`.
2. After every live process is cleaned up, run the GUI basic phase once, then
   inspect any usable images. Use separate phase outputs so a transparent startup
   capture cannot hide the planned capture/watch scope. The runner stops at the
   first failed case; later cases then remain unexecuted.
3. Run the full non-AI saved-report capture phase. Open and review its actual PNGs.
4. Run the AI-off actual-engine watch phase, then inspect its captures. It performs
   a real watch/engine workflow; it is not a provider or model response test.
5. Review each completed saved AI generation without another model call. Use the
   normal non-closing saved-report window and, if useful, one saved AI capture
   recovery attempt. Validate actual visible content, report identity and mode.
6. Exercise abnormal broker and controlled provider faults separately. Complete
   human keyboard/Narrator checks in the identified actual full product window.

## Exact GUI runner commands

From the repository root, each first command is read-only preflight and starts
zero app/provider processes. Only append `--run` after the values and emitted
argv are reviewed. Preflight does not create or reserve the requested output.

```powershell
& $taskPython -B $taskGui @taskArgs --phase basic --output "$taskEvidence\sol-newcandidate-basic-01"
& $taskPython -B $taskGui @taskArgs --phase basic --output "$taskEvidence\sol-newcandidate-basic-01" --run
& $taskPython -B $taskGui @taskArgs --phase capture --output "$taskEvidence\sol-newcandidate-capture-01"
& $taskPython -B $taskGui @taskArgs --phase capture --output "$taskEvidence\sol-newcandidate-capture-01" --run
& $taskPython -B $taskGui @taskArgs --phase watch --output "$taskEvidence\sol-newcandidate-watch-01"
& $taskPython -B $taskGui @taskArgs --phase watch --output "$taskEvidence\sol-newcandidate-watch-01" --run
```

Basic expands to startup, readiness, menu, history-baseline, retention. Their
per-app ceilings are 180/120/120/120/120 seconds. Capture is 600 seconds; watch is
1500. All delegate isolated task AppData/settings and owned Windows Job cleanup
to the primary harness. Require `exited`, `owned_job_assigned`,
`owned_tree_cleanup_verified`, exit 0 and `timed_out=false`, plus unchanged inputs.
None requests a provider call. Capture requires `aiMode=null`,
`providerCalled=false`, exact seed hash and Architecture/Inventory/Reports/Settings/
FindingDetail views. Watch requires its real completed run, three observed events,
four captures, cancelled/settled state and preserved report, plus zero provider
request flag. Readiness proof includes response timings; it is not a human
usability or accessibility measurement.

Capture acceptance requires no native `*-failure.json`, complete manifests and
checksums, safe output paths, actual Light/Dark themes and genuinely increasing
logical sizes for requested 1024x700 versus 1600x1000. `capture-validation.json`
must pass bounded PNG decode/CRC/filter/pixel checks. The 33 passed deterministic
pixel tests prove guard behavior only. Nonuniform pixels alone do not establish
legible controls, correct data or usability; root must open the saved images and
record what was actually seen. Architecture/Inventory row diagnostics must exist.

## Saved AI generations: existing paths and runner boundary

For each successful canonical generation, bind its own artifact/run manifests
and selected AI artifact/export hashes. Preserve all originals. Open one report:

```powershell
& $taskPython -B $taskInspect --app $taskApp --release-lock $taskLock --manifest-sha256 $taskPin --report $taskSeed --output "$taskEvidence\sol-newcandidate-visible-review-01"
& $taskPython -B $taskInspect --app $taskApp --release-lock $taskLock --manifest-sha256 $taskPin --report $taskSeed --output "$taskEvidence\sol-newcandidate-visible-review-01" --run
```

Run this owner nonblockingly in root's execution session so root can activate and
inspect the window, then explicitly close that task-owned window. Default 1800
seconds is a bounded review ceiling, not an AI deadline. The helper validates
normal exit and unchanged generation/candidate/helper; it always leaves
`accepted_visual=false`. Add separate observed evidence for Reports navigation,
selected mode/provider/model/status, actual AI content, findings identity and
export. Check known Hunt semantic observations independently from transport.

The existing **app** recovery argv, within a fresh root-owned harness launch, is:

```text
APP --capture-smoke CANONICAL_JSON EXISTING_EMPTY_PHASE_DIR --capture-ai-mode MODE
```

It loads existing output without scan/provider execution, activates the window,
selects Reports and emits four theme/size captures. The current GUI runner has no
AI-mode option and its `capture` verifier deliberately requires `aiMode=null`.
Therefore do not pass an AI manifest to `verify_case('capture', ...)` or call that
path a pass. Root needs a reviewed evidence-only owner/validation invocation for
AI captures: same package/generation/selected artifact before/after hashes, native
manifest `aiMode=MODE`, `providerCalled=false`, exact selected report hash,
expected=completed=capture count=4, no failure JSON, and
`captures_check(captures, folder, {'Reports'})`. This helper writes a new validation
file and rejects bad pixels. It still requires actual image viewing. Do not use
`--capture-reports-artifacts`: it substitutes synthetic rows/text. Do not repeat
live parity/model work solely to repair an image.

Try saved Review capture recovery once before extending to other modes. If it is
transparent again, preserve the failure and use an authorized actual-window
capture bound to the identified PID/generation. Do not composite opaque pixels
over it or rename a metadata/control proof as a screenshot. Prior external WGC
capture timed out and geometry was unavailable; another failure remains a concrete
capture/interaction blocker, not proof the live window itself is black or frozen.

## Fault and human gates remain distinct

Use the existing `native-fault-plan.md` for root's owned launch and full check
list. Exact abnormal-broker app argv:

```text
APP --fault-smoke C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP023\astra-native-20261022\staged-brokers\NativeFaultBroker\attackmap.exe PREVIOUS_CANONICAL NEW_PROOF_JSON
```

Check staged broker runtime/source identity first; provide repository .tools/dotnet
as DOTNET_ROOT/DOTNET_ROOT_X64 if required. Fresh isolated profile/owned Job;
120-second ceiling. Require `passed=true`, `error=null`, `callbacks=0` and all ten
checks, with unchanged inputs and verified cleanup. This exercises hardcoded
`completed_exit7`, no HTTP or model. It does not prove provider-down, malformed
response, actual retry/reveal execution or readable error layout.

Provider faults need the separately reviewed owned loopback fixture/controller
and normal native controls described in that plan. No such controller is created
here. Use an allocated non-1234 port, fresh isolated profile, no production HTTP
audit override, explicit request/terminal counts, previous-report retention for
cancel and no stale publication. A valid deterministic generation after AI failure
may be correct: require honest unavailable/fallback state and absent usable model
output rather than imposing previous-report retention on every provider failure.
Never occupy/reconfigure LM Studio or count a fixture as a real model response.

Actual visual and human checks cover Light/Dark and two actual viewport sizes,
navigation/selection/detail, no clipping/overlap, readable uncertainty/budget/error
states, keyboard focus/tab traversal and activation, Narrator names/state/order,
cancel/repository switch, and scan→inspect→suppress→rescan→compare→export as
applicable to the active WP023 journey. Log performed observations individually;
unperformed checks remain open. Automated smoke, pixel guards, live HTTP and human
accessibility evidence are separate scopes.

## Current blockers / exit record

- Future repaired candidate, reviewed manifest pin and matching source lock are
  not supplied to this agent; commands remain deliberately unexecuted templates.
- The existing AI capture branch has no matching CLI mode in this GUI runner;
  its separate evidence owner/validator must be prepared/reviewed by root.
- Usable actual-window capture/coordinate geometry has not been demonstrated;
  prior transparent PNGs and WGC timeouts remain retained failures.
- Provider-down/malformed/cancel native transport journey needs the owned fixture
  controller and actual UI operation. The broker smoke cannot substitute for it.
- Human visual/keyboard/Narrator, K2/K4, WP017/WP023 and release acceptance remain
  open until their stated evidence exists.

Every run must record candidate/source/lock/generation/runner identities, exact
argv/time budgets, per-case process cleanup and results, actual image review and
remaining checks. A preflight-only record proves no execution. On a failure,
preserve that output and use a new suffix for a reviewed retry; do not overwrite
retained evidence or rerun unrelated broad matrices.
