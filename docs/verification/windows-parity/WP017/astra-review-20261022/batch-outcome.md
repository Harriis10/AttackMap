# First packaged live batch outcome — 2026-10-22

Candidate `dev-20261022113134-4de136c6` remains unchanged. This batch did **not**
complete WP017. Original runtime evidence is retained under
`../astra-live-20261022/`.

| Mode | Actual request/response | Process and artifact outcome |
| --- | --- | --- |
| Review | 1 dispatch, 1 completed HTTP 200 response | Exact artifact/export and 21 manifest files verified; exit 0, 164.04 s, owned Job clean |
| Hunt | 1 dispatch, 1 completed HTTP 200 response | Exact artifact/export and 21 manifest files verified; exit 0, 863.30 s, owned Job clean |
| Hunt+verify | 1 dispatch, no HTTP response/completion observed | AI unavailable, no requested AI artifact; exit 0 after 927.62 s with owned Job clean; live harness correctly FAIL |
| Remediate | Not started | Batch stopped at failed Hunt+verify |
| Triage | Not started | Batch stopped at failed Hunt+verify |

Hunt+verify generation `6bd4a2cdd360493c875108783f246f9e` preserves deterministic
output. Its run manifest records one reserved call, unknown usage, zero remaining
provider seconds, `desktop_ai.status=unavailable` and no AI artifact. The native
smoke failure is `Requested AI mode artifact is missing`. The outer process did
not time out or require manual cancellation; the harness's exit code is 1.
This is an exhausted AI allowance with no observed completed response, not a
successful model run. No unsupported claim of a killed or completed LM server
request is inferred from client exit.

At 12:47 UTC root checked the actual LM Studio window through Computer Use:
model `cyberstag-security-26b-a4b-v1` was **READY**, server Running. The user also
reported no further requests. The audit still contains exactly three model
dispatches and two completed responses; no Remediate/Triage folder or dispatch
exists. No model call was sent by this status check.

## Separate visible-review attempt

After the batch and owned Jobs ended, `inspect_saved_report.py --run` opened the
saved Review generation through `--show-report` in a new isolated task profile.
Preflight started no processes; the executed session is recorded in
`saved-review-window/`. The actual accessibility state confirmed:

> 18 of 18 engine findings - C:\tmp\juice-shop - saved generation
> 62feae910edd4843aef42f98e53fdd36; manifest integrity checked; origin unverified.

The window remained open until root closed this task-owned window with Alt+F4.
The launcher then confirmed normal exit, unchanged package/source/generation
inputs and empty owned Job. No scan or provider request was requested.

Actual visual acceptance is still absent: screenshot capture after activation
failed with `window capture timed out: timed out waiting on channel`; attempting
Reports navigation through the observed accessibility element failed with
`coordinate input geometry is unavailable`. A fresh state still showed Findings.
The successful saved-generation import is not a visible Reports acceptance.

Both original AI PNGs are completely transparent. The new evidence-only PNG
guard rejects them; see `original-capture-check.json` and
`../../WP023/astra-gui-20261022/pixel-guard-review.md` (33 fixture tests passed).
Hunt also has three material unsupported semantic claims documented separately
in `semantic-observations.md`; transport success does not establish accuracy.

## Next implementation lease

The user explicitly warned that local model runs take a long time. The existing
provider setting permits up to 3600 seconds, while hidden core/per-call and QA
caps still constrain this path. Root now owns integration of a focused explicit
long-local allowance fix. Astra/high agents own disjoint core, native/harness and
independent review work. Defaults, remote behavior, call/token/jury limits and
shared budget accounting must remain intact. A changed source requires a new
candidate before further live acceptance; original evidence is not rewritten.
