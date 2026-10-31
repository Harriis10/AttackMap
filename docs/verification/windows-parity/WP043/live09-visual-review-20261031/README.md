# WP043: live-09 bounded visual checkpoint

Follow-up: [live-10 automatic Fit and Findings wrapping](../live10-fit-wrapping-20261031/README.md)
records the fresh candidate, source/output hashes and 75 reviewed captures.
The observations below remain the unchanged live-09 checkpoint.

Date: 2026-10-31. WP043 remains **IN_PROGRESS**, global rendering remains
**FAILED**, and V01–V03 are not closed. This diagnostic checkpoint grants no
package or release acceptance.

## Candidate and runs

The [self-contained diagnostic build](../../../../../artifacts/wp043-context-diagnostics-20261031/manifest-task-precompiled/README.md)
uses a precompiled unchanged SDK manifest task via `UsingTask Override="true"`:
exit 0, 0 warnings/errors. Ordinary SDK inline task hosting still stalls in
`RoslynCodeTaskFactory`. The candidate is source-bound diagnostic output,
not a release-qualified build.

| Run | Captures / discarded | Complete rounds / diagram activations | Result |
| --- | --- | --- | --- |
| [live-08](../../../../../artifacts/wp043-context-diagnostics-20261031/live-08/evidence.json) | 10 / 0 | 0 / 0 | Missing engine; diagram activation failed, timeout retained |
| [live-09](../../../../../artifacts/wp043-context-diagnostics-20261031/live-09/evidence.json) | 75 / 0 | 5 / 5 | Clean close, no recorded error |

Live-09 runId: `293803d9a5a541369d81f042a986caad`, PID 24972. It explicitly
uses retained `ordinary-candidate-10/engine/attackmap.exe`, SHA-256
`792184c584895bab68e4260447fe89543486ae228bd8ad85234ae3ca87ce8bba`.
This is not fresh common-source frozen-engine qualification. The report hash is
`860343835432b3267da81f4b4124925eeae94ea570ed972cb3c4b040875d581d`.

## Visual review and limits

All **75** captured images were actually visually reviewed in this session:
agents reviewed rounds 1–2 and 3–4, and root reviewed round 5. No disappearing
text or popup was observed; Overview and finding detail were readable. This
session review is separate from the raw harness JSON, whose `manual_review:
not-run` and `rendering_acceptance: not-established` values remain unchanged.

The observation covers one saved report, Dark theme and a 1600×1000 window.
The diagram is small/clipped, Findings text has truncation, and an unsupported
offline diagram fallback remains. Scroll behavior was not verified. Five
successful rounds do not prove the root cause or a general rendering repair.
Light, another size/report, keyboard/Narrator, representative fleet, ordinary
build recovery, clean-host and release gates remain open.

## Harness verification

The follow-up adds explicit `--engine` selection and timing/fail-fast behavior.
The coordinating agent reports **110 unittest PASS** and independent review.
This is session-output evidence from agent `diagram_activation_forensics`:
`python -m unittest tests.test_wp043_live_capture -q`, 43.748 seconds, `OK`,
executed in an elevated session. No persisted successful log artifact is claimed.
The later persisted pytest verification completed exit 0: **110 tests + 156
subtests PASS**, 29.75 seconds, using `.venv\Scripts\python.exe -m pytest
tests\test_wp043_live_capture.py -q --junitxml=docs\verification\windows-parity\WP043\popup-tooltip-recovery-20261031\harness-engine-activation.xml`.
The [fresh JUnit](../popup-tooltip-recovery-20261031/harness-engine-activation.xml)
records this separate pass; it does not rewrite the earlier failed log.
These deterministic checks do not substitute for the separate image review.
Earlier failed harness attempts are retained and are not final pass evidence.

See the [preceding recovery/build checkpoint](../popup-tooltip-recovery-20261031/README.md)
for exact UIA recovery scope, invalid overlays and the live-07 foreground stop.
