# Independent provider-budget preview hook review — 2026-10-23

**CLEAR for root-controlled application, actual WinUI compilation and preview. No blocking source defect found.** This is static source review only, not compiled or visual acceptance.

| Input | Reviewed SHA-256 |
| --- | --- |
| provider-budget-preview.patch | d2e9bd6982df8dceaaac163b05118651d4ff6436253f4dd2bbb49929c308d508 |
| active MainWindow.ProviderScrollSmoke.cs | a9c5a7c8a5cef91f7d8fbfc30a651a046c3843265d27e51813a0ab82f0d7d1f9 |
| NativeCaptureProbe.cs | 7247f9b91264379b4fcc37a8b3a385f37a8fe96109b528e10a27822a9f3ced62 |

Used CodeGraph before reading current handler and NativeCaptureProbe. Reviewed the exact one-file patch, output-pin record, and existing startup routing. Active handler hash still matches its before/proposed-owner freeze. Read-only `git apply --check` passed; patch was not applied by this reviewer.

## Findings

- The optional exact `--provider-scroll-capture` flag rejects duplicates, equals-form and missing/nonabsolute arguments. It requires a fresh PNG in the same existing caller-owned QA directory as the fresh JSON proof. The current proof-directory ancestor reparse guard remains in force. NativeCaptureProbe additionally rejects UNC output, rechecks directory redirection, and publishes via a fresh temporary file and non-overwriting move; the new branch uses those existing protections.
- Existing bottom-scroll button checks run first. Their measured before/after bounds and original bottom offset are preserved. Only the explicit capture branch then changes the scroll position to the actual budget control; its different capture offset is recorded separately. A screenshot is not misleadingly described as the bottom-button state.
- The control is the actual Provider TextBox selected by its current total-time-allowance header, with its realized header TextBlock. The branch brings it into view, waits for dispatch/layout, checks nonempty fully clipped header/field bounds, then invokes NativeCaptureProbe on the original loaded root. The PNG and returned metadata come from WinUI RenderTargetBitmap, including actual theme, root bounds, scale, output path and SHA-256. No synthetic screenshot or duplicate product controls are introduced.
- The patch does not force theme, enable AI, edit field values, save settings, invoke provider buttons or start network/model work. Existing startup routing takes provider-scroll smoke before normal personal settings/provider restore. Actual label, current field value, element bounds and capture offset remain in the proof. In a fresh session the expected provider default is600; the preview need not select7200 to demonstrate the new disclosure.
- Failures leave completed=false with the existing error handling. Acceptance remains false; the NativeCaptureProbe scope accurately limits in-process captures and requires independent live-window confirmation before treating renderer anomalies as UI defects.

No new test was run: this patch depends on realized WinUI layout rather than a separable parser contract, and a mirrored source/assertion test would not establish it. Root must compile the actual WinUI application, run the explicit QA path with fresh isolated output, validate actual image bytes/dimensions/visibility and inspect the displayed label and field in the preview. Runtime proof should confirm original button-state offset versus captured budget-state offset and inherited theme. Existing visual/manual/accessibility/release findings remain separate.

No active source changes, imports, tests, build, GUI, provider, engine scan or model execution occurred during this review. Only this new review artifact was authored. A source-bound freeze/package must include the applied hook before its preview is attributed to that candidate.
