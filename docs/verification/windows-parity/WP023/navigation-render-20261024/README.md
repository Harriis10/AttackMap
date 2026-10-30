# Post-scan navigation rendering investigation — 2026-10-24

Status: **OPEN — user-visible defect confirmed by the user's screenshots; root cause and repair not established.**

Latest follow-up: a bounded Diagrams text layout with zero diagnostic captures
passed the user's repeated live-window checks. See the [scoped result and exact
build](../diagram-render-20261024/README.md#user-checked-run-without-captures).
This older navigation experiment remains rejected; the runtime root cause is
still unproven.

Later on 2026-10-24 the user reproduced the defect in the delivered Z.AI preview
as well and isolated opening Diagrams / `architecture.md` as the trigger.
[The follow-up](../diagram-render-20261024/README.md) retains the exact report,
measures the oversized text layout and implements a bounded-text candidate.
The original-build attribution below is historical, not a statement that the
Z.AI preview is unaffected.

The reported journey is a completed scan, sequential navigation through the menu
including Fleet, followed by disappearing menu/content text. A later screenshot
also shows selection decoration that does not match the displayed content.

The user subsequently confirmed that the latest screenshot is from the **original
Fleet build**, not `AttackMap-Windows-zai-20261024-final-verified.zip`. The delivered
Fleet installation is `C:\Projects\AttackMap-Windows-x64-fleet16-20261023\AttackMap-Windows`,
package ID `dev-20261023121609-df55da0b`. Direct SHA-256 comparison with the Z.AI
preview found identical WinUI XAML, XAML Controls, DWriteCore, dcompi, WebView2 Core
and WebView2Loader binaries. The original captured `Navigate` method is also
identical to current production navigation. Application/graph assemblies differ;
this comparison does not establish identical overall behavior or a GUI fix in
the newer preview. Evidence: `build-runtime-comparison.json` and
`build-attribution.json` in the retained artifact directory.

The source inspection found no code that clears the navigation labels. The shell
keeps all destination controls in one Grid and switches Visibility. Fleet owns a
WebView2 graph surface, but the captured missing-text symptom starts before Fleet
is selected; this does not establish WebView2 as the cause.

## Executed checks

All output is retained under `artifacts/navigation-render-20261024/`.

| Run | Result | Scope |
| --- | --- | --- |
| `before` | Actual Juice Shop static scan completed; 39 navigation states; 13 PNGs and 6 rejected blank captures | Original navigation. Missing menu text is visible in inspected History/Risk/Findings captures. State still contains correct labels and active panel. |
| `single-capture` | 39 transitions with an existing real report; only the final capture attempted, and it was blank | Repeated captures are not required for the capture failure. This remains in-process capture evidence. |
| `detach` | 39 transitions; final Settings capture readable | Initial diagnostic experiment detaching hidden pages; one successful image was insufficient to accept a fix. |
| `after2` | Another actual Juice Shop static scan completed; 39 transitions; 19 nonblank PNGs; filter and edited timeout retained | Candidate kept only the active page attached. Several inspected PNGs still have missing navigation labels. **Visual gate failed**, despite successful structural assertions and no fully blank images. |
| `menu-proof.json` | PASS | Loaded command binding/routing test against candidate; no OS keyboard acceptance. |
| `fleet-regression3` | 94 checks PASS, 16 fixture repository children completed, 8 captures | Candidate Fleet graph/evidence/source/child/back workflow. Includes native vector layout and interactive layout acknowledgment. Does not prove WebView2 pixels or repair the menu defect. |
| `final-diagnostic-check` | Final diagnostic-only source compiled; 39 transitions; final Settings PNG readable with original production navigation | No new scan. This successful repeat also shows that the earlier isolated success cannot be attributed to page detachment. The defect/capture symptom is intermittent. |

No AI requests were made in these runs. The prior approved Z.AI response and
provider compatibility work remain separate evidence.

An intermediate candidate failed startup because Parent was unavailable before
Loaded; `native-after2` fixed that test implementation using a named host. The
first Fleet attempt also encountered sandbox denial for its action output under
LocalAppData; the subsequent authorized native run completed. These failures are
retained, not counted as passes.

## Visual review and decision

Manually inspected `before/round0-Overview.png`, `before/round0-History.png`,
`before/round0-Risk-and-paths.png`, all three `before/round1-*` images,
`detach/round2-Settings.png`, and `after2` Reports/History/Fleet/Inventory images.
In the candidate, Fleet content and many page bodies recovered, but the History
and Inventory images still omit parts of the navigation. Nonblank image checks
must never be treated as text-rendering acceptance.

The unsuccessful production navigation change was withdrawn. Only an explicit,
isolated `--navigation-render-smoke REPORT OUTPUT ENGINE` diagnostic entry point
remains in source. `ATTACKMAP_NAVIGATION_QA_MODE` selects `all-captures` (default,
actual static scan), `single-capture`, or the diagnostic-only `detach` experiment.
Normal application startup/navigation is unchanged by this investigation.

No new portable archive was produced. The prepared packaging script has an
explicit failing visual-acceptance gate. Previous delivered builds are preserved.
Owned test scans and preview processes were verified terminated; the execution
lease was released. The final source retains no experimental navigation change.

The Windows Computer Use helper exposed the candidate window, but direct capture
failed with `FrameArrived timed out: timed out waiting on channel`, then again
with `window capture timed out: timed out waiting on channel` after window
selection was refreshed. Accessibility capture returned no tree. In-process
RenderTargetBitmap images do not replace independent OS compositor verification.
No display-driver reset was found in the targeted recent event query. Installed
adapters: Quadro P3000 32.0.15.8267 and Intel HD 630 31.0.101.2130; neither was
changed or identified as the cause.

Next gate: reproduce the confirmed original Fleet build in a normally visible
window without intermediate bitmap capture, compare the newer Z.AI preview, and
observe resize/minimize/restore behavior. A fix must keep all menu labels visible
through repeated scan → pages → Fleet → back and preserve navigation/form state.
WP023/WP043, manual/accessibility, OS appearance and release acceptance stay open.
