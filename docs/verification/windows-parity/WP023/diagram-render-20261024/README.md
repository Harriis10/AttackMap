# Diagrams long-line rendering investigation — 2026-10-24

Status: **SCOPED USER CHECK PASS for the zero-capture build.** The user confirmed
that text remains visible and, after further use, that this version works correctly.
The earlier final-capture window failed; its briefly positive observation remains
retracted. These are different runs. The runtime root cause and general release
qualification remain unproven.

The user reproduced the defect in the delivered Z.AI preview, then narrowed the
trigger to opening Diagrams after a completed scan and navigating away. The new
screenshots show progressive loss of navigation, headings and button text while
some artifact text remains visible. This supersedes the earlier attribution to
only the original Fleet build. The actual running executable was the delivered
`artifacts/AttackMap-Windows-zai-20261024-final/AttackMap.NativeSpike.exe`.

The selected real run is `f6ba35b3f2ac47d397d82d3a81849dfc`. Its `architecture.md`
is 19,201 bytes and contains a line of 18,152 characters listing external targets.
`DiagramView` put the complete source into a read-only, unwrapped WinUI TextBox.
In the A/B native control, its horizontal extent reached 62,461 logical pixels
inside a 1,582-pixel viewport (777 at the smaller size). No source is interpreted
as HTML or executed. This is a text-layout problem, not evidence of provider or
report corruption.

The focused production patch enables `TextWrapping.Wrap`, disables horizontal
text scrolling and exposes vertical scrolling. The full accepted source and
copy/export actions are unchanged. The bounded variant measures 1,582/1,582 and
777/777 for extent/viewport, with identical complete text after navigation.
This follows the supported multiline TextBox configuration in
[Microsoft's documentation](https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.UI.Xaml.Controls.TextBox).

## Evidence and limits

Artifacts are under `artifacts/diagram-render-20261024/`.

- `native-wrap`: initial candidate; first QA failed because the generic visual-tree
  query matched the ComboBox's internal TextBox too. No production startup failure.
- `native-wrap2`, `nowrap-control2`, `wrapped`: same executable with a QA-only
  switch restoring the old layout. Exact selected real report, 15 transitions
  through Fleet / Inventory / Findings / Reports / Diagrams, text unchanged.
- Both all-capture runs contain rejected blank images and partial text in some
  images. The wrapped Diagrams end image correctly displays the end of the source;
  the old layout shows malformed/repeated long-line content. The wrapping change
  fixes the excessive extent but these captures do not establish that all missing
  text is repaired. In particular `wrapped/round1-Findings.png` is not accepted as
  a complete visual pass.
- `native-final` / `final-capture`: final diagnostic variant suppresses all
  intermediate bitmap captures. Actual layout/text assertions and one final
  small-window image are retained. Optional keep-open mode leaves the explicit
  test window available for direct user inspection with isolated settings.
- Production navigation, provider integration and the engine are unchanged.
  These runs load the existing completed report and make zero AI calls.
- The focused `Diagram.Tests` runner passed all 20 checks. The native build passed.

Windows Computer Use enumerated the actual user window and read its accessibility
tree, which still contained menu labels and the full text. Image capture failed
with `FrameArrived timed out: timed out waiting on channel`, then
`window capture timed out: timed out waiting on channel` after target refresh.
An accessibility-index click also failed with `coordinate input geometry is unavailable`.
No successful automated interaction with the user's original window is claimed.
The retained native RenderTargetBitmap images exclude OS compositor acceptance.

The new package is a candidate for the concrete long-line defect, not a claim of
full rendering, accessibility or release acceptance. Prior delivered builds and
the earlier rejected navigation experiment remain preserved.

## Earlier failed candidate

`artifacts/AttackMap-Windows-diagrams-20261024-preview.zip` (127,555,331 bytes)
has SHA-256 `19db068c5cbb413bf661100d1ac014e902299fb2340b5e1b5d847d5333fa6789`.
ZIP CRC and copied-file hashes passed. `package-startup/settings.json.result.json`
confirms the packaged executable selects its bundled engine, starts no scan and
does not enable AI/CVE or read personal settings in the isolated startup test.
The prior frozen Z.AI engine is unchanged; no new live AI acceptance is inferred.

The final diagnostic run passed 15 transitions, complete-text retention and both
width assertions, with the actual longest line measured as 18,152 characters.
Its only bitmap was blank and rejected. Earlier A/B logs used a newline counter
that missed TextBox-normalized carriage returns; their 19,474 `longestLine` field
is the whole alternative length, not the real line length. The final diagnostic
corrects that counter; input source itself was never changed.

Window `AttackMap — Diagrams render fix (test)` remains open intentionally for
the user's requested direct check (PID 28496 at handoff), using isolated settings.
Computer Use confirmed that titled window and activated it, but capture again
timed out. The user initially reported visible text, then immediately corrected
this: "ne,uz zase mizi!". Therefore the archive is a failed diagnostic candidate,
not a delivered fix. Other owned QA processes exited.

## User-checked run without captures

The next executable is `artifacts/diagram-render-20261024/native-no-capture/AttackMap.NativeSpike.exe`.
The window title is `AttackMap — bez snímání (test)`, PID 2348 when reviewed.
The `zero-capture` run loaded the same completed report, retained all 19,474
characters, and passed 15 transitions with no provider calls and **zero** calls
to native bitmap capture. Its main viewport measured 1,582/1,582. The helper
skips its settling delay in this mode, so the recorded small-window 1,582/1,582
values are stale and are not accepted as small-window evidence. The earlier
wrapped run independently measured 777/777.

The user first answered `Zatím zůstává viditelný`, then after further use wrote
`vzpada to ze v te verzi cos mi ukazoval to funguje spravne`. This is direct user
visual evidence for this session, not an assistant-captured OS screenshot.
The earlier failed candidate is not retrospectively accepted. The unchanged
production patch wraps the complete diagram source and disables horizontal
scrolling. The no-capture switch changes diagnostic behavior only. Normal startup
already selects no bitmap-capture handler; all such handlers require explicit
diagnostic command-line switches. Consequently capture involvement is a
hypothesis, not an established cause of the original normal-startup defect.

`zero-capture/user-review.json` retains the observations and limits. Packaging
uses these exact native binaries without recompilation, together with the same
previously tested frozen Z.AI engine. The current user-checked window is left open.

## Portable build from the user-checked binaries

`artifacts/AttackMap-Windows-diagrams-20261024-user-checked.zip` contains 531
copied native files and 308 engine files, verified byte-for-byte by SHA-256.
Archive size: 127,568,470 bytes. SHA-256:
`e5e3cceabae9807975b5f3ac366a4524987fe7e58bc5f9f721b89f5fe41fefda`.
ZIP CRC passed. `user-checked-startup/settings.json.result.json` confirms the
packaged executable selects the bundled engine without starting a scan or
reading personal settings. This isolated startup assertion does not replace
the user's visual review of the identical native payload. No new AI calls were
made. Packaging script: `artifacts/diagram-render-20261024/package_user_checked.py`;
result: `user-checked-package-proof.json`. Launch with `Spustit-AttackMap.bat`.

No production source changed after the user's successful test. The zero-capture
window remains open intentionally; the earlier failed test process had already
exited. Earlier packages are preserved. Current build is an unsigned development
preview with scoped user verification, not a broad Windows or macOS release gate.
