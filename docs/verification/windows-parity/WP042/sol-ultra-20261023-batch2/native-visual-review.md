# WP042 native visual review — 2026-10-23 batch 2

Independent image review by the native-profile agent, using `view_image` on
actual full-application captures. No source edits were made for this review.
This is a scoped appearance review, not manual usability, keyboard, Narrator,
accessibility, clean-host, macOS or release acceptance.

**Final scoped result:** the usable preview5 profile/theming/collision images
and the separately captured final4 populated report ledger passed this image
review. No overlap or unreadable text was found in their visible content.
These are explicitly combined observations from two runs, not a claim that
one final candidate passed every functional and visual gate. Final4's blank
images and the failed full-scan final5 capture remain failed evidence below.

## First frozen-build run retained

Capture directory:
`.tmp/wp042-sol-ultra-20261023-batch2/native-final-run/`.

| Image | Actual PNG pixels | Observed state |
| --- | --- | --- |
| `1024x700-Light-Analyzers.png` | 1008 × 661 | Node/ATProto profile, Light, small window |
| `1024x700-Dark-Analyzers.png` | 1008 × 661 | Same profile, Dark, small window |
| `1600x1000-Light-Analyzers.png` | 1584 × 961 | Profile plus first installed row and origin, Light |
| `1600x1000-Dark-Analyzers.png` | 1584 × 961 | Same content, Dark |
| `1600x1000-Dark-Ledger.png` | 1584 × 961 | Expanded selected-report ledger, Dark |

File names describe the requested outer-window sizes. The measured PNG sizes
above describe the captured client content; they are not identical dimensions.

The profile selector, qualified `node-atproto@1.0` identity and all six expanded
module names are readable in both themes and sizes. Experimental and opt-in
layers are visibly named. The text explicitly says selection does not establish
applicability or execution and that no automatic installation/download occurs.
Long profile text wraps at the small size without overlapping neighboring
controls. Installed rows lie below that small capture's current viewport;
those images alone do not prove their small-window appearance after scrolling.

Both large profile captures show the checked `atproto` row, Experimental/Opt-in
status, plugin origin and package/analyzer versions. The implementation class
is visible; its long source digest continues below the scroll viewport. This
is a scrolling boundary, not evidence that the complete digest was visually
reviewed. No overlap or unreadable foreground/background combination was seen
in the displayed content.

The large Dark ledger capture visibly labels `C:\tmp\juice-shop` and the
selected generation, `node-atproto@1.0`, supplied-candidate scope, resolution
and terminal-outcome status. It records four succeeded, zero failed and two
skipped, with an explicit statement that completion can include failures/skips
and does not prove full coverage. Visible JavaScript, Node-service and config
rows distinguish recorded builtin/plugin implementations, applicability,
execution and analysis-start state. The ledger is a separate Expander from
installed inventory and explicitly states their independence. Remaining rows
extend below its captured viewport and are not visually attested here.

The first run's `analyzer-smoke.json` reports `result:null` and
`InvalidOperationException: Sequence contains more than one element` in the
QA-only collision-capture selector (`MainWindow.AnalyzerSmoke.cs:84`). Root
later identified the remaining unqualified `TextBox.Single()` call as including
internal templated controls and changed the QA selector to target the filter's
specific `PlaceholderText`. Five images were retained; the intended
sixth Dark collision image was not produced. This failed harness result is
not counted as a completed smoke pass. Root owns its corrected capture rerun.

The five images do not visually prove shadowed PHP provenance, small-window
expanded-ledger state or a Light expanded-ledger state. No implementation
layout defect was identified in their visible content; the unresolved first
attempt defect is the QA selector and its missing sixth capture.

## Second capture attempt retained

Directory `.tmp/wp042-sol-ultra-20261023-batch2/native-final-run2/` again contains
the four profile images and the large Dark ledger image. All five were opened
independently with `view_image`; their layout/readability observations match
the first run. The ledger correctly displays a different selected generation
(`bc3010217d5a4873bc422137422dab2f`) while retaining the four-succeeded,
two-skipped result and the scope limitations.

This attempt's `analyzer-smoke.json` again reports `result:null` and the same
`Single()` exception at QA line 84. There is still no Dark collision image.
Root was notified promptly. No six-capture smoke pass or visually verified
PHP collision state is claimed from either attempt. Root identified the
remaining QA `TextBox.Single()` ambiguity and is preparing a `native-final4`
capture with an exact filter selector. A further corrected capture must be
reviewed separately; both failed attempts remain retained. The intermediate
`native-final3` publish is not claimed as a tested run.

## Fourth attempt: functional pass, capture failure

All six files in
`.tmp/wp042-sol-ultra-20261023-batch2/native-final-run4/` were opened with
`view_image`. Its `analyzer-smoke.json` reports `passed:true`, settings
round-trip, stale selection blocking and a completed scan, with zero live
provider calls. Recorded report generation: `1dbfff3d6468484d8a2835a08f205d41`;
report SHA-256:
`0978c70561fba5d57286e7fe4316f980a4d3540e1e45c13a595571e9be19b2a4`.
Those automated results do not establish screenshot quality.

Only `1600x1000-Dark-Ledger.png` contains visible app content. It is readable,
shows this generation, four succeeded/two skipped and the same independent
recorded implementation/status boundaries described above. The four profile
images and `1600x1000-Dark-Collision.png` are visually blank. Independent PNG
IHDR/IDAT and zlib inspection proves every pixel in those five images is
exactly RGBA `(0,0,0,0)`: fully transparent, displayed as black by the viewer.
There are 666,288 such pixels per small image and 1,522,224 per large image.
All five use PNG filter 0 with zero scanline payload. The Dark ledger image
has nonzero pixel payload. Details: `native-final4-pixel-review.json`.

The identical small-image hashes and identical large blank-image hashes agree
with the direct pixel result. These five files are retained failed visual
evidence; they cannot establish final profile/theming/collision appearance.
This is a capture anomaly, not proof of an opaque black product window. Root
was notified before copying or accepting the images. In-process bitmap capture
does not independently establish the live displayed window's composition.

## Fifth attempt: empty-image guard rejects capture

Directory `.tmp/wp042-sol-ultra-20261023-batch2/native-final-run5/` contains no
PNGs. Its `analyzer-smoke.json` has `result:null` and
`InvalidDataException: Capture contains no visible RGB content` at
`NativeCaptureProbe.cs:52`, through `CaptureAnalyzerReview` line 115 and the
first main capture at QA line 78. Root was notified promptly. The new guard
correctly prevents writing/accepting blank images, but this attempt does not
record a final smoke pass or provide a final visual capture set.

Provisional conclusion before the subsequent preview: final4 records a functional smoke pass; retained
first/second-attempt images support scoped appearance observations for the
profile picker in Light/Dark at two sizes and the large Dark ledger. The
final4 readable ledger provides a source-bound selected-report image. PHP
shadowed/collision appearance is still visually unverified. No product UI
defect is inferred solely from the in-process capture anomaly. A further
usable collision capture is required before claiming that visual check.
Manual UX/accessibility acceptance remains open regardless of an automated
smoke or image-review result.

## Final usable preview and combined scoped evidence

All six PNGs in
`.tmp/wp042-sol-ultra-20261023-batch2/native-final-preview5/` were independently
opened with `view_image`. All contain visible content, and all six have
distinct SHA-256 hashes. Its smoke result is `passed:true`,
`scanCompleted:false`, `liveProviderCalls:0`, `acceptedManualUi:false`, with an
empty capture-retry list. This preview used actual new-engine capability and
profile discovery; no completed scan is attributed to it.

The four profile screenshots show readable labels, the qualified revision,
six-member expansion and explicit experimental/opt-in names in Light/Dark at
both requested sizes. The small layout wraps the long summary without
overlap; the first installed checkbox/status is visible near the viewport's
bottom, with remaining inventory requiring scrolling. The large screenshots
show the selected ATProto plugin's origin and package/analyzer versions.
No unreadable theme contrast or horizontally lost profile text was observed.

The final collision image has the filter text `php-laminas` and **one displayed
inventory record**. It visibly distinguishes:

- Effective `Built-in · attackmap version unknown · analyzer 0.1.0`.
- `Implementation: attackmap.ecosystem_php.PhpLaminasAnalyzer`.
- `Shadowed implementations (not selected): Plugin · attackmap-analyzer-php-laminas 0.1.0 · analyzer 0.1.0`.

The unknown package version is shown as unknown. The three lines are readable
without overlap. This proves visible implementation precedence information
in the preview, not repository applicability or PHP execution. No claim is
made that every selected installed row stays visible through a filter;
selected **missing** rows have a separate retention rule.

The preview's expanded ledger correctly says `No selected report` and that
execution is unknown until a compatible selected-report ledger exists. It
does not reuse or invent the previous scan's outcomes. This empty state is
retained separately from the populated ledger used for scoped review.

The six images selected for the final combined evidence are:

| Image | Source run | Scope |
| --- | --- | --- |
| `1024x700-Light-Analyzers.png` | `native-final-preview5` | Small Light profile/inventory |
| `1024x700-Dark-Analyzers.png` | `native-final-preview5` | Small Dark profile/inventory |
| `1600x1000-Light-Analyzers.png` | `native-final-preview5` | Large Light profile/inventory |
| `1600x1000-Dark-Analyzers.png` | `native-final-preview5` | Large Dark profile/inventory |
| `1600x1000-Dark-Collision.png` | `native-final-preview5` | Filtered effective/shadowed PHP implementations |
| `1600x1000-Dark-Ledger.png` | `native-final-run4` | Actual completed-scan selected-report ledger |

Root copies those exact images into the retained evidence captures directory
with a per-image origin manifest. The preview's empty-ledger image is additional
unknown-state evidence, not a replacement for the actual-run ledger.
`native-visual-reviewed-images.json` independently records original paths,
actual PNG dimensions and hashes for all seven usable reviewed images.

## Independent source-input comparison

The `inputs_after.release_inputs` key union from
`native-final4/build-proof.json` and `native-final5/build-proof.json` contains
223 paths. Independent comparison found exactly two differing source hashes:
`MainWindow.AnalyzerSmoke.cs` and `NativeCaptureProbe.cs`, the QA/capture helpers.
All other recorded inputs match, including the product profile model/view,
request/settings/report adapters and protocol inputs. In particular:

- `AnalyzerSelectionModel.cs`: `71d3e21ae27b7d5f0ff9a0e9aa2e817deb2763008e9d30c1eb44136ce6c85c04` in both.
- `AnalyzerSelectionView.cs`: `1713978c250d1544af60dce0395d5a76aca7dcaec63d9959579910089622d6b6` in both.

`native-visual-source-comparison.json` records both proof-file hashes and the
two differences. This establishes equality of the recorded product source
inputs, not whole published DLL identity: the native builds differ because
their QA helpers differ. No product-source appearance defect was identified
from the usable images. Full manual workflow, keyboard/Narrator, unpictured
small expanded-ledger states, OS composition/scaling and release acceptance
remain open.
