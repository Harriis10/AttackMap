# Actual saved-PNG review — 2026-10-23

Reviewer `/root/sol_gui_plan` opened the twelve original PNGs listed below with
`view_image`. These are actual rendered full-product captures, not mocks or
fixture images. No GUI, provider, model, build or product-source operation was
performed by this reviewer. Only this review document was written. Root expressly
authorized review while the outer pixel validator was still running after native
process cleanup; the final validator result below supersedes that pending state.

## Identity and terminal result

Output: `sol-newcandidate-capture-01/capture/` beside this document.
Candidate: `dev-20261022220136-08e1c566`.
Package manifest SHA256: `e717a64e2bc46fc05326d082e708d488b830a5bd259ae424e392a095ee1bf536`.
Seed generation: `754712b4b86e4330bdc79df4f2ab83f8` under WP024's
`astra-long-local-20261022/runtime/reports/`.
Canonical report SHA256: `919619d6ffe6a8ccdf153f83d9b127ae06aa46c1b68351ee770565edbeb5b8c9`.
Runner `inputs-after.json` reports `passed=true` for preserved package/source/seed
identity. Native PID 16980 exited 0 after 24.228 seconds, `timed_out=false`,
`owned_job_assigned=true`, `owned_tree_cleanup_verified=true`.

The outer runner **failed**, retaining `failure.json` with the sole validator
error `Missing required views: ['Settings']`. `capture-validation.json` contains
56 measured PNGs, four per view including four named `Nastavení`, and no pixel,
theme, checksum or viewport errors. This is a label mismatch, not missing raw
settings captures: the two opened `Nastavení` PNGs visibly contain the Settings
heading and provider controls. The retained failed result is not rewritten here.

Small-Light images actually measure 1008×661 logical/pixel at scale 1; Large-Dark
images measure 1584×961 at scale 1. Requested outer sizes in filenames are
1024×700 and 1600×1000. The two real viewports are distinct.

## What was actually visible

| View | Small Light | Large Dark |
| --- | --- | --- |
| Reports | Export JSON/Markdown/PDF/HTML and Show folder labels are legible; AI disclosure says no review loaded, default off; raw and AI artifact expanders are collapsed. Lower content extends below viewport. | Export controls, honest AI-off/no-review state and deterministic Defensive Review/System Overview are legible. This is not a completed AI-mode display. Blue nav accent remains beside Inventory although Reports row is shaded and Reports content is shown. |
| FindingDetail | Selected first HIGH finding, uncertainty text, recommendation, Inspect live source locations and changed-source warning are legible. List titles are cut at the right edge; inspector is intentionally scrolled, so its heading is above the viewport. | Recommendation and uncertainty disclosures are legible, but lower inspector has two unlabeled button rectangles and an unlabeled expander bar. A broad pale solid rectangle replaces part of the third finding's secondary row. These incomplete pixels block a clean visual verdict. Nav accent appears at Settings while Findings content is shown. |
| Scan options | Engine-path placeholder, compatibility explanation, unchecked watch opt-in and Watch is off are legible. Save/Clear controls begin at the bottom edge. | Corresponding labels, watch-off state, Save/Clear and AI off/CVE off are legible. Engine input boundary is not discernible at this capture scale, although placeholder text is visible. Blue nav accent remains beside History while Scan options row/content is selected. |
| Inventory | 489 of 489, coverage disclosure, filter, route records and explicit unknown relationship/basis are legible. Empty selection pane explicitly asks to select a supplied record. | Same count and disclosures; more route rows fit, source locations remain legible. No selected-row detail workflow was exercised by viewing this PNG. |
| Diagrams | architecture.md is selected. Visible generation-bound disclosure says Unsupported graph header; no graph inferred; accepted source remains plain text. Zoom/pan labels and beginning of complete source are visible. | **Incomplete:** seven toolbar button rectangles have no labels, text/source area is a large blank panel, two lower controls are blank, and the generation/unsupported-header disclosure visible in Small Light is absent. Title and architecture.md dropdown remain visible. Global nonuniform pixels do not prove this page is rendered correctly. |
| Settings (filename Nastavení) | Actual Settings heading, AI/privacy disclosure and unchecked Enable AI review are legible. Disabled options are muted; content continues below the viewport. | Actual Settings heading, disabled mode/effort/speed, provider openai, loopback endpoint and configured model are legible. AI checkbox remains unchecked. Lower credential/save controls are below the viewport and were not inspected. |

The differing missing text/controls and navigation accent positions might involve
capture timing, rendering or actual presentation. Still images do not establish
which cause applies. They must not be silently dismissed as animation or accepted
as correct final displayed UI. Preserve these originals and obtain a settled,
identified-window observation or a separately reviewed capture change before
accepting the affected view. No product fault was independently reproduced here.

## Exact PNG pins actually viewed

All names below are relative to `sol-newcandidate-capture-01/capture/`.

| File | SHA256 |
| --- | --- |
| 1024x700-Light-Reports.png | `e783707adbbe12e9308f7f9aa194a00d69e208da6bb05d1fc4249b8d720b3abd` |
| 1600x1000-Dark-Reports.png | `b3f3fab14cec3f7cc04683d3b05317107a5d633d8598ae65cace25084cd46c18` |
| 1024x700-Light-FindingDetail.png | `c897aeb450b7ec45ba9bf7bcc98928e11760e9095ee49d1178a533aab1e9e32a` |
| 1600x1000-Dark-FindingDetail.png | `a0bee302b1659be56ae8cb4d7bd4a9180839eab52427580d211772e54e9b4f4a` |
| 1024x700-Light-Scan options.png | `aa86e6fb7ae395169362dc6427b811f4571cfd381391b5dccf7995acb12eef39` |
| 1600x1000-Dark-Scan options.png | `a74cfbc855ba003d4fd153159f6cfea1e0c51bb3f7311a6ff18e58a5895915ef` |
| 1024x700-Light-Inventory.png | `d0ba64d55511276688889608ab9436092d557a2e3af8fb6ef14811b3db19fb8b` |
| 1600x1000-Dark-Inventory.png | `2277e8a4f1d196459435c8b61ab609a56be21a9db1ab8e5929d626912506e565` |
| 1024x700-Light-Diagrams.png | `af0bf21182bd159212bc182867b311baef6ecbb1da447327dce6b4f60b79ce97` |
| 1600x1000-Dark-Diagrams.png | `d15dc0ca5c186d8e3d6fded2ffbf36df534452599cb72560a025b25caebe3995` |
| 1024x700-Light-Nastavení.png | `d1463e7cba883f1e0b23358a5c95ef4213c3c17cbf5904eb65d65d5e8ca1be9d` |
| 1600x1000-Dark-Nastavení.png | `924aee2ae566309696368a4ebf01455297490754122e85ad9b16f14a9a921dbe` |

## Evidence-only alias repair proposal, not applied

Normalize exactly filename-derived `Nastavení` to canonical `Settings` for group
and required-view comparisons; retain the original view label separately in
measurements. Do not remove required Settings coverage or accept arbitrary names.
Maintain four safe captures, both actual size/theme pairs, duplicate detection,
checksums and PNG decoding rules. Test a full localized pair set succeeds while
missing pairs and mixed English/localized duplicates still fail. Root owns review
and any edit. A label-only validator correction cannot resolve the visual defects
above or upgrade old failure evidence in place.

## Verdict and limits

Actual agent image review performed: **yes**, twelve pinned originals. Completely
transparent capture problem: absent in these twelve images. Clean overall visual
acceptance: **no**, incomplete Large-Dark Diagrams/FindingDetail pixels and nav
accent discrepancies remain. Runner acceptance: **failed** on Settings alias.
No interaction, keyboard, focus traversal, Narrator, human participant, provider
response, selected AI artifact, export action or accessibility acceptance was
performed. WP017/WP023, K2/K4 and release acceptance remain open.
