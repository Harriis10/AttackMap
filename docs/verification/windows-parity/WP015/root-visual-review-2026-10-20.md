# WP015 root review — 2026-10-20

Status: **IN_PROGRESS**, visual gate **not accepted**.

Fresh managed checks: 49 PASS, zero dispatches. Capture-source build:
0 warnings/errors, 4:37.85. Subsequent preview-only bounds-clip build:
0 warnings/errors, 7:45.16. Product settings/models were unchanged in this
resume slice; preview instrumentation and containment changed.

Root launched the actual WinUI preview twice with synthetic capabilities,
bounded execution, process-local Windows error-dialog suppression, explicit
trace paths, capture directories and automatic close. Both exited 0 without
timeout. Both `images/result.json` files assert supported request validation,
unsupported request rejection, exact retained preferences and inert reset;
no Save/Test handler, provider call or engine process was dispatched.

- Initial evidence: `root-visual-resume-20261020/`.
- After bounds clip: `root-visual-resume-20261020-fixed/`.

All seven PNGs in each directory were actually viewed: clean AI-off,
supported pages 0–2, and unsupported-retained pages 0–2. Labels, values,
disabled state, cost/output-cap explanations and bottom actions are readable.
However scrolled text overlaps the fixed preview status/header in the
RenderTargetBitmap captures. Explicit clipping to the ProviderSettingsView
bounds did not remove this from the second capture. Preserve both sets as
failed visual evidence. A compositor/capture-specific effect is possible,
but it has not been established; do not claim that native layout is fixed.

Keyboard/Narrator, dark theme, another size/200% text, shell binding,
protected-store actions and real LM Studio responses remain unaccepted.
Fixture capability metadata and successful build/runtime assertions do not
replace those gates.

The user then explicitly requested an interactive window. Root opened a
separate normal preview with fixture and trace arguments, without capture,
smoke, or auto-close flags. `user-visible-process.json` records PID 30868,
start UTC `2026-10-20T21:50:58.3927067Z`; `user-visible-startup.log` confirms
`Window Activate returned` at 21:51:28Z. The process was intentionally left
open for the user. Save/Test are intercepted by this preview; no network or
credential persistence is wired. Do not rebuild its output directory or
terminate this user-visible window automatically during cleanup.
