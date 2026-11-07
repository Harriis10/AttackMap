# Native C24 scoped audit and manual checklist

Status: NOT RUN for manual keyboard/Narrator. Source guard checks passed; runtime
compile/audit belongs to root's loaded integration. No full C24 proof or contrast
claim is established by this helper. Use a supported Windows 11 host and record
OS/app/engine builds, display/text scale, theme/high contrast, tester and artifacts.

Root integration: set AutomationId=scan/cancel and MinHeight=32 on primary
buttons. Retain the IDisposable from NativeAccessibility.Bind(root,commands) and
dispose it on window close. Command delegates must validate availability/state.
The helper independently ignores F5/Escape when the named primary control is
missing/disabled, leaving ordinary handling available. Call ApplyNames before
Audit after Loaded; repeat per selected destination once visible.

Audit scope: visible loaded interactive controls, exposed peer names/roles,
enabled/focusability and scan/cancel size. Collapsed descendants and template
non-tab-stop parts are excluded. Disabled controls are not expected to accept
focus. Custom roles produce review notes, not automatic failures. Popup/dialog
trees, virtualized item row semantics, focus order, keyboard tasks, Narrator,
contrast, text scaling and motion remain manual checks. Names derive only from
existing Header/Content text, never from an invented control description or
credential/input value. Audit does not change theme or claim contrast ratios.

| Workflow | Keyboard-only procedure | Required evidence | Status |
| --- | --- | --- | --- |
| Open repository | Ctrl+Shift+O; navigate folder picker; confirm and return | Correct repository, visible returned focus, no automatic scan | NOT RUN |
| Default scan | F5; navigate while running; Escape to cancel; retry F5 after confirmed cleanup | Stage/state announcement, disabled start during cleanup, no stale result promotion | NOT RUN |
| Advanced options | Tab to Advanced; expand; change numeric/module controls and return | Bounds actionable; defaults local; no hidden network opt-in | NOT RUN |
| Browse/filter findings | Tab to search; type/clear; arrows through list | Exact selection/detail, visible focus and readable row names | NOT RUN |
| Inspect evidence | Tab into inspector; select/copy text; traverse source/provenance | Basis/uncertainty/conflicts/source locations readable without pointer | NOT RUN |
| Architecture/inventory | Keyboard navigation to each destination; filter/select records | Candidate/unknown relationships and dependency versions preserved | NOT RUN |
| Compare runs | Ctrl+H; choose baseline/current using keyboard | Correct identities; changed coverage distinguished from resolution | NOT RUN |
| Reasoned suppression | Keyboard finding action; enter reason; save; reverse | Dialog focus contained/restored, reason required, reversal shown; Escape closes dialog without unintended scan action | NOT RUN |
| Export selected run | Ctrl+E; native save dialog; choose destination; export review button separately | Selected run hash/labels unchanged, focus returns, legacy restriction actionable | NOT RUN |
| Optional provider access | Ctrl+Comma; navigate provider/endpoint/model/key/budget controls; restore saved settings | Restore zero requests; local LM Studio test only explicit action; credential never spoken/logged as value | NOT RUN |

Repeat every row with Narrator from Windows accessibility settings. Capture names,
roles, selected/expanded/enabled state, reading order, dialog focus and scan/live
status announcements. Verify dynamic findings/structure rows and all dialogs
separately; a zero-issue visible-root audit does not cover them.

Repeat keyboard flows at 200% text size and 100/150/200% display scaling, both
themes and high contrast. Check that focus is visible/unobscured, labels reflow,
no traps or lost focus occur, and normal/large/non-text contrast meet C24 only
after actual measurement. Record defects or unsupported flows rather than
marking a whole gate passed from native defaults.
