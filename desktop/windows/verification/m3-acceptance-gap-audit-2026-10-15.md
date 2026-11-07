# Native Windows C21–C26 gap audit, 15 October 2026

Scope: source review of desktop/windows, roadmap C21–C26, Windows native design
and recorded native evidence. A passing bounded smoke does not close a gate.

| Gate | Current evidence | Acceptance gap |
| --- | --- | --- |
| C21 parity | Native report open; repository picker; supervised local scan; finding filter/selection; real Juice Shop run imported 18 findings. Explicit Save/Clear and restore local paths added. | Typed advanced options and installed-module selection are now implemented; searchable supplied-record architecture/inventory lists are now implemented; diagrams, compare, suppression, export and optional-provider configuration remain absent. Native menus, clipboard, reveal, shortcuts and window restoration unverified/absent. Full shared ten-workflow proof absent. |
| C22 scan | Typed broker identity/revision checks, one active session, cancel channel and current artifact import; prior failed imports retain valid report. | Shared fault injection suite, redacted diagnostic reveal and complete cancellation race proof. Persistent run/report identity, client request/open time, supplied coverage limitations and previous-result labels now implemented; engine scan timestamps remain unavailable in legacy artifacts. |
| C23 evidence | Engine title/severity/score/confidence, source paths/lines, evidence and mitigation preserved. Missing legacy classification remains unknown. | Priority factors and controls not systematically joined; raw code flows are not full trust-chain presentation; conflicting/missing/partial golden corpus, reasoned reversible suppression, history coverage and exact-run export absent. |
| C24 accessibility | Native controls, selected automation names, polite status and selectable text exist. | No keyboard-only ten-workflow proof, Narrator recording, automated native accessibility audit, contrast/scaling/focus acceptance or measured scan/cancel target sizes. |
| C25 visual | Native theme defaults and constrained findings list exist. | Fixed split inspector/horizontal command area still need responsive layout. Nine-view themes/sizes/scaling captures and exceptional-state review absent. |
| C26 performance | Separate synthetic 10,000-row smoke and real report smoke pass. | Synthetic DTO lacks 50,000 observations/20 MiB fixture; no required launch/load/filter/detail samples, memory/cycle data or qualifying reference-host evidence. |

## Small patch selected

C21 explicitly requires settings persistence. The preview lost Python and
repository paths between launches. Added an explicit Save/Clear local settings
flow backed by version 1 JSON, bounded to 16 KiB, validated absolute paths and
atomic same-directory replacement. Invalid/unsupported files are preserved and
produce actionable UI text. Store contains only Python and repository paths; no
provider, credential, AI or CVE option exists. Restoration sets local controls
without launching analysis or network work. Smoke modes bypass personal settings.

Focused store/report checks and two-process native save/restore smoke are recorded
in native-settings-2026-10-15.json. This establishes this narrow persistence slice,
not keyboard, Narrator or full settings/provider acceptance.

Next focused native patch: persistently show selected repository, exact run ID,
timestamp, coverage limitations and previous-result state during rescans (C22),
using broker/report metadata without changing engine scoring or policies.

## C22 incremental follow-up

RunPresentation now keeps selected/active/displayed identities separate. It retains
previous valid results through rescan/cancel/failure and replaces them only on
parsed ready report promotion. Active broker request identity is carried into the
view; imported identity and engine timestamps stay explicitly unavailable. Coverage
uses canonical supplied limitations/errors with aggregate-count uncertainty.
Focused checks and native smokes remain bounded implementation evidence. Next:
shared broker fault cases and diagnostic reveal, then real keyboard/Narrator and
responsive-layout verification before claiming gate completion.

## C21 advanced scan configuration follow-up

Advanced controls now forward the core typed recall, strict_analyzers, no_suppress,
cve, secrets_history and timeout_seconds options, with validated installed-module
selection. CVE/network defaults off; selecting or restoring CVE opt-in displays an
OSV/dependency-data disclosure next to the main controls. No analyzer installation
or AI provider capability is added. Settings remain version 1 with additive
optional fields; old path-only settings load defaults without rewriting.

41 focused checks, native two-process restore/disclosure and a real Juice Shop
advanced scan passed. The live scan selected javascript-web/config, strict errors,
suppression bypass and timeout 120 while leaving CVE/AI off: 18 findings, 859
reported aggregate files, zero analyzer errors. Request and prepared engine options,
current pointer and all 19 artifact hashes/sizes verified. Live OSV behavior,
manual keyboard/Narrator and full C21 parity are not established. Evidence:
native-advanced-options-2026-10-15.json.

## C21 architecture/inventory follow-up

Architecture and Inventory now have native searchable supplied-record lists and
selectable evidence details. No graph nodes/edges or ownership are generated by
the UI. Supplied evidence classifications, relationship uncertainty, source paths,
roles/kinds, origins and conflicts remain explicit. Missing arrays/locations and
malformed rows have unavailable/unknown/partial labels. Dependency version and
ecosystem metadata are preserved, including unknown missing values. Secret-hint
evidence is outside this slice. Report identity/coverage remains shared.

50 focused checks passed, including versioned golden fixtures for Unicode, long
paths, missing structure, candidate edges, conflicts and partial malformed rows.
Native real-report exploration passed: 1547 architecture records, 472 inventory
records, 176 filtered dependencies. Golden native exploration passed 7 architecture
records and 4 inventory records. Release publish and finding detail regression
passed. Smoke event waits synchronize dispatch; they are not timing evidence.
Evidence: native-structure-2026-10-15.json. Diagram exploration, responsive layout,
keyboard/Narrator and complete C21 acceptance remain open.

## C21 selected-run export follow-up

Native save-picker actions now copy exact selected JSON and same-manifest review
Markdown. Captured read-time hash/run identity stays bound across new active runs.
Changed source/manifest/review fails before atomic destination replacement. Legacy
imports remain explicitly unverified and JSON-only. 60 focused checks and native
programmatic export smoke passed; dialog/keyboard/Narrator proof is still open.
Evidence: native-export-2026-10-15.json.
