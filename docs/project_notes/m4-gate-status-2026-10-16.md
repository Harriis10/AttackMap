# M4 gate status — 2026-10-16 night session (final)

**Baseline:** working tree at the end of the 2026-10-16 night session; final package `dev-20261016211158-6f0b8b18` (ZIP SHA256 0dc947fe…499a), installed and engine-verified. Integration regression: **3,407 passed / 6 skipped** (one release-tooling test made fixture-based after the live snapshot was superseded; 14/14 green after the fix).

Status legend: **passed** (criterion's stated proof exists), **partial** (real evidence, explicit gaps), **open** (no qualifying evidence). Dates are 2026-10-16 unless stated.

## Night deliverables (all independently re-verified by the root session)

| Item | Result | Evidence |
| --- | --- | --- |
| AM040 deployment aliases + three-service reference fixture | done | `DeploymentAliases` + `--service-alias`/`--service-dns-suffix`; 92 tests; real CLI fleet resolved `auth.bsky.social`→`auth-api` observed; installed engine re-verified |
| AM044 watch correctness (C31) | done (Win32) | ReadDirectoryChangesW + shared output exclusion + pending-dirty/follow-up + switch-stop + honest notices; 105 UI tests + node 12/0; live win32 probe |
| AM037 evaluation harness + seed corpus | infrastructure done, corpus far below target | `attackmap evaluate`; 28 cases / 10 repos honestly labeled; gap printed in every report; 66 tests + live runs (source and installed) |
| AM041 release readiness (unsigned) | tooling done | SBOM (785 files, deterministic), release lock, rollback procedure test exit 0; 14 tests |
| Final package `dev-20261016211158-6f0b8b18` | delivered + installed | engine-verification binds 107 core modules / 274 payload files / snapshot hashes; installed engine: version, evaluate, alias fleet, Juice Shop scan + diagnostics |

## Criterion matrix (C01–C32)

| Criterion | Status | Evidence / blocking gap |
| --- | --- | --- |
| C01 release baseline | partial | Fresh full runs: 3,336 (pre-integration) and 3,407 (post-integration) passed, 6 explained skips each; packaged smoke green. Remaining: recorded platform matrix refresh in CI. |
| C02 guard safety | passed (2026-10-15) | 194 paired guard cases green; no counterexample since. |
| C03 scoped evidence | passed (2026-10-15) | 100 focused tests; labels unified. |
| C04 fresh results | passed (2026-10-15) | 100-sequence frontend tests; watch race fixed and watch suite extended tonight. |
| C05 scan isolation | passed (2026-10-15) | root/nested/external ×3 runs stable; pins + diagnostics files recognized as generated. |
| C06 fleet formats | partial | Worker interchange fixed; tonight's installed-engine serial/parallel parity green (repo-a/repo-b, identical normalized results); packaged Unicode-path matrix open. |
| C07 honest AI | passed (2026-10-15) | Vote truth table, abstentions, disclosures; live LM Studio run honored "claim support not assessed". |
| C08 run protocol | partial | Contract schemas + adapter shipped; full consumer-compatibility matrix open. |
| C09 process supervision | partial | 77 focused tests; 50-cycle/p95 platform proof open. |
| C10 atomic results | partial | Fault-injection matrix green at unit level; interrupted-write OS matrix open. |
| C11 source provenance | partial | Signal merge provenance tests; broader conflict fixtures open. |
| C12 evidence ownership | partial | Source roles + candidate edges; ranking-factor exposure open. |
| C13 finding identity | partial | Identity scheme + migration exist; full rename/migration fixture matrix open. |
| C14 AI boundaries | partial | Budget ledger + citation validation shipped; claim-support remains "not_assessed" by design pending AM016 completion. |
| C15 architecture seams | partial | Diagnostics structured; import-boundary checks partial. |
| C16–C20 (design/prototypes) | historical M2/M3 evidence | Windows bounded acceptance recorded 2026-10-15; C19 participant study NOT done. |
| C21 desktop parity | partial | Automated action/journey evidence exists; manual dialogs/clipboard/reveal pass moved to M4 queue — NOT done. |
| C22 scan experience | partial | Fake-engine suites green; full exceptional-state matrix on current build open. |
| C23 evidence experience | partial | Finding contexts + comparisons shipped; golden-report matrix open. |
| C24 accessibility | open (manual) | Automated audits zero-issue; Narrator/keyboard-only manual pass NOT done — requires a human with assistive tech. |
| C25 visual quality | open (manual) | Captures exist with recorded limitations; 72-view human design review NOT done. |
| C26 performance | Windows: removed by user decision 2026-10-15; macOS unchanged | — |
| C27 detector evaluation | partial (harness done, corpus open) | Harness + honest seed corpus delivered (28/10); 30 repos/300+300/10-clean CANNOT be met without human-reviewed labeling — every report prints the gap; all families flagged experimental. |
| C28 service resolution | partial (identity core done) | AM039+AM040: observed-vs-candidate resolution, no truncation, explicit aliases (hosts/DNS suffixes/ports), three-service reference fixture; installed-engine alias fleet verified. Open: protocol/proxy modeling, alias provenance on links, server-declared ports. |
| C29 release distribution | open (signing) | SBOM/lock/rollback tooling delivered and green; **code-signing certificate does not exist** — signed builds impossible tonight; clean-machine + real-upgrade tests need a human host. |
| C30 retention & diagnostics | partial | Engine + UI + two installed-package verifications (dev-…9d9074f2 and dev-…6f0b8b18); loopback binding re-checked (127.0.0.1-only + test); diagnostic export preview parity proven. Remaining: formal C30 proof write-up in the acceptance ledger. |
| C31 watch correctness | partial (Win32 done) | Debounce/pending-dirty/output-exclusion/switch-stop implemented and live-probed on Windows; POSIX backend and true all-repo fleet watch open. |
| C32 beta exit | open | Requires the C19 participant study + 4-week beta + 100 runs/platform — **cannot be executed by agents overnight by design**; no telemetry fabricated. |

## What was deliberately NOT faked

- No participant studies, usability ratings, or beta telemetry were invented (C19/C32).
- No accessibility or visual acceptance claimed without manual AT passes (C24/C25).
- No signatures claimed (C29); packages remain `unsigned-development`.
- Evaluation labels are only what fixtures justify; per-family counts below C27 minimums stay visibly experimental.
- Historical test results are cited with their dates; tonight's runs (3,336 and 3,407 passed) are fresh executions.

