# AttackMap implementation TODO



**Updated:** 15 October 2026.  

**Acceptance authority:** [AttackMap roadmap 2026 to 2028](roadmap-2026-2028.md).  

**Scope change — 15 October 2026, user decision:** C26 performance qualification is removed from Windows M3 acceptance. A Windows 11 performance host and repeated performance campaign are not required; no replacement Windows 10 performance gate is introduced. Existing measurements remain optional diagnostics, not a performance pass. Other requirements retain their evidence status; the later Windows M3 closure moves remaining manual UX/accessibility and participant validation to M4. macOS C26 is unchanged. Historical Windows C26 blockers below are superseded by this decision.

**Windows M3 closed — 15 October 2026, explicit user acceptance:** Windows M3 is complete as a functional beta with documented limitations, delivered in `dev-20261015190038-5667bbbf`. Remaining Windows participant study (C19), manual workflow/UX validation (C21/C25), and manual accessibility validation including Narrator (C24) move to M4. They remain unverified, not passed. Windows C26 is removed. Original M0/M1/M2 evidence and limitations remain recorded; this bounded Windows acceptance does not certify every original prerequisite, macOS completion, clean-machine compatibility, or a signed public release.

**M4 carry-forward:** see the explicit [Windows manual validation queue](roadmap-2026-2028.md#carried-forward-from-windows-m3-by-user-decision-2026-10-15). Original cross-platform task checkboxes remain evidence-based.

**Design decision:** native-first Windows and macOS experiences with shared engine semantics.  

**Starting state:** 54 open tasks; no implementation task was marked complete by the planning exercise. Implementation started on 15 October 2026; see the delivery log for verified scope and remaining gates.



Use this tracker to select work, record dependencies, and attach evidence. The roadmap defines the exact thresholds; this document identifies the changes needed to meet them. Windows and macOS verification must be recorded separately. Tasks referring to macOS implementation belong in the separate `mlaify/AttackMap-mac` repository; attach its issue/PR here when created.



## Tracking rules



- `[ ]` means open. Add `IN PROGRESS`, `BLOCKED`, or `DEFERRED` after the ID when applicable. `[x]` means implemented and verified against the linked criterion.

- Assign a named owner when starting. Role suggestions below indicate required expertise; assignments for active work are recorded below.

- Dependencies name tasks that must complete before this task can close. Design, fixtures, and investigation may start earlier when independent.

- Keep a task open if only one platform passes a criterion that requires both. Record partial progress in the delivery log.

- Record evidence using the template below. A PR merge, attractive screenshot, or successful manual happy path alone is insufficient for a multi-part criterion.

- Do not check off conditional M6 work simply because it is deferred. If C39 yields no-go, explicitly mark AM054 `NOT APPLICABLE` with the decision link.



Priority meanings: **High** blocks a reliable baseline, the native redesign, or its release; **Medium** improves quality or scale after those dependencies; **Low** is conditional expansion. Dependencies can make a High task unready without lowering its importance.



## Milestone dashboard



| Milestone | Task range | Status | Windows evidence | macOS evidence | Exit |

| --- | --- | --- | --- | --- | --- |

| M0 Correctness | AM001 to AM008 | Corrections integrated; complete release matrix remains open | Latest Windows 3.11/3.12: 3,214 passed / 4 explained skips each; corrected full 3.13 pending. Linux 3.12: 3,213 passed / 5 skips; original failures retained | Pending for applicable core checks | C01 to C07 |

| M1 Contracts | AM009 to AM018 | Windows legs delivered for every criterion: contract adapter + compatibility matrix, Windows supervision proof, atomic publication + interrupted-write matrix, provenance/conflict matrix, ranking-factor exposure, identity matrix, budgets + citations + claim support, import-boundary matrix + terminal-outcome diagnostics | Full regression green; installed engine verified | macOS legs open (no adapter/host); CLI end-to-end envelope emission open | C08 to C15 |

| M2 Native design | AM019 to AM025 | Windows bounded WinUI spike/design | Build, publish and synthetic native smoke pass; C19/C20 acceptance open | Inventory only | C16 to C20 |

| M3 Desktop beta | AM026 to AM036 | Windows COMPLETE as functional beta with limitations, user accepted 2026-10-15 | Package dev-20261015190038-5667bbbf; installed Juice Shop + LM Studio pass; Astra review; manual validation moved to M4; C26 removed | Separate lane; not accepted | Scoped Windows closure above; macOS C21 to C26 unchanged |

| M4 Quality and release | AM037 to AM046 plus deferred Windows validation | Planned; manual beta validation carried forward | C19 study; C21/C25 manual UX; C24 accessibility remain open | Pending | C27 to C32 plus carried-forward Windows checks |

| M5 Local scale | AM047 to AM051 | Wave 1 integrated: snapshot identity + publication gate (C33), analyzer protocol + isolated host (C36), setup verifier + contract CI + flaky scaffold (C37); C34/C35 in wave 2 | Wave-1 focused suites green on Windows; full regression per delivery log | Pending (engine-side only so far) | C33 to C37 |

| M6 Expansion | AM052 to AM054 | Future or conditional | Not assessed | Not assessed | C38 to C40 |



## First work queue



Start **AM001** by recording the environment and repairing collection/version checks, then **AM002**, **AM003**, and **AM004** to repair unsafe guard interpretation, unsupported evidence claims, and stale results. AM001 closes last in M0, after the other fixes allow its complete release baseline to pass. **AM019** can run alongside these fixes to inventory both desktop applications and establish design scope.



Once the inventory exists, create the design foundation and workflow prototypes through AM020 to AM025. Do not start a full Windows port before the technology decision. Keep a work-in-progress limit of two implementation tasks per engineer and one active design validation cycle; this is a planning discipline, not a limit on useful read-only investigation.



## M0 Correctness tasks



- [ ] **AM001 IN PROGRESS Restore the release baseline** — High; owner: Codex integration agent; dependencies for closure: AM002, AM003, AM004, AM005, AM006, AM007, AM008.

  Fix the three collection imports at the intended public seam, reconcile version references, document a reproducible environment, and add Windows core tests to the supported matrix. Capture fresh complete-suite and packaged-identity results.

  **Done when:** [C01 Release baseline](roadmap-2026-2028.md#c01-release-baseline) passes. Evidence: test logs, environment record, version outputs, CI links.



- [ ] **AM002 IN PROGRESS Correct guard semantics** — High; owner: Codex guard_safety subagent; dependencies: none.

  Model guard polarity, recognized predicate meaning, control-flow dominance, and value identity. Add the paired safe/unsafe cases for every supported guard frontend; unknown semantics cannot suppress a flow.

  **Done when:** [C02 Guard safety](roadmap-2026-2028.md#c02-guard-safety) passes, including the original reversed-condition reproduction.



- [ ] **AM003 IN PROGRESS Remove unsupported route claims** — High; owner: Codex scoped_evidence subagent; dependencies: none.

  Remove unrelated global-hint propagation, separate repository context from route facts, preserve unknown exposure, and unify static/inferred/runtime labels across reports and AI prompts.

  **Done when:** [C03 Scoped evidence](roadmap-2026-2028.md#c03-scoped-evidence) passes with unrelated-file counterexamples.



- [ ] **AM004 IN PROGRESS Fix current Windows result freshness** — High; owner: Codex result_freshness subagent; dependencies: none.

  Add repository/generation-aware caching, discard stale responses, and serialize state polling. Introduce the smallest needed state fields now; stabilize their formal schema in AM009.

  **Done when:** [C04 Fresh results](roadmap-2026-2028.md#c04-fresh-results) passes across all 100 sequences, including a scan that completes between polls.



- [ ] **AM005 IN PROGRESS Stop generated artifacts from becoming input** — High; owner: Codex result_freshness subagent; dependencies: none.

  Establish authoritative generated-output identification shared with the manifest, preserve legacy exclusions, and avoid excluding legitimate files solely by basename.

  **Done when:** [C05 Scan isolation](roadmap-2026-2028.md#c05-scan-isolation) passes for all three output locations and three repeated runs.



- [ ] **AM006 IN PROGRESS Repair fleet worker interchange** — High; suggested owner: execution and packaging; dependencies: none.

  Separate worker JSON interchange from presentation output, use a frozen-aware launch strategy, and preserve per-repository failures without discarding successful siblings.

  2026-10-17 packaged Unicode matrix delivered: installed package `dev-20261017193157-2f19d5a3` frozen engine ran a two-repository fleet (space + Czech-diacritic paths) in serial and two-worker execution for json/markdown/all — five completed runs produce one identical normalized-findings digest. One first-launch anomaly recorded (three initial launches exited 1 with no output; warm reruns green; suspect AV first-run scan — see delivery log). C06's clean-machine leg remains part of C29.

  **Done when:** [C06 Fleet formats](roadmap-2026-2028.md#c06-fleet-formats) passes in source and packaged execution.



- [ ] **AM007 Represent inconclusive AI assessments honestly** — High; suggested owner: AI integration; dependencies: none.

  Treat missing/failed votes as abstentions and no-majority outcomes as inconclusive, preserve explicit evidence for refutations, and distinguish model assessment from verified facts in the result schema and copy.

  **Done when:** the consensus and labeling portions of [C07 Honest AI and privacy](roadmap-2026-2028.md#c07-honest-ai-and-privacy) pass the complete vote truth table.



- [ ] **AM008 Correct privacy defaults and disclosures** — High; suggested owner: product, AI integration, and security; dependencies: AM007.

  Document AI/CVE network behavior, keep AI disabled on first launch, explain transmitted inputs, and remove misleading local-only claims where optional features send data. Add sentinel-secret tests to diagnostics and output.

  **Done when:** all remaining [C07 Honest AI and privacy](roadmap-2026-2028.md#c07-honest-ai-and-privacy) checks pass for current code and the desktop specifications.



## M1 Engine contract tasks



- [ ] **AM009 IN PROGRESS Define the versioned run contract** — High; suggested owner: core API and desktop integration; dependencies: AM004, AM006, AM007.

  Specify requests, progress, terminal results, run/generation IDs, revisions, policy outcome, artifact readiness, compatibility ranges, and old-report import behavior. Publish shared golden fixtures.

  2026-10-17 consumer-compatibility matrix delivered: all four kinds accept current + previous versions via `parse_run_message`, drop injected additive unknowns (top-level and nested), reject incompatible majors with the supported-range message (now derived from constants); the desktop adapter publishes its range independent of app version. Remaining: CLI/supervisor end-to-end envelope emission, macOS consumer, wiring the `fixtures/run-contract/faults/` corpus.

  **Done when:** [C08 Run protocol](roadmap-2026-2028.md#c08-run-protocol) passes consumer compatibility tests.



- [ ] **AM010 Unify supervision and cancellation** — High; suggested owner: execution and platform engineering; dependencies: AM009.

  Centralize process-tree ownership, bounded logs, timeouts, admission control, and cancellation; keep the slot occupied until exit is verified. Prevent shared mutable request configuration.

  2026-10-17 Windows campaign recorded: `tools/c09_campaign.py` ran 50 real start/cancel cycles with the ignoring-graceful parent/child fixture plus the 20-way simultaneous-start admission check on this Windows 10 dev host — acknowledgement p95 0.000773 s (budget 0.25 s), tree death max 3.030 s / verified exit max 3.042 s (budget 5 s), 1 of 20 concurrent starts admitted with exactly one Popen launch, slot held after acknowledgement until verified exit; evidence JSON with raw samples in `.pytest_cache/c09-campaign/evidence.json`, details in [windows-process-supervision](windows-process-supervision.md). Measured at the core `request_cancel()` return, not an HTTP round trip. No supervision code change was required. macOS proof, packaged and ARM64 acceptance remain open.

  **Done when:** [C09 Process supervision](roadmap-2026-2028.md#c09-process-supervision) passes independently on Windows and macOS, including all 50 cancel cycles and the concurrent-start test.



- [ ] **AM011 IN PROGRESS Publish complete artifact generations** — High; suggested owner: artifacts and execution; dependencies: AM005, AM009, AM010.

  Reuse one atomic publisher for CLI, desktop, and fleet. Validate before switching current, preserve a previous valid generation, finalize error/cancel diagnostics, and include publication timing.

  2026-10-17 Windows interrupted-write leg delivered: real-OS NTFS matrix (child-process mid-write kills with genuine partial bytes on disk, pre-commit hard kills, 12 crash-remnant mangles, real share-mode locking) proves previous-or-new-never-mixture, terminal diagnostics without replacing current, and clean recovery — no publisher defect found. macOS leg remains open (tests ship `skipif(non-nt)`).

  **Done when:** [C10 Atomic results](roadmap-2026-2028.md#c10-atomic-results) passes the interruption/failure matrix without breaking supported output access.



- [ ] **AM012 Preserve provenance and conflicts during merge** — High; suggested owner: data modeling; dependencies: AM003, AM009.

  Extend the existing signal model with observation identity and origin, preserve contradictions and corroboration, deduplicate coverage, and avoid mutating analyzer objects. Adapt legacy plugin output explicitly.

  2026-10-17 conflict/ranking slice delivered: fixture-driven conflict matrix (`tests/fixtures/signal_conflicts/` + `tests/test_merge_conflict_matrix.py`) proving contradictory properties (route auth present/absent and upgrade, taint hops, direct-signal exposure) survive merge as `SignalConflict` with corroborating origins under every input permutation, stable observation IDs, analyzer-input immutability by deep-copy snapshot proof, and coverage counted once. Per-finding ranking-factor decomposition exposed additively in finding contexts and `attackmap-report.json` (`tests/test_ranking_factors.py`, `tests/test_finding_presentation.py`): severity band, confidence multiplier with visible weights, fused exploitability factors summing to the raw score, source-quality qualitative filter, plus explicit `not_applied` factors and unresolved assumptions — no score is changed, only made visible; ranking tests pin confidence and source-quality direction and state scores are not calibrated probabilities. Remaining: finding→score link is value-matched (a `models.py` reference field would make it first-class); trust-boundary crossing is not yet a fused ranking factor; conflict surface beyond route auth/taint hops needs richer analyzer emission.

  **Done when:** [C11 Source provenance](roadmap-2026-2028.md#c11-source-provenance) passes conflict, ordering, and immutability tests.



- [ ] **AM013 Normalize source roles and relationship evidence** — High; suggested owner: evidence and ranking; dependencies: AM002, AM003, AM012.

  Centralize source classification and distinguish observed edges from candidates. Use explicit evidence references for route ownership and expose scoring factors and uncertainty consistently.

  2026-10-17 ranking-exposure note: see the AM012 slice above — the C12 ranking-factor decomposition, direction tests, and explicit unresolved assumptions are delivered there. Source-role classification and candidate-vs-observed edge distinction were already in place; full C12 closure still needs broader route-ownership counterexamples across output formats.

  **Done when:** [C12 Evidence ownership](roadmap-2026-2028.md#c12-evidence-ownership) passes source-quality, ownership, and ranking tests.



- [ ] **AM014 IN PROGRESS Stabilize finding and baseline identity** — High; suggested owner: findings and triage; dependencies: AM012.

  Replace title-dependent identity with stable rule/entity semantics; implement baseline and suppression migration, collision handling, and visible unmapped-record handling.

  2026-10-17 matrix slice delivered: paired fixture matrix under `tests/fixtures/finding-identity/` with `tests/test_finding_identity_matrix.py` (title/recommendation edits, line drift, duplicate routes, moved files, old-baseline migration round-tripping suppression reason/owner/ticket onto stable ids). Two real gaps wired: `compare_reports` now emits `legacy_id_aliases` notices for baselines (foreign/ambiguous ids were silently re-identified before), and `collect_suppressions` accepts baseline-derived `id_aliases`; `pipeline.py` passes baseline-derived aliases end to end (`tests/test_pipeline_suppression_migration.py`: legacy title-id suppression keeps applying; an unrelated legacy id never suppresses). Identity stayed conservative — no title-similarity or rename inference. Remaining: per-instance removal tracking for moved files is documented as intended semantics, not implemented.

  **Done when:** [C13 Finding identity](roadmap-2026-2028.md#c13-finding-identity) passes all migration and identity-change fixtures.



- [ ] **AM015 Enforce AI call budgets before dispatch** — High; suggested owner: AI integration; dependencies: AM007, AM009, AM010.

  Add one reservation ledger for generation, verification, retries, tokens, calls, and time. Surface unknown usage and estimated billing honestly.

  **Done when:** the budget portions of [C14 AI boundaries](roadmap-2026-2028.md#c14-ai-boundaries) pass deterministic fake-provider tests with zero calls after exhaustion.



- [ ] **AM016 IN PROGRESS Validate AI evidence references** — High; suggested owner: AI integration and evidence; dependencies: AM008, AM012.

  Replace substring citation checks with structured IDs and bounded source spans. Distinguish citation validity from claim support, minimize/redact excerpts, and test hostile instructions embedded in analyzed files. Capture the cited contents consistently; the shared snapshot system follows in AM047.

  2026-10-17 claim-support slice delivered: closed-set `claim_support` (`supported_by_cited_evidence` only when a cited captured span names an identifier/route/secret-kind the claim itself names — assessment vocabulary structurally excluded so hostile files cannot spoof it; otherwise `not_assessed`) wired through hunt consensus reports, narrative `reference_validation` (one honest entry per cited claim), and defensive-review JSON weaknesses/recommendations (schema stays 1.5.0, fields additive). `review_eval` gained `claim_support_discipline` (proof verbs attached to citations fail). Excerpt redaction verified across all nine prompt paths; new `tests/fixtures/hostile_citation_repo` proves forged evidence IDs, embedded foreign `source:` IDs, and citation-spoofing text are rejected. Honest limits stated in `docs/ai-citations.md`: token presence is not semantic entailment; narrative prompts still supply no captured spans.

  **Done when:** the citation, privacy, and authority portions of [C14 AI boundaries](roadmap-2026-2028.md#c14-ai-boundaries) pass without weakening deterministic results.



- [ ] **AM017 Separate orchestration from presentation** — High; suggested owner: core architecture; dependencies: AM009, AM010, AM011, AM012.

  Extract typed application boundaries incrementally. Remove Typer/desktop imports from shared application orchestration and prevent analyzers from taking over report or scoring responsibilities.

  **Done when:** the layering portions of [C15 Architecture seams and diagnostics](roadmap-2026-2028.md#c15-architecture-seams-and-diagnostics) pass import-boundary and adapter tests.



- [ ] **AM018 Make failed and degraded runs diagnosable** — High; suggested owner: execution and developer experience; dependencies: AM009, AM010, AM011, AM017.

  Emit structured local run/stage diagnostics and coverage reasons, including startup failure and partial analysis. Redact by default and separate policy from execution failures.

  **Done when:** the diagnostic portions of [C15 Architecture seams and diagnostics](roadmap-2026-2028.md#c15-architecture-seams-and-diagnostics) pass with evidence from each terminal outcome.



## M2 Native design tasks



- [ ] **AM019 Audit both desktop apps and select support targets** — High; suggested owner: Windows lead, macOS lead, and product design; dependencies: none.

  Inspect the actual macOS repository, record both commits, inventory features and contract assumptions, and publish the parity/support matrix. Identify distribution credentials and hardware needs early.

  **Done when:** [C16 Platform inventory](roadmap-2026-2028.md#c16-platform-inventory) passes. Evidence must separate implemented behavior from the historical macOS plan.



- [ ] **AM020 Create two native design systems** — High; suggested owner: product design with platform engineers; dependencies: AM019.

  Specify Windows Fluent and macOS-native foundations, light/dark/system appearance, platform typography, semantic tokens, density, and the 12 required components. Include focus, high-contrast, and reduced-motion states.

  **Done when:** [C17 Native design foundations](roadmap-2026-2028.md#c17-native-design-foundations) passes with platform-specific component specimens.



- [ ] **AM021 Simplify navigation and map every capability** — High; suggested owner: product design and product engineering; dependencies: AM019.

  Map existing destinations into Overview, Findings, Architecture, Inventory, Reports, and History with native Settings placement. Define master/detail behavior, persistent workspace identity, and every exceptional state.

  **Done when:** [C18 Navigation and screens](roadmap-2026-2028.md#c18-navigation-and-screens) passes the capability map and action-count checks.



- [ ] **AM022 Build complete native workflow prototypes** — High; suggested owner: product design; dependencies: AM020, AM021.

  Produce inspectable Windows and macOS prototypes covering the nine views, six study tasks, and exceptional states. Use realistic evidence, ambiguity, long paths, and populated reports.

  **Done when:** both prototypes are ready for the study specified by [C19 Validated prototypes](roadmap-2026-2028.md#c19-validated-prototypes); this task alone does not pass C19.



- [ ] **AM023 Run the first usability study and revise** — High; suggested owner: UX research and product design; dependencies: AM022.

  Recruit the defined 10 participants, run the same tasks without workflow coaching, measure success/time/visual ratings, and revise and retest failed tasks with new participants.

  **Done when:** every threshold in [C19 Validated prototypes](roadmap-2026-2028.md#c19-validated-prototypes) passes. Store anonymized outcomes and unresolved non-blocking observations.



- [ ] **AM024 Validate and decide the Windows implementation** — High; suggested owner: Windows engineering; dependencies: AM019, AM020, AM021.

  Build the bounded WinUI 3 slice, measure it against the current host, test Narrator/keyboard and subprocess control, and produce a development package. Record cost, migration sequence, and fallback evidence.

  **Done when:** the Windows portion of [C20 Technology decision](roadmap-2026-2028.md#c20-technology-decision) is documented within the spike time box, including an explicit implementation choice.



- [ ] **AM025 Validate macOS integration and finalize the desktop decision** — High; suggested owner: macOS engineering and architecture; dependencies: AM019, AM020, AM021, AM024.

  Exercise the SwiftUI slice, VoiceOver, report decoding, worker lifecycle, and development packaging. Combine the results into the desktop architecture decision and a realistic delivery estimate.

  **Done when:** the remaining requirements of [C20 Technology decision](roadmap-2026-2028.md#c20-technology-decision) pass and both platform migration plans are concrete.



## M3 Desktop implementation tasks



M3 tasks may be developed against fixtures early, but the beta milestone cannot close until M0, M1, and M2 pass.



- [ ] **AM026 Build the Windows native shell** — High; suggested owner: Windows engineering; dependencies: AM023, AM024, AM025.

  Implement navigation, native commands/dialogs, workspace identity, system appearance, window restoration, keyboard conventions, and platform view models using the chosen stack.

  **Done when:** the Windows shell portions of [C21 Desktop parity](roadmap-2026-2028.md#c21-desktop-parity) pass; capture installed-build evidence.



- [ ] **AM027 Build the macOS native shell** — High; suggested owner: macOS engineering; dependencies: AM023, AM025.

  Implement sidebar/split views, toolbar/menu commands, Settings, native panels, window restoration, Command-key conventions, and platform view models in the macOS repository.

  **Done when:** the macOS shell portions of [C21 Desktop parity](roadmap-2026-2028.md#c21-desktop-parity) pass independently of Windows.



- [ ] **AM028 Connect Windows to supervised scans** — High; suggested owner: Windows engineering; dependencies: AM009, AM010, AM011, AM018, AM026.

  Wire immutable requests, progress, run revisions, policy outcomes, cancellation, generation loading, previous-result labels, and recovery actions. Exercise the shared fake-engine scenarios.

  **Done when:** Windows passes [C22 Scan experience](roadmap-2026-2028.md#c22-scan-experience), including the C04/C08/C09 requirements.



- [ ] **AM029 Connect macOS to supervised scans** — High; suggested owner: macOS engineering; dependencies: AM009, AM010, AM011, AM018, AM027.

  Implement the same run contract using macOS process and UI-state adapters, with independent lifecycle and schema compatibility tests.

  **Done when:** macOS passes [C22 Scan experience](roadmap-2026-2028.md#c22-scan-experience), including stale/rapid/cancelled runs and subprocess failures.



- [ ] **AM030 Build Windows findings and evidence exploration** — High; suggested owner: Windows engineering and product design; dependencies: AM012, AM013, AM014, AM028.

  Implement virtualized findings, filters, evidence detail, uncertainty and scoring explanations, architecture/list views, and inventory. Preserve clear source and generation identity.

  **Done when:** Windows passes the investigation portions of [C23 Evidence experience](roadmap-2026-2028.md#c23-evidence-experience).



- [ ] **AM031 Build macOS findings and evidence exploration** — High; suggested owner: macOS engineering and product design; dependencies: AM012, AM013, AM014, AM029.

  Implement the same evidence semantics with native lists/tables, split views, and inspectors. Include an accessible alternative to every diagram interaction.

  **Done when:** macOS passes the investigation portions of [C23 Evidence experience](roadmap-2026-2028.md#c23-evidence-experience).



- [ ] **AM032 Implement history and triage on both platforms** — High; suggested owner: both desktop teams; dependencies: AM014, AM030, AM031.

  Add run comparison, reversible reasoned suppression, exact-run export, existing-report import, and settings/history migration with preserved originals. Cover changed analysis coverage in comparisons.

  **Done when:** both platforms pass the history/export portions of [C21 Desktop parity](roadmap-2026-2028.md#c21-desktop-parity) and [C23 Evidence experience](roadmap-2026-2028.md#c23-evidence-experience).



- [ ] **AM033 Implement secure settings and provider controls** — High; suggested owner: both desktop teams and security; dependencies: AM008, AM015, AM016, AM028, AM029.

  Add advanced configuration, clear provider/data disclosure, OS-protected credentials, local-only defaults, and actionable unavailable-provider states. Never silently fall back to plaintext storage.

  **Done when:** settings satisfy [C21 Desktop parity](roadmap-2026-2028.md#c21-desktop-parity), [C07 Honest AI and privacy](roadmap-2026-2028.md#c07-honest-ai-and-privacy), and [C14 AI boundaries](roadmap-2026-2028.md#c14-ai-boundaries).



- [ ] **AM034 Complete accessibility verification** — High; suggested owner: accessibility QA and both desktop teams; dependencies: AM030, AM031, AM032, AM033.

  Test all ten workflows with keyboard only, Narrator, and VoiceOver. Resolve focus, names, contrast, text scaling, target sizing, reduced motion, and high-contrast failures.

  **Done when:** [C24 Accessibility](roadmap-2026-2028.md#c24-accessibility) passes with separate platform reports and zero critical/serious automated findings.



- [ ] **AM035 Finish visual polish and layout regression coverage** — High; suggested owner: product design and both desktop teams; dependencies: AM030, AM031, AM032, AM033, AM034.

  Capture the 72-view matrix, inspect exceptional states and display scaling, and repair spacing, hierarchy, clipping, theme switching, and token inconsistencies.

  **Done when:** [C25 Visual quality](roadmap-2026-2028.md#c25-visual-quality) passes with platform/OS-version-specific references.



- [ ] **AM036 Meet desktop performance budgets** — High; suggested owner: desktop performance engineering; dependencies: AM030, AM031, AM032, AM033, AM035.

  Create the published large-report fixture, profile startup/list/detail/filter behavior, virtualize heavy views, and run the defined memory-cycle and latency measurements on both reference hosts.

  **Done when:** [C26 Desktop performance](roadmap-2026-2028.md#c26-desktop-performance) passes with raw measurements and hardware/build metadata.



## M4 Quality and release tasks



- [ ] **AM037 Build the independent evaluation corpus** — High; suggested owner: security research and analysis QA; dependencies: AM002, AM003, AM012, AM013.

  Collect and label the required positive/negative/clean repositories, freeze repository-level holdouts, define finding matching, and report family sample counts and uncertainty.

  **Done when:** the corpus and reporting requirements of [C27 Detector evaluation](roadmap-2026-2028.md#c27-detector-evaluation) pass. Do not tune against the held-out set.



- [ ] **AM038 IN PROGRESS Improve weak detection families and establish quality scope** — High; suggested owner: analysis engine; dependencies: AM037.

  Improve BOLA and unauthenticated state-change detection using training fixtures; run frozen evaluation for every advertised family and preserve negative controls. Keep immature capabilities visibly experimental.

  2026-10-17 quality slice delivered: bench recall bola 1/2→3/3, unauth 2/5→8/8, webhook 0/1→2/2 at precision 100% (0 FPs) with labels untouched; frozen evaluate tuning side 100%/100% for all three families, holdout recorded never tuned against; Juice Shop findings byte-identical. See delivery log for the diagnosed heuristic fixes. C27's corpus-size targets still need human-reviewed labels — every family stays visibly experimental until then.

  **Done when:** the quality/scope requirements of [C27 Detector evaluation](roadmap-2026-2028.md#c27-detector-evaluation) pass with complete results, not selected favorable scores.



- [ ] **AM039 IN PROGRESS Preserve service identity** — High; suggested owner: topology modeling; dependencies: AM012, AM013.

  Replace hostname truncation with explicit endpoint/service identity and deployment aliases. Preserve protocol/port/namespace distinctions and uncertain mappings.

  2026-10-16 first slice delivered: `link_contracts` now resolves the call's destination authority against repo identities (fleet id + root directory name, case-normalized, no truncation). Unresolved hosts, DNS suffixes without aliases, relative targets, ambiguous identities, and explicit ports produce candidate links (`resolution_reason` explains each) that never support cross-boundary flows, trust gaps, or observed graph edges; markdown/mermaid/JSON summaries render candidates distinctly. Deployment aliases and the three-service reference fixture remain open (AM040 scope).

  **Done when:** the identity portions of [C28 Service resolution](roadmap-2026-2028.md#c28-service-resolution) pass, including the `auth-api` and `auth-worker` counterexample.



- [ ] **AM040 Resolve cross-repository edges conservatively** — High; suggested owner: distributed-system analysis; dependencies: AM039.

  Match destinations using service identity and endpoint semantics; preserve ambiguous candidate edges and case-sensitive paths. Build the three-service reference fixture.

  2026-10-17 remainder slice delivered: protocol/proxy/port modeling and alias provenance. `DeploymentAliases` gained `proxies` (proxy host → exactly one backend identity), `service_ports` (identity → declared listen port), and `service_protocols` (identity → http/https), all positive-only with malformed values rejected, exposed as fleet-only `--via-proxy`/`--service-port`/`--service-protocol` flags. `ContractLink` records the call's `scheme`, `alias_provenance` (`hosts:`/`dns_suffix:`/`host_ports:`/`service_ports:`/`proxies:`, `None` for identity matches), and `proxy_host`; same-host scheme contradictions stay candidates (`scheme_mismatch`) and only fire when the destination already resolved to that server; declared listen ports resolve explicit-port calls; a declared proxy resolves its portless calls as `observed_via_proxy` — a distinct resolution rendered through a proxy node in mermaid and its own markdown section, never a direct edge or trust-path finding (crossrepo gates pinned by test with a direct-link control). Three-service reference fixture extended (12 calls / 16 links, exact observed/candidate sets with reasons and provenance); real CLI fleet run verified all flags end to end. Remaining: config-file extraction (k8s/nginx/compose) of ports/schemes/proxies; multi-backend proxy routing; other protocols (grpc/ws).

  **Done when:** the cross-repository portions of [C28 Service resolution](roadmap-2026-2028.md#c28-service-resolution) pass without unsupported observed links.



- [ ] **AM041 Ship a verified Windows release candidate** — High; suggested owner: Windows release engineering; dependencies: AM006, AM024, AM034, AM035, AM036.

  Produce signed packages with explicit dependencies, release-build inputs, checksums, SBOM, and a previous-version rollback path. Exercise installation, first scan, cancel, export, upgrade, and uninstall on clean supported hosts.

  **Done when:** the Windows portion of [C29 Release distribution](roadmap-2026-2028.md#c29-release-distribution) passes for every advertised architecture.



- [ ] **AM042 Ship a verified macOS release candidate** — High; suggested owner: macOS release engineering; dependencies: AM025, AM034, AM035, AM036.

  Decide engine discovery/bundling behavior, produce signed and notarized builds, enforce engine compatibility, and test the full clean-machine lifecycle and rollback path.

  **Done when:** the macOS portion of [C29 Release distribution](roadmap-2026-2028.md#c29-release-distribution) passes for every advertised architecture.



- [ ] **AM043 IN PROGRESS Add safe retention and diagnostic export** — High; suggested owner: artifacts, both desktop teams, and security; dependencies: AM011, AM018, AM032, AM033.

  Implement the generation count/size policy, pinning, protected-current invariants, redacted export preview, secure-store failure behavior, and loopback security checks where applicable.

  2026-10-16 first slice delivered: core retention engine (`src/attackmap/retention.py`) with default keep-20/2 GiB soft budget, pin store (`pinned-generations.json`), protection of current/pinned/active runs, interrupted-cleanup recovery, and fail-open wiring after every publish site (CLI pipeline, desktop worker, fleet). Pins file is manifest-recognized generated output. Diagnostic export preview/redaction, desktop pin UI, and remaining C30 proofs are still open.

  2026-10-16 second slice delivered: `src/attackmap/diagnostics_export.py` plus `attackmap diagnostics <output-dir> [--out] [--max-generations]` — bounded, source-free export payload (generation contexts, terminal diagnostics, pins, dry-run retention posture) with credential redaction; the written bundle is byte-identical to the preview and recognized as generated output. Desktop pin controls and installed-engine verification remain open.

  2026-10-16 third slice delivered: desktop retention end to end. New supervised engine actions (`pin_generation`, `unpin_generation`, `diagnostics_preview`, `diagnostics_export`); native scans publish into a stable per-repository base (`ScanLocations`) so generations accumulate; the History view gained a Generation-retention section (list, pin/unpin, diagnostics export via save picker) with an explicit item template after captures proved the code-created ListView never painted DisplayMemberPath rows. Live verification: two real Juice Shop scans, pin→keep/unpin→delete retention passes (31.5 MiB freed, current stayed valid), broker-transport diagnostics/pin/export/unpin e2e, and visually reviewed captures in 2 sizes × 2 themes. C30's loopback, secure-store fail-closed, and sentinel-secret clauses are covered by existing tests (`test_ui_privacy.py`, `test_llm_loopback_privacy.py`). Still open: verification on an installed/frozen engine via a future package rebuild, manual keyboard/Narrator pass over the new controls.

  **Done when:** [C30 Retention and diagnostics](roadmap-2026-2028.md#c30-retention-and-diagnostics) passes the storage, secret, and local-API test cases.



- [ ] **AM044 Make watch mode reliable on both platforms** — High; suggested owner: filesystem and platform engineering; dependencies: AM005, AM010, AM028, AM029.

  Use filename-aware changes, output exclusion, debounce, pending dirty state, watcher shutdown on repository switches, and honest fleet coverage.

  **Done when:** [C31 Watch correctness](roadmap-2026-2028.md#c31-watch-correctness) passes every platform filesystem scenario.



- [ ] **AM045 Run the implemented-app usability study and beta** — High; suggested owner: product research and QA; dependencies: AM038, AM040, AM041, AM042, AM043, AM044.

  Repeat the defined study with new participants, run the four-week beta, collect consented evidence, and resolve blocker defects. Include visual coherence and native-feel ratings separately for each platform.

  **Done when:** the study, participation, run-count, and defect requirements of [C32 Beta exit](roadmap-2026-2028.md#c32-beta-exit) pass.



- [ ] **AM046 Close release gates and publish the supported scope** — High; suggested owner: release lead and product; dependencies: AM045.

  Review C01 through C31 evidence, reproduce relevant release checks, document experimental/deferred capabilities, update release guidance and parity, and retain the rollback artifact. Retire the old Windows renderer only after its replacement gates pass.

  **Done when:** the final release-readiness requirements of [C32 Beta exit](roadmap-2026-2028.md#c32-beta-exit) pass for the actual advertised scope.



## M5 Local scale tasks



- [ ] **AM047 IN PROGRESS Make analysis use one consistent snapshot** — Medium; suggested owner: indexing and evidence; dependencies: AM011, AM012, AM016, AM018, AM046.

  Route deterministic passes, fingerprints, and excerpts through captured content identities; handle additions, deletion, and mutation explicitly. Keep path and filesystem safety protections.

  2026-10-18 first slice delivered: content-identified `ScanSnapshot` in `index.py` (per-file sha256 on the index text basis, snapshot id over the sorted path→hash set, config identity over index acceptance limits), additive `ScanResult.scan_snapshot` carrying identity into `scan.json` and `run_identity.snapshot` in the manifest (schema keys declared), publication gate re-verifying the working tree and marking drifted runs `snapshot_state:"incomplete"` with a limitation listing changed/deleted/new paths (bounded mark-incomplete policy, no retry loop), content-confirmed `mutation_warnings()` with new-file detection, snapshot-pinned fingerprint source lines (optional index param), AI-excerpt spans recorded under their capture snapshot id. Mutation tests at all four roadmap phases (indexing, detection, report writing, excerpt extraction); real CLI run verified manifest↔scan.json identity match. Open: whole-repo passes (sbom/supply-chain/workflows/authz/anomalies/go.mod) still read live files and rely on verify-and-mark-incomplete; `recon_to_analysis.py` not yet passing the index to fingerprints (threading through `analyze_repository` return is the follow-up); byte-budget effects not replayed for new-file detection.

  **Done when:** [C33 Consistent snapshots](roadmap-2026-2028.md#c33-consistent-snapshots) passes mutation tests across the entire pipeline.



- [ ] **AM048 Add incremental analysis with equivalence tests** — Medium; suggested owner: indexing and performance; dependencies: AM047.

  Build complete cache keys, dependency invalidation, corruption recovery, and incremental/full differential testing. Select storage from measured needs; preserve report artifacts as the external contract.

  **Done when:** [C34 Safe incremental analysis](roadmap-2026-2028.md#c34-safe-incremental-analysis) passes all 100 edit sequences and the performance targets.



- [ ] **AM049 Enforce large-repository resource budgets** — Medium; suggested owner: execution and performance; dependencies: AM010, AM015, AM018, AM047.

  Add finite source/file/graph/time/concurrency limits, explicit degraded coverage, fleet memory admission, and reproducible large-repository benchmarks.

  **Done when:** [C35 Resource limits](roadmap-2026-2028.md#c35-resource-limits) passes, including peak memory, cancellation under load, and visible budget exhaustion.



- [ ] **AM050 IN PROGRESS Introduce optional isolated analyzer execution** — Medium; suggested owner: plugin SDK and platform security; dependencies: AM009, AM010, AM012, AM049.

  Define the extraction protocol and host, enforce actual supported limits, test hostile/crashing workers, and document the difference between process isolation and a security sandbox.

  2026-10-18 first slice delivered: extraction protocol v1.0 (`analyzer_contracts.EXTRACTION_PROTOCOL_VERSION` + machine-readable contract description + compatibility check; all registered analyzers pass) and optional isolated host `src/attackmap/analyzer_host.py` reusing `execution/` supervision — time, stream/output-size, result-size limits plus a Windows Job Object memory cap; named partial-coverage outcomes (`AnalyzerHostTimeout/OutputLimit/MemoryLimit/Crash/InvalidOutput/LaunchFailed/Stuck`) that never touch sibling results. Eight malicious fixtures (crash, forced-kill hang, 10 MB stdout flood, malformed output, 1.5 GB memory hog, out-of-workdir write, namespace forgery) each yield the named result with siblings intact; forged provenance dropped by core-owned merge. Opt-in `--isolated-analyzers` CLI flag wired through ScanRequest/AnalyzeOptions (built-ins always in-process). Docs state explicitly: lockfile pinning is not authenticity and the host is fault containment, not a sandbox — no network/filesystem restriction (the escape test proves the outside-write succeeds). Open: memory cap Windows-only; stream cap is cooperative interposition; provenance not authenticated.

  **Done when:** [C36 Analyzer boundary](roadmap-2026-2028.md#c36-analyzer-boundary) passes current-analyzer compatibility and controlled failure tests.



- [ ] **AM051 IN PROGRESS Improve contributor setup and cross-client contract CI** — Medium; suggested owner: developer experience; dependencies: AM017, AM025, AM046.

  Document reproducible core and desktop setup, automate contract-consumer checks, run onboarding trials, and track delivery friction without introducing unnecessary infrastructure.

  2026-10-18 machine slice delivered: `scripts/verify_setup.py` one-command setup verifier with per-stage JSON timing (measured stages 4.63 s / 81 tests on this host; fresh temp venv 14.57 s; install stage honestly recorded as skipped locally — deferred to the CI clean-runner log), `tools/flaky_tracker.py` stdlib-only per-test flakiness scaffold (two real runs aggregated), path-filtered `client-contract-fixtures.yml` CI gate over the run-contract + desktop/client fixture suites (YAML validated; remote runs pending push), CONTRIBUTING.md measured-setup + desktop-recipe pointers, and `docs/delivery-efficiency.md` as the C37 evidence page with recording templates for the human parts. Open by design: three-contributor onboarding trials (template provided, zero recorded), the eight-week flaky/lead-time window, the separate macOS repo's CI link, and the first real CI run after push.

  **Done when:** [C37 Delivery efficiency](roadmap-2026-2028.md#c37-delivery-efficiency) passes the timing trials and eight-week tracking requirement.



## M6 Conditional expansion tasks



- [ ] **AM052 Deepen reusable ecosystem support** — Medium; suggested owner: analyzer maintainers and security research; dependencies: AM038, AM040, AM047, AM050.

  Strengthen language/framework/protocol layering for the three named stacks, with capability matrices and production-like fixtures. Add infrastructure/config observations through the shared evidence model.

  **Done when:** [C38 Ecosystem depth](roadmap-2026-2028.md#c38-ecosystem-depth) passes contract and detector-quality checks for all advertised mature features.



- [ ] **AM053 DEFERRED Decide whether a team product is justified** — Low; suggested owner: product and architecture; dependencies: AM046, AM048, AM049, AM051.

  Collect the defined three-team/eight-week evidence, compare artifact exchange, a shared read service, and remote workers, and record a costed go/no-go decision.

  **Done when:** [C39 Team product decision](roadmap-2026-2028.md#c39-team-product-decision) passes. A documented no-go is a valid completion of this task.



- [ ] **AM054 DEFERRED Deliver the smallest justified team pilot** — Low; suggested owner: product, backend, operations, and security; dependencies: AM050, AM053 and a C39 go decision.

  Implement only the selected shared capability, with authorization, retention/deletion, auditability, isolated jobs if required, recovery, and a numeric operating budget established before build.

  **Done when:** [C40 Conditional team pilot](roadmap-2026-2028.md#c40-conditional-team-pilot) passes; otherwise retain as deferred or mark not applicable with the no-go decision.



## Cross-platform acceptance ledger



Keep this table current as work progresses. A row is ready only when the linked evidence covers all associated criteria; an unchecked cell does not imply the capability is absent today.



| Area | Criteria | Windows status and evidence | macOS status and evidence |

| --- | --- | --- | --- |

| Inventory and support matrix | C16 | Pending | Pending |

| Native design foundations | C17, C18 | Pending | Pending |

| Prototype study | C19 | Pending | Pending |

| Technology and packaging slice | C20 | Pending | Pending |

| Core workflow parity | C21 | Pending | Pending |

| Current results and cancellation | C04, C09, C22 | Pending | Pending |

| Evidence, history, and exports | C13, C23 | Pending | Pending |

| Accessibility | C24 | Pending | Pending |

| Visual layout and themes | C25 | Pending | Pending |

| Startup and large reports | C26 | Pending | Pending |

| Signed install and rollback | C29 | Pending | Pending |

| Credentials and retention | C07, C14, C30 | Pending | Pending |

| Watch behavior | C31 | Pending | Pending |

| Implemented-app study and beta | C32 | Pending | Pending |



## Delivery evidence template



Copy this record for a task when work starts. Put concise outcomes here and link larger logs, recordings, fixture results, or screenshots. Do not store credentials or private source excerpts in this tracker.



```text

Task ID:

Status: TODO | IN PROGRESS | BLOCKED | DONE | DEFERRED | NOT APPLICABLE

Named owner:

Repository and commit or build:

Issue or PR:

Started:

Completed:

Acceptance criteria covered:

Changes delivered:

Verification command or exact manual procedure:

Windows OS and architecture, result, evidence:

macOS OS and architecture, result, evidence:

Other core CI matrix results where applicable:

Measured values compared with required thresholds:

Remaining limitations or blocked dependencies:

Evidence paths or links:

Reviewer:

```



## Delivery log



| Date | Task | Status change | Evidence or blocker | Next action |

| --- | --- | --- | --- | --- |

| 2026-10-15 | Planning | Roadmap and tracker created | Native-first design preference recorded; implementation remains open | Start AM001 and AM019 |

| 2026-10-15 | AM001–AM004 | Implementation started | Four bounded workstreams: release baseline, guard safety, scoped evidence, Windows report freshness. Existing user edits retained. | Integrate focused tests, complete suite, and Juice Shop scan; record unpassed gates explicitly |

| 2026-10-15 | AM005 | Implementation started | Full-suite integration reproduced root-output re-ingestion (8 files instead of 1). Manifest-based identification assigned before the user's stop-after-current-work instruction. | Verify repeated root/nested/external outputs and same-name user files |

| 2026-10-15 | AM001–AM005 | First integration batch locally verified; agents stopped | 2,684 passed, 6 explained skips, no failures/collection errors; current wheel matches 98 source files; Juice Shop and local LM Studio smoke completed. AI claim discipline and webhook recall gaps remain documented. | On resumption, use GPT-6.1 Sol for AM006/AM007 and remaining acceptance proof; no new task started now |

| 2026-10-16 | AM043 | First retention slice implemented and verified | Core `retention.py`: keep-20/2 GiB soft budget, pinning, current/pinned/active protection, leftover recovery, fail-open post-publish wiring (pipeline, desktop worker, fleet); pins file recognized as generated output. Focused verification 190 distinct tests passed: `tests/test_retention.py` 15 (within an 8-file batch of 165) plus pipeline/fleet 25. Windows beta package untouched. | Diagnostic export preview/redaction slice, desktop pin UI, retention on installed engine via future rebuild, C30 remaining proofs |

| 2026-10-16 | AM043 | Diagnostic export slice implemented and verified | `diagnostics_export.py` + CLI `diagnostics`: redacted source-free preview, `--out` writes the identical payload, sentinel-secret and source-marker tests pass; export file recognized as generated output. Focused verification 195 distinct tests passed (export 8, plus retention/manifest/publisher/exclusion/CLI/capabilities/diagnostic-context/output-format). No model calls; Windows beta package untouched. | Desktop pin UI, loopback re-check, installed-engine verification via future rebuild, C30 remaining proofs |

| 2026-10-16 | AM043 | Desktop retention slice implemented, live-verified | Engine actions pin/unpin/diagnostics via supervised broker; native stable per-repo scan base; History generation-retention UI with explicit item template (capture proved DisplayMemberPath rows never painted); `--retention-smoke` passed and captures visually reviewed (2 sizes × 2 themes, `.pytest_cache/am043-captures/`). Live: 2 real Juice Shop scans, pin keeps / unpin deletes 31.5 MiB with valid current, broker e2e pin→export(preview-parity)→unpin (`.pytest_cache/am043-live-evidence.json`). Final focused verification: 100 passed (privacy/loopback, desktop actions, retention, diagnostics export, output exclusion). | Installed/frozen-engine verification at next package rebuild; manual keyboard/Narrator pass on new controls; C30 acceptance write-up |

| 2026-10-16 | AM043 | Development package dev-20261016201719-9d9074f2 with retention engine delivered and installed-verified | New unsigned dev package (ZIP SHA256 60c41051…6976): native app with History generation-retention UI (explicit item template; DisplayMemberPath rows never painted) + frozen engine from today's snapshot (engine-verification binds exe/payload/snapshot hashes; real worker scan + compare and retention actions through the frozen exe; 19 analyzers). Installed verification: retention/history app smokes passed; 2 real Juice Shop scans via installed engine (no retention warnings); diagnostics CLI + broker-transport pin/export(preview parity)/unpin all completed; probe scan-smoke passed (forward-slash CLI path is a test-only artifact; UI flow unaffected). Evidence: .pytest_cache/am043-captures/installed-package-verification-2026-10-16.json. | Manual keyboard/Narrator on new controls; C30 acceptance write-up; broad regression at next stable checkpoint |

| 2026-10-16 | AM039 | Audit complete; implementation starting | Root defect confirmed: contracts.link_contracts matches client calls to server routes by normalized path+method only — the destination hostname in call.target is ignored, so cross-repo links can wire the wrong service (C28 forbids path-only resolution). | Implement authority extraction + repo identity resolution; unresolved → candidate links, never observed trust paths |

| 2026-10-16 | AM039 | Identity-preserving resolution implemented and focused-verified | ContractLink gained destination/resolution/resolution_reason; link_contracts resolves the call's host against repo identities (fleet id + root dir name, no truncation: auth-api/auth-worker stay distinct; DNS suffixes, relative targets, ambiguous identities, explicit ports stay candidates). crossrepo flows/trust-gaps consume observed links only; fleet markdown/mermaid/summary render candidates separately (dashed edges, reasons). Focused verification: 61 passed (contracts incl. 8 new C28 cases, fleet, crossrepo) + 35 passed (scan service, fleet parallelism/publication) after fixture updates that make the destination identify the server. | AM040 cross-repository reference fixture; broad regression at stable checkpoint |

| 2026-10-16 (night) | AM040 | Explicit deployment aliases + three-service reference fixture | `DeploymentAliases` (hosts / dns_suffixes / host_ports; positive declarations only, malformed rejected) threaded ScanRequest→link_contracts and exposed as `--service-alias`/`--service-dns-suffix` CLI flags (fleet-only, single-repo rejected). Three-service reference fixture asserts the exact observed edge set, per-candidate reasons, and no unsupported resolved edges. Verification: 92 passed (contracts/crossrepo/fleet) by agent + independently rerun by root; real CLI fleet run resolved auth.bsky.social→auth-api as observed. Open: protocol/proxy modeling, alias provenance on links. |

| 2026-10-16 (night) | AM044 | Watch correctness (C31) implemented | Win32 loop switched to ReadDirectoryChangesW with path-aware filtering that reuses OUTPUT_MARKER + generated_artifact_names; debounce burst→one scan preserved; pending-dirty during analysis with exactly one follow-up after completion (dropped on user cancel); repository switching stops the previous watcher; fleet watch shows an explicit "1 of N" notice; platform limits surfaced. Verification: 13 new + 105 UI-suite tests + node freshness 12/0, independently rerun; live win32 loop probe (1 debounced scan, own output ignored, pending-dirty). Open: POSIX backend, true all-repo fleet watch, WebView2 visual label check. |

| 2026-10-16 (night) | AM037 | Evaluation harness + honest seed corpus (C27 infrastructure) | `attackmap evaluate` + `src/attackmap/evaluation.py`: versioned manifest with per-case rationale, repository-level seeded holdout ≥20%, shared matching semantics with bench, per-family TP/FP/FN + precision/recall + Wilson intervals, experimental flag below 30/30, no family ever hidden. Seed corpus v0.1.0: 28 cases / 10 repos (17 pos / 9 neg / 2 clean) — every label fixture-justified; both clean repos currently violated (honest FP signal). Gap to C27 targets printed in every report (repos 10/30, pos 17/300, neg 9/300, clean 2/10). Verification: 66 passed + live CLI run. Open: corpus growth toward thresholds (human-reviewed labels required). |

| 2026-10-16 (night) | AM041 | Release-readiness tooling (unsigned) | SBOM generator (re-verifies every package manifest entry, deterministic; live run over dev-20261016201719: 785 files, 50 pinned Python deps), release lock (canonical source inventory + toolchain probes), rollback procedure test on synthetic packages (install v1→v2→rollback, user files preserved, exit 0). 14 tests + docs; canonical-format test made fixture-based after the live snapshot was superseded. Open: signing certificate, clean-machine, real-release upgrade. |

| 2026-10-16 (night) | AM046 prep | Gate matrix written | docs/project_notes/m4-gate-status-2026-10-16.md: honest C01–C32 status with evidence pointers and an explicit not-faked list (C19/C24/C25/C27/C29/C32). Integration regression 3,407 passed / 6 skipped / 1 fixed. | Final package rebuild + morning summary |

| 2026-10-17 | AM014 | C13 matrix slice: identity fixtures + migration wiring | Fixture matrix (9 tests) for title edits, line drift, duplicate routes, moved files, old-baseline suppression round trips; `compare_reports` emits `legacy_id_aliases` notices (silent re-identification fixed); `collect_suppressions` accepts baseline `id_aliases`; `pipeline.py` wires baseline aliases end to end (2 CLI tests). | C13 acceptance review; per-instance removal tracking intentionally absent |

| 2026-10-17 | AM016 | C14 claim-support slice: closed-set states | `assess_claim_support` (`supported_by_cited_evidence` only on deterministic token presence in cited captured spans, else `not_assessed`) wired through hunt consensus, narrative `reference_validation`, and defensive-review JSON (schema 1.5.0 additive); `review_eval` rejects proof verbs on citations; redaction verified across all nine prompt paths; hostile citation-spoofing fixture rejected. 302 focused tests passed (1 env-gated skip). Live LM Studio verification at integration: real `cyberstag-security-26b-a4b-v1` call via loopback (140.96 s, 6,302/3,885 tokens, completed) produced 28 per-claim assessments, all honestly `not_assessed` on the narrative path, closed set held — evidence `.pytest_cache/m5-juice-shop/<gen>/live-claim-support-smoke.meta.json`. | Semantic entailment remains unassessed by design; narrative prompts supply no captured spans |

| 2026-10-17 | AM040 | C28 remainder: protocol/proxy/ports + alias provenance | `proxies`/`service_ports`/`service_protocols` declarations + CLI flags; scheme-aware resolution (`scheme_mismatch` candidates); `observed_via_proxy` distinct resolution never feeding trust gaps; provenance on every alias-resolved link; three-service fixture 12 calls/16 links; real CLI fleet run verified. 104 contracts/crossrepo/fleet tests passed. `fleet.py` rendering-only edits accepted by root review. | Config-file extraction; multi-backend proxies; grpc/ws |

| 2026-10-17 | AM010 | C09 Windows campaign evidence | 50 real start/cancel cycles with ignoring-graceful child: ack p95 0.000773 s (≤250 ms), tree death max 3.030 s (≤5 s), verified exit max 3.042 s; 20-way admission → exactly one launch; slot held until verified exit. `tools/c09_campaign.py` + `.pytest_cache/c09-campaign/evidence.json` + windows-process-supervision.md section. No code change required. | macOS, packaged/ARM64, HTTP-layer ack measurement |

| 2026-10-17 | AM012/AM013 | C11 conflict matrix + C12 ranking-factor exposure | 5 conflict fixtures × permutation/immutability/coverage proofs (21 tests); additive per-finding score decomposition (severity band, confidence multiplier, exploitability factors summing to raw score, source-quality filter, `not_applied` factors, unresolved assumptions) in finding contexts + report JSON; direction tests for confidence/source quality (8 tests). No score policy changed. | models.py reference field for finding→score link; trust-boundary crossing not yet fused |

| 2026-10-17 | Integration | Five-agent batch integrated and verified | Root reviewed all diffs (fleet.py rendering-only edits accepted; crossrepo proxy gates inspected), wired the missing `pipeline.py` baseline-alias pass-through with 2 end-to-end CLI tests, appended the claim-support semantics section to docs/ai-citations.md. Combined focused pass 572 passed; full regression **3,510 passed / 6 explained skips in 426.13 s** (exit 0, basetemp outside checkout; log `.pytest_cache/m5-batch-full.log`); fresh Juice Shop scan 862 files → 18 findings / 266 routes, zero analyzer errors, report carries the new ranking decomposition and claim-support fields; live LM Studio claim-support call completed (above). | Package rebuild deferred — engine changes will need a new dev package identity before installed-engine re-verification |

| 2026-10-17 | AM041/AM006 | Development package dev-20261017193157-2f19d5a3 with the integrated engine delivered and installed-verified | Full re-freeze from `617f4bd` (124-file snapshot inventory; 107 core modules, 276 payload files, 19 analyzers; worker scan + compare + diagnostics actions verified through the frozen exe). Package ZIP SHA256 871ee933…3df8; installed as current. Installed verification: Juice Shop scan exit 0 (18 findings, zero analyzer errors, decomposition + claim_support fields present); diagnostics CLI redacted; menu/retention/history/scan smokes all exit 0 (backslash paths); **C06 packaged Unicode/space-path fleet matrix**: serial + 2-worker × json/markdown/all on Czech-diacritic + space paths → 5 warm runs with one identical normalized digest; **C28 flags on frozen engine** produce observed_via_proxy / service_ports / scheme_mismatch / hosts resolutions. Evidence: `.pytest_cache/package-verification/installed-package-verification-2026-10-17.json`. | Two recorded anomalies: first-launch exit 1 with no output (suspect AV first-run scan; not reproduced warm — clean-machine first-launch check belongs to C29), and analyzer pin drift dev-.venv vs freeze venv (270 vs 266 routes incl. EXPOSE surfacing; findings identical 18=18). C06 clean-machine leg stays open |

| 2026-10-17 | Audit | Mimosa deep scan completed; 10 engine-source findings dispositioned | Scan `scan-2026-10-17T19-52-20.280Z-3fdd21eef98c` (seal 1c46a933…5a76) returned 54 findings; coverage partial, offline advisory DB unavailable. All 10 findings in maintained `src/attackmap` reviewed one by one in [mimosa-audit-dispositions-2026-10-17](project_notes/mimosa-audit-dispositions-2026-10-17.md): 3 loopback-only placeholder keys, 1 reproducibility RNG, 2 opt-in/constant-destination network features, 2 false positives (docstring example, local UI transport), 2 schema/channel-guarded desktop paths — none actionable; two optional hardening notes recorded (`--offline` modules listing, `quote(vuln_id)`). Remaining 44 findings point at test harnesses, byte-identical package-artifact copies, and deliberate vuln fixtures. Not a safety certification — coverage was partial. | Optional hardening follow-ups only; rescan when advisory DB is reachable |

| 2026-10-17 | AM009 | C08 consumer-compatibility matrix closed at contract level | `test_consumer_compatibility_matrix` (4 kinds × 4 modes via `parse_run_message`): accepts current 1.1 + previous 1.0, drops injected additive unknowns (top-level and nested), rejects major 2.0 with the supported range and upgrade/export action (message now derived from `SUPPORTED_SCHEMA_VERSIONS`, cannot drift); adapter test proves `/api/state` publishes its range from contract constants independent of app version. 40 focused tests green. | CLI/supervisor end-to-end envelope emission, macOS consumer, `fixtures/run-contract/faults/` corpus wiring |

| 2026-10-17 | AM011 | C10 Windows interrupted-write leg delivered | Real-OS NTFS matrix in `tests/test_artifact_publisher.py` (17 new tests + `tests/fixtures/interrupted_publish_worker.py` kill harness): child `TerminateProcess` mid-write of run-manifest/artifact-manifest/pointer tmp (genuine partial bytes), hard kill pre-commit (stray tmp proven unswapped), 12 crash-remnant mangles through the real validator, real share-mode lock during switch (WinError 5). Every case: complete previous or new generation current, never a mixture; terminal diagnostics without replacing current; half-published runs can never commit; clean recovery. **No publisher defect found — `artifact_publisher.py` unchanged.** 100/100 across the four publication files. | macOS leg (tests are `skipif(non-nt)`); orchestration faults stay mock-based by design |

| 2026-10-17 | AM038 | Weak-family recall raised with labels untouched | Diagnosed and fixed heuristic gaps: BOLA ownership markers now handler-region-scoped with caller-identity-coupled query scoping and unauthenticated-write defer (`authz.py`); unauth-state-change covers admin + evidence-backed internal mutations and resolves in-handler 401/403 gates (`route_auth_fusion.py`); webhook exposure synthesizes for webhook/hook/callback paths without region-scoped signature verification. Bench: **bola 1/2→3/3, unauth 2/5→8/8, webhook 0/1→2/2, precision 100%, 0 FPs** (new paired bench case `hooks-admin-demo`, append-only). Frozen evaluate (tuning side): all three families 100%/100%, both pre-existing unauth FPs cleared; holdout recorded, never tuned against. 190 focused tests (557 incl. adjacent); Juice Shop findings byte-identical before/after. One test-pin split (`test_admin_route_not_double_reported`) justified against immutable labeled ground truth, not a score. | Corpus still 10/17+/9/2 vs 30/300/300/10 (human labels); webhook evidence same-file not route-linked; upload mutations + JS in-handler gates open |

| 2026-10-17 | AM040 | C28 config-file seam extraction delivered | `extract_deployment_aliases` in `config_scanner.py`: k8s Service/Deployment manifests, docker-compose ports, nginx upstream blocks → `DeploymentAliases` declarations with per-file provenance (`service_ports:auth-api:8443 (auth-api/k8s/service.yaml)`); malformed/conflicting/multi-backend declarations skipped with explicit reasons; CLI flags override/add. Config-only fleet run over the new three-service `deployment-seam-fleet` fixture resolved k8s port + compose port + nginx proxy (observed_via_proxy) with negative controls staying candidates. 119 focused tests green (config/contracts/fleet). | Multi-backend proxies, grpc/ws, extraction-side protocol declarations (TLS never guessed) |

| 2026-10-17 | AM043/AM014/AM016 | Formal acceptance write-ups for C30/C13/C14 | [criterion-acceptance-2026-10-17](criterion-acceptance-2026-10-17.md): clause-by-clause mapping with fresh test runs (283 passed, 1 explained env-gated skip): C30 51 fresh tests + recorded live/installed evidence; C13 35 fresh tests; C14 197 fresh tests + live LM Studio smoke. Verdicts non-overclaiming — all three "passed within recorded scope" with explicit outside-scope lists (manual Narrator pass, macOS, semantic entailment, per-instance removal tracking, dollar ceiling vacuous, findings byte-immutability regression noted). | Clauses marked qualified are listed in the document; no clause marked open |

| 2026-10-17 | AM017/AM018 | C15 layering + terminal-outcome legs delivered | Import-boundary matrix in `tests/test_application_boundary.py` (full resolver: relative, aliased, function-level imports): service layer (`pipeline`/`scan_service`/`run_contract`/`application_errors`) imports zero Typer/Click/UI/desktop modules; the 39-module analyzer-facing closure imports zero rendering/scoring modules — **zero violations, zero exceptions**. Terminal-outcome matrix (`tests/test_diagnostic_context.py` + adapters): execution failure vs degraded coverage vs policy failure are pairwise-distinct, source-free, exercised engine-direct, via CLI and the desktop-worker adapter; `diagnostics.py` now marks analyzer-error runs `coverage.status="partial"` (a dead analyzer no longer reports complete coverage). 74 + 52 consumer tests green. | Single-fixture-through-both-adapters test; macOS adapter does not exist; resource-limit-only runs keep `complete` coverage by documented design |



### First integration batch — verification record



- Owners: Codex integration agent (AM001 and integration), `guard_safety`

  (AM002), `scoped_evidence` (AM003 and independent AM004 review), and

  `result_freshness` (AM004/AM005). Base commit:

  `4366b40b52cccbb4095fb61b3a8f316b8b735132` plus the preserved user working tree

  and this batch. No PR or commit created.

- Environment: Windows 10 Pro, build 19045, AMD64; Python 3.13.15 in `.venv`,

  installed with `python -m pip install -e ".[llm,dev]"`. Dependency versions

  recorded locally in `.pytest_cache/m0-environment.txt` (pytest 9.1.1,

  Pydantic 2.14.1, Typer 0.27.3, NetworkX 3.7, PyYAML 6.0.3).

- AM001: CLI banner compatibility imports restored; README/project facts match

  source 1.5.1. Seven release identity tests pass; source and existing frozen

  `--version` both report 1.5.1. The existing frozen binary was not rebuilt with

  this patch. CI now declares Windows/Linux/macOS × Python 3.11–3.13 and installs

  Node.js 22; remote matrix results remain pending.

- AM002: 390 focused tests pass, including 194 guard safety cases across Python,

  JavaScript/TypeScript, Go, PHP, Java, and C#. Exact command:

  `python -m pytest tests/test_taint_guard_safety.py tests/test_taint_flow.py tests/test_taint_sanitizer.py tests/test_taint.py tests/test_taint_sinks.py -q`.

  Unknown/custom predicates, named collections, regexes, derived hosts, and

  transformed arguments remain conservatively unsanitized. Original fixtures

  are retained; literal-safe and reversed-condition counterparts were added.

- AM003: 100 focused tests pass across scoped evidence, analyzer, review JSON,

  review prompts, defensive review, context pack, threat model, recon translation,

  and report modules. Review JSON 1.5.0 replaces misleading runtime labels;

  external macOS consumer compatibility is unverified. Static relationships and

  exposure remain inferences; nearby auth hints do not establish enforcement.

- AM004: 68 Python UI/freshness/export tests pass, one Windows symlink-privilege

  skip. `node tests/ui_freshness.cjs` passes 12 scenarios, including 100 scan

  sequences and delayed responses during watch/native workspace changes. An

  independent review reproduced and fixed the watch-driven delayed-report race.

  Native WebView2/manual accessibility and rebuilt-package tests remain pending.

- AM005: 126 focused tests pass, one Windows permission-semantics skip. Command:

  `python -m pytest tests/test_output_exclusion.py tests/test_artifact_manifest.py tests/test_config_scanner.py tests/test_index.py tests/test_safe_fs.py tests/test_sdk_fs.py tests/test_output_format.py -q -ra`.

  Three consecutive scans in each root/nested/external output location for both

  JSON and all formats preserve exact findings and indexed source coverage.

  Manifest checksums identify only known core artifact names; replaced files,

  invalid manifests, and forged claims on arbitrary source files remain inputs.

  Legacy artifact recognition uses structure, not cryptographic provenance.

- Targeted source scan: `python -m attackmap analyze C:\tmp\juice-shop --output .pytest_cache/m0-juice-shop --format all --progress-format json`

  completed with 862 files, 266 routes, 42 taint chains, 18 findings, and zero

  analyzer errors, using the four built-in analyzers. This is not a test of all

  15 optional plugins. Artifacts and progress logs are local under `.pytest_cache`.

  The final integrated rerun in `.pytest_cache/m0-juice-shop-final` produced the

  same counts with no analyzer errors.

- Live AI smoke: the public `generate_llm_review` API consumed that Juice Shop

  report with provider `openai`, backend `api`, local placeholder key, endpoint

  `http://127.0.0.1:1234/v1`, model `cyberstag-security-26b-a4b-v1`, effort `low`,

  and 4096 maximum output tokens. It completed in 447.62 seconds with 43,238

  input tokens and 3,257 output tokens. Evidence:

  `.pytest_cache/m0-juice-shop/local-ai-smoke.meta.json`. This establishes adapter

  integration, not model accuracy or C07/C14 completion. Reading the generated

  narrative exposed remaining overclaims about anonymous access and asset

  reachability despite the static-evidence policy. AM003's end-to-end claim

  discipline and AM016's claim-support validation therefore remain open; do not

  treat this generated review as verified evidence.

- Detector benchmark: `python -m attackmap bench --output .pytest_cache/m0-benchmark`

  completes. Injection recall is 5/5, BOLA 1/2, unauthenticated state change 2/5,

  and webhook exposure 0/1. The webhook recall regression after removing

  unsupported route relationships is recorded in [benchmark notes](benchmark.md#m0-scoped-evidence-check-2026-10-15-source-151-working-tree);

  labels were not changed. The tiny corpus does not establish general quality.

- Test execution: restricted Windows pytest runs encountered temporary-directory

  ACL errors; valid integration runs use the normal user context. Put the full

  suite's temporary root outside the checkout so its non-Git-directory fixture

  cannot inherit this repository. No macOS/Linux run is claimed.

- Final full suite after all agent edits stabilized:

  `.venv\Scripts\python.exe -m pytest -q -ra --basetemp=<unique directory under the user TEMP outside the checkout>`

  returned **2,684 passed, 6 skipped in 139.25 seconds**, exit 0, with no collection

  errors. Local log: `.pytest_cache/m0-final-full.log`. Skips: two optional PHP

  plugin tests (plugin not installed), one explicitly opt-in authenticated Claude

  CLI test (not run; live AI uses LM Studio), two POSIX chmod semantics tests on

  Windows, and one symlink privilege test on Windows. These skips do not pass

  missing-plugin or other-platform release gates.

- Packaging: `python -m pip wheel --no-deps --wheel-dir .pytest_cache/m0-dist .`

  built `attackmap-1.5.1-py3-none-any.whl`. All 98 current package source/assets

  were compared byte-for-byte with the wheel; no mismatch. SHA-256:

  `182f8d9ce00efc5e0a22966dfa6e31cd4a76bdcb968abbd3402ec7d25eec3e70`.

  Log: `.pytest_cache/m0-final-wheel.log`. `git diff --check` passed.

- User handoff: current subagents finish only their assigned work and are then

  stopped. Future subagents use **GPT-6.1 Sol** (`gpt-6.1-sol`), recorded in

  `AGENTS.md` and project facts. M0 is still open until AM006–AM008 and the full

  release/platform proof are complete.

  All three subagents have now finished and been stopped; no follow-on assignment

  was started. Open task checkboxes reflect remaining acceptance proof and

  documented limitations, not active agent processes.



## Decision log



| Decision | Status | Required evidence or next step |

| --- | --- | --- |

| Platform-specific native design | Confirmed by user, 2026-10-15 | Carry into both prototypes and all usability reviews |

| WinUI 3 Windows shell | Preferred, pending spike | AM024 measurement and migration decision |

| SwiftUI macOS direction | Preferred, existing plan to verify | AM019 actual-repository inventory and AM025 integration slice |

| Supported OS and architectures | Unassigned | AM019 support matrix with available verification hosts |

| Bundled versus discovered engine | Unassigned per platform | AM024/AM025 decision; verify packages in AM041/AM042 |

| Shared evidence and run schemas | Planned | AM009 compatibility policy and golden fixtures |

| General-release signing credentials | Availability unverified | Identify during AM019; needed to close AM041/AM042 |

| Team/hosted capability | Deferred | AM053 demand, cost, and go/no-go decision |



## Weekly review checklist



- Review failed gates and evidence before adding new scope.

- Update task owners, statuses, dependencies, and the delivery log.

- Check Windows/macOS parity and outstanding accessibility defects.

- Record actual measurements beside the roadmap thresholds.

- Keep unresolved experimental capabilities visible in the supported-scope statement.

- Re-estimate the next milestone from current staffing and measured work.

- Choose the next ready tasks without increasing work in progress unnecessarily.



Use milestone closure as the progress signal. Task counts are useful inventory, but AM004 and AM054 have very different costs and should not contribute equally to a claimed completion percentage.





### Second integration batch — GPT-6.1 Sol (2026-10-15)



- AM006: private JSON worker interchange independent of presentation; frozen-aware launch; ordered results and successful siblings preserved on failures. Changed scan_service.py, CLI option, fleet parallelism tests and packaged smoke script. Focused verification: 49 passed. Actual rebuilt frozen execution remains pending; C06 stays open.

- AM007: missing/failed/malformed votes abstain; every verdict needs a strict majority of planned votes; otherwise inconclusive. Reports label model assessments. Focused verification: 66 passed, including 1,365 vote arrangements. Root integrated inconclusive/abstention/failure metadata and corrected CLI help. AM008 privacy and AM016 claim support remain open.

- AM019: source-backed inventory in [desktop platform inventory](desktop-platform-inventory-2026-10-15.md), including actual macOS repository at 5f2e8b4d84f9dff06e0f87c69c861a434981bd6a. Signing/notarization infrastructure exists in source. Runtime parity, credentials, supported targets and named hosts remain unverified; C16 stays open.

- All three agents used GPT-6.1 Sol. No real AI calls or commits were needed for this batch. Integrated test result follows below.



- Integrated full run: 2,711 passed, 6 explained skips, one fleet configuration-error regression in 139.76s. The regression was then fixed: missing suppress-file configuration stops serial and parallel fleets with CLI exit 2; per-repository policy failures still preserve siblings. Focused post-fix run (fleet modules plus unreadable/fleet failures): 52 passed, 1 Windows chmod skip in 8.77s. The complete suite was not repeated after this focused fix. Full log: `.pytest_cache/sol-integration-full.log`. `git diff --check` passed. AM006 remains open for packaged proof.





### Windows M3 target execution (2026-10-15)



User explicitly selected Windows M3 as the active goal. Three GPT-6.1 Sol lanes:

AM009 run-contract foundation/adapter (new contract/schema files), AM008 privacy

(config/secrets/runner), AM020/AM021/AM024 bounded WinUI feasibility/design

(desktop/windows and dedicated design/decision docs). Root owns existing server,

frontend integration, global documentation and regression verification. Existing

working changes are preserved. M0/M1/M2 gates remain required; macOS delivery is

outside the current implementation focus and is not implicitly certified.



Initial findings: native spike host has .NET runtime but no SDK; no native build,

Narrator, Windows11 performance or usability-study proof may be claimed. Root

corrected optional-network disclosures, generic secure-store failure response,

and unbounded-stage fabricated percentage display. Full M3 remains active/open.





Windows foundation results: AM009 adds run_contract.py, four schemas, shared

fixtures, explicit current/previous compatibility and legacy adapter. Root wired

ui/contract_adapter.py into /api/state as runContract with adapter scope; active

run repository identity remains stable on workspace selection changes. Policy

and artifact integrity remain unverified, so this does not close C08/C10.

AM008 Windows privacy adds fail-closed DPAPI storage, exact loopback credential

handling, inherited provider-env stripping, payload disclosures and sentinel

tests. UI secure-store errors are generic; arbitrary remote endpoints need a key.

Full foundation run: 2,758 passed, 6 explained skips in 172.13s

(.pytest_cache/m3-foundation-full.log). Subsequent server adapter integration:

77 passed; final endpoint/adapter/contract assertions: 42 passed. Full suite was

not repeated after that additive endpoint integration. No complete M3 gate is

claimed. Workspace-local .NET8 SDK8.0.426 installed for native feasibility;

actual native build result is pending.





Windows M3 continuing work: isolated WinUI project now builds with zero warnings/

errors and publishes a self-contained development folder (511 files,229298005

bytes). Published startup still fails with XamlParseException/0xC000027B;

root requested continued XAML isolation, so C20 remains open. Neither process

liveness nor synthetic10k source fixture is native UI/performance acceptance.

Next parallel lanes are AM010 process-tree supervision (runner/spawn and scoped

cancel endpoint) and AM012 provenance-preserving normalized Signal merge.

Initial supervisor fixtures prove exclusive admission under20 simultaneous calls

and controlled descendant cleanup; full50-cycle/p95/platform proof pending.

No M3 completion is claimed; active goal remains Windows desktop beta.





### Windows integration checkpoint — 2026-10-15



- Complete integrated regression suite after contract/server/privacy/supervision/

  provenance changes: **2,778 passed,6 explained skips in203.62s**, exit0.

  Command: `.venv/Scripts/python.exe -m pytest -q -ra --basetemp=<unique user TEMP outside checkout>`;

  evidence `.pytest_cache/m3-integrated-full.log`. Skip reasons remain optional

  PHP plugin(two), opt-in authenticated Claude CLI(one), Windows POSIX chmod(two)

  and symlink privilege(one). No release/platform gate is inferred from skips.

- AM010:77 focused tests, controlled ignoring-graceful parent/child cleanup,

  20-way admission, bounded output and async cancel HTTP acknowledgment. Windows

  Job Object assigned before resume. Slot remains held until cleanup verified;

  cleanup failure blocks restart with generic error. CLI/fleet shared supervision,

  packaged proof,50cycles and p95 remain open. See windows-process-supervision.md.

- AM012:62 focused tests; deep-copy merge, normalized Signal origins/conflicts/

  stable observation IDs, explicit coverage dedupe and legacy coverage uncertainty.

  Additional kinds, analyzer-version coverage, findings/client propagation remain

  open. See signal-merge-provenance.md.

- Native spike: workspace-local .NET8.0.426 and WindowsAppSDK2.4.0 build/publish

  pass. Missing application PRI initially caused XamlParseException; fixed via

  EnableMsixTooling while retaining unpackaged WindowsPackageType=None. Published

  `--smoke` exits0:10,000 synthetic rows loaded,filtered1,selected

  synthetic-00042,recommendation detail verified,six destinations. Evidence:

  desktop/windows/verification/native-smoke-2026-10-15.json. Real reports,

  worker lifecycle integration,Narrator/keyboard,clean installation,Windows11

  performance and usability study remain unverified; C20/M3 stay open.

- Next useful work: shared atomic publisher and common supervisor integration;

  real-report/native-worker slice before technology decision; remaining evidence

  ownership,AI budgets/citations,finding identity and desktop acceptance proof.

  Active goal remains Windows M3; no full port or accepted beta is claimed.



- Final targeted Juice Shop scan (`C:\tmp\juice-shop`, output

  `.pytest_cache/m3-juice-shop`, all format) exits 0: 862 files, 266 routes,

  42 taint chains, 18 findings, 2,378 normalized observations, no analyzer errors.

  No live AI call was required for this batch.



### Windows broker integration checkpoint — 2026-10-15



- Three GPT-6.1 Sol agents cover separate native integration, broker/supervision

  tests, and atomic-publication review scopes. Windows M3 remains the active target.

- Actual tiny-repository desktop broker completed with stdin control pipe held

  open: queued, running, completed; contiguous revisions 1–12, ready artifact,

  exit 0 in 2.53s. Run `50a96de60631467384800721bb5d0a0c` under

  `.pytest_cache/broker-integration-probe/out`. Worker stdin is now DEVNULL;

  broker reads controls without a buffered daemon stdin shutdown lock.

- Focused output-format/safe-filesystem/UI/fleet regression: **82 passed in

  20.92s**, evidence `.pytest_cache/m3-current-focused.log`.

- Postcommit flat compatibility-export errors now emit a warning while preserving

  the successfully published authoritative generation and execution outcome.

- Real native Juice Shop scan, policy-failure protocol regressions, fleet shared

  supervision and parent-generation publication are undergoing verification.

  No accepted desktop beta or accessibility/usability gate is claimed.



- Native LIVE Juice Shop scan passed via WinUI → typed desktop worker → core:

  run `e53ed4e064a94e83b5818e54f82275fc`, 862 files, 18 findings, zero analyzer

  errors, no AI usage. Current pointer plus all 19 artifact hashes/sizes verified;

  native and worker processes exited. Evidence:

  `desktop/windows/verification/native-engine-2026-10-15.json`.

- Local native settings: explicit Save/Clear, bounded/versioned atomic storage

  for absolute Python/repository paths only. 16 focused checks, Release publish,

  two-process save/restore and real-report regression passed. Evidence:

  `desktop/windows/verification/native-settings-2026-10-15.json`.

- CLI/fleet integration now stages the parent generation, binds validated child

  manifests and uses common process supervision for parallel children. Failed

  siblings preserve previous current and keep partial summary/successful child

  generations separate. Postcommit exports preflight root/child collisions and

  only copy known manifest-bound files. 51 publisher/pipeline-publication checks

  passed; integrated fleet/broker/service set: 41 passed, one platform skip

  (`.pytest_cache/m3-fleet-final.log`). A broader final regression is running.

- C21–C26 gaps are enumerated in

  `desktop/windows/verification/m3-acceptance-gap-audit-2026-10-15.md`; advanced

  workflows, accessibility, reference captures and measured performance remain

  open. Native real scan/settings evidence does not establish desktop-beta parity.



- Additional race/integrity hardening: broker accepts cancellation during artifact

  validation, emits diagnostics on invalid successful-worker results and rejects

  redirected output ancestors without resolving them away. Atomic single-repo

  responses never fall back to stale flat reports when current fails validation.

  Fleet publication cancellation resolves as cancelled/130 rather than failed.

  Seven focused real-publisher regression cases passed. Full desktop/fleet/service

  focused rerun: 21 passed; actual Windows serial/parallel matrix: 3 passed for

  all/json/markdown including Unicode paths.



### Advanced desktop integration checkpoint — 2026-10-15



- Previous goal turn made implementation/verification progress; goal remains

  Windows M3 with the original M0/M1/M2 prerequisites and C21–C26 acceptance.

- Full regression completed: **2,842 passed, 4 failed, 6 explained skips in

  500.07s**, `.pytest_cache/m3-next-full.log`. Failures were stale flat-layout

  expectations (fleet report_dir generation/marker and postcommit symlink export)

  plus a redaction test reading generation directories as files. Updated assertions

  explicitly preserve the safety property and inspect all artifact files recursively.

  Focused rerun covering these and broker/options: **115 passed in 41.45s**,

  `.pytest_cache/m3-regressions.log`. This is not recorded as a new full green run.

- Desktop request adds typed local scan options and explicit opt-in CVE enrichment;

  defaults remain no network/AI. Desktop and parallel fleet supervised workers have

  a finite 600-second timeout; desktop accepts a validated configurable override.

  Version1.0 requests without options preserve safe defaults. Schema regenerated.

- Broker now binds both artifact manifest repo_root and canonical report scan.root

  to the requested repository before publishing. Foreign artifacts fail while

  preserving previous current; no stale flat-report fallback.

- Native C22 persistent active/displayed-run metadata and coverage slice passed

  24 focused checks, Release publish, fixture/report smokes and a live Juice Shop

  scan. Evidence `desktop/windows/verification/native-run-context-2026-10-15.json`.

  Unknown engine timestamps remain unknown; client request time is labeled separately.



### Current Windows workflow and protocol checkpoint — 2026-10-15



Functional native integration now includes coverage-aware History comparison,

reasoned suppression preview/apply/undo, selected-run export and optional provider

settings/actions. This supersedes earlier statements that these slices had no

native integration; it does not close AM026–AM036 or C21–C26.



- Release publish: `.pytest_cache/m3-ten-workflows-build.log`. Actual native

  action smoke `.pytest_cache/m3-native-workflows/actions/native-actions-smoke.json`

  passes seeded comparison (1 new, 2 persisted, 1 resolved, 1 newly suppressed),

  suppression undo and provider-disabled restore. Manual dialogs are explicitly

  unaccepted. Python action-focused run: 99 passed in 3.82s

  (`.pytest_cache/m3-actions-focused.log`).

- Actual controlled runner/session QA: eight action-runner and seven engine-session

  cases pass. Evidence: `desktop/windows/verification/native-action-runner-qa-2026-10-15.json`

  and `native-engine-session-qa-2026-10-15.json`. Fake brokers are childless;

  schema/policy/revision/identity/hash/admission/EOF/race checks do not certify the

  complete UI or descendant-tree matrix.

- Five loaded native accessibility audits report zero scoped issues

  (`.pytest_cache/m3-native-accessibility.json`). This advances the earlier

  pending runtime-hook record only. Manual keyboard/Narrator, dialogs, virtualized

  rows, contrast, text scaling and C24 acceptance remain open.

- New report finding contexts expose static heuristic claims, supplied priority,

  source roles, conflicts, candidate observation references and direct static

  code flows. 38 focused tests pass; saved Juice Shop: 18 contexts, 48 candidate

  references, four direct static flows. No proximity-based control/trust claims:

  missing finding-owned control/attack-path links and score decomposition remain

  explicit unknowns. See [finding presentation](finding-presentation.md).

- Accepted/scanned-file enumeration and version provenance now support shared

  CLI/native coverage-aware comparisons. Missing coverage cannot silently become

  resolved; analyzer/config parity and runtime remediation remain unverified.

  See [comparison semantics](report-comparison.md) and

  [provenance](signal-merge-provenance.md).

- C26 reference fixture is generated and checksum verified: 10,000 findings,

  50,000 observations, exactly 20 MiB. Measurement harness exists; its handoff

  record has no qualifying performance result. A Windows 10 quick diagnostic is

  not C26 acceptance. See [reference fixture](desktop-reference-fixture.md).

- Last complete Python baseline: 2,924 passed / 6 skipped in 499.42s,

  `.pytest_cache/m3-frozen-full.log`, before subsequent integration edits. Do not

  present this as current full-suite success. Subsequent checks are scoped only.



Shortest remaining work is current-build regression/protocol/context validation,

recorded ten-workflow journeys including errors and manual dialogs, qualifying

Windows 11 performance/accessibility/visual proof, and outstanding prerequisite

credibility, packaging, participant-study and technology-decision evidence.

The detailed current ledger is [Windows M3 acceptance](windows-m3-acceptance.md).

No calendar estimate or accepted beta is asserted.



### Regression correction and responsive placement checkpoint — 2026-10-15



- The prior current full run (`.pytest_cache/m3-current-full.log`, PID 58200)

  was deliberately **aborted as an obsolete imported snapshot** after stack

  diagnosis of quadratic citation regex matching. It is neither a pass nor a

  naturally completed failure. Record: `.pytest_cache/m3-current-full-aborted.json`.

  The focused citation fix passes 68 tests; the isolated complete regex-budget

  module passes 574 in 36.08s. Replacement full regression PID 59825,

  `.pytest_cache/m3-fixed-full.log`, is running; no result is claimed.

- WindowPlacement: 33 pure helper checks plus actual two-process 1100x720

  save/restore with work-area containment true. Evidence directory:

  `.pytest_cache/placement-runtime-2a8659e83a9d4c13ae267326e8a58961`.

  Startup-monitor clamp only; DPI/multiple-monitor restoration is not accepted.

- Native viewport smokes load 18 findings with review visible: 1024x700 gives

  332-unit content height and stacked inspector; 1600x1000 gives 632-unit height

  and split inspector. Evidence `desktop/windows/verification/native-viewport-1024-2026-10-15.json`

  and `native-viewport-1600-2026-10-15.json`. Full C25 visual acceptance remains open.

- Earlier versioned development ZIP install/launch/report/uninstall proof exists

  in `desktop/windows/verification/native-development-package-2026-10-15.json`;

  it predates this snapshot and does not certify current packaging, a clean host

  or bundled engine. Fresh frozen-engine build from an isolated citation-fixed

  snapshot is underway; no new artifact or packaged execution success yet.



The next useful evidence is the replacement full-regression result and fresh

frozen execution, followed by the still-open workflow, accessibility, qualifying

performance, visual and prerequisite gates in the [acceptance ledger](windows-m3-acceptance.md).



### Integrated snapshot and full-count performance checkpoint — 2026-10-15



The replacement baseline is **3,127 passed, 6 skipped in 592.27s**

(`.pytest_cache/m3-fixed-full.log`), before later C03/provenance/C14/entry changes.

Newer focused checks pass: provenance/reports 192 in 2.61s, AI pipeline/fleet 150

in 42.46s, redirected entry four. Current full regression PID 48828,

`.pytest_cache/m3-final-integrated-full.log`, is running; no current full green is

asserted. Scoped checks do not retrospectively certify the whole snapshot.



Prior bundled development ZIP `dev-20261015124518-6a81a884` is 119,753,126 bytes,

SHA-256 `914a8fe1e027917abfb635fdddac625b92934aa6cc58417cb17696d0cbf940fd`.

Verification: `desktop/windows/verification/native-bundled-engine-package-2026-10-15.json`.

Actual frozen C# runners additionally match Juice Shop's 18 findings and normalized

IDs/severity/confidence/score with that same frozen CLI, verify manifest/report

hashes and cleanup (`native-frozen-runners-juice-current.json`). This certifies its

prior revision only. Fresh final frozen build is ongoing, with no final artifact

yet; clean-host/signing/manual installation acceptance is still separate.



The Windows 10 full-count diagnostic now completes 30 launches/30 loads,

100 sampled interactions after warmups and 100 open/close cycles. p95 Loaded

marker/report/filter/detail: 1.276s/0.950s/27.916ms/15.761ms. Loaded working set

364.24 MiB; retained working-set growth **50.28 MiB fails the 50 MiB target**.

Proof: `desktop/windows/verification/native-performance-full-2026-10-15.json`,

raw `.pytest_cache/native-performance-full-3c874d53547b4d86bde3de1024dc6a4d`.

Windows 10 and unverified action readiness do not accept C26 even with full counts.

Bounded-read optimization has 68 scoped checks; reprobe is ongoing, not a passing

replacement result. Optional Windows 11 host availability question remains pending.



See [current acceptance ledger](windows-m3-acceptance.md) for remaining gates;

finish current regression/frozen proof and inspect the reprobe before making

new current-version claims. No calendar estimate or beta acceptance is asserted.



### Latest verified checkpoint — 2026-10-15



Full integrated Python regression completed: **3,174 passed, 6 skipped in

735.40s**, `.pytest_cache/m3-final-integrated-full.log`. Final frozen engine

build, UTF-8 command checks and eight C# runner checks passed. Installed bundled

native/engine composition completed a real Juice Shop scan (18 findings, zero

errors, artifact hashes verified). See the acceptance ledger for exact proofs.



Bounded report reads reduce the observed 100-cycle retained working-set growth

from 50.28 to 30.625 MiB in a Windows 10 diagnostic reprobe; qualified C26 remains

open (one launch in reprobe, concurrent regression, no Windows 11 action-ready

proof). Two fake-analyzer test fixtures now index a one-file temporary repository:

54 checks take 1.71s instead of 245.41s without changing assertions or engine code.



Next parallel work: installed startup/report package checks; standalone native

fault-composition tests; documentation reconciliation. Root is compiling an

app-owned capture hook for 28 main-view images. Captures are review inputs, not

manual acceptance. Windows 11 accessibility/scaling/performance and outstanding

participant/prerequisite gates remain required; no M3 completion is asserted.



### Matrix correction follow-up — 2026-10-15



Initial complete Python 3.11/3.12 runs each produced 3,170 passes, six failures

and four explicit skips. A real coarse-clock run-ID collision is fixed with a

full UUID4 suffix. Five installed-plugin-dependent test assumptions are now

hermetic. Malformed npm lockfile root/nested mappings are conservatively rejected

without partial exact-resolution hints or manifest supersession. Focused suites

pass 65/85/61 cases per interpreter; inspect the focused evidence's import/log

limitations. Current full reruns and a fresh immutable frozen build are ongoing.

The earlier 3,174-pass baseline and packaged engines predate these core fixes;

no current full-matrix or final new-package acceptance is asserted.



### Verified post-matrix package checkpoint — 2026-10-15



All three corrected Windows full runs now report 3,195 passed and four explicit

skips (3.11/3.12/3.13); source and test inventories stayed unchanged during each.

Package `dev-20261015144954-78c3f581` passes installed startup/report checks and

one real installed native/engine Juice Shop scan: exit zero, 18 findings,

no supplied analyzer errors, all 19 manifest-listed artifacts verified.

See `native-post-matrix-installed-juice-2026-10-15.json` and the acceptance ledger.

The same frozen engine passes fleet format/parallel parity and guarded worker

death publication checks. Thirty actual native primary-control responses provide

a narrow Windows 10 readiness measurement, not qualified Windows 11 C26 evidence.



Next work: diagnose the separate Linux 3.12 full-suite failure, correct the

remaining overstated static/model output wording, reconcile acceptance evidence,

and retain manual/platform/participant gates as open. The immutable preview

currently open for the user must remain available during QA cleanup.



### Native command and Linux verification follow-up — 2026-10-15



Read-only C21 audit found concrete reveal/clipboard failure-handling gaps and

missing application command menus. Reveal/clipboard corrections compiled in a

separate QA output; File, Scan and View commands now reuse existing action

handlers, and picker failures preserve the selected workspace/report with an

actionable message. The combined menu build and bounded app-owned checks are

still pending; no OS dialog or keyboard-only acceptance is inferred.



Five original Linux failures pass in focused verification after correcting

omitted example inputs and POSIX process doubles. The final two expectations

now preserve exact unreadable-file diagnostics/coverage and the revised static

empty-state explanation. A fresh isolated full Linux run is active; prior

negative records remain authoritative historical evidence until a terminal

result is inspected. The actual engine scan timestamp is still unavailable;

manifest creation time must not be relabeled as scan start/completion.





### Current sealed candidate and corrective verification checkpoint — 2026-10-15



This checkpoint supersedes earlier ongoing-run/timestamp statements above for

its named scope. Candidate `dev-20261015153700-2ef7b386` is pending, not M3

accepted. Archive SHA256 `b8fcb9ec291b6831ab33fc784285365e85be3ba1dc8c70276d12e21aa4f7241a`;

native DLL `a7201cb2ecddd9eaeabd3481566e7237ce2c4298883c383a5a38fe2f92f5dce9`;

engine `b5f839a26d3f2f0bb93a77a555e75fb0b48583b89b30e85688a746f2ee43a7dd`.

Installed startup, saved-report import (18 findings), tiny actual scan with

canonical engine UTC timing and 19 verified artifacts, rollback/rollforward and

uninstall passed in the isolated Windows 10 development scope. Evidence:

`desktop/windows/verification/native-final-source-candidate-package-2026-10-15.json`.

No manual dialogs, clean host, signing or Windows 11 acceptance follows.



Final sealed Windows original regressions remain separate: 3.11 reports 3,214

passed/four skipped; 3.13 reports 3,213 passed/one PID-file synchronization

failure/four skipped; 3.12 has three wall-clock-limit failures/four skipped.

The same three 3.12 cases pass isolated in 23.59s, without relaxed limits.

Corrective full 3.12 session 58170 and corrected 3.13 50-cycle target 86238 are

active at this checkpoint. Do not label them green until terminal results are

reviewed. Original negatives remain preserved in

`desktop/windows/verification/final-source-windows-matrix-2026-10-15.json`.

Final copied-source Linux 3.12 is green: 3,213 passed/five explicit skips in

146.53s, unchanged source/test inventories; see

`desktop/windows/verification/final-source-linux312-full-2026-10-15.json`.



True engine UTC start/end are now additive run-manifest fields, explicitly

before publication and distinct from client request time or manifest created_at.

Generic redacted startup diagnostics cover atomic service requests and both

ordinary/fleet CLI requested-module preflight; storage failures preserve the

original error. Legacy/missing timing stays unknown and diagnostics remain best

effort. The final frozen engine contains these changes.



History's baseline-change setter retains old comparison rows/detail; a narrow

native presentation invalidation fix is in progress, outside this immutable

candidate. Validate that correction in a separately identified build before

claiming the journey passes. The next essential work is to inspect corrective

regression terminals and the native fix, then perform the ten manual workflows

in [Windows 11 runbook](windows-11-beta-validation.md) when a host is available.

Windows 11 remains unavailable; keyboard/Narrator/contrast/scaling, full visual

and qualifying performance campaigns, macOS, C19 participants and C20 decision

evidence remain open. No calendar estimate or M3 completion is asserted.


2026-10-17 delivery: Raw artifacts alignment fix. The WinUI `Expander`

default horizontally centers its content, so the Reports "Raw artifacts"

block rendered as an indented zig-zag (user screenshot: content column ~x530

vs card column ~x240). All four expanders now set

`HorizontalContentAlignment=Stretch`; the artifact list shows name + muted

role with joined action buttons and monospace artifact text in a raised

block. Verified with a new `--capture-reports-artifacts` mode (fixture

artifact rows, expanded expander, 1024/1600 x light/dark): pixel scan shows

every expander-region content row starting at the card column (x253 logical)

with nothing in the old centered zone, plus vision review of both themes;

evidence in `.pytest_cache/artifacts-alignment/alignment-verification.json`.

Menu-smoke passed on the published and installed builds. Packaged

`dev-20261017165121-8042887d` (SHA256 62e00ac8…0bc2) reusing the unchanged

verified frozen engine; installed as current. No engine or analyzer changes.
