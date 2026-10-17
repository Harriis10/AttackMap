# Criterion acceptance: C30, C13, C14 — 2026-10-17

Formal clause-by-clause acceptance write-ups for C30 (Retention and
diagnostics), C13 (Finding identity), and C14 (AI boundaries). Criterion text
is quoted clause-by-clause from [roadmap-2026-2028.md](roadmap-2026-2028.md).

**Method.** Every "fresh" test count below was produced this session
(2026-10-17) with `.venv/Scripts/python.exe -m pytest <files> -q` on this
Windows 10 19045 x64 host (Python 3.13.15), against working tree `9052d98`
plus unrelated in-progress run-contract edits (`docs/run-contract.md`,
`src/attackmap/contracts.py`, `src/attackmap/run_contract.py`, three
publisher/contract test files) owned by the root session; none of those files
are exercised by the suites cited here. The full regression suite was NOT
rerun for this document. Recorded evidence produced on earlier dates is cited
with its date and was only re-read, never re-executed. Fresh totals across
all three criteria: **283 passed, 1 explained env-gated skip, 0 failures**.

Status legend: **passed** (clause proof exists and was executed or read this
session), **partial** (real evidence, explicit gap), **open** (no qualifying
proof). Engine/desktop scope is Windows; macOS is called out where it is a
gap.

---

## C30 Retention and diagnostics (AM043)

Criterion: retain the current valid generation and by default the latest 20
completed generations per repository, with a 2 GiB soft storage budget; pin
protection; redacted, source-free diagnostic export; platform-protected
credentials with fail-closed secure store; locally-bound loopback control API.

Fresh verification this session (all green):

| Suite | Result |
| --- | --- |
| `tests/test_retention.py` | 15 passed |
| `tests/test_diagnostics_export.py` | 8 passed |
| `tests/test_ui_privacy.py` | 16 passed |
| `tests/test_llm_loopback_privacy.py` | 11 passed |
| `tests/test_ui.py::test_loopback_binds_localhost_and_requires_token` | 1 passed |

### Clause-by-clause

| Clause (from C30) | Status | Proof |
| --- | --- | --- |
| Retain the current valid generation and by default the latest 20 completed generations per repository, with a 2 GiB soft storage budget | passed | `src/attackmap/retention.py` `DEFAULT_KEEP_COMPLETED = 20`, `DEFAULT_SOFT_BUDGET_BYTES = 2 * 1024**3` (read this session); `tests/test_retention.py::test_keep_window_deletes_only_oldest_unprotected` (fresh, 15-passed suite) |
| If the protected current generation exceeds that budget, retain it and show the overage | passed | `tests/test_retention.py::test_soft_budget_trims_unprotected_then_reports_overage` pins protected retention plus `budget_overage_bytes` reporting (fresh suite) |
| Users can pin a run; cleanup never removes pinned, active, or current runs | passed | `tests/test_retention.py::test_pinned_and_active_survive_beyond_window`, `test_pointer_named_current_survives_beyond_window`, `test_unpin_allows_deletion_next_pass`, `test_pin_unpin_validation` (fresh suite); desktop pin/unpin engine actions and live pin→keep / unpin→delete behavior recorded 2026-10-16 in `.pytest_cache/am043-live-evidence.json` (read this session: 2 real Juice Shop scans, unpin freed 32,988,224 bytes, current stayed valid) |
| Diagnostic export shows a preview, redacts secrets, and excludes source excerpts by default | passed | `tests/test_diagnostics_export.py` (fresh, 8 passed): `test_preview_lists_generations_current_pins_and_retention`, `test_secrets_in_terminal_diagnostics_are_redacted`, `test_report_source_content_is_never_read`, `test_export_file_matches_preview_and_is_recognized_output` (written bundle byte-identical to preview), `test_cli_preview_and_out_round_trip` |
| Stored credentials use platform-protected storage; an unavailable secure store produces an explicit error, never plaintext fallback | passed | `tests/test_ui_privacy.py` (fresh, 16 passed): `test_unsupported_secure_store_never_saves_or_loads_plaintext`, `test_secure_store_failure_preserves_existing_blob_and_hides_secret`, `test_windows_dpapi_blob_is_not_plaintext`; loopback-credential isolation additionally pinned by `tests/test_llm_loopback_privacy.py` (fresh, 11 passed) |
| Proof row: retention tests at count/size limits, interrupted cleanup recovery, pin/current invariants, sentinel-secret tests; sensitive settings never appear in report files | passed | `tests/test_retention.py::test_invalid_leftover_removed_even_inside_window`, `test_pointer_named_corrupt_generation_is_never_deleted`, `test_corrupt_pins_abort_retention_fail_closed`, `test_dry_run_reports_plan_without_deleting`, `test_staged_and_foreign_content_untouched` (fresh suite); sentinel in prompt+report: `tests/test_ui_privacy.py::test_sentinel_source_secret_is_masked_in_verification_prompt_and_report` (fresh suite) |
| Proof row: any loopback control API remains bound locally and rejects unauthenticated or disallowed-origin requests; if retired, verify its listener is gone | passed | Loopback API is not retired. `tests/test_ui.py::test_loopback_binds_localhost_and_requires_token` (fresh, 1 passed): server address is `127.0.0.1`/`localhost` and every `/api/*` request without the per-session token gets 403; binding is `ThreadingHTTPServer(("127.0.0.1", 0), …)` at `src/attackmap/ui/server.py:868`, token gate at lines 288–289/318–319 (read this session). See limitations: origin control is the token gate, not an Origin-header allowlist |

Additional recorded evidence (re-read, not re-run, this session):

- `.pytest_cache/am043-captures/` — visually reviewed History-retention captures
  (2 sizes × 2 themes) plus `installed-package-verification-2026-10-16.json`
  (dev package `dev-20261016201719-9d9074f2`; retention/history/diagnostics
  actions verified through the frozen engine, including broker pin→export
  preview-parity→unpin).
- `.pytest_cache/package-verification/installed-package-verification-2026-10-17.json`
  — dev package `dev-20261017193157-2f19d5a3`, ZIP SHA256
  `871ee933…3df8`: `retention_smoke` PASS, `history_baseline_smoke` PASS,
  `diagnostics_cli` PASS (redacted export, no secret markers), Juice Shop scan
  through the frozen engine exit 0.

### Remaining limitations

- **Manual keyboard/Narrator pass on the new retention controls is not done.**
  The History pin/unpin/export controls have automated smokes and visual
  captures but no assistive-technology pass by a human (same class of gap as
  C24). This is the main genuinely open C30 item.
- **Loopback re-check is covered by an automated test** (fresh this session:
  1 passed) proving 127.0.0.1-only binding and 403 for unauthenticated
  requests. Honest nuance: there is no explicit `Origin`-header allowlist;
  the origin control is the unguessable per-session token required on every
  `/api/*` endpoint. No cross-origin request is accepted without it.
- **Desktop and installed-engine retention evidence is Windows-only.** The
  macOS desktop retention surface has not been built or exercised.
- **Installed-engine verification used unsigned development packages**
  (`dev-20261016201719-9d9074f2`, `dev-20261017193157-2f19d5a3`). Signed
  builds and clean-machine first-launch behavior belong to C29; the
  2026-10-17 verification JSON itself records a first-launch exit-1 anomaly
  (suspected AV first-run scan; warm reruns green) that stays open under C29.
- **Retention wiring is fail-open by design**: a retention/cleanup failure
  never fails the scan (`tests/test_retention.py::test_pipeline_retention_failure_never_fails_the_scan`),
  so a skipped cleanup is visible in notices/logs rather than as a scan
  error. The 2 GiB budget is soft and enforced on cleanup passes after
  publication, so transient overage between publishes is possible.

**Verdict — C30: passed within recorded scope: engine retention (keep-20,
2 GiB soft budget, overage reporting, pin/current/active protection,
interrupted-cleanup recovery), redacted source-free diagnostics export,
fail-closed secure store, sentinel-secret, and loopback-binding clauses are
proven by 51 fresh focused tests plus recorded live and installed-engine runs
on Windows dev packages; outside scope remains: a manual keyboard/Narrator
pass on the new retention controls, the macOS desktop retention surface, and
signed/clean-machine package legs (C29).**

---

## C13 Finding identity (AM014)

Criterion: title/recommendation edits must not re-identify findings; stable
rule/entity identity with a documented collision policy; a migration adapter
for existing baselines and suppression references; unmappable records
reported, not dropped; renames resolved by explicit mapping or visibly
uncertain.

Fresh verification this session (all green):

| Suite | Result |
| --- | --- |
| `tests/test_finding_identity.py` | 24 passed |
| `tests/test_finding_identity_matrix.py` | 9 passed |
| `tests/test_pipeline_suppression_migration.py` | 2 passed |

### Clause-by-clause

| Clause (from C13) | Status | Proof |
| --- | --- | --- |
| Changing a title or recommendation does not turn an unchanged finding into new/resolved findings | passed | `tests/test_finding_identity.py::test_title_recommendation_severity_and_location_addition_do_not_replace_aggregate`; paired fixture `tests/test_finding_identity_matrix.py::test_title_and_recommendation_edit_is_persisted_not_new_or_resolved` (both fresh) |
| Stable identity uses rule and entity/location semantics with a documented collision policy | passed | Scheme documented in [finding-identity.md](finding-identity.md): `identity_scheme` is `rule-aggregate/v2`, `rule-entity/v2`, or `legacy-title/v1`; 16-hex SHA-256 over scheme+rule(+entity); titles/recommendations/severity/locations excluded from the hash. Collision policy: duplicate semantic IDs are rejected with an explicit `Ambiguous finding identity` error, never overwritten. Proven by `test_same_title_distinct_rules_have_distinct_ids`, `test_same_rule_distinct_explicit_entities_do_not_collide`, `test_duplicate_rule_identity_fails_visibly_instead_of_overwriting`, `test_dependency_entity_key_never_serializes_source_credentials` (fresh, 24-passed suite) |
| A migration adapter reads existing baselines and suppression references | passed | `legacy_id_aliases()` + `SuppressionSet(selectors, id_aliases=…)` documented with a usage snippet in [finding-identity.md](finding-identity.md); `test_existing_baseline_with_old_title_id_migrates_using_recorded_rule`, `test_baseline_adapter_migrates_old_suppression_across_title_edit` (fresh unit), plus end-to-end CLI wiring `tests/test_pipeline_suppression_migration.py` (fresh, 2 passed: legacy title-id suppression keeps applying via baseline aliases; an unaliased unrelated legacy id never suppresses) |
| Unmappable records are reported for review rather than silently dropped | passed | `test_unrecoverable_legacy_dependency_is_retained_for_review`, `test_malformed_baseline_records_are_reported_instead_of_silently_dropped`, `test_ruleless_baseline_is_retained_and_visible_for_review` (fresh suite); matrix: `test_old_baseline_migrates_via_recorded_rule_and_flags_unmappable_records`, `test_foreign_recorded_baseline_id_is_flagged_not_silently_reidentified` (fresh) |
| Renames are either resolved by an explicit mapping or visibly treated as uncertain | passed | Conservative semantics, no rename inference: `test_explicit_rule_rename_remains_new_and_resolved_without_guessed_mapping`, `test_file_rename_is_visible_as_new_instance_without_guessed_mapping`; matrix `test_migration_without_aliases_leaves_title_edited_finding_visible`. Explicit mapping is the only resolution path: the migration adapter's reviewed `id_aliases` (fresh suites) |
| Proof row: title changes, nearby line insertions, duplicate routes, moved files, and old-baseline migration fixtures; suppression reasons and provenance survive round trips | passed | Paired fixture matrix under `tests/fixtures/finding-identity/` driven by `tests/test_finding_identity_matrix.py` (fresh, 9 passed): `test_nearby_line_insertion_drifts_line_numbers_but_not_instance_identity`, `test_duplicate_routes_keep_one_identity_and_surface_only_the_new_location`, `test_moved_file_persists_identity_and_reports_new_instance_not_resolution`, `test_old_baseline_migrates_via_recorded_rule_and_flags_unmappable_records`, `test_legacy_suppression_round_trips_reason_and_provenance_through_migration` (reason/owner/ticket round-trip), `test_baseline_snapshots_round_trip_finding_ids_from_saved_reports` |

### Remaining limitations

- **Per-instance removal tracking for moved files is not implemented.** A
  moved file keeps the aggregate identity and surfaces as a new instance at
  the new path; the disappearance of the old-path instance is not separately
  tracked as a removal. This is recorded as intended semantics in the AM014
  2026-10-17 delivery-log entry, not an implemented feature.
- **`load_baseline` silent re-identification is fixed and covered.** Foreign
  or ambiguous recorded baseline ids were previously re-identified silently;
  `compare_reports` now emits `legacy_id_aliases` notices and the matrix test
  `test_foreign_recorded_baseline_id_is_flagged_not_silently_reidentified`
  pins the flagging (fresh this session).
- **Rule renames intentionally remain new/resolved findings.** There is no
  title-similarity or rename inference anywhere; an explicit reviewed alias
  is the only mapping mechanism (documented in
  [finding-identity.md](finding-identity.md)).
- **Legacy dependency recovery is grammar-bound.** Old core dependency
  records recover their entity only from the exact historical emitter grammar
  `Vulnerable dependency: name@version (ecosystem)`; anything else stays on
  legacy-title identity with a visible diff note.
- **One-time SARIF identity migration.** Explicit-rule repository-level SARIF
  results changed identity scheme; existing Code Scanning dismissals in that
  fallback scope may require review ([finding-identity.md](finding-identity.md)).
- **Evidence scope is engine-level.** The identity matrix and migration proofs
  cover the diff/baseline/suppression/CLI pipeline; desktop triage UI
  consumption of the new ids (AM032) is not part of this proof.

**Verdict — C13: passed within recorded scope: identity stability under
title/recommendation/line/location changes, documented rule+entity scheme
with explicit collision rejection, baseline/suppression migration with
visible unmappable-record handling, and the full fixture matrix (title edits,
line drift, duplicate routes, moved files, old-baseline round trips) are
proven by 35 fresh focused tests; outside scope remains: per-instance removal
tracking for moved files, any rename inference (deliberately absent), and
desktop-UI triage consumption of the new ids.**

---

## C14 AI boundaries (AM015 budgets, AM016 citations/claim support, AM007 votes)

Criterion: pre-dispatch call/time/token reservations including retries and
verification; fixed-ledger exhaustion proofs; unknown usage never reported as
zero; dollar ceilings are estimates; citations resolve only to allowed IDs
and exact snapshot spans; reference validity distinct from claim support;
redacted/minimized excerpts; embedded repository instructions cannot change
tool permissions; AI cannot rewrite deterministic findings or apply
remediation without a separate user action.

Fresh verification this session:

| Suite | Result |
| --- | --- |
| `tests/test_ai_budget.py` | 24 passed |
| `tests/test_citations.py` | 81 passed |
| `tests/test_prompt_injection.py` | 14 passed |
| `tests/test_hunt_harness.py` | 50 passed |
| `tests/test_llm_cli_isolation.py` | 9 passed, 1 skipped (env-gated live test: `ATTACKMAP_LIVE_CLI_TESTS=1` with an authenticated `claude` CLI) |
| `tests/test_review_json_claim_support.py` | 2 passed |
| `tests/test_review_eval.py` | 13 passed |
| `tests/test_review_prompts.py` | 4 passed |

### Clause-by-clause

| Clause (from C14) | Status | Proof |
| --- | --- | --- |
| Every provider call reserves a call, time, and token allowance before dispatch, including retries, generation, and verification | passed | `tests/test_ai_budget.py` (fresh, 24 passed): `test_reservations_fit_remaining_and_known_usage_refunds_only_unused_output`, `test_sdk_requests_fit_reservation_and_retries_require_new_allowance`, `test_manual_retry_is_a_second_call_and_third_is_rejected`, `test_all_hunt_lenses_and_verification_share_remaining_reservations`, `test_multiround_critic_and_skeptic_reserve_from_same_call_ledger`, `test_shared_budget_cannot_be_replaced_by_a_fresh_provider_ledger`, `test_each_dispatch_requires_unique_reservation_and_usage_overrun_blocks_next` |
| Tests with a fixed ledger prove zero calls begin after allowance exhaustion and requested output limits fit remaining reservations | passed | `test_expired_or_cancelled_reservation_cannot_dispatch`, `test_provider_dispatch_after_rendered_deadline_does_not_begin`, `test_nonfinite_or_empty_time_allowance_is_rejected`, `test_cancelled_hunt_does_not_call_any_provider` (fresh budget suite); hunt-level: `test_hunt_harness.py::test_loop_respects_token_budget`, `test_loop_respects_max_rounds_cap` (fresh, 50-passed suite) |
| Unknown provider usage is marked unknown, not zero | passed | `test_provider_missing_usage_is_unknown_and_exhausts_its_reserved_output`, `test_malformed_usage_is_unknown_instead_of_reported_zero`, `test_hunt_unknown_usage_is_never_fabricated_as_token_count` (fresh); `test_hunt_harness.py::test_budget_reservation_is_retained_when_backend_reports_no_usage`; `LlmReviewResult.usage_status` distinguishes reported/partial/unknown ([ai-budgets.md](ai-budgets.md)) |
| A dollar ceiling is an estimate unless the provider supports enforceable billing controls | passed (vacuous — no dollar ceiling is offered) | No dollar/cost parameter exists anywhere in `src/attackmap/ai_budget.py` (read this session: the ledger reserves calls, seconds, and output tokens only; module docstring states allowances "do not bound … billing"). [ai-budgets.md](ai-budgets.md) records the stance: "A dollar ceiling would remain an estimate without enforceable provider billing controls." Nothing in code or docs claims dollar enforcement, so nothing can overclaim; see limitations |
| Evidence references resolve to allowed IDs and exact snapshot spans; basename or substring matches cannot validate a citation | passed | `tests/test_citations.py` (fresh, 81 passed): `test_exact_allowed_reference_resolves_to_captured_span`, `test_exact_source_id_resolves_without_live_filesystem_guess`, `test_basename_substring_case_alias_and_unknown_span_do_not_validate`, `test_same_basename_in_different_directories_remains_distinct`, `test_only_explicit_producer_evidence_arrays_can_allowlist_ids`, `test_duplicate_producer_ids_are_ambiguous_and_rejected`; semantics documented in [ai-citations.md](ai-citations.md) (content-addressed source ids bind canonical path, exact captured line range, full file SHA-256, redacted excerpt SHA-256) |
| Reference validity remains distinct from whether evidence supports a claim | passed | Closed-set `claim_support` (`supported_by_cited_evidence` only on deterministic token presence in the cited captured span, else `not_assessed`): `test_structured_reference_without_source_is_valid_but_not_source_or_claim_support`, `test_reference_validity_alone_never_yields_support`, `test_assess_claim_support_requires_identifier_in_cited_span`, `test_assessment_vocabulary_in_cited_span_cannot_manufacture_support` (fresh); consumers wired: `tests/test_review_json_claim_support.py` (fresh, 2 passed — defensive-review weaknesses/recommendations), `tests/test_prompt_injection.py::test_consensus_report_carries_closed_set_claim_support` (fresh), `tests/test_review_eval.py::test_proof_verbs_attached_to_citations_fail` (fresh, 13 passed) |
| Proof row: fake-provider tests for multi-round budgets, retries, cancellation, missing usage, malformed citations, and unsupported claims | passed | The four core suites above, all fresh (24 + 81 + 14 + 50). Vote-citation linkage (AM007 lineage): CONFIRMED/REFUTED votes require a valid captured-source reference — `tests/test_prompt_injection.py::test_enforce_citations_downgrades_uncited_votes`, `test_replayed_compliant_output_is_not_refuted`; full consensus truth table including abstentions/inconclusive is pinned inside the fresh `test_hunt_harness.py` run (`test_consensus_complete_vote_truth_table` and neighbors) |
| Source excerpts are minimized and redacted | passed | `tests/test_citations.py::test_capture_redacts_before_retaining_or_exporting_excerpt`, `test_capture_bounds_locations_bytes_and_line_range`, `test_capture_refuses_noncanonical_or_escaping_paths`, `test_capture_refuses_symlink_even_with_follow_enabled`, `test_multiple_locations_read_same_file_once` (fresh); all nine AI prompt paths redact a hardcoded AWS key and fence/withhold injection-shaped lines: `tests/test_review_prompts.py::test_every_prompt_path_redacts_secrets_and_fences_repo_text` (fresh, 4-passed suite) |
| Embedded repository instructions cannot change tool permissions, recipients, or analysis policy | passed | `tests/test_llm_cli_isolation.py` (fresh, 9 passed): `test_claude_argv_disables_tools_project_settings_and_mcp`, `test_refuses_cli_without_hardening_flags`, `test_claude_runs_in_empty_temp_dir_never_the_repo_or_caller_cwd`, `test_subprocess_env_is_scrubbed`; repo-side injection becomes a visible low-severity finding and forged evidence ids are rejected: `tests/test_prompt_injection.py::test_injection_lines_become_a_low_severity_finding`, `test_forged_evidence_ids_embedded_in_analyzed_files_do_not_validate`, `test_citation_spoofing_text_cannot_flip_claim_support` (fresh). The live hostile-repo CLI test is env-gated and was skipped in today's run (see limitations) |
| AI cannot rewrite deterministic findings or apply remediation without a separate user action | passed (structural evidence) | Remediation is an opt-in mode (`--remediation`) that writes review-first suggestions to `remediation.md`/`remediation.meta.json` only — `src/attackmap/pipeline.py:776–802` and CLI help; both files are recognized generated outputs (`src/attackmap/artifact_manifest.py:38`) and never feed back into `attackmap-report.json`. [ai-citations.md](ai-citations.md): reference checks "cannot promote model text to deterministic findings"; targeted test `tests/test_citations.py::test_empty_context_never_promotes_uncited_or_invented_claims` (fresh). No dedicated byte-immutability regression exists — see limitations |

Recorded live evidence (re-read, not re-run, this session):
`.pytest_cache/m5-juice-shop/20261017T185044-72fb8ef8d479492dbf46bc037f445760/live-claim-support-smoke.meta.json`
(2026-10-17): one real LM Studio call (`cyberstag-security-26b-a4b-v1`, api
backend over loopback, 140.96 s, usage reported 6,302 input / 3,885 output,
stop reason completed) produced 28 per-claim assessments, all honestly
`not_assessed` on the narrative path with the closed set held.

### Remaining limitations

- **Token presence is not semantic entailment.**
  `supported_by_cited_evidence` only verifies that a cited captured span
  names an identifier/route/secret-kind that the claim's own text names. A
  hostile analyzed file that prints a claim's identifier can still earn the
  token-level state; assessment vocabulary is structurally excluded so
  spoiler text like "confirmed" cannot flip it, but semantic support is not
  assessed by design ([ai-citations.md](ai-citations.md), also stated in
  report limitations text).
- **Narrative prompts supply no captured snapshot spans**, so every
  narrative-path claim is honestly `not_assessed` even when its producer-ID
  references are valid (28/28 `not_assessed` in the recorded live smoke).
  The check never reads live source files to manufacture support.
- **Unknown-usage marking is conservative, not informational.** Missing or
  malformed usage retains the full output reservation
  (`unknown_output_usage_calls` on hunt results); it can never be refunded,
  which is the safe direction but means charged numbers can exceed actual
  usage.
- **Dollar-ceiling clause is satisfied only vacuously.** No dollar ceiling
  exists to test; [ai-budgets.md](ai-budgets.md) records that one would
  remain an estimate without enforceable provider billing controls. If a
  dollar control is ever added it must ship labeled as an estimate and carry
  its own tests — none exist today.
- **The live hostile-CLI test is environment-gated and skipped today**
  (`tests/test_llm_cli_isolation.py::test_live_hostile_repo_hooks_and_mcp_never_fire`
  requires `ATTACKMAP_LIVE_CLI_TESTS=1` and an authenticated `claude` CLI).
  Fixture-based hardening tests passed fresh; the live proof stands only on
  its recorded runs, not on this session.
- **No dedicated regression pins deterministic findings as byte-identical
  with AI features enabled.** The "cannot rewrite findings" clause rests on
  structural evidence (opt-in remediation writing only to `remediation.md`;
  narrative output persisted as its own artifact; no write path from model
  text into report findings) plus the no-promotion test above.
- **Fleet-global AI allowance is not established.** Fleet scans currently
  reject narrative/hunt/remediation/triage AI flags outright; per-repository
  ledgers only ([ai-budgets.md](ai-budgets.md)).
- **Output-token ceilings cannot be enforced on subscription CLI backends**
  (unverified output cap), so an explicit output ceiling fails closed and
  requires the API backend (`test_strict_output_budget_refuses_cli_before_dispatch`);
  the ledger also does not itself interrupt an already-running SDK request
  on cancellation — it prevents further dispatch.

**Verdict — C14: passed within recorded scope: pre-dispatch call/time/output-
token reservations across retries, generation and verification, fixed-ledger
exhaustion semantics, unknown-usage honesty, exact-span citation validation
with no basename/substring acceptance, and closed-set claim support separate
from reference validity are proven by 197 fresh focused tests (1 explained
env-gated skip) plus the recorded 2026-10-17 live LM Studio smoke; outside
scope remains: semantic entailment (token presence only), captured spans for
narrative prompts, any dollar-based ceiling (none offered), the live
hostile-CLI proof for this session, a byte-immutability regression for
deterministic findings under AI features, and fleet-global AI allowances.**
