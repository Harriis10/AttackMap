<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# AI allowance reservations (C14 prerequisite)

`attackmap.ai_budget.AiBudget` reserves a call, a finite remaining wall-time
allowance, and a requested **output-token** allowance before dispatch. Admission
and settlement are protected by one lock. `output_token_limit` is explicitly
output-only: it does not bound input tokens, unreported reasoning, dollars, or
provider billing. A dollar ceiling would remain an estimate without enforceable
provider billing controls.

`generate_llm_review(..., budget=ledger)` shares an explicit ledger across calls.
`budget_scope(ledger)` shares it implicitly within the current execution context.
The hunt harness creates one ledger across generation lenses, completeness
critics, rounds, and skeptic votes. Its existing `token_budget` argument now
limits reservations before every pass instead of checking only after a round.
The per-call output request is clamped to the remaining reservation. The planned
call count and a 900-second wall deadline also bound the harness when no output
ceiling is configured. An unscoped individual provider call has its own one-call
ledger and the backend's finite timeout.

The public single-repository `run_scan` entrypoint creates one shared ledger for
narrative review, hunt/jury, remediation and triage. `ScanAiLimits` defaults to
**8 provider attempts, 32,000 output tokens and 600 elapsed seconds**. The deadline
starts on entry to `run_scan`, so deterministic scanning and report preparation
also consume this elapsed allowance before the first AI request. No new ledger or
provider request is created when all AI features are off. An already-active
caller/desktop ledger is inherited without replacement: its original deadline,
cancellation and limits remain authoritative.

CLI flags `--ai-max-calls`, `--ai-output-tokens` and `--ai-timeout-seconds` configure
this per-repository allowance through the neutral `ScanRequest` contract. The
output-token limit does not cap input tokens, hidden reasoning or billing. Its
strict cap requires an API backend; subscription CLI providers fail closed before
dispatch because their output cap is unverified. `--hunt-budget 0` disables only
the hunt sublimit; the enclosing whole-scan limit still applies. The final
`run-manifest.json` records `ai_allowance` before artifact hashes and generation
publication, including unknown usage even when no numeric usage was returned.

This is **not a fleet-global AI ledger**. Fleet scans currently reject narrative,
hunt, remediation and triage flags. Serial per-repository options and parallel
child CLI arguments preserve the requested typed limits, but no aggregate fleet
AI execution or allowance is claimed. Supporting fleet AI would require a shared
parent-owned aggregate admission design, rather than separate child ledgers.

Provider-reported nonnegative integer output usage refunds unused output
reservation. Missing or malformed usage, including transport failure with unknown
billing, keeps the full reservation charged. Zero is accepted only when reported
explicitly. The ledger snapshot distinguishes reported output from charged or
reserved allowance and records unknown usage and provider-limit violations.
`LlmReviewResult.usage_status` distinguishes reported, partial and unknown usage.
Hunt results carry an `allowance` snapshot; their usage dictionary includes
`unknown_output_usage_calls` rather than estimating a token count from text length.
Skipped skeptic slots remain abstentions rather than votes.

Real SDK clients run with automatic retries disabled. Every explicit retry must
enter `generate_llm_review` again and reserve another call and output allowance;
no internal retry loop is introduced. Request timeouts fit the remaining wall
deadline. Programmatically injected custom transports must themselves honor
timeouts and avoid hidden retries; AttackMap cannot enforce behavior inside an
arbitrary caller-supplied implementation. The context must be propagated explicitly
if callers create new threads.

CLI backends have no verified output-token cap, so an explicit output ceiling
refuses CLI dispatch and asks for the API backend. Without an output ceiling,
CLI calls still reserve a call and wall time; usage may remain unknown. Cancellation
and expiry prevent further dispatch, but this ledger does not itself interrupt an
already running SDK request. Subprocess/process supervision remains separate.

Engine-created SDK clients for literal loopback endpoints use an isolated HTTP
transport with environment proxies and redirect following disabled. They use a
local credential placeholder instead of inherited cloud credentials. An explicit
local endpoint never automatically falls back to a cloud CLI when an SDK or
cloud key is missing. Remote endpoint transport defaults remain unchanged;
programmatically supplied clients remain the caller's transport responsibility.

Fake-provider tests cover concurrent admission, retry accounting, multi-lens and
multi-round generation/critic/verification sharing, timeout/cancellation checks,
remaining output limits, CLI refusal, missing usage, and duplicate dispatch.
Focused pipeline tests additionally verify one SDK attempt across two enabled
features, inherited expired ledgers, no-AI behavior, conservative unknown usage,
atomic manifest integrity, CLI typed limits and serial/parallel propagation.
This slice does not close C14: semantic claim-support acceptance remains open;
fleet-global AI allowances and every-entrypoint acceptance are not established.
The connected jury citation boundary is described in [ai-citations.md](ai-citations.md).
