# WP014 core desktop AI mapping

This slice connects the desktop transport to existing AI service paths. All validation and tests here are offline with deterministic fake SDK providers. No live HTTP call, remote provider, subscription CLI process, product UI, package build or installed-app change is part of this evidence.

## Existing paths and smallest change

The pipeline already supports Review, Hunt, single-pass Hunt+verify, majority-jury Hunt+verify, Remediate and Triage. It already routes calls through `generate_llm_review`, maintains one inherited `AiBudget` across provider retries and jury passes, preserves captured citation contexts, and rejects subscription CLI dispatch when its output-token cap cannot be enforced. Desktop schema 1.0–1.2 previously mapped only `enable_ai` to Review with API backend. Their provider model, payload fields, defaults and default run schema **remain unchanged**. The default run schema remains **1.2**.

Explicit **schema 1.3** adds `ProviderOptionsV13` through `ScanOptionsV13`, a small `desktop_ai.py` mapper, per-schema capability metadata and a `desktop_ai` summary inside the existing publisher-bound `run-manifest.json`. Existing desktop-worker transport and its inherited budget scope already cover these paths and needed no code change. No new AI output artifact type or failure sidecar was introduced.

| Provider mode | Existing service mapping | Existing output |
| --- | --- | --- |
| `none` | All AI feature flags false | No model output; `not_requested` manifest status |
| `review` | `llm=True` | `defensive-review-llm.md` + `.meta.json` |
| `hunt` | `hunt=True` | `vulnerability-hypotheses.md` + `.meta.json` |
| `hunt_verify` | `hunt=True, verify=True` | Same hypothesis artifact; one integrated pass for jury_votes=1, existing majority harness for >1 |
| `remediate` | `remediate=True` | `remediation.md` + `.meta.json`; suggestions only |
| `triage` | `triage=True` | `triage.md` + `.meta.json`; deterministic fallback remains labeled |

`mode` defaults to null for compatibility: enabled means Review, disabled means None. An explicit mode must agree with `enable_ai`. Jury votes are optional, default to 3 for Hunt+verify, range 1–7 and are rejected for other modes. Effort maps to the existing low/medium/high/xhigh/max service argument; OpenAI's existing xhigh/max→high mapping is exposed in capabilities and persisted as requested/mapped parameters. Fast speed is accepted only for the existing fast-capable Claude API model allowlist. API backend remains mandatory: any CLI request fails before worker/application/provider dispatch because the mandatory strict output cap cannot be guaranteed there. No alternate shell/backend adapter was added. Unknown or conflicting controls are rejected rather than silently ignored. Fleet AI remains rejected.

## Output, budgets and citations

AI output remains separate from deterministic findings. The run-manifest summary distinguishes `not_requested`, `unavailable`, `fallback`, `partial` and `completed`; these describe model-output availability, not validated findings or human acceptance. Review/Hunt/Remediate failures produce no invented success Markdown/meta artifact. A completed static scan may honestly have `desktop_ai.status=unavailable`. Triage provider failure uses its existing deterministic output and `fallback` status with `model_output_available=false`.

Availability requires an output marker from this exact run, not just a matching old filename. Missing/stale artifacts cannot masquerade as current completed model output. A truncated stop reason, failed jury passes or abstaining jury votes yields `partial`. Unknown usage stays unknown separately from whether prose was returned. The same inherited ledger accounts for all attempts, elapsed time and output reservations; it is not replaced per mode, retry or jury vote. These are **output-token** allowances, not bounds on input tokens, hidden reasoning or billing. Its elapsed clock starts around the repository service invocation, not after deterministic scanning.

The first final mode run exposed an actual gap: the shared wrapper validated narrative references only for Review, so the new Remediate/Triage metadata assertion failed (54 passed, 1 failed). The approved minimal predicate extension now applies the same captured-evidence ID validator to Review, Remediate and Triage; those results are persisted in their existing metadata artifacts. Triage fallback has null model reference assessment. Hunt and Hunt+verify semantics are unchanged: their existing captured citation context, assessment kind, failed/abstained pass counts and allowance remain authoritative. Missing citation metadata is unknown; valid IDs do not prove claim support. No live files are reread to fabricate support.

## Native integration gaps — WP015 / WP016

WP015 must negotiate explicit schema 1.3 before sending these fields, while keeping the WP005 schema 1.2 producer path valid. Use `desktop.provider_options_by_schema`, `modes_by_schema` and `provider_tuning`; default/legacy clients remain on 1.2. Native mode labels must serialize the exact lower-case tokens above. Keep enablement and selected mode consistent. Disable unsupported fast/model combinations and CLI backend; show OpenAI's mapped effort and the output-only allowance scope. Native protocol/version handling must accept 1.3 for requests that actually negotiate it. No C# or settings migration was edited here.

WP016 must load the captured selected generation's manifest-bound `run-manifest.json` and its `desktop_ai` summary, then the listed Markdown/meta artifact for the selected mode. Show unavailable/fallback/partial separately from completed model prose and static scan completion. Preserve the ledger's unknown usage and citation uncertainty; do not reuse a different mode's citation state or turn reference validity into claim verification. A failed feature's absent success sidecar is intentional. Endpoint/credential handling continues through the existing worker child environment and protected native provider workflow; this slice adds no credential fields.

## Live acceptance gap — WP017

No connectivity, model response, GUI rendering, keyboard or accessibility result is inferred from these tests. WP017 still needs actual LM Studio HTTP calls to `http://127.0.0.1:1234/v1`, model `cyberstag-security-26b-a4b-v1`, and the authorized `C:\tmp\juice-shop` repository, with reports outside that repository. Real response status, mode-specific artifacts, budget behavior, citation display and deterministic findings invariance must be demonstrated separately. No switch to a remote provider is authorized by this slice.

Published run schema companions include additive 1.3; actual request admission also applies model validators for cross-field and provider/model combinations. Existing golden 1.0/1.1 fixtures and all legacy provider fields/defaults are preserved.

## Verification checkpoint

The broad offline checkpoint passed **389 tests**, with one authenticated live CLI test deliberately skipped. After the reference-validator gap was exposed and corrected, the final narrow mode/remediate/triage/narrative run passed **72 tests**. Six parametrized narrative cases cover valid and invalid IDs for all three affected modes while asserting one API dispatch, the same one-call budget, output cap and requested effort.

The retained six-mode matrix has identical `findings.json` content: **4,871 bytes**, SHA-256 `ee071c99076fc80af9d1be8e9243bfb75063f5b52c992e6d9fed52561631af49`. All six captured generations pass publisher validation. See `verification.json` for exact commands and failure history, and `matrix-evidence.json` for mode artifacts, status, allowance and mapped parameters. Temporary artifact ACLs require approved out-of-sandbox reads; the collector excludes pytest's duplicate `current` alias. These fixture results do not close native or live acceptance.
