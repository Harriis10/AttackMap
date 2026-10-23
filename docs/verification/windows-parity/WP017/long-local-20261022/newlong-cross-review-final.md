# Independent frozen-patch review — 2026-10-23

**Verdict: the three proposed code/test patches are clear for coordinated application and focused verification, but the full change is not ready until the published request schemas are included.** No runtime acceptance is implied. This supersedes the initial endpoint mismatch findings for the exact hashes below; the initial report remains retained.

| Reviewed patch | SHA-256 |
| --- | --- |
| newlong-budget-core.patch | 0203daf0d55f9cd06e27b6f8e29e77131f5c5b84da596d5499fb090cdddadca1 |
| newlong-budget-native.patch | 068817229f9a491a9155e7fc8b7ba9f1f5b7048bc98defcc0bc664f9a0993e2d |
| newlong-budget-runner.patch | ac5f30a4973176bcd95c9d4a33187c73af74808eea5f9d079dd8ac268cfac3b1 |

## Remaining omission

Published static schemas still cap the provider field at 3600:

- `schemas/run-request.schema.json:53`: `$defs.ProviderOptions.properties.timeout_seconds.maximum`.
- `schemas/run-request.schema.json:120`: `$defs.ProviderOptionsV13.properties.timeout_seconds.maximum`.
- `schemas/run-fleet-request.schema.json:77`: `$defs.ProviderOptionsV13.properties.timeout_seconds.maximum`.

An external JSON Schema validator using these contracts would reject the new 7200 request. `tests/test_run_contract.py:83-89` also requires the published request schema to equal the Pydantic-generated model schema, so leaving these files unchanged creates a known contract/test mismatch after core patch application. Add a companion schema patch with the generated absolute bound7200 while retaining defaults600. Endpoint-conditional restrictions remain enforced by runtime model/native validators; the existing published schema already omits other after-validator semantics.

No additional independent runtime request/protocol cap was found. Current native `NativeScanRequest.Serialize` validates through `NativeScanOptions`/`ProviderConfiguration`; Python `desktop_worker.run_request_file` calls `validate_desktop_request`, which dispatches to `RunRequest.model_validate` and the inherited ProviderOptions models. The worker constructs one `AiBudget` directly from `provider.timeout_seconds`. It does not load these static JSON schemas. Thus the static schema omission is a published-contract/verification blocker, not a separately observed failure of a new native7200 run.

## Resolved and preserved behavior

- Python/native extended allowance checks use configuration-owned HTTP endpoints, exact literal authorities localhost/127.0.0.1/[::1], ASCII optional ports, positive valid port semantics, no credentials/query/fragment or dangling markers, and consistent ordinary surrounding-space/case handling. Short/numeric/alternate IP aliases, empty explicit ports, signed/spaced/fullwidth ports and remote/HTTPS targets do not acquire extended allowance. Native URI normalization cannot alone promote an alias. No environment variable or DNS resolution determines eligibility.
- Provider default600 and QA900/1200/1500 stay unchanged. Remote configured allowance remains at most3600; actual SDK remote900/local3600 ceilings remain untouched. The proposed7200 is the shared total allowance, not a per-vote reset or hard global in-flight operation deadline. Token/call/jury counts remain unchanged.
- The added7200 fake-clock cases cover four1000-second calls, and consumed-time3600/3600/2100 dispatch ceilings followed by denial/abstention on the same expired ledger. These are proposed tests, not executed results.
- Runner process bound10800, explicit7200/7800/8100, strict integer/order/provenance, fixed-endpoint guard, native request/argv/process evidence and legacy900 compatibility are retained in the proposal. Existing3600/4200/4500 cases remain.
- Native label accurately discloses conditional allowance, request/proof serialization and saved local preference/remote-switch tests are included. Existing control-character endpoint normalization differences predate this change; no equivalent behavior is claimed for arbitrary malformed/unsupported URL syntax.

## Verification scope

CodeGraph was queried before additional protocol discovery; direct source/schema searches completed the indexed results. Read the exact frozen patches and current validation/serialization/worker chain. Combined `git apply --check` succeeded for all three patches without applying them. No source/helper writes, module imports, tests, GUI, scan, provider/model or build execution occurred during this review. Only this evidence report was authored. Root retains live slots and application timing.
