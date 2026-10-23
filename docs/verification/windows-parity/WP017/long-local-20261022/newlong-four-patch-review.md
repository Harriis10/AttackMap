# Final independent four-patch review — 2026-10-23

**CLEAR for coordinated application and focused verification after root releases the live/source lease. No remaining blocking source or published-schema omission found in this exact patch set.** Patches remain unapplied and untested. This closes the source-review findings in `newlong-cross-review-initial.md` and the schema omission in `newlong-cross-review-final.md`; both earlier reports remain retained as history.

| Patch | Reviewed SHA-256 |
| --- | --- |
| newlong-budget-core.patch | 0203daf0d55f9cd06e27b6f8e29e77131f5c5b84da596d5499fb090cdddadca1 |
| newlong-budget-native.patch | 068817229f9a491a9155e7fc8b7ba9f1f5b7048bc98defcc0bc664f9a0993e2d |
| newlong-budget-runner.patch | ac5f30a4973176bcd95c9d4a33187c73af74808eea5f9d079dd8ac268cfac3b1 |
| newlong-budget-schema.patch | 3f2a5efafe24dd42400a61be2531bf910a0649b6931771e16d58b12243be25d1 |

The schema companion changes only three specific maximum values3600→7200: ProviderOptions and ProviderOptionsV13 in `schemas/run-request.schema.json`, and ProviderOptionsV13 in `schemas/run-fleet-request.schema.json`. Independent structural comparison of before/proposed JSON confirms no other changes. Defaults600, bounds/types and unrelated fleet admission metadata remain intact. Fleet AI admission remains unsupported and unchanged; sharing the provider definition does not authorize fleet AI.

All four patches passed one combined read-only applicability check:

```powershell
git apply --check docs/verification/windows-parity/WP017/long-local-20261022/newlong-budget-core.patch docs/verification/windows-parity/WP017/long-local-20261022/newlong-budget-native.patch docs/verification/windows-parity/WP017/long-local-20261022/newlong-budget-runner.patch docs/verification/windows-parity/WP017/long-local-20261022/newlong-budget-schema.patch
```

`newlong-four-patch-source-proof.json` pins all four patches and independently confirms that all13 affected active source/schema files still match the frozen before hashes. No active source/helper/schema edits, imports, tests, builds, GUI, scan or provider/model execution occurred in this review; only new evidence files were written.

The prior core/native/runner assessment still applies: configuration-owned strict literal HTTP loopback eligibility, positive ASCII optional ports, ordinary trim/case agreement, no environment/DNS promotion, remote configured ceiling3600, actual SDK remote900/local3600 ceilings, one inherited total ledger, zero retries, unchanged calls/tokens/jury, provider600/QA900 defaults, explicit7200/7800/8100 and process ceiling10800. Empty explicit ports and dangling delimiters no longer acquire the extension. No additional runtime protocol cap was found outside the coordinated model/native/runner checks; native/Python runtime uses model validation rather than the published JSON files.

## Required focused verification after actual application

Run the affected provider, shared-budget, desktop mapping/protocol, runner/verifier and native settings/request tests. Do not promote static preparation or proposed tests into execution evidence.

Published-model equality is a required gate for **both** request schemas:

1. Run the existing `tests/test_run_contract.py::test_published_schemas_match_models` request case (or its focused module). It must compare the entire published RunRequest schema to the generated schema with the existing `$schema`/supported-version adjustments.
2. Explicitly add or execute a focused full-document comparison for `FleetRunRequest.model_json_schema()` from `attackmap.desktop_fleet`: add `$schema = https://json-schema.org/draft/2020-12/schema` exactly as the publication convention requires, then compare the whole object to `schemas/run-fleet-request.schema.json`. Do not merely assert the timeout maximum. Existing fleet behavior tests do not substitute for this equality check. If the generated document differs, reconcile the schema before claiming the focused checkpoint passed.

Only after focused verification succeeds may root create a fresh source-bound freeze/native pair/package and decide whether the conditional new local-budget run remains needed. No actual model completion, saved capture, human visual/accessibility, clean-host, signing, WP017/WP023 or release acceptance closes through this review.

## Final five-patch addendum

**Full five-patch set CLEAR and ready for later coordinated application and focused testing after the live/source lease is released.** Reviewed the additional `newlong-fleet-schema-test.patch`, SHA-256 `eb519526a84ebf8af898f2aab7d05a571095395574e6231b96b85a3dbbbe5206`, alongside the four exact patch hashes above.

The new13-line `tests/test_fleet_schema_contract.py` performs whole-document equality between published `schemas/run-fleet-request.schema.json` and `FleetRunRequest.model_json_schema()` with the exact draft2020-12 `$schema` addition. It has no key filtering or timeout-only shortcut, and leaves the existing RunRequest equality test unchanged. This satisfies the requested missing test coverage in the proposed patch set; it has not yet been executed.

One combined `git apply --check` of all five patches succeeded with exit0, without application. `newlong-five-patch-source-proof.json` confirms all15 observed active source/schema files still match their frozen before hashes and the proposed new test is still absent from active `tests/`. No model/module imports, tests, source/helper writes, build, GUI, engine or provider execution occurred. Only this addendum and a new evidence proof were written.

After actual application, include the new fleet test plus existing request-schema equality and affected focused suites in the required checkpoint. Passing patch review/applicability does not establish schema equality at execution time or authorize changing the ongoing candidate/live results.
