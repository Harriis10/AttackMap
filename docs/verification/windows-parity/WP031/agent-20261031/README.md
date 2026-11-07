# WP031 — literal imported Express handler / id-only lookup — 2026-10-31

This bounded implementation closes one reproduced BOLA coverage gap. It does
not complete WP031 or C27. BOLA and all advertised families remain experimental.
There is no native/UI, provider, frozen-package, production, maturity or release
acceptance in this evidence.

## Behavior and smallest change

Previously `authz` consulted the registration file/module's datastore hints and
broad ownership text. A handler imported from another file could be missed;
an unrelated auth hint, identity read, or a logged ownership mismatch is not an
object authorization check.

The additive producer resolves one literal ESM named/aliased/namespace import
to an exact exported function, or a zero-argument factory returning an Express
arrow handler. It accepts direct registrations and one `asyncHandler` wrapper
shape. For GET routes with a path ID it recognizes one `findOne` query whose
WHERE consists only of the request ID (directly or through one local alias),
followed by a response referencing the queried object. The finding remains a
medium-confidence **possible** BOLA candidate. It cites both the concrete
handler lookup `file:line` and its registration binding `file:line`.

Extra WHERE predicates, an explicit denial/throw, or a known policy invocation
remain outside this bounded positive claim. They are not certified safe.
Auth-only/identity/logging text does not suppress the candidate. This slice
does not change unauthenticated-write deferral or global auth fusion rules.

Dynamic imports, reexports, unknown wrappers, custom/argument-bearing factories,
shadowed import names, missing/ambiguous module files and low-quality
test/example/mock/vendor sources do not create new bound-handler evidence.
Source reads use `PassSources`, including captured bytes under an explicit or
ambient snapshot. No live read fallback was added.

## RED, focused verification and correction history

The authored fixtures are tuning/regression examples, separate from the frozen
upstream corpus. They are inline source builders in
`tests/test_authz_bound_handlers.py`; they are not production samples.

- [Decisive pre-integration RED](red-corrected.xml): **8 failed, 8 passed**.
  All eight failures are missing expected imported-handler BOLA detections.
- [Final source suite](focused-location-final.xml): **169 passed, 0 failed,
  0 errors, 0 skipped**, 28.13 seconds. This includes 25 new bounded-handler
  tests, plus existing authz, auth fusion, recall, snapshot consistency,
  evaluator and frozen-increment integrity tests.
- `git diff --check` passed for the changed source/tests and evidence.

The first attempted run failed on Windows temporary-directory ACLs. The first
qualified RED also used `scan_files`, a per-file extractor that never runs
authz; its initial result is not runtime proof. The fixture entry was corrected
to `scan_repo` / explicit snapshot-pinned `analyze_authz`, the additive
integration was temporarily absent, and the decisive RED was reproduced.
No expected fixture outcome changed in that correction. The earlier XML files
are retained and are not added to the final test count.

The first real post-implementation CLI score is retained unchanged in
[initial increment report](evaluation-increment-initial/evaluation-report.json):
**0 TP / 0 FP / 16 FN**. The scanner already emitted the correct basket
candidate, but the text evidence omitted the handler line number, so the
line-anchored label correctly remained unmatched. The producer now cites its
actual lookup `file:line`; a generic regression verifies exact source matching
and rejects the adjacent request-read line. No evaluator, matcher, corpus or
label was altered to obtain a match. This is a truthful citation-contract fix,
not a special matching rule.

## Frozen corpus results and limits

[Qualified execution ledger](evaluation-execution.json) records exact CLI
commands, exit codes, elapsed times, and before/after source and input hashes.
Both actual offline CLI commands exited **0**, with zero scan errors. The
original frozen increment files are byte-identical to the
[preimplementation inventory](preimplementation-freeze.json); membership,
seed, split, line window and labels were not changed or relabeled after score.
Sources and inputs did not change during the qualified commands.

[Final increment JSON](evaluation-increment-qualified/evaluation-report.json)
and [readable report](evaluation-increment-qualified/evaluation-report.md):

| Scope | TP | FP | FN | Meaning |
| --- | ---: | ---: | ---: | --- |
| All increment families | 1 | 0 | 15 | One BOLA gap closed; remaining 15 misses visible |
| Tuning BOLA | 0 | 0 | 0 | No BOLA samples on the DVWA tuning side |
| Holdout BOLA | 1 | 0 | 0 | One positive, one negative, one clean repository |
| All tuning families | 0 | 0 | 10 | Unchanged |
| All holdout families | 1 | 0 | 5 | Basket positive matched; other misses retained |

The matched source is `routes/basket.ts:19`, bound at `server.ts:631`.
`juice-address-owner` remains unviolated, as do all ten explicit negative
expectations and the synthetic clean repository. BOLA holdout precision and
recall are arithmetically 100%, but **each 95% Wilson interval is only
20.65%–100%**. One case is not meaningful mature-family validation.

The corpus split remains seed `20261011`, 50% fraction: DVWA tuning; Juice
Shop and the authored clean catalog holdout. There are no upstream BOLA
tuning cases; authored paired fixtures guided the bounded implementation.
Juice Shop labels/source were already exposed during WP030 and this known-gap
investigation. The final score follows the retained initial score and source
citation correction. Therefore this is a **frozen regression holdout result,
not an unseen blind holdout**. No claim of statistical independence follows.
The selected upstream slices are training applications with missing dependencies
and pending independent human label review, not representative production apps.

[Original v0.2.0 baseline](evaluation-baseline-qualified/evaluation-report.json)
is **exactly JSON-equal** to the retained WP030 baseline: all 46 expectations,
split, per-case outcomes and per-family scores are unchanged. The known
clean-node injection violation and all earlier misses remain visible.

## Reproduce

From the checkout root (use a fresh temporary directory):

```powershell
.venv/Scripts/python.exe -B -m pytest tests/test_authz_bound_handlers.py tests/test_authz.py tests/test_route_auth_fusion.py tests/test_recall.py tests/test_snapshot_consistency.py tests/test_evaluation.py tests/test_evaluation_increment.py -q -p no:cacheprovider --basetemp artifacts/wp031-recheck-temp
.venv/Scripts/python.exe -B docs/verification/windows-parity/WP031/agent-20261031/evaluate_frozen.py
```

The runner invokes the real `attackmap evaluate` CLI over increment and original
baseline and records their identities; it makes no provider calls.

## Remaining work

- Independent human label review and production-diverse, genuinely unseen
  repository holdouts remain necessary. No 30/30 BOLA or whole C27 threshold
  is met; WP031 remains open/in progress at integrator discretion.
- The `asyncHandler` transparency and `findOne` datastore interpretation are
  bounded conventions, not proof of arbitrary wrapper semantics or a runtime
  Sequelize type. Dynamic policies, aliases/reexports, arbitrary ownership
  helpers and query forms remain unsupported or conservative.
- The new slice covers object reads, not unauthorized state mutations.
  The existing unauthenticated-write/auth fusion behavior is unchanged.
- No GUI/native visual review, live LM Studio, external HTTP/provider call,
  packaged build, performance campaign or clean-host/release test ran.
- Existing shared ownership-marker heuristics outside this slice are unchanged.
