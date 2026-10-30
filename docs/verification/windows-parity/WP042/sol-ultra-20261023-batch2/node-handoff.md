# WP039 Node/ATProto preparatory extraction slice — 2026-10-23

Scoped source implementation only. WP039/WP042, their dependencies and C27/C38 maturity remain unaccepted. No models, merge, registry, plugin pins, scoring, shared schema or GUI source was changed by this agent. No commit/reset, plugin install, external target scan, provider call or fresh freeze was performed.

Final reviewed `src/attackmap/ecosystem_node_atproto.py` SHA-256:
`0a07ba2174996189cd2b5e4c4c817cccb6c2679f3d0d048001a22395eff9360d`.
Source released to root after its independent escaped-key and opaque-slash review fixes. Base HEAD remains `507bddacd72a246a136ca2d46faad2aa661806c1` in the shared dirty checkout.

## Before/after proof

[node-before.json](node-before.json) and [node-after.json](node-after.json) retain complete paired inputs, input byte hashes, exact implementation source hashes, raw routes/hints per selected implementation, and a raw merge in actual `(priority, name)` order. All eight cases retain identical input hashes across phases; [node-result.json](node-result.json) records the comparison.

The before builtin source was `8b2f3e131bf14e9b87145d6a12df77688841612b2570eb94c4322efaa9b6f0cc`. The installed source environment was `.tools/wp024-freeze-venv/Scripts/python.exe` plus this repository's `src`.

| Paired fixture | Builtin before | Builtin after |
| --- | --- | --- |
| Subscription, literal `streamMethod`, supported direct verifier | GET / unknown, lexicon only | WS / required, handler evidence |
| Subscription, `auth: null` or optional reference | GET / unknown, lexicon only | WS / unknown, handler evidence + optional hint |
| Query, `auth: null` | GET / required, guard `null` | GET / unknown, no guard |
| Query, `ctx.authVerifier.readOptional` | GET / required, guard `ctx` | GET / unknown, optional hint |
| Query, unrelated application middleware mount | GET / required, guard `unrelatedAuth` | GET / unknown; mount observation retained |
| Query, direct supported `authVerifier` | GET / required | GET / required |

These are deterministic synthetic extraction fixtures, not executed SDK servers, full Lexicon schema validation, credential verification or runtime reachability tests. Query/procedure transports also have focused negative controls.

### Actual previous frozen engine

Read-only executable identity:
`.tmp/wp042-sol-ultra-20261023/frozen-engine-final/dist/attackmap/attackmap.exe`,
SHA-256 `341ae7a9619bbf54b1d4207c468055ff540a2ff20b9295f4b9b1109bd6e6d0fa`.

Its two canonical local static fixture scans used the unchanged `node-atproto@1.0` profile and wrote reports outside the fixture repositories. [node-frozen-before.json](node-frozen-before.json) retains report hashes and exact routes:

- Subscription `streamMethod` fixture: **2** routes, WS and GET, both at the lexicon file. The old builtin does not recognize `streamMethod`; the pinned plugin already maps subscription to WS.
- Query `auth: null` fixture: **2** GET routes, one declared in the lexicon and one at the handler with the false required guard `null`.

An earlier diagnostic used `.method(...)` for a subscription. Primary SDK review showed that this combination is rejected by the current API. It is retained explicitly as an invalid-shape parser diagnostic in [node-before-initial-method-shape.json](node-before-initial-method-shape.json), not used as canonical subscription wiring proof. Its actual frozen result was WS at the lexicon, WS at the handler and GET at the handler with guard `null`. The later canonical fixtures use `streamMethod` for subscriptions and `method` for query auth cases.

## Implementation and focused tests

- Subscription transport is `WS`; query stays GET and procedure stays POST. Literal `streamMethod` registrations are recognized. A declared registrar/type mismatch remains unwired with an explicit hint, and a stream registration without a lexicon still records WS with the existing no-lexicon hint.
- The existing bounded registration seam now balances all delimiter types, ignores strings/comments/templates as structure and reads the complete second argument. Only a direct top-level `auth` property containing an existing supported conventional verifier symbol can retain required auth. Optional/null/undefined/false references stay unknown, with `atproto:xrpc_auth_optional`; unsupported/custom expressions stay unknown with `atproto:xrpc_auth_unresolved`.
- Duplicate/escaped/computed auth keys, spreads, opaque expressions, handler-body/nested/comment/string decoys and malformed/over-bound registrations cannot certify auth. Unresolved evidence contains syntax categories rather than raw opaque config values.
- Middleware mounts remain observed auth hints. They do not certify a handler without application binding, even when a same-file or cross-file mount string covers the route path. The existing chat fixture's auth assertion is corrected to unknown; its bytes are unchanged.
- Regex versus division is deliberately unsupported. A slash outside a recognized string/comment/template hides the rest of that source line for registration extraction. Hidden candidates receive a named limitation. Any such opaque marker inside a parsed call/object rejects the parse, preventing hidden commas or auth overrides. A real registration on the next line is still found. A real call after division on the same line can remain unwired; that is an explicit conservative no-go.

Current limits remain the 1 MB per-file policy and 2,000-character registration window; delimiter depth is capped at 64. The implementation is a bounded registration/config scanner, not a JavaScript parser.

```powershell
.venv/Scripts/python.exe -m pytest tests/test_ecosystem_node_atproto.py tests/test_ecosystem_node_atproto_routes.py -q --basetemp=.tmp/wp039-node-20261023-batch2/focused-final-01 -p no:cacheprovider --junitxml=docs/verification/windows-parity/WP042/sol-ultra-20261023-batch2/node-focused-tests.xml
```

**68 passed**, 2.79 s. This includes 16 existing tests and 52 new controls. Before the patch, the selected canonical controls produced **17 failed, 2 passed**, with 25 deselected; [baseline JUnit](node-before-tests.xml) and [final JUnit](node-focused-tests.xml) are retained. All 15 tracked original `atproto-service` fixture files remain unchanged from base under normalized LF comparison; their current hashes are in the result JSON.

```powershell
.venv/Scripts/python.exe -m pytest tests/test_regex_budget.py -q -k ecosystem_node_atproto --basetemp=.tmp/wp039-node-20261023-batch2/regex-budget-01 -p no:cacheprovider --junitxml=docs/verification/windows-parity/WP042/sol-ultra-20261023-batch2/node-regex-tests.xml
```

**24 passed, 683 deselected**, 4.20 s, at source stage `9bb0a70e69c1b573f67132be8731ee0c26d049be21857ecf58868dfb36982983`. The final NUL rejection changed no regex declarations. [Scoped regex JUnit](node-regex-tests.xml). `git diff --check` passed for the changed source and existing test file. The sandbox temporary-directory restriction was handled by the authorized targeted test escalation.

## Primary semantics and effective pinned implementations

Sources were read on 2026-10-23. The current primary SDK snapshot was independently resolved to commit `3b3bb05411992daa8a67837c9a9a15e3286fb2d8`.

- [AT Protocol Lexicon specification](https://atproto.com/specs/lexicon) and [event-stream specification](https://atproto.com/specs/event-stream): queries/procedures bind to GET/POST; subscriptions carry WebSocket event streams. A WebSocket upgrade starts over HTTP, which does not make its analyzed endpoint a plain GET route.
- [SDK server.ts, lines 288–332](https://github.com/bluesky-social/atproto/blob/3b3bb05411992daa8a67837c9a9a15e3286fb2d8/packages/xrpc-server/src/server.ts#L288-L332): `method` accepts query/procedure lexicons; `streamMethod` accepts subscriptions.
- [SDK auth wrapper, lines 617–626](https://github.com/bluesky-social/atproto/blob/3b3bb05411992daa8a67837c9a9a15e3286fb2d8/packages/xrpc-server/src/server.ts#L617-L626): falsy auth config does not install a verifier. The primary [HTTP auth specification](https://atproto.com/specs/xrpc) also does not make a global marker proof of a particular endpoint's auth.
- [Pinned ATProto analyzer source](https://github.com/mlaify/attackmap-analyzer-atproto/blob/d2cb6ed6d5e69adf929a1fd7f66947830ecfd5fc/src/attackmap_analyzer_atproto/analyzer.py): already maps subscriptions to WS and emits optional/anonymous protocol hints. Its installed normalized Git blob SHA-1 `dec4a613504be4bc6d4c4913ca59179d488c4469` exactly matches the fetched immutable file; installed SHA-256 is recorded in the result JSON.
- [Pinned Node-service source](https://github.com/mlaify/attackmap-analyzer-node-service/blob/8573b4a8dcefda5518a771c1a84be93b2eb9be05/src/attackmap_analyzer_node_service/analyzer.py): broad XRPC registrations emit ANY. Its installed normalized Git blob `133b37ddfe0c6d8bc588439c91574eae241dd0f7` also matches the fetched immutable file.

Actual priorities are javascript-web 20, node-service 25, atproto 90, node-atproto 150. The three ATProto-related names coexist rather than shadowing one another. Source registration code changed concurrently in the parent lane; each capture includes its actual hash and selected classes. The extraction module and installed plugin identities are bound separately.

**Plugin-update no-go for this particular fix:** the pinned ATProto plugin already has WS transport. Updating that plugin alone would not change the separate builtin's GET mapping or its false typed auth claims. This local builtin patch is the bounded alternative. No plugin update was installed or qualified.

The complete route duplication problem remains open. The raw paired merge still has distinct declaration/handler files, and direct Node-service analysis can emit a separate ANY route when selected. Its detector does not select it in the minimal actual frozen profile fixture, so an ANY route must not be attributed to those actual frozen reports. Subscription raw route counts stay 2 before/after while identities change from conflicting GET/WS declarations to separate WS declaration/handler evidence. Generated API calls, cross-file identity fusion, custom verifier bodies/aliases and richer auth semantics remain unsupported or unresolved; conventional verifier recognition is a static association, not proof that its implementation enforces credentials.

## Root continuation gate

The same immutable canonical fixtures are available at:

- `C:\Projects\INPROGRESS\AttackMap\.tmp\wp039-node-20261023-batch2\paired\subscription_null`
- `C:\Projects\INPROGRESS\AttackMap\.tmp\wp039-node-20261023-batch2\paired\query_null_negative`

Run the root's fresh frozen executable with:

```text
<new-executable> analyze <fixture-path> --analyzer-profile node-atproto --format json --output <fresh-output-outside-fixture>
```

Compare fixture hashes to `node-before.json`/`node-after.json`, bind the new executable/source manifest, and verify resulting route method/auth/provenance and coverage. This agent supplies no fresh-frozen-after, packaging/SBOM, Juice Shop, native UI, macOS or maturity acceptance. Those remain independent root integration and active roadmap gates.

## Fresh frozen fixture verification — later update, 2026-10-23

The root's fresh engine was subsequently supplied and the two fixture runs were completed. This updates only the fresh-frozen-after deferral above; broader acceptance remains open.

Executable: `C:\Projects\INPROGRESS\AttackMap\.tmp\wp042-sol-ultra-20261023-batch2\engine-final\dist\attackmap\attackmap.exe`.
SHA-256: `487e2f368bcb5323341fc96c9b2a2597cc97d431a4c5377790b60dd9bf7b445c`.
The immutable frozen source and current Node extraction source both retain SHA-256 `0a07ba2174996189cd2b5e4c4c817cccb6c2679f3d0d048001a22395eff9360d`.

Both original canonical fixture byte hashes were verified unchanged before execution and afterward. The `verify_batch.py` `run` helper was imported with `importlib` and invoked under the requested labels [node-frozen-after-subscription](node-frozen-after-subscription/) and [node-frozen-after-query](node-frozen-after-query/), with a 180-second timeout each. Their process evidence records exit 0, no timeout, assigned owned job and verified owned-tree cleanup. Outputs are outside the fixture repositories. No source or test files were edited.

| Actual frozen fixture | Previous engine | Fresh engine |
| --- | --- | --- |
| Subscription, `streamMethod`, `auth: null` | WS + GET, both lexicon evidence | WS lexicon + WS handler evidence; both auth unknown, no guards |
| Query, `auth: null` | GET handler falsely required with guard `null` | GET handler auth unknown, no guards; GET lexicon evidence retained |

Both runs retain **2** route records. This proves the scoped transport/auth correction, not complete declaration/handler deduplication.

For each actual run, `scan.analyzer_run_ledger` in the report equals `analyzer_run_ledger` in `run-manifest.json` exactly; the compatibility copies also match their immutable run copies byte for byte. The ledger has six entries and records `resolution_complete=true`, `execution_complete=true`, profile `node-atproto@1.0`, and five successful analyzers: javascript-web, config, atproto, default and node-atproto. Node-service is explicitly skipped as unmatched, with `analysis_started=false`. There are no analyzer errors. Runtime plugin pin status remains `unverified` and builtin source status `unavailable` in that ledger; source/build attestation and the earlier independently checked pinned-file blobs remain separate evidence.

[node-frozen-after.json](node-frozen-after.json) retains the new and previous executable hashes, frozen source/build-proof hashes, fixture hashes, exact before/after route records, full analyzer ledgers, equality checks, artifact hashes, process evidence and manifest LLM-usage fields. This is actual frozen static fixture execution only. It does not close WP039/WP042, package/SBOM, Juice Shop, native UI, macOS or C27/C38 gates.
