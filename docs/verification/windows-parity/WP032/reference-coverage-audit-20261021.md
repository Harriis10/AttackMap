# WP032 modeled-reference coverage audit — read-only

This is a source/test audit, not a new suite, scan, provider, UI, or runtime pass.
The earlier 175 + 67 checks remain their recorded evidence; their totals do not
establish coverage of every reference. CodeGraph was called first and reported a
frozen index, so current exact source was read. Source hashes captured beside this
note identify this audit's bytes, not the bytes of the earlier test runs.

Scope: fleet/service identity, seam-to-source and downstream risk references,
finding-to-score/evidence references incorporated by WP032. Other product graphs
and provider citation semantic-support validation are separate tasks.

## Producer/reference matrix

| Emitted relationship | Canonical producer identity actually available | Production binding and existing fixture coverage | Remaining coverage/implementation gap |
|---|---|---|---|
| Fleet result → repository | `fleet_repo_ids(paths)` yields unique slug/suffix IDs in input order; `FleetRepoResult.repo_id` | fleet.py:42–63,67–75; scan_service.py:534–561,684–687; test_fleet.py:57–80 | Unique within this fleet, not a globally stable repository ID. Duplicate-basename config provenance still uses the basename instead of that fleet ID. |
| Contract client/server → fleet repository | `(client_repo,server_repo)` copied from supplied `(repo_id,ScanResult)` pairs | contracts.py:522–524,632–674; test_contracts.py:279,296,421; test_service_identity.py:55 | No explicit link ID, generation ID, or snapshot ID. Duplicate caller-supplied repo IDs overwrite dict entries; production `fleet_repo_ids` prevents this on its normal path. Add rejection fixture at public linker boundary if accepting arbitrary pairs is intended. |
| Contract → outbound call | Typed merge key `(target,method,file)`; normalized observation identity also includes line and method | merge.py:69–73; signal_provenance.py:39–59; contracts.py:642–650; test_contracts.py:142,173 | Contract carries location/target/method values, not the producer observation ID. Its dedup key omits target/method, collapsing distinct same-line authorities or verbs. Existing dedup fixture covers same authority/different instance IDs only. R1. |
| Contract → server route | Typed key `(path,method,file)`; normalized route observation ID derives kind/label/file and intentionally ignores line | merge.py:69; models.py:1025–1033; contracts.py:647–666; test_service_identity.py:19; test_contracts.py:75,309 | Route case survives; method normalization is explicit. Route file remains available for downstream exact binding. No named route observation ID is emitted on ContractLink. |
| Authority/alias → server identity | Fleet ID + complete root basename; normalized host/port, exact alias, declared DNS suffix, explicit port/protocol | contracts.py:321–423,526–628; test_contracts.py:207–770; test_service_identity.py:19–93 | Candidate/proxy gates covered for many cases, but no namespace-qualified Kubernetes service identity model. Do not infer namespace resolution or TLS from names. Same-line dedup can make the chosen resolution depend on call order. R1/R6. |
| Proxy → backend | `proxies:<host>` declaration; exact backend identity matching, `observed_via_proxy` separate from direct | contracts.py:568–579; config_scanner.py:675–752,838–914; tests/test_contracts.py:562–616; tests/test_config_scanner.py:423,632 | Multi-backend cases intentionally skipped. Add same name in two namespaces and ambiguous same-basename repo cases; keep candidate/unmodeled rather than invent a direct link. |
| Alias → declaring source | Provenance string key → `repo-basename/relative-file` | config_scanner.py:921–1016; contracts.py:282–315; tests/test_contracts.py:734,770; tests/test_config_scanner.py:330,459,497 | No canonical fleet repo ID, source hash, line or snapshot binding. CLI override clearing omits service_protocols; final fleet extraction occurs after child pins are cleared and may read new live bytes. R4/R5. |
| Cross-boundary flow → server taint chain | Typed taint key `(route_method,route_path,route_file,sink_kind,sink_file,sink_line)` | merge.py:84–94; crossrepo.py:75–106,131–196; test_crossrepo.py:61–168,208–235 | `_route_taint` omits `route_file` even though producer supplies it. A different handler's same-path/method chain may be borrowed. R2. Flow has no chain or link ID. |
| Cross-boundary flow → BOLA candidate | Typed key `(route_method,route_path,route_file,id_param)` | merge.py:103–105; models.py:427–437; crossrepo.py:90–104; test_crossrepo.py:91,99,168 | `_route_bola` likewise omits route_file. R2. Both helpers require direct `observed`; candidate/proxy exclusion tested at :178. |
| Trust gap → link, server route and auth map | `(repo_id,route.file,route.method,route.path)`; caller verb retained for ANY route | crossrepo.py:235–305; tests/test_crossrepo.py:242–280,331 | Server file binding is correct and missing auth defaults safe/True. Current helper trusts supplied link client/source identity; stale/unknown client refs are not revalidated against current source pairs. R7 boundary fixture. |
| Cross-repo anomaly → repo/peer route cohort | `(route_template,upper(method),repo_id)`; peer IDs come from current cohort | crossrepo.py:308–359; test_crossrepo.py:287–329,346 | Missing auth-map entries default False here, unlike trust-gap safe default. Add unknown-auth negative fixture before treating unknown as an omitted control. R8. No explicit per-peer route/observation ID emitted. |
| Finding → finding identity | Detector rule aggregate/entity ID, legacy title fallback explicitly versioned | finding_identity.py:16–71; report.py:102–117; test_finding_identity*.py | Finding IDs are per-report rule/entity IDs; use repository + generation scope when placing them in a fleet. Do not assume the same rule aggregate ID uniquely names one repository's finding globally. |
| Finding → fused exploitability score/factors | Producer selects `best_by_sink_kind(score_exploitability(...))`, but only numeric score+tier are retained | exploitability.py:139–203; threat_model.py:1604–1613; finding_presentation.py:174–217; tests/test_finding_presentation.py:47–83 | There is no score ID/ref on Finding or ExploitabilityScore. Presentation selects all equal score/tier records, including unrelated sink/route candidates, while `point_contributions` says supplied. A value match is disclosed but cannot meet an exact modeled-reference gate. R3. |
| Finding → evidence observation | `obs-<sha256(canonical normalized signal tuple)>`; exact source location produces candidates only | signal_provenance.py:39–59; finding_presentation.py:42–68,119–168; test_finding_presentation.py:86–125 | Correctly labeled candidate/unknown, not detector ownership. Taint observation identity omits `properties.route_file`, so two distinct typed chains to one shared sink can collapse to one observation with a conflict. Add identity fixture before using obs IDs as exact chain IDs. R9. IDs also lack repository/snapshot scope. |
| Finding → controls/attack paths | No detector-owned association supplied | finding_presentation.py:119–168; models.py:795–798; tests/test_finding_presentation.py:16,86,156 | Explicit unknown/empty is honest. Absence of a reference is not an incorrect reference, but WP032's requested explicit finding→evidence association remains open. Do not backfill by co-location or matching prose. |
| Single-report topology → service nodes/edges | Lowercased service hint/layout names; ServiceEdge(source,target,kind,file,evidence) | topology.py:103–215,252–300; test_topology.py:20–183; diagrams.py:61–113 | This is a separate heuristic graph, not fleet's exact identity resolver. `_service_from_url` truncates hyphenated host to first token; `_file_service_map` first-wins conflicts, while threat_model.py:331–340 uses last-wins. Add consistency/ambiguity tests; don't relabel these edges as verified fleet identity. R10. |

## Concrete minimal next fixtures / reproducer proposals

These are source-backed hypotheses and acceptance proposals, **not executed
reproducers**. See `reference-reproducer-proposals.py` for minimal pure-data
setups for R1–R3; it is deliberately not wired into canonical tests or executed.

1. **R1, high:** one client source line emits both `https://api/Api/Users/42`
   and `https://unresolved/Api/Users/42`, then reverse input order. Require the
   emitted canonical seam/resolution set to be invariant; preserve distinct
   authority declarations. Add GET + POST on one line against an ANY route and
   require caller verbs to survive (POST can produce a trust gap, GET cannot).
   Preserve existing same-authority per-instance dedup from test_contracts:142;
   don't merely add raw instance URL to the key without reviewing that policy.
2. **R2, high:** observed link identifies `public.py` GET `/items/{id}`; only
   taint/BOLA evidence belongs to `private.py` with the same route/method.
   Require no flow for public.py, and a positive control for private.py. Add
   both signal/route order permutations. Small fix scope crossrepo helpers and
   focused test_crossrepo additions; carry server file through helper signatures.
3. **R3, high:** two different sink kinds/routes receive identical numeric
   score/tier and only one producer score was selected for a finding. Require
   an exact producer reference or explicit unlinked candidate factors; never
   promote every equal-valued score to finding-owned contributions. Producer
   reference must be attached at threat_model fusion, not inferred in UI.
4. **R4, medium:** config declares service_protocols `api:https`; CLI redeclares
   that same value. Effective provenance must not retain config file ownership
   as though the CLI declaration came from that file. Repeat with a different
   scheme and assert obsolete protocol source keys are absent. Current
   scan_service.py:718–725 clears ports but not protocols; fleet test:608–618
   exercises only the port case.
5. **R5, high consistency:** child scan snapshot captures a service declaration;
   edit its protocol/port after the child completes and before fleet finalize.
   Parent aliases must remain bound to captured child bytes or be marked
   unavailable/stale; newer live config must not upgrade an old seam to observed.
   `pipeline.py:1021–1024` clears the child pin; `_finalize_fleet:751` re-extracts
   via `PassSources.for_root`, whose unpinned behavior is live. Parallel child
   processes never install their captured index in the parent. The same risk
   applies to `_finalize_fleet:756` → `anomalies.route_auth_signals:209–234`,
   which explicitly falls back to live handler bytes without an ambient pin.
   This needs a
   controlled pipeline fixture, not a real scan or relaxed snapshot acceptance.
6. **R6, bounded identity:** two repositories with basename `api`, each containing
   the same config relative path, plus two Kubernetes namespaces with Service
   name `api`. Assert candidates/unmodeled until explicit qualified identity
   exists, and ensure displayed origins distinguish the canonical repo IDs.
7. **R7, boundary:** feed an old link to helpers with no current client repo/call,
   changed client file/method, or a changed server route file. Define whether
   helpers require validated-current links as a documented precondition or reject
   them. Do not treat arbitrary ContractLink default `resolution="observed"` as
   authenticated proof; production currently supplies its own freshly built list.
8. **R8, honest unknown:** two/three authenticated peer repos and one identical
   route with absent auth-map entry. Require unknown rather than omitted-control
   anomaly; retain positive control with explicit False. The current default
   False creates a potential speculative false positive; it is not runtime proof.
9. **R9, canonical identity:** two TaintChains share method/path/sink file/line,
   but have different route_file. Typed merge must retain both (already keyed
   correctly); normalized evidence IDs must remain distinct if used as exact
   chain refs, or remain explicitly conflicted candidates rather than unique
   ownership. Include two repositories with identical relative source paths.
10. **R10, topology consistency:** `auth-api` and `auth-worker` HTTP targets from
    one explicit caller; two conflicting service_name hints on one file; service
    hint/layout disagreement. Assert no accidental single `auth` owner and no
    first-wins vs last-wins service ownership inconsistency across consumers.
    Keep the graph explicitly heuristic while exact fleet identity is separate.

## Smallest implementation sequence to request

First lease only **contracts.py + crossrepo.py + test_contracts.py +
test_crossrepo.py** for R1/R2 and explicit compatibility tests; no broad rewrite.
Run that focused set after changes, preserve existing observed/candidate/proxy
gates and case-sensitive paths. R4 is a separate tiny scan_service/test_fleet
lease. R5 requires captured deployment facts to cross the worker boundary and is
a distinct snapshot/transport design slice. R3/R9 require additive producer-owned
reference fields and a schema/fixture review across models, exploitability,
threat_model, report/finding presentation; do not fake completion through UI
inference. R6/R8/R10 can start as negative fixtures without expanding observations.

No claim here establishes TLS, mTLS, live connectivity, deployed reachability,
runtime enforcement, provider completion, or correctness of an unmodeled proxy.
WP032 should remain open until the missing reference cases are implemented and
focused acceptance evidence is actually run against one identified source basis.
