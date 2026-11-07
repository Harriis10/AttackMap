# WP039 PHP route-tree preparatory slice — 2026-10-23

This is a source-bound, extraction-only implementation under the active WP039/WP042 plan. It does not close either task, the WP031/WP032/WP035/WP042 dependencies, C27/C38 maturity, a release, GUI acceptance, or either platform lane. Base HEAD: `507bddacd72a246a136ca2d46faad2aa661806c1`; the shared dirty checkout was preserved, without a commit/reset or plugin installation.

Final independently reviewed `src/attackmap/ecosystem_php.py` SHA-256:
`6b70741e058d4132d7d9a611fc2324a31ad64d0a278d2fb2d205fc27fe6a2161`.
Released to the root agent for its separate final source snapshot/build. This agent performed no freeze, packaging, GUI interaction, target-repository scan or provider calls.

## Reproduced active defect and paired result

Before editing, registration selected `attackmap.ecosystem_php.PhpLaminasAnalyzer`. Its `_ROUTE_DEF_RE` read every literal `route` value in config independently. Parent ownership, effective child URL and inherited controller/action defaults were lost. The Omeka overlay used the same regex independently and classified the detached child as a generic route.

The new nested/wrong-parent assertions first failed **4/4** against the original builtins. Original extraction was captured before source edits in [php-routes-before.json](php-routes-before.json); the same two input texts and byte hashes were used for [php-routes-after.json](php-routes-after.json). Both JSONs retain the full input source, normalized-text and raw-byte hashes, selected class, implementation hash and structured output.

| Paired input | Before routes | After routes |
| --- | --- | --- |
| Parent `/admin`, child `/item/:id` | `/admin`, `/item/:id` | `/admin/item/:id` |
| Wrong-parent negative `/public`, same child | `/public`, `/item/:id` | `/public/item/:id`; no `/admin/item/:id` |

Those paired inputs omit `may_terminate`; the parent is therefore a prefix rather than a terminal endpoint. The after output deliberately removes that false parent endpoint as well. Child route evidence remains at source line 8; inherited controller default evidence points to line 6 and the full parent/child chain. The local action default remains at line 8. Auth stays `unknown`, with no guards inferred from global auth markers.

## Focused change

- `src/attackmap/ecosystem_php.py`: one shared static returned-config reader and Laminas route-tree walker replaces the two regex route loops. It reads `[]` and `array()`, balances delimiters, ignores comments/strings as structure, follows only `router.routes` and correctly placed `child_routes`, and preserves literal separators and Segment template syntax.
- Static HTTP Literal/Segment children receive the complete parent prefix. Only parents with explicit boolean `may_terminate => true` also emit terminal routes. Sibling routes and duplicate local names keep their own ancestry. Omeka classification uses the composed path.
- Route/default hints retain file, line, symbolic controller/action/namespace values and chain evidence. Composition and inherited defaults are labelled `(inferred)`; local declarations/defaults are labelled `(observed)`. These describe configured defaults, not proof of runtime dispatch or controller-class resolution. Core retains ownership of scoring, linking, auth and analyzer provenance stamping.
- Reader limits: 1,000,000 source characters, at most 100,000 retained tokens, delimiter nesting at most 64. Exceeded bounds produce an unsupported-config hint and no partial route output. These are parser limits, not a claim of whole-engine resource containment.
- `tests/test_ecosystem_php.py`: five existing assertions/comments corrected for the composed URLs/classification. Original PHP fixture bytes are unchanged; base/current SHA-256 equality is recorded in [php-routes-result.json](php-routes-result.json).
- `tests/test_ecosystem_php_nested_routes.py`: dedicated paired/multilevel/sibling/duplicate-name/default-provenance tests and negative controls.

This adds no dependency, model/schema field, merge rule, score, registry policy or CLI option. A bounded structural reader is necessary to establish array ownership; an expanded route regex cannot safely distinguish siblings, comments and nested unrelated config arrays.

## Primary semantics checked live

Sources were read on 2026-10-23. The Laminas repository default branch `3.20.x` resolved to commit `14b147522a23a220dbbb2d68d3a68afe809952ac`; source files were fetched again at that immutable commit.

- [Official child-routing guide](https://docs.laminas.dev/tutorials/in-depth-guide/understanding-routing/): child patterns are relative, defaults are inherited and `may_terminate` defaults to false.
- [TreeRouteStack.php, lines 216–226](https://github.com/laminas/laminas-router/blob/14b147522a23a220dbbb2d68d3a68afe809952ac/src/Http/TreeRouteStack.php#L216-L226): `child_routes` creates the Part wrapper, using the explicit termination flag.
- [Part.php, lines 149–170](https://github.com/laminas/laminas-router/blob/14b147522a23a220dbbb2d68d3a68afe809952ac/src/Http/Part.php#L149-L170) and [assembly at line 209](https://github.com/laminas/laminas-router/blob/14b147522a23a220dbbb2d68d3a68afe809952ac/src/Http/Part.php#L209): matching advances by the consumed parent length; assembly concatenates the route strings. Extraction preserves repeated/trailing slashes rather than normalizing them.
- [RouteMatch.php, lines 55–60](https://github.com/laminas/laminas-router/blob/14b147522a23a220dbbb2d68d3a68afe809952ac/src/Http/RouteMatch.php#L55-L60): child parameters overwrite inherited defaults.
- [PHP name-resolution rules](https://www.php.net/manual/en/language.namespaces.rules.php): imports and current namespaces affect unqualified/qualified class references. Only canonical fully qualified Laminas/Zend route `::class` references are accepted here; documented string route-plugin aliases are handled separately.

Independent review by `/root/analyzer_catalog` caught an initial custom-class alias false positive. The final guard rejects imported `Custom\Literal`, relative namespaced `Laminas\...`, global `\Literal::class`/`\Segment::class`, and the string `'Literal::class'`. The reviewer independently confirmed six semantic probes at the final source hash; the 90-test suite was run by this implementation agent.

## Verification

Final PHP suite:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_ecosystem_php.py tests/test_ecosystem_php_nested_routes.py -q --basetemp=.tmp/wp039-php-20261023/regression-final-02 -p no:cacheprovider --junitxml=docs/verification/windows-parity/WP042/sol-ultra-20261023/php-routes-focused.xml
```

**90 passed**, 4.61 seconds. [JUnit](php-routes-focused.xml) and [source/result hashes](php-routes-result.json). This includes the pre-existing applicability, extraction protocol, merge and indexed/direct parity tests as well as the new controls. Initial sandbox pytest temporary-directory access failed with WinError 5; the same focused tests ran successfully with the authorized targeted escalation and unique temporary directories.

PHP regex subset:

```powershell
.venv/Scripts/python.exe -m pytest tests/test_regex_budget.py -q -k ecosystem_php --basetemp=.tmp/wp039-php-20261023/regex-budget-01 -p no:cacheprovider --junitxml=docs/verification/windows-parity/WP042/sol-ultra-20261023/php-routes-regex.xml
```

**66 passed, 642 deselected**, 17.14 seconds. [JUnit](php-routes-regex.xml). This ran at source stage `f9a0f0f87baa57ed226cba7a863eeeda887d8dbfc5659cd1ae029a211a72259e`; the subsequent namespace and incremental token-collection fixes did not change any regex declarations. It is scoped regex evidence rather than a final-stage full regression claim.

Three final-source boundary probes exceeded the character, retained-token and nesting limits independently: no routes, named unsupported-config hint, no crash. Observed durations were approximately 0.26 s, 0.33 s and 0.001 s, respectively; these single observations are not a performance benchmark. `git diff --check` passed for the source and existing test changes.

## Unsupported scope and upgrade decision

Explicit unsupported hints cover dynamic/concatenated/interpolated paths or ancestry, unresolved/custom route types, Method/Hostname/Scheme/Regex wrappers, `chain_routes`, empty paths (including empty Segment patterns conservatively), opaque/dynamic keys and unpacking that could change route ownership, dynamic defaults/children/termination, and malformed or nonliteral returned config. Descendants of unresolved parents never receive guessed absolute paths. Misplaced `options.child_routes`, unrelated config arrays and route-looking comment/string contents do not become routes.

Import/namespace resolution for route class aliases, translated patterns, executable/merged configuration, complex framework routing, full Segment/constraint validation and runtime dispatch are outside this slice. Controller/action class references remain symbolic source declarations. A validator elsewhere does not prove validation of this route, and an auth marker elsewhere does not prove a route guard. Generic parser-bound/unsupported hints do not yet constitute a typed per-analyzer partial-coverage ledger.

**Upstream PHP plugin upgrade: no-go as the effective fix in this lane.** Current registration appends discovered plugins after builtins and deduplicates by name before run-order sorting. The reproduced effective implementation is the builtin, so changing the external `php-laminas`/`omeka-s` pins alone cannot replace it. No external source change is being claimed or installed here, and no plugin lock was changed. The concrete alternative is this locally verified WP039 builtin extraction patch. An upstream switch still requires WP042's explicit compatibility/provenance/precedence policy and paired contract qualification; a package version is not proof of effective extraction.

Remaining acceptance belongs to the root integration lane: final source/frozen identity, complete source/frozen discovery and plugin inventory, real scan/coverage and Juice Shop non-regression, package/SBOM, native UI where affected, and the open WP031/WP032/WP035/WP042 plus C27/C38 gates. This handoff supplies none of those unperformed acceptances.
