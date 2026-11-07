# Independent PHP route-tree review

Reviewer: `/root/analyzer_catalog`, GPT-6.1 Sol / ultra. Read-only review of the PHP agent's `src/attackmap/ecosystem_php.py` diff and `tests/test_ecosystem_php_nested_routes.py` against the active scoped slice. CodeGraph was consulted first.

Final reviewed source SHA-256: `6b70741e058d4132d7d9a611fc2324a31ad64d0a278d2fb2d205fc27fe6a2161`.

One P2 issue was found and resolved before freeze: class-reference spellings were treated as standard route aliases without honoring PHP namespace/import rules. `use Custom\Literal; type => Literal::class` and a relative `Laminas\Router\Http\Literal::class` inside another namespace initially fabricated paths. A first correction still accepted global custom `\Literal::class`/`\Segment::class`; the final guard restricts class references to canonical fully qualified built-in names, while string aliases remain supported. The [official PHP name-resolution rules](https://www.php.net/language.namespaces.rules.php) support this distinction.

Six independent in-memory semantic probes used `_extract_laminas_route_tree` and fresh `ScanResult(root='.')`, with a returned literal router/routes tree and `/proven` path. No files were scanned, packages installed, or provider calls made.

| Type expression/context | Expected and observed paths |
| --- | --- |
| `Literal::class`, with `namespace App; use Custom\Literal;` | none |
| `Laminas\Router\Http\Literal::class`, with `namespace App;` | none |
| `\Literal::class` | none |
| `\Segment::class` | none |
| `\Laminas\Router\Http\Literal::class`, with `namespace App;` | `/proven` |
| string `'Literal'` | `/proven` |

All six assertions passed at the hash above. The author separately reports 90 focused PHP tests passing; this reviewer did not duplicate that suite.

Parent/child array ownership, default-binding inference markers, static termination behavior, unknown route auth/no invented guards, dynamic unsupported reasons, and bounded token collection were reviewed. Token collection now stops before retaining a 100001st token instead of allocating the full match list first. No remaining blocker was found within the declared literal-array HTTP route-tree subset. Dynamic imports/namespaces, source-runtime semantics, native UI, packaged builds, and ecosystem maturity remain outside this review's acceptance scope.
