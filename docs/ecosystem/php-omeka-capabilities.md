<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](../README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# PHP / Laminas / Omeka S — analyzer capability matrix (AM052 / C38)

Layered built-in analyzers in `src/attackmap/ecosystem_php.py`:

| Layer | Analyzer | Priority | Detects on | Claimed suffixes |
|---|---|---|---|---|
| Language | `php-web` | 20 | any non-vendored `.php` file | `.php` (generic per-file pass + layered extraction) |
| Framework | `php-laminas` | 60 | `laminas/`/`zendframework/` composer require, or a `Module.php` carrying `Laminas\`/`Zend\` markers | `.php` |
| Application | `omeka-s` | 160 | `Omeka\Module\AbstractModule` marker, or an `omeka/*` composer require | `.php` + `.phtml` (module scope) |

Each layer only enriches; detection is conservative, so a plain-PHP repo
produces no framework signals and a non-Omeka Laminas app produces no Omeka
signals (pinned by `tests/test_ecosystem_php.py`). Every hint carries
file+line evidence and an explicit `(observed)` / `(inferred)` marker.
No layer scores, ranks, or renders — that stays in core. Route-level auth
resolution, taint flow tracing, and CVE lookup all remain core-owned.

## Capability matrix

### php-web (language layer)

| Feature | Basis | Notes |
|---|---|---|
| Request-input usage (`$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES/php://input`) | observed | first occurrence per token per file |
| Input → sink co-occurrence (query/exec/mysqli_query/header/system/shell_exec/passthru/exec/popen/proc_open/eval/unserialize/include/require/file_put_contents/move_uploaded_file) | observed | request input and sink call on the *same line*; sink names stay syntax-level |
| Input → sink via same-file variable propagation | inferred | `$q = $_GET[...]` then `$pdo->query(... $q ...)`; downgraded confidence |
| `include`/`require` literal edges (incl. `__DIR__ . '...'`) | observed | target recorded verbatim, not resolved |
| Dynamic include (`include $var`) | observed | flagged as dynamic, no target guessed |
| `session_start`, `session_regenerate_id`, `$_SESSION` state | observed | regenerate-id is a positive session-fixation control |
| `setcookie` / `session_set_cookie_params` flags | observed | httponly / samesite / secure per call site; plain `setcookie` observed as `php-setcookie-no-flags` (confidence 0.6) |
| `password_hash` / `password_verify` | observed | positive credential-handling controls |
| `new PDO(...)` / `mysqli_connect` / `new mysqli` / DSN literals | observed | driver kind taken from a literal DSN when present |
| Inline PDO credentials (`new PDO($dsn, 'user', 'pass')`) | observed | emitted as a `literal` SecretHint; evidence redacted by the model layer |
| Outbound HTTP with a literal URL (`curl_init('http…')`, `CURLOPT_URL`, `file_get_contents('http…')`) | observed | URL recorded as ExternalCall |
| `curl_*` usage without a literal URL | observed | `php-curl-outbound` entrypoint hint; never an invented target |
| Output encoding: `htmlspecialchars`/`htmlentities` vs `echo $var` | observed | escaped is a control; bare `echo $var` is `php-output-unescaped` (confidence 0.6, one per file) |
| File-upload handling (`move_uploaded_file`, `$_FILES`) | observed | |
| Generic scanner pass (Laravel/Slim/Symfony routes, generic DB/auth/secret heuristics) | observed | the analyzer class delegates to `scanner.scan_files` so claiming `.php` loses nothing |

### php-laminas (framework layer)

| Feature | Basis | Notes |
|---|---|---|
| Composer `laminas/`/`zendframework/` dependency evidence | observed | `laminas (observed)` framework hint citing the require line |
| `Module.php` module identity | observed | namespace + Laminas/Zend marker |
| Router config (`'route' => '/path'` in `*.config.php` or `config/`) | observed | method `ANY` — Laminas route defs are method-agnostic at this level |
| MVC controllers (`…Controller extends AbstractActionController/AbstractRestfulController/AbstractConsoleController`) | observed | |
| Actions (`public function xAction()`), attributed to the owning class | observed | owner resolved by nearest preceding `class` in the same file |
| `'controllers' =>` wiring section | observed | |
| `'service_manager' =>` + `::class` wiring entries | observed | bracket-matched section window, not a fixed byte window |
| Middleware pipelines (`MiddlewarePipe`, `'middleware' =>`) | observed | |
| Application module lists (`'modules' => [...]`, `modules.config.php`) | observed | |
| `use Laminas\X\Y` imports per component | observed | component = first namespace segment |
| Forms / `InputFilter` / `->isValid()` | observed | surfaced as input-validation controls |
| `AuthenticationService` / Laminas ACL usage | observed | |
| Framework request input (`params()->fromQuery/fromPost/fromRoute/fromFiles`) | observed | |

### omeka-s (application overlay)

| Feature | Basis | Notes |
|---|---|---|
| Composer `omeka/*` dependency evidence | observed | |
| Omeka S module identity (`Module extends Omeka\Module\AbstractModule`) | observed | |
| `api_adapters` / `media_ingesters` / `media_renderers` config sections | observed | per-resource entrypoint hints; container sub-keys (`factories`, `invokables`, …) excluded |
| API adapter / representation classes (`extends AbstractEntityAdapter`, `extends AbstractEntityRepresentation`) | observed | |
| Route families: `/admin…` vs `/api…` vs `/s/…`/`:site-slug` vs generic | observed | trust-boundary labeling of the route surface |
| Route records from module config | observed | deduped against php-laminas at merge (first-seen wins) |
| Admin auth plugins (`identity()`, `auth()`, `Omeka\Entity\ApiKey`) | observed | identity guard is the positive control on admin controllers |
| `Omeka\Api\Manager` usage | observed | service-boundary marker (controllers reach persistence through it) |
| `Omeka\File\` store / `getFileData()` upload requests | observed | |
| View scripts (`.phtml`): `escapeHtml*` vs bare `<?= $var ?>` | observed | escaped is the control; bare short-echo of a non-`$this` variable is `php-output-unescaped` |

## Explicitly unsupported / out of scope

- **No Twig / Blade template dataflow.** View analysis covers plain
  `.phtml` short-echo and `escapeHtml`/`htmlspecialchars` only. Twig
  `{{ }}` auto-escape semantics and Blade `{{ }}`/`{!! !!}` are not modeled.
- **No dynamic route resolution.** Routes built at runtime
  (`$router->add($config['route'])`), YAML/XML route files, and child-route
  parent context (`'/item/:id'` under `'admin-board'`) are not resolved —
  child routes emit only the relative path and a generic classification.
- **No cross-file taint tracing.** Input→sink co-occurrence is line-level,
  plus one-step same-file variable propagation. Real flow tracing (source →
  propagation → sink, cross-file) stays in core's taint pass, which already
  treats PHP superglobals as sources and PDO/mysqli/header()/exec-family as
  sinks.
- **No composer dependency re-emission.** Core's SBOM pass
  (`sbom.analyze_sbom`) owns composer manifest inventory; it appends rather
  than dedups, so this module reads composer.json only for detection and
  framework evidence.
- **No runtime semantics.** `->query(` is recorded as a `query` sink call,
  not asserted to be SQL; the classification is syntax-level on purpose.
- **No session/cookie posture beyond call sites.** `php.ini` settings,
  framework-level session config, and positional `setcookie` arguments
  (flags beyond arg 7) are not decoded; only named flag keys are read.
- **No vendor/test analysis.** `vendor/`, minified files, and test paths are
  skipped by the shared `srcpaths` policy (`ATTACKMAP_INCLUDE_VENDORED` /
  `ATTACKMAP_INCLUDE_TESTS` opt back in, as everywhere in core).
- **No multi-line setcookie edge cases.** The flag window is the
  bracket-matched call; a malformed call falls back to a bounded window and
  may miss flags on continuation lines.
- **No Omeka S version-specific behavior.** Markers cover the common
  Omeka S 3/4 module layout; core-application internals (not module code)
  are out of scope.

## Maturity

**Experimental** for `php-laminas` and `omeka-s` (the metadata says so and
listings show it). `php-web`'s language extraction is fixture-pinned but the
lane as a whole stays experimental until the C27 labeled-corpus policy
passes human label review — the corpus entries contributed for this lane are
proposals for merge into `fixtures/evaluation/corpus.json`, not yet part of
the frozen evaluation corpus, and no family here should be treated as
meeting C27's 30/300/300/10 targets.

Dedup note: `php-laminas` and `omeka-s` both emit the same module-config
routes; merge order is `(priority, name)` with first-seen-wins, so
php-laminas's record wins and omeka-s's duplicate is dropped (pinned in
`test_merge_across_layers_dedups_routes`).
