<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](../README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Python web-services capabilities (`ecosystem_python`)

Technical capability update for active WP039/WP042, 23 October 2026. The
current Python profile also includes the separately installed official `python`
plugin. Its raw regex/local-path and comment/foreign-call route observations
are not corrected by this overlay. The bounded overlay and the complete
profile therefore have different false-positive/duplicate-route limits; see
[paired qualification](../verification/windows-parity/WP039/sol-ultra-20261023-python/upstream-qualification.md).

Capability matrix for the `python-service` framework-enrichment overlay
(`src/attackmap/ecosystem_python.py`, AM052 / C38). The overlay is a thin
cross-file layer on top of the built-in `python-web` per-file analyzer; it
introduces no findings, no scoring and no report output of its own — every
signal is evidence-cited (file + line) and merges through the standard
pipeline (`merge.MERGE_SCHEMA`).

**Maturity: experimental.** Signals are deterministic and fixture-tested,
but the overlay stays flagged experimental until the C27 labeled-corpus
policy (human label review of detector expectations) passes for the
Python service families.

## Relationship to the per-file `python-web` pass

The per-file pass (scanner.py) already extracts, per file: FastAPI/Flask
route decorators with intra-file prefix resolution (`APIRouter(prefix=…)`,
`Blueprint(url_prefix=…)`, same-file `include_router` /
`register_blueprint` chains), file-level auth keyword hints
(`@login_required`, `OAuth2PasswordBearer`, inline `Depends(auth)`),
`create_engine`/`connect` database usage, `os.getenv` secret reads, and
CORS wildcards. Core's `route_auth_fusion` resolves per-route guards from
the route's **own file** (decorators, handler-signature `Depends`/
`Security`, in-handler 401/403 gates, same-file router dependencies), and
`authz` computes BOLA candidates from route + datastore signals.

The overlay only adds what that architecture structurally cannot see:
anything spanning files or requiring framework semantics.

## Supported features

### Observed (a concrete file/line construct backs the claim)

| Capability | Evidence shape | Signal |
|---|---|---|
| FastAPI `include_router` prefix + dependency wiring | exact imported app/router/dependency identities | mount hints; auth upgrade only for the exact router when every observed direct app mount has a statically validated guard; mixed public/guarded or unresolved mounts remain unknown |
| Flask cross-module `register_blueprint` mounts | exact register call + blueprint definition | mount hints; registration `url_prefix` overrides the blueprint default; repeated mounts remain distinct observations |
| Flask `before_request` auth hooks | hook registration + validated guard function body | `blueprint_auth_hook:<fn>` auth hint; `Route` auth upgrade for the blueprint's routes |
| Custom auth decorators validated at the definition site | `@<custom>` on a handler + `def <custom>` body that reads identity and rejects | `custom_auth_decorator:<name>` auth hint; `Route` auth upgrade |
| FastAPI auth dependency definitions | `def get_current_user`/`verify_*`/`require_*` whose body verifies credentials | `auth_dependency_definition` auth hint |
| Django URLconf tree | statically bound `urlpatterns`, imported `path`/`include` aliases, literal tuple includes and namespaces | `ANY` routes, converter normalization, repeated child mounts; cycles/depth/expansion limits are explicit |
| Django literal `re_path` | imported function, anchored literal regex only | normalized route; groups, alternatives, character classes and quantifiers remain unsupported |
| Django per-view decorator/wrapper auth | exact imported function and Django `login_required` identity | evidence-backed required guard; foreign or rebound names, unknown wrappers and unresolved targets remain unknown |
| Django class-based view URL | statically bound path target `ImportedView.as_view()` | route surface is retained; class/mixin/DRF auth remains unknown |
| Django middleware chain | `MIDDLEWARE = [...]` literal in settings | `django_middleware_chain` framework hint; `global_auth_middleware` auth hint (session/auth middleware present) |
| Django admin surface | `path(..., admin.site.urls)` | `django_admin_surface` framework hint |
| ORM raw SQL escapes | Django `.extra(`/`.raw(`, SQLAlchemy `text(` with a SQL literal | `DatabaseHint(kind="sql")` with escape-named evidence |
| ORM scoped queries | `.filter(<owner/user/tenant kwarg>)` | `orm_scoped_query` auth hint (strength signal) |
| Celery worker surface | `Celery(...)` application | `celery_worker` service hint; broker datastore hint (e.g. `redis`) |
| Celery task entrypoints | `@app.task` / `@shared_task` decorators | `celery_task` entrypoint hint |
| Async task dispatch | `.delay(` / `.apply_async(queue=…)` / `send_task(` | `queue://celery/<queue>` external calls (topology renders async-queue edges) |
| pydantic settings secret fields | `class X(BaseSettings)` secret-named field / `env=` alias | `SecretHint(kind="env_reference")` |
| `os.environ` secret reads | `os.environ[...]` / `os.environ.get(...)` with secret-shaped names | `SecretHint(kind="env_reference")` |
| CLI entry points | `def main()` with argparse/click/typer in the file | `cli_entrypoint` entrypoint hint |
| WSGI/ASGI boundaries | `FastAPI(`, `Flask(`, `uvicorn.run(`, `get_wsgi_application(`, `get_asgi_application(` | framework + entrypoint hints |
| Hardening middleware | `app.add_middleware(<Name>)` | `hardening_middleware:<Name>` framework hint (strength signal) |

### Inferred (heuristic, always confidence-labeled and lower-confidence)

| Capability | Basis | Signal |
|---|---|---|
| Django `LoginRequiredMiddleware` auth | exact literal ordered AuthenticationMiddleware + LoginRequiredMiddleware, scoped to resolved ROOT_URLCONF | resolved plain function views may inherit a required guard; opt-outs, unknown decorators, conflicting settings, dynamic/rebound/deleted settings and class views do not |
| Django urlconf root when `ROOT_URLCONF` is unresolvable | every `urlpatterns` module treated as a root | `django_urlconf_inferred_root` framework hint (confidence 0.5) |
| Unscoped per-request ORM lookups | `.objects.get(pk=/id=)` / `query(X).get(` with no ownership filter in the file | `orm_unscoped_lookup` auth hint (confidence ≤ 0.5; BOLA-relevant lead, core owns the finding) |

## Explicitly unsupported

- **Template dataflow** (Jinja2/Django template rendering and context
  propagation) — no template parsing, no `|safe` analysis.
- **Dynamic dependency graphs** — constructed dependencies, conditional or
  rebound router identities, factory-returned routers and runtime configuration
  remain unresolved. Direct lexical wiring inside a factory is only an observed
  declaration, not proof that the factory executes.
- **General Django regex routes** — only exact anchored literal `re_path`
  patterns are normalized; no invented regex-to-template conversion.
- **Class-based Django views** (`View.as_view()`) — auth stays `unknown`.
- **Route path correction** — per-file FastAPI/Flask routes keep their
  router-local prefix; the true mount point is documented via the
  `*_mount` framework hint instead of emitting a second (duplicate)
  Route. Avoids double-counting attack surface and BOLA candidates.
- **FastAPI/Flask route re-emission without auth** — bare routes are the
  per-file pass's output; the overlay emits `Route` records only when it
  resolves a guard (they merge onto the existing route via
  `_upgrade_route_auth`).
- **Ambiguous cross-file references** — unresolved/conditional/rebound mount
  identities produce limitations and cannot upgrade sibling route auth.
  Per-file prefix resolution is bounded; multiple mounts, cyclic ancestry and
  oversized prefixes retain the local prefix rather than choosing one mount.
- **Raw-SQL taint flows** — escapes are recorded as signals only; the
  taint pass (sources → sinks) does not trace ORM escape parameters.
- **DRF (Django REST Framework) permission classes, `APIView` sets,
  viewsets/routers** — not modeled.
- **Celery routing/schedules beyond queue names** — beat schedules,
  routing tables and task signatures beyond `queue=` are not extracted.
- **`os.environ.setdefault`, `.env` files, secret literal values** — only
  the reference is captured (`env_reference`); literal classification for
  Python source stays with the core hardcoded-secret pass.

## Merge behavior

Routes dedup by `(path, method, file)`; the per-file pass (priority 20)
runs first, and the overlay's same-key routes only fill in
`auth`/`guards`/`guard_evidence` (`_upgrade_route_auth`). Hint families
dedup by `(hint, file)`. `queue://celery/*` external calls follow the
node-service async-queue convention and are rendered as service-graph
edges by `topology.py`.

## Applicability

`detect()` requires a framework marker in first-party code or a manifest:
`from/import fastapi|flask|django|celery|starlette`, `FastAPI(`/`Flask(`/
`Blueprint(`/`Celery(`/`APIRouter(` call shapes, `urlpatterns`, or
`ROOT_URLCONF =`, or a declared dependency in requirements/pyproject/
setup/Pipfile. Plain-Python and non-Python repositories stay silent.
Test scaffolding (`tests/`, `test_*.py`, conftest) does not count toward
applicability.
