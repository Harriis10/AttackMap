# Python web-services capabilities (`ecosystem_python`)

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
| FastAPI `include_router` prefix + dependency wiring | include call in the app module, router defined elsewhere | `fastapi_router_mount:<full-prefix>` framework hint; `Route(auth="required", guards=[include site])` upgrade |
| Flask cross-module `register_blueprint` mounts | register call + blueprint definition files | `flask_blueprint_mount:<full-prefix>` framework hint |
| Flask `before_request` auth hooks | hook registration + validated guard function body | `blueprint_auth_hook:<fn>` auth hint; `Route` auth upgrade for the blueprint's routes |
| Custom auth decorators validated at the definition site | `@<custom>` on a handler + `def <custom>` body that reads identity and rejects | `custom_auth_decorator:<name>` auth hint; `Route` auth upgrade |
| FastAPI auth dependency definitions | `def get_current_user`/`verify_*`/`require_*` whose body verifies credentials | `auth_dependency_definition` auth hint |
| Django URLconf tree | `ROOT_URLCONF` → `path(...)` → `include("pkg.urls")` recursion | net-new `Route` records (method `ANY`, `<converter:name>` → `{name}`) |
| Django per-view decorator auth | view def site resolved via the urlconf's imports | `Route(auth="required", guards=["@login_required (file:line)"])` |
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
| Django `LoginRequiredMiddleware` global auth | middleware entry in settings | all URLconf routes `Route(auth="required")`, guard names the middleware |
| Django urlconf root when `ROOT_URLCONF` is unresolvable | every `urlpatterns` module treated as a root | `django_urlconf_inferred_root` framework hint (confidence 0.5) |
| Unscoped per-request ORM lookups | `.objects.get(pk=/id=)` / `query(X).get(` with no ownership filter in the file | `orm_unscoped_lookup` auth hint (confidence ≤ 0.5; BOLA-relevant lead, core owns the finding) |

## Explicitly unsupported

- **Template dataflow** (Jinja2/Django template rendering and context
  propagation) — no template parsing, no `|safe` analysis.
- **Dynamic dependency graphs** — dependencies constructed at runtime
  (factory patterns, `Depends(get_dep_factory())`, string-based
  `include()` tuples with namespaces) are not resolved.
- **Django `re_path` / regex routes** — skipped (regex→path conversion
  would invent surface).
- **Class-based Django views** (`View.as_view()`) — auth stays `unknown`.
- **Route path correction** — per-file FastAPI/Flask routes keep their
  router-local prefix; the true mount point is documented via the
  `*_mount` framework hint instead of emitting a second (duplicate)
  Route. Avoids double-counting attack surface and BOLA candidates.
- **FastAPI/Flask route re-emission without auth** — bare routes are the
  per-file pass's output; the overlay emits `Route` records only when it
  resolves a guard (they merge onto the existing route via
  `_upgrade_route_auth`).
- **Ambiguous cross-file references** — a dotted include target
  (`module.router`) whose head symbol cannot be resolved to a file, or a
  bare router/blueprint name defined in several files, stays silent.
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
