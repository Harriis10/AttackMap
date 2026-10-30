"""Python web-services ecosystem overlay (AM052 / C38).

A framework-enrichment overlay for Python web services: cross-file,
framework-semantic signals the built-in ``python-web`` per-file pass
structurally cannot see. It follows the ``config_scanner.scan_config_repo``
delegation pattern — a whole-repo extraction returning a ``ScanResult``
that merges through the standard pipeline. Scoring stays in core; this
module only emits evidence-cited signals.

What the per-file pass already covers (and this overlay deliberately does
not re-extract): FastAPI/Flask route decorators with intra-file prefix
resolution, file-level auth keyword hints, ``create_engine``/``connect``
database usage, ``os.getenv`` secret reads, CORS wildcards (web-hardening)
and per-route auth resolution from the route's *own* file
(``route_auth_fusion``).

The gaps this overlay fills — all cross-file or framework-semantic:

- **FastAPI router wiring** — ``include_router`` calls in the app module
  carry an extra ``prefix`` and ``dependencies`` that change both the
  mounted path and auth posture. Emitted as import-bound mount hints plus
  ``Route`` auth upgrades only for the exact router when all its observed
  direct mounts carry a validated blocking dependency. Their
  ``(path, method, file)`` match the per-file routes, so the merge's
  ``_upgrade_route_auth`` fills the guard in without duplicating surface.
  Cross-file mounted URLs are not re-emitted; unresolved/dynamic wiring
  remains explicit and cannot certify route auth.
- **Flask blueprint wiring** — cross-module ``register_blueprint`` mounts
  and ``before_request`` auth hooks, which per-route resolution never sees.
- **Custom auth decorators validated at the definition site** — a wrapper
  whose body actually checks identity and rejects (401/403) before the
  handler runs, defined in a shared module.
- **Django URLconf trees** — ``ROOT_URLCONF`` → ``include()`` recursion →
  net-new ``Route`` objects (the per-file pass extracts no Django routes),
  with per-view decorator auth, the ``MIDDLEWARE`` chain and the admin
  surface.
- **ORM query scoping** — Django ``.extra()``/``.raw()`` and SQLAlchemy
  ``text()`` raw-SQL escapes; per-request scoped vs unscoped lookups
  (BOLA-relevant authorization evidence).
- **Background/service surface** — Celery task entrypoints, broker
  datastore, and ``.delay()``/``.apply_async()`` dispatches emitted as
  ``queue://celery/<queue>`` external calls (the ``topology`` pass renders
  them as async-queue service edges, mirroring the node-service
  convention).
- **Settings and boundaries** — pydantic ``BaseSettings`` secret fields,
  ``os.environ`` secret reads, CLI entrypoints, and WSGI/ASGI boundary
  observations.

Applicability is conservative: silent on repositories without Python web
framework markers (imports, call shapes, or declared requirements).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import (
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)
from .safe_fs import max_file_bytes, read_repo_text, walk_repo
from .python_route_binding import BindingIndex
from .scanner import (
    FASTAPI_API_ROUTE_PATTERN,
    FASTAPI_DECORATOR_PATTERN,
    FLASK_ROUTE_PATTERN,
    _extract_methods,
    _join_route_parts,
    _line_of,
    _line_snippet,
    _python_route_prefixes,
)
from .srcpaths import in_skipped_dir, is_skipped_dir, is_test_file, is_vendored_file

_MAX_FILE_BYTES = 1_000_000
_MAX_DETECT_FILES = 5_000

__all__ = ["scan_python_services", "detect_python_service_repo"]


# ---------------------------------------------------------------------------
# Applicability detection
# ---------------------------------------------------------------------------

# Conservative marker set: real framework imports / call shapes only.
_PY_WEB_MARKER_RE = re.compile(
    r"(?:from|import)\s+(?:fastapi|flask|django|celery|starlette)[.\s(]"
    r"|\bFastAPI\s*\(|\bAPIRouter\s*\("
    r"|\bFlask\s*\(|\bBlueprint\s*\(|\bCelery\s*\("
    r"|\burlpatterns\b|\bROOT_URLCONF\s*=",
)
_REQUIREMENT_MARKER_RE = re.compile(
    r"^\s*[\"\']?(?:fastapi|flask|django|celery|starlette)\b", re.MULTILINE
)
_DEPENDENCY_MANIFEST_NAMES = ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile")


def detect_python_service_repo(root: str | Path) -> bool:
    """True when the repo shows Python web-service framework markers.

    Deliberately conservative: framework imports, framework call shapes,
    Django urlconf declarations, or a declared framework dependency. A
    repo of plain Python scripts stays silent.
    """
    from .index import PassSources
    repo = Path(root).resolve()
    sources = PassSources.for_root(repo)
    if not sources.is_dir(repo):
        return False
    try:
        examined = 0
        for candidate in sources.iter_files(prune=is_skipped_dir):
            examined += 1
            if examined > _MAX_DETECT_FILES:
                return False
            rel = candidate.relative_to(repo)
            if in_skipped_dir(rel):
                continue
            name = candidate.name
            is_manifest = name in _DEPENDENCY_MANIFEST_NAMES or name.startswith("requirements")
            if not is_manifest and candidate.suffix != ".py":
                continue
            if not is_manifest and (is_test_file(rel.as_posix()) or is_vendored_file(rel.as_posix())):
                continue  # framework markers in test scaffolding don't make a repo a Python web service
            try:
                text = sources.gated_text(rel.as_posix(), max_bytes=_MAX_FILE_BYTES, errors="replace")
                if text is None:
                    continue
            except OSError:
                continue
            marker = _REQUIREMENT_MARKER_RE if is_manifest else _PY_WEB_MARKER_RE
            if marker.search(text):
                return True
    except OSError:
        return False
    return False


# ---------------------------------------------------------------------------
# Small parsing helpers (string/comment-aware, dependency-free)
# ---------------------------------------------------------------------------

def _skip_string(text: str, i: int) -> int:
    """Index just past the string literal starting at ``i`` (a quote char)."""
    quote = text[i]
    triple = text[i : i + 3] == quote * 3
    i += 3 if triple else 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if triple:
            if text[i : i + 3] == quote * 3:
                return i + 3
        elif ch == quote:
            return i + 1
        i += 1
    return n


def _call_args(text: str, open_idx: int) -> str | None:
    """Argument text between the parens of the call whose ``(`` is at
    ``open_idx``. String- and comment-aware; ``None`` when unbalanced."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "#":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if ch in ("'", '"'):
            i = _skip_string(text, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
        i += 1
    return None


def _bracket_block(text: str, open_idx: int) -> str | None:
    """Text between the square brackets whose ``[`` is at ``open_idx``
    (the MIDDLEWARE / INSTALLED_APPS list literals). String- and
    comment-aware; ``None`` when unbalanced."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "#":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if ch in ("'", '"'):
            i = _skip_string(text, i)
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
        i += 1
    return None


def _iter_calls(text: str, name: str):
    """Yield ``(offset_of_call, args_text)`` for every ``name(...)`` call.

    The lookbehind allows a receiver prefix (``app.add_middleware(...)``),
    only a bare identifier prefix is rejected (``notadd_middleware(``).
    """
    for match in re.finditer(rf"(?<!\w){re.escape(name)}\s*\(", text):
        args = _call_args(text, match.end() - 1)
        if args is not None:
            yield match.start(), args


def _iter_assignments(text: str, call_name: str):
    """Yield ``(var_name, offset, args_text)`` for every ``var = call(...)``."""
    pattern = re.compile(rf"(?<!\w)(\w+)\s*=\s*(?<![\w.]){re.escape(call_name)}\s*\(")
    for match in pattern.finditer(text):
        args = _call_args(text, match.end() - 1)
        if args is not None:
            yield match.group(1), match.start(), args


def _split_args(args: str) -> list[str]:
    """Split a call's argument text on top-level commas."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i, n = 0, len(args)
    while i < n:
        ch = args[i]
        if ch == "#":
            j = args.find("\n", i)
            i = n if j == -1 else j
            continue
        if ch in ("'", '"'):
            j = _skip_string(args, i)
            buf.append(args[i:j])
            i = j
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


_STR_TOKEN_RE = re.compile(r"^\s*[fFrRbBuU]{0,2}['\"](.*)['\"]\s*$", re.DOTALL)


def _first_string(token: str) -> str | None:
    match = _STR_TOKEN_RE.match(token)
    return match.group(1) if match else None


def _kwarg(args: str, key: str) -> str | None:
    """Raw value token of the ``key=`` keyword argument, if present."""
    prefix = f"{key}="
    for token in _split_args(args):
        if token.startswith(prefix):
            return token[len(prefix) :].strip()
    return None


# ---------------------------------------------------------------------------
# Collection state
# ---------------------------------------------------------------------------

@dataclass
class _RouteUse:
    """A route decorator observed with its per-file (scanner-parity) path."""

    file: str
    router: str  # router/blueprint variable name
    framework: str  # "fastapi" | "flask"
    path: str
    method: str
    line: int
    decorators: list[str] = field(default_factory=list)


@dataclass
class _FastAPIRouter:
    file: str
    name: str
    prefix: str
    line: int


@dataclass
class _PyState:
    files: dict[str, str]

    # FastAPI wiring
    fastapi_routers: dict[str, list[_FastAPIRouter]] = field(default_factory=dict)
    includes: list[dict] = field(default_factory=list)  # {file,parent,child,prefix,auth,deps,line}
    add_middleware: list[tuple[str, str, int]] = field(default_factory=list)  # (file,name,line)
    uvicorn_runs: list[tuple[str, int]] = field(default_factory=list)
    fastapi_apps: list[tuple[str, int]] = field(default_factory=list)

    # Flask wiring
    blueprints: dict[str, list[tuple[str, str, int]]] = field(default_factory=dict)  # name -> (file,prefix,line)
    registers: list[dict] = field(default_factory=list)
    before_hooks: list[dict] = field(default_factory=list)  # {file,receiver,target,line}
    flask_apps: list[tuple[str, int]] = field(default_factory=list)

    # Routes
    routes: list[_RouteUse] = field(default_factory=list)

    # Custom decorator validation: candidate name -> def sites (file, line, body)
    defs: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)
    custom_auth_candidates: set[str] = field(default_factory=set)

    # Django
    django_settings: list[dict] = field(default_factory=list)  # {file,root_urlconf,middleware,auth_mw,login_required_mw}
    url_entries: dict[str, list[tuple[str, str, int]]] = field(default_factory=dict)  # file -> (route,target,line)
    django_limitations: list[str] = field(default_factory=list)
    wsgi_apps: list[tuple[str, str, int]] = field(default_factory=list)  # (file,kind,line)

    # Per-file import symbol map: file -> {symbol -> dotted module}. Used to
    # resolve dotted references (items.router / api_views.bp / views.health)
    # across files.
    symbol_imports: dict[str, dict[str, str]] = field(default_factory=dict)

    # Services
    celery_apps: list[tuple[str, str, int]] = field(default_factory=list)  # (file,broker_url,line)
    celery_tasks: list[tuple[str, int, str]] = field(default_factory=list)
    dispatches: list[tuple[str, int, str, str]] = field(default_factory=list)  # (file,line,queue,evidence)
    cli_entrypoints: list[tuple[str, int]] = field(default_factory=list)

    # Settings / secrets / ORM
    pydantic_secrets: list[tuple[str, str, int, str]] = field(default_factory=list)  # (name,file,line,evidence)
    env_secrets: list[tuple[str, str, int, str]] = field(default_factory=list)
    raw_sql: list[tuple[str, str, int, str]] = field(default_factory=list)  # (kind,file,line,evidence)
    orm_scoped: list[tuple[str, int, str]] = field(default_factory=list)
    orm_unscoped: list[tuple[str, int, str]] = field(default_factory=list)
    auth_dependency_defs: list[tuple[str, int, str]] = field(default_factory=list)


_AUTH_DEP_NAME_RE = re.compile(
    r"(?:Depends|Security)\s*\(\s*[\w.]*?"
    r"(?:oauth2_scheme|get_current_user|current_user|current_active_user|verify_\w+|"
    r"require_\w+|auth\w*|authenticate\w*|HTTPBearer|HTTPBasic|JWTBearer|APIKeyHeader|get_user)",
    re.IGNORECASE,
)

# Decorator names the per-route fusion pass already resolves by itself;
# custom validation below only needs the names it does NOT know.
_KNOWN_AUTH_DECORATORS = frozenset({
    "login_required", "jwt_required", "token_required", "auth_required",
    "requires_auth", "require_auth", "authenticated", "permission_required",
    "require_oauth", "require_api_key", "require_token", "protected",
})
_AUTHISH_NAME_RE = re.compile(
    r"require|check|ensure|verify|auth|login|token|api[_-]?key|session|permission|guard|staff|subscription",
    re.IGNORECASE,
)
_WRAPPER_IDENTITY_RE = re.compile(
    r"request\.headers|Authorization|api[_-]?key|\bsession\b|\btoken\b|jwt|current_user|user_id",
    re.IGNORECASE,
)
_WRAPPER_REJECT_RE = re.compile(
    r"\b40[13]\b|abort\s*\(|raise\b|HTTPException|PermissionDenied|Unauthorized|Forbidden",
    re.IGNORECASE,
)

_DEF_RE = re.compile(r"^[ \t]*(?:async\s+)?def\s+(\w+)\s*\(", re.MULTILINE)
# Line-anchored with bounded runs: the anchor keeps finditer from retrying
# at every position of a hostile space run, and the bounds keep one attempt
# from backtracking across a whole line (tests/test_regex_budget.py).
# Used only via ``.match(line)`` — indent ≤256 and names ≤256 cover every
# realistic ``def`` while keeping each attempt O(bound).
_HANDLER_DEF_RE = re.compile(r"^\s{0,256}(?:async\s{1,64})?def\s{1,64}\w{1,256}\s{0,64}\(")


def _decorator_names(text: str, offset: int) -> list[str]:
    """Decorator names on the handler introduced at/after ``offset``.

    Walks forward to the handler ``def`` (bounded window, mirroring the
    fusion pass), then collects the contiguous decorator stack above it.
    """
    line_no = _line_of(text, offset) - 1
    lines = text.splitlines()
    def_idx = None
    for j in range(line_no, min(len(lines), line_no + 9)):
        if _HANDLER_DEF_RE.match(lines[j]):
            def_idx = j
            break
    if def_idx is None:
        return []
    names: list[str] = []
    k = def_idx - 1
    while k >= 0 and lines[k].strip().startswith("@"):
        match = re.match(r"\s*@\s*([\w.]+)", lines[k])
        if match:
            names.append(match.group(1).split(".")[-1])
        k -= 1
    return names


def _def_body(text: str, def_offset: int, max_lines: int = 120) -> str:
    """Bounded source region of the function defined at ``def_offset``."""
    end = min(len(text), def_offset + max_lines * 120)
    region = text[def_offset:end]
    lines = region.splitlines()
    if not lines:
        return region
    body_indent = len(lines[0]) - len(lines[0].lstrip())
    kept = [lines[0]]
    for line in lines[1:]:
        stripped = line.strip()
        if stripped and (len(line) - len(line.lstrip())) <= body_indent and (
            stripped.startswith(("def ", "class ", "@")) or re.match(r"^\w", stripped)
        ):
            break
        kept.append(line)
    return "\n".join(kept)


# ---------------------------------------------------------------------------
# Per-file extraction
# ---------------------------------------------------------------------------

def _collect_defs(rel: str, text: str, state: _PyState) -> None:
    for match in _DEF_RE.finditer(text):
        state.defs.setdefault(match.group(1), []).append((rel, match.start(), _def_body(text, match.start())))


def _extract_fastapi(rel: str, text: str, state: _PyState) -> None:
    for name, offset, _args in _iter_assignments(text, "FastAPI"):
        state.fastapi_apps.append((rel, _line_of(text, offset)))
    for name, offset, args in _iter_assignments(text, "APIRouter"):
        prefix = _first_string(_kwarg(args, "prefix") or "") or ""
        state.fastapi_routers.setdefault(name, []).append(
            _FastAPIRouter(file=rel, name=name, prefix=prefix, line=_line_of(text, offset))
        )
    for match in re.finditer(r"(?<!\w)(\w+)\.include_router\s*\(", text):
        args = _call_args(text, match.end() - 1)
        if args is None:
            continue
        parts = _split_args(args)
        if not parts:
            continue
        prefix = _first_string(_kwarg(args, "prefix") or "") or ""
        deps = _kwarg(args, "dependencies") or ""
        state.includes.append({
            "file": rel,
            "parent": match.group(1),
            "child": parts[0],
            "prefix": prefix,
            "deps": deps,
            "has_auth": bool(_AUTH_DEP_NAME_RE.search(deps)),
            "line": _line_of(text, match.start()),
        })
    for offset, args in _iter_calls(text, "add_middleware"):
        parts = _split_args(args)
        if parts:
            state.add_middleware.append((rel, parts[0].split(".")[-1], _line_of(text, offset)))
    for offset, _args in _iter_calls(text, "uvicorn.run"):
        state.uvicorn_runs.append((rel, _line_of(text, offset)))


def _extract_flask(rel: str, text: str, state: _PyState) -> None:
    for name, offset, args in _iter_assignments(text, "Flask"):
        state.flask_apps.append((rel, _line_of(text, offset)))
    for name, offset, args in _iter_assignments(text, "Blueprint"):
        parts = _split_args(args)
        prefix = _first_string(_kwarg(args, "url_prefix") or "") or ""
        state.blueprints.setdefault(name, []).append((rel, prefix, _line_of(text, offset)))
    for match in re.finditer(r"(?<!\w)(\w+)\.register_blueprint\s*\(", text):
        args = _call_args(text, match.end() - 1)
        if args is None:
            continue
        parts = _split_args(args)
        if not parts:
            continue
        prefix = _first_string(_kwarg(args, "url_prefix") or "") or ""
        state.registers.append({
            "file": rel,
            "parent": match.group(1),
            "child": parts[0],
            "prefix": prefix,
            "line": _line_of(text, match.start()),
        })
    for match in re.finditer(r"(?<!\w)(\w+)\.before_request\s*\(\s*([\w.]+)\s*\)", text):
        state.before_hooks.append({
            "file": rel,
            "receiver": match.group(1),
            "target": match.group(2).split(".")[-1],
            "line": _line_of(text, match.start()),
        })


def _extract_routes(rel: str, text: str, state: _PyState) -> None:
    """Route decorators with paths computed exactly like the per-file pass.

    Reuses the scanner's own prefix resolution so auth-upgrade routes hash
    to the same ``(path, method, file)`` merge keys as the ``python-web``
    routes; only the auth fields differ.
    """
    prefixes = _python_route_prefixes(text)

    def emit(router: str, framework: str, route_path: str, methods: list[str], offset: int) -> None:
        line = _line_of(text, offset)
        decorators = _decorator_names(text, offset)
        for method in methods:
            state.routes.append(
                _RouteUse(
                    file=rel,
                    router=router,
                    framework=framework,
                    path=_join_route_parts(prefixes.get(router, ""), route_path),
                    method=method,
                    line=line,
                    decorators=list(decorators),
                )
            )

    for match in FASTAPI_DECORATOR_PATTERN.finditer(text):
        router, method, route_path = match.groups()
        emit(router, "fastapi", route_path, [method.upper()], match.start())
    for match in FASTAPI_API_ROUTE_PATTERN.finditer(text):
        router, route_path, args = match.group(1), match.group(2), match.group("args")
        emit(router, "fastapi", route_path, _extract_methods(args), match.start())
    for match in FLASK_ROUTE_PATTERN.finditer(text):
        router, route_path, args = match.group(1), match.group(2), match.group("args")
        emit(router, "flask", route_path, _extract_methods(args, default_method="GET"), match.start())


_ROOT_URLCONF_RE = re.compile(r"ROOT_URLCONF\s*=\s*['\"]([\w.]+)['\"]")
_IMPORT_FROM_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([^)\n]+)\)?\s*$", re.MULTILINE)
_IMPORT_PLAIN_RE = re.compile(r"^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*$", re.MULTILINE)


def _import_symbols(text: str) -> dict[str, str]:
    """Map imported symbols to their dotted modules (``items`` → ``app.routers.items``)."""
    symbols: dict[str, str] = {}
    for match in _IMPORT_FROM_RE.finditer(text):
        base, names = match.group(1), match.group(2)
        for part in names.split(","):
            part = part.strip()
            if not part:
                continue
            symbol = part.split(" as ")[-1].strip() if " as " in part else part
            symbols[symbol] = f"{base}.{symbol}"
    for match in _IMPORT_PLAIN_RE.finditer(text):
        module, alias = match.group(1), match.group(2)
        symbols[alias or module.split(".")[0]] = module
    return symbols


def _extract_django(rel: str, text: str, state: _PyState) -> None:
    from .python_django_routes import extract_django_url_entries

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return
    settings: dict[str, list[ast.AST]] = {"ROOT_URLCONF": [], "MIDDLEWARE": []}
    star_import = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in settings:
            settings[node.id].append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in settings:
            settings[node.name].append(node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                star_import = star_import or alias.name == "*"
                name = alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
                if name in settings:
                    settings[name].append(node)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name in settings:
            settings[node.name].append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest in settings:
            settings[node.rest].append(node)
    if star_import:
        for assignments in settings.values():
            if assignments:
                assignments.append(tree)
    values: dict[str, object] = {}
    lines: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
        else:
            continue
        if name not in settings or len(settings[name]) != 1:
            continue
        try:
            values[name] = ast.literal_eval(node.value)
            lines[name] = node.lineno
        except (ValueError, TypeError, SyntaxError, RecursionError):
            pass
    middleware_value = values.get("MIDDLEWARE")
    if any(isinstance(node, ast.Name) and node.id == "MIDDLEWARE" and isinstance(node.ctx, ast.Load)
           for node in ast.walk(tree)):
        # A referenced list may be mutated or passed to arbitrary code.
        middleware_value = None
        state.django_limitations.append(
            f"ecosystem_python: {rel}: referenced or mutated MIDDLEWARE; no settings auth inference"
        )
    middleware = list(middleware_value) if (
        isinstance(middleware_value, (list, tuple))
        and all(isinstance(value, str) for value in middleware_value)
    ) else []
    root = values.get("ROOT_URLCONF")
    if not isinstance(root, str) or not re.fullmatch(r"\w+(?:\.\w+)*", root):
        root = None
    auth_middleware = "django.contrib.auth.middleware.AuthenticationMiddleware"
    login_middleware = "django.contrib.auth.middleware.LoginRequiredMiddleware"
    login_required = (auth_middleware in middleware and login_middleware in middleware
                      and middleware.index(auth_middleware) < middleware.index(login_middleware))
    if any(settings.values()):
        state.django_settings.append({
            "file": rel,
            "root_urlconf": root,
            "middleware": middleware,
            "mw_line": lines.get("MIDDLEWARE"),
            "login_required_mw": login_required,
            "auth_mw": bool(set(middleware) & {
                "django.contrib.sessions.middleware.SessionMiddleware", auth_middleware, login_middleware,
            }),
        })
        for name, assignments in settings.items():
            if assignments and name not in values:
                state.django_limitations.append(
                    f"ecosystem_python: {rel}: dynamic or ambiguous Django {name}; no settings auth inference"
                )
        if login_middleware in middleware and not login_required:
            state.django_limitations.append(
                f"ecosystem_python: {rel}: LoginRequiredMiddleware requires preceding AuthenticationMiddleware; auth unknown"
            )
    entries, limitations = extract_django_url_entries(rel, text)
    state.django_limitations.extend(limitations)
    if entries:
        state.url_entries[rel] = entries


def _extract_wsgi_asgi(rel: str, text: str, state: _PyState) -> None:
    for offset, _args in _iter_calls(text, "get_wsgi_application"):
        state.wsgi_apps.append((rel, "wsgi_boundary:django", _line_of(text, offset)))
    for offset, _args in _iter_calls(text, "get_asgi_application"):
        state.wsgi_apps.append((rel, "asgi_boundary:django", _line_of(text, offset)))


_BROKER_RE = re.compile(r"broker\s*=\s*['\"](\w+)://[^'\"]*['\"]")
_TASK_DECORATOR_RE = re.compile(r"@(\w+)\.task\b|@shared_task\b|@task\s")
_DELAY_RE = re.compile(r"(?<!\w)(\w+)\.(delay|apply_async)\s*\(")
_SEND_TASK_RE = re.compile(r"send_task\s*\(\s*['\"]([\w.]+)['\"]")
_QUEUE_KWARG_RE = re.compile(r"queue\s*=\s*['\"](\w+)['\"]")
_CLI_MAIN_RE = re.compile(r"^[ \t]*def\s+main\s*\(", re.MULTILINE)
_CLI_LIB_RE = re.compile(r"\bargparse\b|\bimport\s+click\b|@click\.|\btyper\b")


def _extract_services(rel: str, text: str, state: _PyState) -> None:
    for name, offset, args in _iter_assignments(text, "Celery"):
        broker = _BROKER_RE.search(args)
        url = broker.group(0) if broker else None
        if url is None:
            first_url = re.search(r"['\"](\w+)://[^'\"]*['\"]", args)
            url = first_url.group(0).strip("'\"") if first_url else ""
        else:
            url = url[len("broker") :].lstrip(" =").strip("'\"")
        state.celery_apps.append((rel, url, _line_of(text, offset)))

    for match in _TASK_DECORATOR_RE.finditer(text):
        line = _line_of(text, match.start())
        def_match = re.search(r"def\s+(\w+)\s*\(", text[match.start():])
        task_name = def_match.group(1) if def_match else "<anonymous>"
        state.celery_tasks.append((rel, line, f"@{match.group(0)[1:]} def {task_name}"))

    for match in _DELAY_RE.finditer(text):
        args = _call_args(text, match.end() - 1)
        queue = "default"
        if args:
            kw = _QUEUE_KWARG_RE.search(args)
            if kw:
                queue = kw.group(1)
        state.dispatches.append((rel, _line_of(text, match.start()), queue, _line_snippet(text, match.start())))
    for match in _SEND_TASK_RE.finditer(text):
        args = _call_args(text, match.end() - 1)
        queue = "default"
        if args:
            kw = _QUEUE_KWARG_RE.search(args)
            if kw:
                queue = kw.group(1)
        state.dispatches.append((rel, _line_of(text, match.start()), queue, _line_snippet(text, match.start())))

    if _CLI_LIB_RE.search(text):
        for match in _CLI_MAIN_RE.finditer(text):
            state.cli_entrypoints.append((rel, _line_of(text, match.start())))


_ENV_SECRET_RE = re.compile(
    r"os\.environ(?:\.get)?\s*\(\s*['\"]([\w.]*?(?:SECRET|TOKEN|KEY|PASSWORD)[\w.]*)['\"]"
    r"|os\.environ\s*\[\s*['\"]([\w.]*?(?:SECRET|TOKEN|KEY|PASSWORD)[\w.]*)['\"]",
    re.IGNORECASE,
)
_BASE_SETTINGS_CLASS_RE = re.compile(r"^([ \t]*)class\s+(\w+)\s*\([^)]*BaseSettings[^)]*\)\s*:", re.MULTILINE)
_FIELD_LINE_RE = re.compile(r"^([ \t]+)(\w+)\s*:\s*\S")
_SECRETISH_RE = re.compile(r"SECRET|TOKEN|KEY|PASSWORD", re.IGNORECASE)
_ENV_ALIAS_RE = re.compile(r"env\s*=\s*['\"]([\w.]+)['\"]")

_RAW_SQL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\.extra\s*\("), "django-orm .extra()"),
    (re.compile(r"\.raw\s*\("), "django-orm .raw()"),
    (re.compile(r"(?<!\w)text\s*\(\s*['\"f]"), "sqlalchemy text()"),
)
_ORM_SCOPED_RE = re.compile(r"\.filter\s*\([^)\n]*(?:user|owner|tenant|account|org)", re.IGNORECASE)
_ORM_UNSCOPED_DJANGO_RE = re.compile(r"\.objects\.get\s*\(\s*(?:pk|id)\s*=", re.IGNORECASE)
_ORM_UNSCOPED_SA_RE = re.compile(r"\.query\s*\([^)\n]*\)\s*\.get\s*\(")
_AUTH_DEP_DEF_RE = re.compile(
    r"def\s+(get_current_user|get_user|verify_\w+|require_\w+|authenticate\w+|auth\w*)\s*\("
)
_AUTH_DEP_BODY_RE = re.compile(r"decode|verify|jwt|HTTPException|\b40[13]\b|compare_digest", re.IGNORECASE)


def _extract_settings_and_orm(rel: str, text: str, state: _PyState) -> None:
    for match in _ENV_SECRET_RE.finditer(text):
        name = match.group(1) or match.group(2)
        state.env_secrets.append((name, rel, _line_of(text, match.start()), _line_snippet(text, match.start())))

    for match in _BASE_SETTINGS_CLASS_RE.finditer(text):
        class_indent = len(match.group(1))
        lines = text.splitlines()
        start_line = text[: match.start()].count("\n")
        for line_no, line in enumerate(lines[start_line + 1 : start_line + 80], start=start_line + 2):
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= class_indent:
                break
            field = _FIELD_LINE_RE.match(line)
            if not field:
                continue
            alias = _ENV_ALIAS_RE.search(line)
            env_name = alias.group(1) if alias else field.group(2)
            if _SECRETISH_RE.search(env_name):
                state.pydantic_secrets.append((env_name, rel, line_no, line.strip()))

    for pattern, label in _RAW_SQL_PATTERNS:
        for match in pattern.finditer(text):
            state.raw_sql.append(("sql", rel, _line_of(text, match.start()), f"{label}: {_line_snippet(text, match.start())}"))
            break  # one escape observation per file per pattern family

    for match in _ORM_SCOPED_RE.finditer(text):
        state.orm_scoped.append((rel, _line_of(text, match.start()), _line_snippet(text, match.start())))
        break  # per-file dedup (merge key is (hint, file) anyway)
    for pattern in (_ORM_UNSCOPED_DJANGO_RE, _ORM_UNSCOPED_SA_RE):
        match = pattern.search(text)
        if match:
            state.orm_unscoped.append((rel, _line_of(text, match.start()), _line_snippet(text, match.start())))
            break

    for match in _AUTH_DEP_DEF_RE.finditer(text):
        body = _def_body(text, match.start())
        if _AUTH_DEP_BODY_RE.search(body):
            state.auth_dependency_defs.append(
                (rel, _line_of(text, match.start()), f"def {match.group(1)} verifies caller credentials")
            )
            break  # one definition hint per file (merge dedups by (hint, file))


# ---------------------------------------------------------------------------
# Cross-file resolution + emission
# ---------------------------------------------------------------------------

def _module_to_candidate_files(module: str) -> list[str]:
    base = module.replace(".", "/")
    return [f"{base}.py", f"{base}/__init__.py"]


def _resolve_module(state: _PyState, module: str) -> str | None:
    for candidate in _module_to_candidate_files(module):
        if candidate in state.files:
            return candidate
    return None


def _resolve_child(state: _PyState, child_token: str, registry: dict, importer_file: str):
    """Resolve an include/register child token to a definition record.

    ``child_token`` forms: ``router`` (bare), ``items.router`` /
    ``api_views.bp`` (dotted). For dotted forms the head symbol is resolved
    through the *referencing* file's import map to a module, then to a file;
    definitions in that file win. Ambiguous bare names with definitions in
    several files resolve only when unique (conservative — silence over a
    guess).
    """
    tail = child_token.split(".")[-1].strip()
    head = child_token.split(".")[0].strip() if "." in child_token else None
    candidates = registry.get(tail, [])
    if not candidates:
        return None
    if head:
        module = state.symbol_imports.get(importer_file, {}).get(head)
        if module:
            target_file = _resolve_module(state, module)
            if target_file:
                for candidate in candidates:
                    candidate_file = candidate[0] if isinstance(candidate, tuple) else candidate.file
                    if candidate_file == target_file:
                        return candidate
        return None  # dotted reference we could not pin to a file — stay silent
    if len(candidates) == 1:
        return candidates[0]
    files = {c[0] if isinstance(c, tuple) else c.file for c in candidates}
    if len(files) == 1:
        return candidates[0]
    return None  # ambiguous across files — stay silent


def _validate_def_body(state: _PyState, name: str) -> tuple[str, int, str] | None:
    """Definition-site validation: a ``def name`` whose body both reads
    caller identity (headers/session/token/user) and rejects with an
    auth-shaped failure (401/403/abort/raise). Returns the evidence site."""
    for rel, offset, body in state.defs.get(name, []):
        if _WRAPPER_IDENTITY_RE.search(body) and _WRAPPER_REJECT_RE.search(body):
            return (rel, _line_of(state.files[rel], offset), f"def {name} gates on caller identity and rejects")
    return None


def _validated_custom_decorators(state: _PyState) -> dict[str, tuple[str, int, str]]:
    """Decorator names whose definition site is a real auth wrapper.

    A name qualifies when some ``def name(...)`` body in the repo both
    reads caller identity (headers/session/token/user) and rejects
    (401/403/abort/raise). The evidence cites the definition site. Names
    the per-route fusion pass already resolves by pattern are excluded —
    validating them again would duplicate its signal.
    """
    validated: dict[str, tuple[str, int, str]] = {}
    for name in state.custom_auth_candidates:
        if name in _KNOWN_AUTH_DECORATORS:
            continue
        site = _validate_def_body(state, name)
        if site is not None:
            validated[name] = site
    return validated


def scan_python_services(root: str | Path, index: object | None = None) -> ScanResult:
    """Walk a Python web-services repository and emit overlay signals.

    Silent (empty result) on repositories that fail the conservative
    applicability check. Extraction-only: no findings, no scoring — every
    emitted signal carries file/line evidence.
    """
    repo = Path(root).resolve()
    result = ScanResult(root=str(repo), scanned_files=[])
    from .index import PassSources
    if not PassSources.for_root(repo, index).is_dir(repo):
        return result
    if not detect_python_service_repo(repo):
        return result

    files = _collect_files(repo, index, result)
    state = _PyState(files=files)

    for rel in sorted(files):
        text = files[rel]
        _collect_defs(rel, text, state)
        state.symbol_imports[rel] = _import_symbols(text)
    for rel in sorted(files):
        text = files[rel]
        _extract_fastapi(rel, text, state)
        _extract_flask(rel, text, state)
        _extract_routes(rel, text, state)
        _extract_django(rel, text, state)
        _extract_wsgi_asgi(rel, text, state)
        _extract_services(rel, text, state)
        _extract_settings_and_orm(rel, text, state)

    for route in state.routes:
        for name in route.decorators:
            if name not in _KNOWN_AUTH_DECORATORS and _AUTHISH_NAME_RE.search(name):
                state.custom_auth_candidates.add(name)

    _emit(state, result)
    result.languages.append("python")
    return result


def _collect_files(repo: Path, index: object | None, result: ScanResult) -> dict[str, str]:
    files: dict[str, str] = {}
    limit = min(_MAX_FILE_BYTES, max_file_bytes())
    indexed = getattr(index, "files", None) if index is not None else None
    if indexed is not None:
        for item in indexed:
            rel_path = Path(item.rel)
            if rel_path.suffix != ".py" or in_skipped_dir(rel_path):
                continue
            if is_test_file(item.rel) or is_vendored_file(item.rel):
                continue
            if len(item.text.encode("utf-8")) > limit:
                result.limitations.append(
                    f"ecosystem_python: skipped oversized file {item.rel} (>{limit} bytes)"
                )
                continue
            files[rel_path.as_posix()] = item.text
    else:
        for path in walk_repo(repo, prune=is_skipped_dir):
            rel_path = path.relative_to(repo)
            if rel_path.suffix != ".py" or in_skipped_dir(rel_path):
                continue
            rel = rel_path.as_posix()
            if is_test_file(rel) or is_vendored_file(rel):
                continue
            try:
                if path.stat().st_size > limit:
                    result.limitations.append(
                        f"ecosystem_python: skipped oversized file {rel} (>{limit} bytes)"
                    )
                    continue
                files[rel] = read_repo_text(repo, path, errors="replace")
            except OSError:
                continue
    result.files_scanned = len(files)
    result.scanned_files = sorted(files)
    return files


# Emission-time dedup mirrors MERGE_SCHEMA keys so a single overlay result
# never carries duplicate signals even before the pipeline merges it.
def _emit(state: _PyState, result: ScanResult) -> None:
    seen_routes: set[tuple[str, str, str]] = set()
    seen_hints: dict[str, set[tuple[str, str]]] = {
        family: set()
        for family in ("auth", "service", "framework", "entrypoint")
    }
    seen_databases: set[tuple[str, str]] = set()
    seen_secrets: set[tuple[str, str]] = set()
    seen_calls: set[tuple[str, str]] = set()

    def route(path: str, method: str, file: str, line: int, auth: str, guards: list[str], evidence: str | None) -> None:
        key = (path, method, file)
        if key in seen_routes:
            return
        seen_routes.add(key)
        result.routes.append(
            Route(path=path, method=method, file=file, line=line, auth=auth, guards=guards, guard_evidence=evidence)
        )

    def hint(family: str, hint_value: str, file: str, line: int, evidence: str, confidence: float) -> None:
        key = (hint_value, file)
        if key in seen_hints[family]:
            return
        seen_hints[family].add(key)
        model = {
            "auth": AuthHint,
            "service": ServiceHint,
            "framework": FrameworkHint,
            "entrypoint": EntrypointHint,
        }[family]
        result.__getattribute__(f"{family}_hints").append(
            model(hint=hint_value, file=file, line=line, evidence_text=evidence, confidence=confidence)
        )

    validated = _validated_custom_decorators(state)

    # --- FastAPI wiring ----------------------------------------------------
    for rel, line in state.fastapi_apps:
        hint("framework", "asgi_app:fastapi", rel, line, "FastAPI() application object", 0.9)
    for rel, line in state.uvicorn_runs:
        hint("entrypoint", "asgi_server:uvicorn", rel, line, "uvicorn.run(...) serves the ASGI app", 0.85)
    for rel, name, line in state.add_middleware:
        hint("framework", f"hardening_middleware:{name}", rel, line, f"add_middleware({name})", 0.85)

    bindings = BindingIndex(state.files)
    for issue in bindings.issues:
        result.limitations.append(issue)
    for mount in bindings.mounts:
        if mount.framework == "fastapi" and mount.supported:
            child = mount.child
            full = _join_route_parts(mount.prefix, child.prefix)
            hint(
                "framework",
                f"fastapi_router_mount:{full}",
                mount.file,
                mount.line,
                f"router '{child.name}' mounted at {full} "
                f"(defined in {child.file}:{child.line}; route paths retain per-file extraction; declared wiring only)",
                0.85,
            )

    # --- Flask wiring -------------------------------------------------------
    for rel, line in state.flask_apps:
        hint("framework", "wsgi_app:flask", rel, line, "Flask() application object", 0.9)
    for mount in bindings.mounts:
        if mount.framework == "flask" and mount.supported:
            child = mount.child
            full = _join_route_parts("", mount.prefix)
            hint(
                "framework",
                f"flask_blueprint_mount:{full}",
                mount.file,
                mount.line,
                f"blueprint '{child.name}' mounted at {full} "
                f"(defined in {child.file}:{child.line}; registration prefix overrides its default; "
                "route paths retain per-file extraction; declared wiring only)",
                0.85,
            )

    # Auth hooks: a blueprint/app-level ``before_request`` guard the per-route
    # resolution never sees (it only reads route decorators and handler
    # signatures). The hook target must be a function whose body actually
    # checks identity and rejects — known-name or not.
    hook_guards: dict[object, list[tuple[str, int]]] = {}
    for file, line, receiver, target in bindings.hooks:
        if not (target.blocking_guard and _WRAPPER_IDENTITY_RE.search(target.text) and _WRAPPER_REJECT_RE.search(target.text)):
            continue
        hint(
            "auth",
            f"blueprint_auth_hook:{target.name}",
            file,
            line,
            f"before_request({target.name}) guards {receiver.file}:{receiver.line}; "
            f"guard defined in {target.file}:{target.line}",
            0.8,
        )
        hook_guards.setdefault(receiver, []).append((target.file, target.line))

    for name, (rel, line, evidence) in validated.items():
        hint("auth", f"custom_auth_decorator:{name}", rel, line, evidence, 0.8)

    # --- Route auth upgrades (FastAPI include deps / Flask hooks / decorators)
    include_auth: dict[object, list] = {}
    unresolved_fastapi_child = False
    for mount in bindings.mounts:
        if mount.framework != "fastapi":
            continue
        if mount.child is None:
            unresolved_fastapi_child = True
        else:
            include_auth.setdefault(mount.child, []).append(mount)

    route_receivers: dict[tuple[str, str, str], set] = {}
    for use in state.routes:
        route_receivers.setdefault((use.path, use.method, use.file), set()).add(
            bindings.route_object(use.file, use.line))

    for use in state.routes:
        guards: list[str] = []
        evidence_parts: list[str] = []
        receiver = bindings.route_object(use.file, use.line)
        if len(route_receivers[(use.path, use.method, use.file)]) != 1:
            receiver = None  # a shared merge key cannot carry one object's mount guard
        if use.framework == "fastapi":
            mounts = include_auth.get(receiver, [])
            if not unresolved_fastapi_child and mounts and all(
                mount.supported and any(
                    target.blocking_guard and _WRAPPER_IDENTITY_RE.search(target.text) and _WRAPPER_REJECT_RE.search(target.text)
                    for target in mount.dependencies
                ) for mount in mounts
            ):
                for mount in mounts:
                    guards.append(f"include_router dependencies ({mount.file}:{mount.line})")
                    evidence_parts.append(f"bound router auth dependencies at include site {mount.file}:{mount.line}")
        else:  # flask
            for file, line in hook_guards.get(receiver, []):
                guards.append(f"before_request auth hook ({file}:{line})")
                evidence_parts.append(f"bound blueprint before_request guard defined in {file}:{line}")
        for name in use.decorators:
            target = bindings.route_decorator(use.file, use.line, name)
            if target is not None and target.wrapper_guard:
                guards.append(f"@{name} ({target.file}:{target.line})")
                evidence_parts.append(f"bound @{name} wrapper defined in {target.file}:{target.line}")
        if guards:
            route(
                use.path,
                use.method,
                use.file,
                use.line,
                "required",
                guards,
                "; ".join(evidence_parts)[:400],
            )

    # --- Django URLconf tree -------------------------------------------------
    _emit_django(state, result, route, hint, validated)

    # --- Background / service surface ----------------------------------------
    for rel, broker, line in state.celery_apps:
        hint("service", "celery_worker", rel, line, "Celery() worker application", 0.85)
        scheme = broker.split("://", 1)[0] if "://" in broker else ""
        if scheme:
            key = (scheme, rel)
            if key not in seen_databases:
                seen_databases.add(key)
                result.databases.append(
                    DatabaseHint(kind=scheme, file=rel, line=line, evidence_text=f"celery broker {broker}")
                )
    for rel, line, evidence in state.celery_tasks:
        hint("entrypoint", "celery_task", rel, line, evidence, 0.85)
    for rel, line, queue, evidence in state.dispatches:
        target = f"queue://celery/{queue}"
        key = (target, rel)
        if key not in seen_calls:
            seen_calls.add(key)
            result.external_calls.append(ExternalCall(target=target, file=rel, line=line, evidence_text=evidence))

    # --- Settings / ORM / boundaries ------------------------------------------
    for rel, line in state.cli_entrypoints:
        hint("entrypoint", "cli_entrypoint", rel, line, "def main() with an argument-parsing CLI library", 0.7)
    for name, rel, line, evidence in state.pydantic_secrets:
        key = (name, rel)
        if key not in seen_secrets:
            seen_secrets.add(key)
            result.secret_hints.append(
                SecretHint(name=name, file=rel, line=line, evidence_text=evidence, kind="env_reference", confidence=0.6)
            )
    for name, rel, line, evidence in state.env_secrets:
        key = (name, rel)
        if key not in seen_secrets:
            seen_secrets.add(key)
            result.secret_hints.append(
                SecretHint(name=name, file=rel, line=line, evidence_text=evidence, kind="env_reference", confidence=0.75)
            )
    for rel, kind, line in state.wsgi_apps:
        hint("framework", kind, rel, line, "server boundary via django wsgi/asgi helper", 0.9)

    for kind, rel, line, evidence in state.raw_sql:
        key = (kind, rel)
        if key not in seen_databases:
            seen_databases.add(key)
            result.databases.append(DatabaseHint(kind=kind, file=rel, line=line, evidence_text=evidence))
    for rel, line, evidence in state.orm_scoped:
        hint("auth", "orm_scoped_query", rel, line, evidence, 0.8)
    for rel, line, evidence in state.orm_unscoped:
        hint("auth", "orm_unscoped_lookup", rel, line, evidence, 0.45)
    for rel, line, evidence in state.auth_dependency_defs:
        hint("auth", "auth_dependency_definition", rel, line, evidence, 0.8)


_DJANGO_PARAM_RE = re.compile(r"<(?:(\w+):)?(\w+)>")


def _django_route_path(raw: str) -> str:
    """``notes/<int:pk>`` → ``notes/{pk}`` (converter syntax normalized)."""
    return _DJANGO_PARAM_RE.sub(lambda m: "{" + (m.group(2) or m.group(1)) + "}", raw)


def _emit_django(state: _PyState, result: ScanResult, route, hint, validated) -> None:
    from .python_django_routes import DjangoAuthResolver

    result.limitations.extend(state.django_limitations)
    if not state.url_entries and not state.django_settings:
        return

    for setting in state.django_settings:
        if setting["middleware"]:
            hint(
                "framework",
                "django_middleware_chain",
                setting["file"],
                setting["mw_line"] or 1,
                "MIDDLEWARE: " + ", ".join(setting["middleware"])[:200],
                0.9,
            )
        if setting["auth_mw"]:
            hint(
                "auth",
                "global_auth_middleware",
                setting["file"],
                setting["mw_line"] or 1,
                "session/authentication middleware present in MIDDLEWARE",
                0.7,
            )

    roots: dict[str, tuple[bool, bool]] = {}  # module -> (inferred, all settings require login)
    for setting in state.django_settings:
        if setting["root_urlconf"]:
            module = setting["root_urlconf"]
            if _resolve_module(state, module):
                previous = roots.get(module, (False, True))[1]
                roots[module] = (False, previous and setting["login_required_mw"])
            else:
                result.limitations.append(
                    f"ecosystem_python: could not resolve Django ROOT_URLCONF module '{module}' to a file"
                )
    if not roots:
        # No resolvable ROOT_URLCONF: treat every urlpatterns module as a
        # root (inferred) so route extraction still happens.
        for rel in sorted(state.url_entries):
            module = rel[:-3].replace("/", ".")
            if module.endswith(".__init__"):
                module = module[: -len(".__init__")]
            roots[module] = (True, False)
    if not roots:
        return

    walk_budget = [0]
    auth_resolver = DjangoAuthResolver(state.files)
    for module, (inferred, login_required_mw) in roots.items():
        if inferred:
            hint("framework", "django_urlconf_inferred_root", module.replace(".", "/") + ".py", 1,
                 "no resolvable ROOT_URLCONF; urlpatterns module treated as a root", 0.5)
        middleware_evidence = "; ".join(
            f"{setting['file']}:{setting['mw_line']}" for setting in state.django_settings
            if setting["root_urlconf"] == module and setting["login_required_mw"]
        ) if login_required_mw else None
        _walk_urlconf(state, result, route, hint, validated, module, "", set(), login_required_mw,
                      middleware_evidence, walk_budget, auth_resolver)


def _walk_urlconf(
    state: _PyState,
    result: ScanResult,
    route,
    hint,
    validated: dict[str, tuple[str, int, str]],
    module: str,
    mount: str,
    visited: set[str],
    login_required_mw: bool,
    middleware_evidence: str | None = None,
    walk_budget: list[int] | None = None,
    auth_resolver=None,
) -> None:
    if auth_resolver is None:
        from .python_django_routes import DjangoAuthResolver
        auth_resolver = DjangoAuthResolver(state.files)
    if walk_budget is None:
        walk_budget = [0]
    walk_budget[0] += 1
    if walk_budget[0] > 4096:
        limitation = "ecosystem_python: Django URLconf expansion limit reached; partial route coverage"
        if limitation not in result.limitations:
            result.limitations.append(limitation)
        return
    if module in visited or len(visited) >= 16:
        result.limitations.append(f"ecosystem_python: Django URLconf cycle/depth limit at '{module}'")
        return
    visited = visited | {module}
    urls_file = _resolve_module(state, module)
    if urls_file is None:
        result.limitations.append(f"ecosystem_python: could not resolve Django include module '{module}'")
        return
    symbols = state.symbol_imports.get(urls_file, {})

    for raw_route, target, line in state.url_entries.get(urls_file, []):
        full_path = _join_route_parts(mount, _django_route_path(raw_route))
        if target.startswith("include("):
            inner = re.search(r"include\s*\(\s*(?:['\"]([\w.]+)['\"]|([\w.]+))", target)
            if not inner:
                continue
            child_module = inner.group(1) or None
            if child_module is None:
                token = inner.group(2)
                head = token.split(".")[0]
                child_module = symbols.get(head, token)
            hint(
                "framework",
                f"urlconf_include:{child_module}",
                urls_file,
                line,
                f"path({raw_route!r}, include({child_module}))",
                0.9,
            )
            _walk_urlconf(state, result, route, hint, validated, child_module, full_path, visited, login_required_mw,
                          middleware_evidence, walk_budget, auth_resolver)
            continue
        from .python_django_routes import DJANGO_ADMIN_TARGET
        if target == DJANGO_ADMIN_TARGET:
            hint("framework", "django_admin_surface", urls_file, line,
                 f"path({raw_route!r}, admin.site.urls)", 0.9)
            continue
        auth, guards, evidence, middleware_eligible = auth_resolver.resolve(urls_file, target, target_line=line)
        if login_required_mw and middleware_eligible and auth != "required":
            auth = "required"
            guards = ["LoginRequiredMiddleware (settings MIDDLEWARE)"]
            evidence = f"ordered Django authentication/login middleware for this URLconf tree: {middleware_evidence}"
        route(full_path, "ANY", urls_file, line, auth, guards, evidence)


def _django_view_auth(
    state: _PyState,
    urls_file: str,
    symbols: dict[str, str],
    target: str,
    validated: dict[str, tuple[str, int, str]],
) -> tuple[str, list[str], str | None]:
    """Resolve exact view/decorator bindings; same-name siblings are not proof."""
    from .python_django_routes import django_view_auth
    auth, guards, evidence, _middleware_eligible = django_view_auth(state.files, urls_file, target)
    return auth, guards, evidence


def _decorator_offset(text: str, def_offset: int, name: str) -> int:
    """Line distance between a def and one of its decorators (for evidence)."""
    lines = text.splitlines()
    def_line = _line_of(text, def_offset)
    for i in range(def_line - 1, max(0, def_line - 8) - 1, -1):
        if re.match(rf"\s*@\s*[\w.]*{re.escape(name)}\b", lines[i]):
            return def_line - (i + 1)
    return 0
