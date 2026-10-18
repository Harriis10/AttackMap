"""Broken object-level authorization (BOLA / IDOR) detection (#69).

OWASP API Security #1. This is the detection AttackMap can do that a
generic linter doesn't emphasize: it composes signals that already exist
in a ``ScanResult`` — routes, per-route auth attribution, datastore
hints, and taint reachability — into a single authorization finding.

## Heuristic

A route is a BOLA/IDOR candidate when ALL of:

1. It takes a **resource identifier** in the path (``/users/{id}``,
   ``/orders/:orderId``, ``/docs/<int:doc_id>``), and
2. It reaches a **datastore** — a DB hint in the same file/module, or a
   taint chain from this route to a ``sql_execute`` sink, and
3. There is **no ownership/authorization check** visible near the
   handler — no ``current_user`` / ``request.user`` / ``owner`` /
   ``authorize`` / policy / guard / caller-scoped ``WHERE user_id``-style
   filtering in the route's handler region or the file's shared preamble.

Condition 3 is the main false-positive reducer: a well-scoped handler
that filters by the caller's identity is not flagged. It is scoped to the
route's own handler region (AM038) so a sibling handler's markers do not
suppress this route. Write routes with *no resolved authentication control*
defer to the unauthenticated-state-change finding instead (authentication
is the missing control; BOLA presupposes an authenticated caller).
Import-edge and name heuristics are imprecise, so findings are evidence,
not proof.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from .index import PassSources
from .safe_fs import is_unsafe_link
from .models import BolaCandidate, Route, ScanResult
from .route_auth_fusion import resolve_route_control
from .srcpaths import JS_TS_SUFFIXES, is_test_file, is_vendored_file

if TYPE_CHECKING:
    from .index import RepoIndex

# Path parameter forms across frameworks:
#   {id} {user_id} {int:id}        Flask / FastAPI / Starlette
#   :id :orderId                   Express / Koa / Rails
#   <id> <int:doc_id>              Flask converters
_PATH_PARAM_RE = re.compile(r"\{([^{}]+)\}|:([A-Za-z_]\w*)|<(?:[^:<>]+:)?([^<>]+)>")

# Which extracted params look like a resource identifier an attacker
# would enumerate. Matches `id`, `user_id`, `orderId`, `uuid`, `slug`,
# `*_key`, `guid`, but not generic words like `format` or `lang`.
_ID_PARAM_RE = re.compile(
    r"(?:^|_)id$|^id$|_id$|(?:^|[a-z])Id$|uuid|guid|slug|(?:^|_)key$|hash$|token$|ref$",
    re.IGNORECASE,
)

# RPC-method scoping (#139). XRPC methods (`/xrpc/<nsid>`) and tRPC procedures
# (`trpc:<name>`) encode an object operation in the route path. An operation is
# an id-bearing object reference when it names an object-access verb and an
# object noun (`getRecord`, `describeRepo`, `updateProfile`) or a by-id form.
_RPC_OBJECT_VERB_RE = re.compile(
    r"^(get|fetch|load|read|update|delete|put|patch|remove|describe|resolve)", re.IGNORECASE
)
_RPC_OBJECT_NOUN_RE = re.compile(
    r"record|blob|profile|repo|post|account|user|doc|order|item|resource|handle"
    r"|did|actor|thread|message|file|node|entity|comment|session|member|invoice",
    re.IGNORECASE,
)
_RPC_BY_ID_RE = re.compile(r"[Bb]y_?[Ii]d\b")

# GraphQL auth is expressed as schema directives. Their presence on an
# id-bearing field means authorization is enforced → suppress (like the
# ownership markers do for HTTP handlers).
_GRAPHQL_AUTH_DIRECTIVE_RE = re.compile(
    r"@(?:auth|authenticated|isAuthenticated|authorized|hasRole|hasScopes?"
    r"|requiresScopes?|requireAuth|requiresAuth|hasPermission|policy|private|acl)\b",
    re.IGNORECASE,
)

# Query-parameter scoping (#139). In real framework code the id arrives in the
# handler body, not the registered path — so scan the route's file for an
# id-shaped query-parameter *access* (`req.query.userId`, `request.args.get('id')`,
# `orderId: str = Query(...)`, `searchParams.get('docId')`, …).
_QUERY_ACCESS_RES = (
    re.compile(r"\b(?:req|request|ctx|c)\s*\.\s*(?:query|args|GET|query_params)\s*\.\s*(\w+)"),
    re.compile(r"""\b(?:req|request|ctx|c)\s*\.\s*(?:query|args|GET|query_params)\s*\[\s*['"](\w+)['"]"""),
    re.compile(r"""\b(?:req|request|ctx|c)\s*\.\s*(?:query|args|GET|query_params)\s*\.\s*get\s*\(\s*['"](\w+)['"]"""),
    re.compile(r"""\bsearchParams\s*\.\s*get\s*\(\s*['"](\w+)['"]"""),
    re.compile(r"""\b(\w+)\s*:\s*[\w\[\]|. ]+?=\s*Query\s*\("""),  # FastAPI `id: str = Query(...)`
)

# Ownership / authorization markers. If ANY appear near the route's handler
# we assume authorization is enforced and suppress the finding. Deliberately
# broad — recall on the *suppression* side keeps false positives down.
# The bare `user_id` name is deliberately NOT a marker, and neither is
# `user_id = ...`: a typed parameter (`def handler(user_id: str)`), a JSON
# key, and a SQL binding (`where user_id = ?`) are declarations/plumbing, not
# checks — query scoping is judged by the coupled rule below (AM038).
_OWNERSHIP_MARKERS = re.compile(
    r"""
    current_user | currentUser | \brequest\.user\b | \breq\.user\b | \bctx\.user\b
    | \bowner\b | owner_id | ownerId | userId
    | account_id | tenant_id | org_id | \bself\.user\b
    | authorize | authoriz | \.can\s*\( | cannot | \bpolicy\b | \bpolicies\b
    | \bguard\b | can_access | canAccess | has_access | hasAccess
    | check_access | verify_owner | assert_owner | ensure_owner
    | require[s]?_permission | permission_required | requiresAuth | requireAuth
    | login_required | @authenticated | ensureAuthenticated | is_authorized
    | scope_to | scoped_to | for_user | belongs_to
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Query scoping by a user-ish column (`WHERE user_id = ?`, `.where(user...)`,
# `filter_by(user...)`). On its own that is *object addressing*, not an
# ownership check: the classic miss is the clause being bound to the request's
# own id parameter. It only counts as a check when the caller's identity is in
# scope in the same region (a session/current_user/… token) (AM038).
_SCOPED_QUERY_MARKERS = re.compile(
    r"filter_by\s*\(\s*user | \.where\([^)]*user | WHERE\s+\w*user",
    re.IGNORECASE | re.VERBOSE,
)
_CALLER_IDENTITY_RE = re.compile(
    r"current_user|currentUser|request\.user|req\.user|ctx\.user|c\.user"
    r"|g\.user|self\.user|\bsession\b|req\.session|getSession",
    re.IGNORECASE,
)

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# The write-defer (AM038) resolves per-route auth controls, which is
# self-contained for JS/TS and Python routes only.
_DEFER_SUFFIXES = JS_TS_SUFFIXES | {".py"}

_MAX_FILE_BYTES = 1_000_000  # skip absurdly large files


def analyze_authz(
    scan: ScanResult, root: str | Path | None = None, index: "RepoIndex | None" = None
) -> list[BolaCandidate]:
    """Return BOLA/IDOR candidates for routes in ``scan``.

    Only genuine candidates are returned: routes with an ID param that
    reach a datastore AND lack an ownership check. Routes that HAVE an
    ownership check, or don't reach a datastore, are dropped.

    Handler and GraphQL file *content* resolves through the run's captured
    index when one is given or pinned for this root (C33/AM047), so a mid-run
    edit cannot flip an ownership-check verdict; the size gates use the
    captured sizes. File enumeration stays the pass's own walk.
    """
    root_path = Path(root or scan.root).resolve()
    sources = PassSources.for_root(root_path, index)

    # DB reachability sources.
    db_files = {_norm(db.file) for db in scan.databases}
    db_modules = {_module_key(db.file) for db in scan.databases}
    taint_sql_routes = {
        (c.route_method, c.route_path)
        for c in scan.taint_chains
        # Speculative recall chains (#148a) are unconfirmed leads — they must
        # not manufacture an asserted HIGH BOLA finding that could trip the
        # baseline gate.
        if c.sink_kind == "sql_execute" and not c.speculative
    }

    # Cache per-file content (read at most once per route file), and the
    # file-level query-param scan: it depends only on the file, and redoing it
    # per route made a many-route file quadratic (#218).
    content_cache: dict[str, str | None] = {}
    query_param_cache: dict[str, str | None] = {}

    seen: set[tuple[str, str, str, str]] = set()
    candidates: list[BolaCandidate] = []

    for route in scan.routes:
        content = _read_file_content(route.file, root_path, content_cache, sources)

        # Path-encoded surfaces (RPC method, path template param) first; then
        # fall back to an id-shaped query-parameter access in the handler body.
        surface = _path_based_surface(route.path)
        if surface is None and content:
            if route.file not in query_param_cache:
                query_param_cache[route.file] = _query_param_in_handler(content)
            qp = query_param_cache[route.file]
            if qp is not None:
                surface = ("query_param", qp)
        if surface is None:
            continue
        surface_kind, id_param = surface

        # RPC methods are object-access operations by definition — they read/
        # write a specific object by id — so the "reaches a datastore" condition
        # is satisfied intrinsically. HTTP path/query surfaces still require an
        # observed datastore link (#139).
        if surface_kind == "rpc_method":
            reaches_db, db_evidence = True, "RPC object-access method"
        else:
            reaches_db, db_evidence = _db_reachability(
                route, db_files, db_modules, taint_sql_routes
            )
        if not reaches_db:
            continue

        has_check = bool(content and _ownership_check_near(scan, route, content))

        key = (route.method, route.path, route.file, id_param)
        if key in seen:
            continue
        seen.add(key)

        if has_check:
            # Authorization is (probably) enforced — not a candidate.
            continue

        # Write-defer (AM038): a *write* route with no resolved authentication
        # control is already claimed by the unauth-state-change finding, and
        # the missing control there is authentication — BOLA presupposes an
        # authenticated caller whose object access is unscoped. Defer the
        # BOLA-write claim to that finding; writes WITH a resolved control
        # still get the classic authenticated-but-unscoped BOLA treatment.
        if (
            route.method in _WRITE_METHODS
            and content
            and Path(route.file).suffix.lower() in _DEFER_SUFFIXES
            and resolve_route_control(route, content) is None
        ):
            continue

        candidates.append(
            BolaCandidate(
                route_path=route.path,
                route_method=route.method,
                route_file=route.file,
                route_line=route.line,
                id_param=id_param,
                surface=surface_kind,  # type: ignore[arg-type]
                reaches_db=True,
                db_evidence=db_evidence,
                has_ownership_check=False,
                source_analyzer="authz",
            )
        )

    # GraphQL fields aren't modeled as routes — scan the repo's SDL directly.
    candidates.extend(_graphql_bola_candidates(root_path, seen, sources))

    candidates.sort(
        key=lambda c: (c.route_method not in _WRITE_METHODS, c.route_file, c.route_path)
    )
    return candidates


# --- Internals -------------------------------------------------------------


def _resource_id_param(path: str) -> str | None:
    """Return the first resource-id-shaped path parameter, or None."""
    # Ignore any query string when scanning path-template params.
    template = path.split("?", 1)[0]
    for match in _PATH_PARAM_RE.finditer(template):
        raw = next((g for g in match.groups() if g), None)
        if not raw:
            continue
        # Flask converter form `int:id` → take the name after the colon.
        name = raw.split(":")[-1].strip()
        if _ID_PARAM_RE.search(name):
            return name
    return None


def _path_based_surface(path: str) -> tuple[str, str] | None:
    """Object-identifier surfaces encoded in the route path (#139): an RPC
    method (XRPC/tRPC) or a path-template parameter. Query parameters are
    resolved from the handler body separately (they aren't in the path)."""
    rpc = _rpc_method_surface(path)
    if rpc is not None:
        return ("rpc_method", rpc)
    path_param = _resource_id_param(path)
    if path_param is not None:
        return ("path_param", path_param)
    return None


def _rpc_method_surface(path: str) -> str | None:
    """An XRPC NSID (`/xrpc/<nsid>`) or tRPC procedure (`trpc:<name>`) whose
    operation is an id-bearing object reference. Returns the method name."""
    if path.startswith("/xrpc/"):
        method = path[len("/xrpc/"):].split("?", 1)[0]
    elif path.startswith("trpc:"):
        method = path[len("trpc:"):].split("?", 1)[0]
    else:
        return None
    op = method.rsplit(".", 1)[-1]  # terminal operation segment
    if _RPC_BY_ID_RE.search(op):
        return method
    if _RPC_OBJECT_VERB_RE.match(op) and _RPC_OBJECT_NOUN_RE.search(op):
        return method
    return None


def _query_param_in_handler(content: str) -> str | None:
    """An id-shaped query parameter read in the handler file, if any — e.g.
    `req.query.userId`, `request.args.get('doc_id')`, `id: str = Query(...)`."""
    for regex in _QUERY_ACCESS_RES:
        for match in regex.finditer(content):
            name = match.group(1)
            if name and _ID_PARAM_RE.search(name):
                return name
    return None


def _read_file_content(
    rel_file: str, root: Path, cache: dict[str, str | None], sources: PassSources
) -> str | None:
    if rel_file in cache:
        return cache[rel_file]
    content = sources.gated_text(rel_file, max_bytes=_MAX_FILE_BYTES, errors="ignore")
    cache[rel_file] = content
    return content


# --- Region-scoped ownership checks (AM038) ----------------------------------


def _ownership_check_near(scan: ScanResult, route: Route, content: str) -> bool:
    """True when ownership/authorization markers appear near THIS route.

    The search is scoped to the route's own handler region (from a couple of
    lines above its registration — stacked decorators — to the next route
    registration in the same file) plus the shared file preamble (imports,
    router-level dependencies, guard helpers), which plausibly guards every
    route in the file. A marker in a *sibling* handler — e.g. another
    handler's `user_id` parameter annotation — says nothing about this route
    and must not suppress it. Without line info the whole file is searched
    (the previous behavior).
    """
    if route.line is None:
        return _ownership_check_text(content)
    lines = content.splitlines()
    if not lines:
        return False
    route_lines = sorted(
        r.line for r in scan.routes
        if r.file == route.file and r.line is not None
    )
    if not route_lines:
        return _ownership_check_text(content)
    first = route_lines[0]
    later = [ln for ln in route_lines if ln > route.line]
    region_start = max(1, route.line - 2)
    region_end = min((min(later) - 1) if later else len(lines), len(lines))
    # Shared preamble (everything before the file's first route) + the route's
    # own region; overlapping slices for the file's first route are harmless.
    preamble = "\n".join(lines[: first - 1])
    region = "\n".join(lines[region_start - 1 : region_end])
    if _OWNERSHIP_MARKERS.search(preamble + "\n" + region):
        return True
    # A user-scoped query only counts as an ownership check when the caller's
    # identity is *used* in the handler region — a `session`/`user` import in
    # the preamble is not usage (see _SCOPED_QUERY_MARKERS).
    return bool(
        _SCOPED_QUERY_MARKERS.search(region) and _CALLER_IDENTITY_RE.search(region)
    )


def _ownership_check_text(text: str) -> bool:
    if _OWNERSHIP_MARKERS.search(text):
        return True
    # A user-scoped query only counts as an ownership check when the caller's
    # identity is in scope nearby (see _SCOPED_QUERY_MARKERS).
    return bool(
        _SCOPED_QUERY_MARKERS.search(text) and _CALLER_IDENTITY_RE.search(text)
    )


def _db_reachability(
    route: Route,
    db_files: set[str],
    db_modules: set[str],
    taint_sql_routes: set[tuple[str, str]],
) -> tuple[bool, str]:
    route_file = _norm(route.file)
    if route_file in db_files:
        return True, "datastore hint in the route's file"
    if _module_key(route.file) in db_modules:
        return True, "datastore hint in the route's module"
    if (route.method, route.path) in taint_sql_routes:
        return True, "taint chain from this route reaches a SQL execute sink"
    return False, ""


# --- GraphQL SDL scoping (#139) --------------------------------------------

_GRAPHQL_EXTS = {".graphql", ".gql"}
_GRAPHQL_CODE_EXTS = JS_TS_SUFFIXES | {".py", ".go", ".rb"}
_GRAPHQL_SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv", "vendor"}
_GRAPHQL_MAX_DEPTH = 6
_GRAPHQL_MAX_FILES = 2000

# One field definition: `name(args): ReturnType [@directives]`.
# (?<!\w) + possessive \w++: never restart mid-word, so a long word can't
# trigger quadratic backtracking (#236).
_GRAPHQL_FIELD_RE = re.compile(
    r"(?<!\w)(?P<name>\w++)\s*+(?:\((?P<args>[^)]*+)\))?\s*+:\s*(?P<rest>[^\n]*)"
)
# `schema { query: RootQuery  mutation: RootMutation }` custom root types.
_GRAPHQL_SCHEMA_BLOCK_RE = re.compile(r"schema\s*\{(?P<body>[^}]*)\}", re.DOTALL)
_GRAPHQL_SCHEMA_ROOT_RE = re.compile(r"\b(query|mutation)\s*:\s*(\w+)", re.IGNORECASE)
_GRAPHQL_SDL_MARKER_RE = re.compile(r"type\s+(?:Query|Mutation)\b|schema\s*\{")


def _graphql_bola_candidates(root: Path, seen: set, sources: PassSources) -> list[BolaCandidate]:
    """Scan the repo's GraphQL SDL for id-bearing Query/Mutation fields that
    lack an authorization check (#139). GraphQL fields aren't routes, so
    they're modeled here as ``graphql_field`` surfaces. Authorization can be an
    SDL directive on the field OR an ownership check in the resolver code."""
    files = list(_iter_graphql_files(root, sources))
    # Resolver-side auth: files carrying an ownership marker (`current_user`,
    # `authorize`, …). A field defined as a resolver in such a file is treated
    # as authorized even without an SDL directive.
    auth_resolver_texts = [text for _rel, text in files if _OWNERSHIP_MARKERS.search(text)]

    candidates: list[BolaCandidate] = []
    for rel, text in files:
        for type_name, method in _graphql_root_types(text).items():
            for body in _graphql_type_bodies(text, type_name):
                for field in _GRAPHQL_FIELD_RE.finditer(body):
                    name = field.group("name")
                    args = field.group("args") or ""
                    rest = field.group("rest") or ""
                    arg_id = _graphql_id_arg(args)
                    if arg_id is None:
                        continue
                    # Suppress when an SDL directive OR a resolver enforces auth.
                    if _GRAPHQL_AUTH_DIRECTIVE_RE.search(args + " " + rest):
                        continue
                    if _graphql_resolver_authorizes(name, auth_resolver_texts):
                        continue
                    route_path = f"graphql:{name}"
                    key = (method, route_path, rel, arg_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append(
                        BolaCandidate(
                            route_path=route_path,
                            route_method=method,
                            route_file=rel,
                            id_param=arg_id,
                            surface="graphql_field",
                            reaches_db=True,
                            db_evidence=f"GraphQL {method.lower()} field resolves an object by `{arg_id}`",
                            has_ownership_check=False,
                            source_analyzer="authz",
                        )
                    )
    return candidates


def _graphql_root_types(text: str) -> dict[str, str]:
    """Map GraphQL root type names → method (`QUERY`/`MUTATION`). Includes the
    conventional `Query`/`Mutation` plus any custom roots from a `schema {…}`
    declaration (`schema { query: RootQuery }`)."""
    roots = {"Query": "QUERY", "Mutation": "MUTATION"}
    schema = _GRAPHQL_SCHEMA_BLOCK_RE.search(text)
    if schema:
        for op, type_name in _GRAPHQL_SCHEMA_ROOT_RE.findall(schema.group("body")):
            roots[type_name] = "MUTATION" if op.lower() == "mutation" else "QUERY"
    return roots


def _graphql_type_bodies(text: str, type_name: str):
    """Yield the field-block body of each `type <type_name> { … }` (SDL field
    blocks don't nest braces, so a non-greedy match to the first `}` works)."""
    pattern = re.compile(
        r"(?:extend\s+)?type\s+" + re.escape(type_name) + r"\b[^{]*\{(.*?)\}",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        yield match.group(1)


def _graphql_resolver_authorizes(field_name: str, auth_resolver_texts: list[str]) -> bool:
    """True if the field is defined as a resolver (`name(` / `name:`) in a file
    that also contains an ownership marker — i.e. auth lives in the resolver."""
    resolver_ref = re.compile(r"\b" + re.escape(field_name) + r"\s*[(:]")
    return any(resolver_ref.search(text) for text in auth_resolver_texts)


def _graphql_id_arg(args: str) -> str | None:
    """Return an id-bearing argument name from a GraphQL field's arg list —
    an id-shaped name (`id`, `userId`) or an `ID`-typed argument."""
    for part in args.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        arg_name, _, arg_type = part.partition(":")
        arg_name = arg_name.strip()
        if _ID_PARAM_RE.search(arg_name):
            return arg_name
        if arg_type.strip().lstrip("[").startswith("ID"):
            return arg_name
    return None


def _iter_graphql_files(root: Path, sources: PassSources):
    """Yield ``(rel_path, text)`` for files relevant to GraphQL authz: `.graphql`
    / `.gql` files, and code files that either contain SDL (`type Query`, a
    `schema {…}`) or an ownership marker (candidate resolver). Test/fixture and
    vendored files are excluded per the repo's source-quality policy (#139).
    Content (and the size gate) resolve through the pinned snapshot when one
    applies (C33/AM047)."""
    count = 0

    def walk(directory: Path, depth: int):
        nonlocal count
        try:
            entries = list(directory.iterdir())
        except (OSError, PermissionError):
            return
        for entry in entries:
            if count >= _GRAPHQL_MAX_FILES:
                return
            if entry.name in _GRAPHQL_SKIP_DIRS or is_unsafe_link(root, entry):
                continue
            if entry.is_dir():
                if depth < _GRAPHQL_MAX_DEPTH:
                    yield from walk(entry, depth + 1)
                continue
            suffix = entry.suffix.lower()
            if suffix not in _GRAPHQL_EXTS and suffix not in _GRAPHQL_CODE_EXTS:
                continue
            rel = _norm(str(entry.relative_to(root)))
            if is_test_file(rel) or is_vendored_file(rel):
                continue
            try:
                text = sources.gated_text(rel, max_bytes=_MAX_FILE_BYTES, errors="ignore")
            except (OSError, ValueError):
                text = None
            if text is None:
                continue
            count += 1
            if suffix in _GRAPHQL_CODE_EXTS and not (
                _GRAPHQL_SDL_MARKER_RE.search(text) or _OWNERSHIP_MARKERS.search(text)
            ):
                continue
            yield rel, text

    yield from walk(root, 1)


def _norm(rel: str) -> str:
    return rel.replace("\\", "/")


def _module_key(rel: str) -> str:
    """Directory of the file — a coarse 'same module' bucket."""
    norm = _norm(rel)
    return norm.rsplit("/", 1)[0] if "/" in norm else ""


__all__ = ["analyze_authz"]
