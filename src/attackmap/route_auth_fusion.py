"""Fuse routes + middleware/guard chains + auth_hints into precise findings (#140).

`scan.auth_hints` are raw signals — a large monorepo emits hundreds. They're
useful evidence, but reviewers want conclusions. This pass resolves, *per
route*, whether an authentication/authorization control guards it, and emits a
single precise finding for the state-changing routes that have none — each
carrying the resolved middleware/guard chain as evidence.

Why not reuse `AttackSurface.auth_signals`? That attribution is file-windowed
(±40 lines), so in a compact file every route inherits a neighbor's auth code.
This module resolves the control on the route's *own* registration chain:

- **Express / Koa / Fastify (JS/TS)** — an auth middleware in the route's
  argument list (`app.post('/x', requireAuth, handler)`) or a global
  `app.use(requireAuth)` / `router.use(...)`.
- **FastAPI / Flask (Python)** — an auth decorator (`@login_required`,
  `@jwt_required`, …), a `dependencies=[Depends(...)]` on the route decorator,
  `Depends(<auth>)` / `Security(...)` in the handler signature, a
  router-level dependency, or an in-handler authentication gate that rejects
  with 401/403 before mutating state (`if "user_id" not in session:
  abort(401)`).
- **Spring (Java)** — `@PreAuthorize` / `@PostAuthorize` / `@Secured` /
  `@RolesAllowed` on the method or controller, or a global security config that
  requires authentication for every request.

Scope (AM038) is the mutating routes the labeled corpus holds to the precise
"no authentication control" claim: `public_api` routes, `admin` routes (the
dedicated admin finding is architectural; it never claims missing auth on a
state change), and `internal`-named paths *only when a route-linked chain
observes an actual state change* — a path name alone does not establish one.
Webhook-style paths (`/webhook/*`, `/hooks/*`, callbacks) are deliberately out
of scope here: their auth model is signature verification, and
:func:`_webhook_exposure_findings` below makes that precise claim instead.
`auth_hints` emission is untouched; this only consumes them.
"""

from __future__ import annotations

import re
from pathlib import Path

from .safe_fs import read_repo_text, walk_repo
from .srcpaths import JS_TS_SUFFIXES
from .models import AttackSurface, AttackTechnique, Finding, FindingLocation, Route, ScanResult

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_WEBHOOK_MUTATING = {"POST", "PUT", "PATCH", "DELETE", "ANY"}
_JS_SUFFIXES = JS_TS_SUFFIXES
_PY_SUFFIXES = {".py"}
_JAVA_SUFFIXES = {".java", ".kt"}

# Webhook-style path segments (AM038): routes that accept inbound events from
# another service. `/webhook/*` (the analyzer's webhook category) plus the
# common `/hooks/*` and callback spellings, which never get that category.
_WEBHOOK_PATH_SEGMENTS = re.compile(r"webhook|hooks?|callbacks?", re.IGNORECASE)

# Signature-verification evidence. A webhook handler that verifies the sender
# (HMAC over the payload, a SDK construct_event call, an explicit verify_*)
# enforces the control this finding is about, so it must not be flagged. Note
# that merely *reading* a webhook secret (`os.getenv("...SECRET")`) is not
# verification — that stays flagged.
_SIGNATURE_VERIFY_MARKERS = re.compile(
    r"\bhmac\b|compare_digest|verify_?signature|verify_?webhook"
    r"|construct_?event|validate_?signature|signature_?check",
    re.IGNORECASE,
)

# A secret env read inside the handler (e.g. STRIPE_WEBHOOK_SECRET) without a
# verification call — worth calling out in the evidence, it shows the intent
# existed but the check is missing.
_SECRET_READ_RE = re.compile(r"(?:getenv|environ\w*)\s*\(\s*['\"][\w.]*SECRET", re.IGNORECASE)

# In-handler authentication gates (Python): a handler that rejects the caller
# with 401/403 *before* mutating state is guarded, even without a decorator.
# Requires BOTH an identity-ish token and an explicit auth-failure rejection —
# a lone `abort(400)` (validation) or a session read that never gates is not
# an authentication control.
_IN_HANDLER_IDENTITY_RE = re.compile(
    r"current_user|currentUser|request\.user|req\.user|ctx\.user|g\.user"
    r"|self\.user|\bsession\b|user_id|userId",
    re.IGNORECASE,
)
_IN_HANDLER_REJECT_RE = re.compile(
    r"\babort\s*\(\s*40[13]\b|HTTPException\s*\([^)]*?40[13]"
    r"|status_code\s*=\s*40[13]|\bstatus\s*=\s*40[13]",
    re.IGNORECASE,
)
# The handler body ends at the next top-level decorator/def/class; bounded so a
# missing boundary can never scan an unbounded region.
_IN_HANDLER_BODY_MAX_LINES = 80

# Identifiers whose presence in a route's chain means it is guarded. Broad
# enough to catch common conventions, specific enough not to match ordinary
# handler code.
_JS_AUTH_TOKEN = re.compile(
    r"\b(?:require(?:Auth|Login|User|Token|Admin)|requiresAuth|isAuthenticated|"
    r"ensureAuth\w*|ensureLoggedIn|ensureAuthenticated|authenticat\w*|authGuard|"
    r"authMiddleware|authenticateJWT|checkAuth|checkJwt|verify(?:Token|Jwt|Auth)|"
    r"jwtMiddleware|passport|protect(?:ed)?Route|withAuth|guard)\b",
    re.IGNORECASE,
)
_PY_AUTH_DECORATOR = re.compile(
    r"@(?:\w+\.)*(?:login_required|jwt_required|token_required|auth_required|"
    r"requires_auth|require_auth|authenticated|permission_required|"
    r"require_(?:oauth|api_key|token)|protected)\b",
    re.IGNORECASE,
)
_PY_DEPENDS_AUTH = re.compile(
    r"(?:Security|Depends)\(\s*(?:[\w.]*)?(?:oauth2_scheme|get_current_user|"
    r"current_user|current_active_user|verify_token|require_\w+|auth\w*|"
    r"authenticate\w*|HTTPBearer|HTTPBasic|JWTBearer|get_user|require_user)",
    re.IGNORECASE,
)
_PY_SECURITY_CALL = re.compile(r"\bSecurity\s*\(")  # fastapi.Security is always auth
_JAVA_AUTH_ANNOTATION = re.compile(
    r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|RoleAllowed|"
    r"Authenticated|HasRole|HasAuthority)\b"
)
_JAVA_GLOBAL_AUTH = re.compile(
    r"\.(?:anyRequest|anyExchange)\s*\(\s*\)\s*\.(?:authenticated|hasRole|hasAuthority|hasAnyRole)"
    r"|\.authorize(?:HttpRequests|Requests|Exchange)\b",
)


def synthesize_unauthenticated_routes(
    scan: ScanResult, surfaces: list[AttackSurface]
) -> list[Finding]:
    """Return the unauthenticated state-changing-route finding (aggregated,
    with the resolved control chain per route as evidence), plus the
    webhook-exposure finding for webhook-style routes without signature
    verification (AM038 — see :func:`_webhook_exposure_findings`)."""
    root = Path(scan.root)
    surface_by_key: dict[tuple[str, str, str], AttackSurface] = {}
    for s in surfaces:
        surface_by_key.setdefault((s.method, s.route, s.file), s)

    content_cache: dict[str, str | None] = {}
    # Only pay the Spring-config scan when there are Java routes to attribute —
    # otherwise this is a no-op that would needlessly walk the whole tree.
    has_java_routes = any(
        Path(r.file).suffix.lower() in _JAVA_SUFFIXES for r in scan.routes
    )
    java_global_auth = (
        _repo_has_java_global_auth(scan, root, content_cache) if has_java_routes else False
    )

    findings: list[Finding] = []
    flagged: list[tuple[Route, str]] = []
    for route in scan.routes:
        if route.method.upper() not in _MUTATING:
            continue
        surface = surface_by_key.get((route.method, route.path, route.file))
        if surface is None:
            continue
        # The auth/upload categories stay out of scope: login/signup handlers
        # are unauthenticated by design and the upload finding is its own
        # claim. Webhook-style paths defer to the webhook-exposure family —
        # their auth model is signature verification, not a middleware/decorator.
        if surface.category in {"auth", "upload", "webhook"}:
            continue
        if _is_webhook_style_path(route.path):
            continue
        # AM038: admin mutations carry the precise missing-auth claim here (the
        # dedicated admin finding is architectural); internal-named paths only
        # count when a route-linked chain observes an actual state change —
        # a path name alone does not establish one.
        is_public_api = surface.category == "public_api" and surface.exposure == "public"
        is_admin = surface.category == "admin" and surface.exposure == "public"
        is_evidenced_internal = (
            surface.category == "internal"
            and (surface.data_store_interaction or surface.outbound_integration)
        )
        if not (is_public_api or is_admin or is_evidenced_internal):
            continue
        # Trust a plugin-declared state (#256); resolve ourselves only when the
        # plugin couldn't tell.
        if route.auth == "required":
            continue
        if route.auth == "anonymous":
            flagged.append((route, _declared_anonymous_evidence(route)))
            continue
        content = _read(root, route.file, content_cache)
        if content is None:
            continue
        control = _resolve_control(route, content, java_global_auth)
        if control is not None:
            continue  # guarded — not a finding
        if is_evidenced_internal:
            # Be explicit that reachability of an internal-named path is
            # inferred: the path name alone does not establish a boundary.
            flagged.append((route, _internal_chain_evidence(route, content, surface)))
        else:
            flagged.append((route, _chain_evidence(route, content)))

    if flagged:
        evidence = [chain for _, chain in flagged[:10]]
        if len(flagged) > 10:
            evidence.append(f"+{len(flagged) - 10} more state-changing route(s) with no resolved auth control")
        findings.append(
            Finding(
                title="State-changing routes are reachable without an authentication control",
                rule_id="unauth-state-change",
                severity="high",
                evidence=evidence,
                locations=[FindingLocation(file=route.file, line=route.line) for route, _ in flagged],
                mitigation=(
                    "Require authentication (and server-side authorization) on every "
                    "state-changing endpoint — attach an auth middleware/guard to the "
                    "route or its router, a dependency/decorator on the handler, or a "
                    "global policy that defaults to deny. Confirm the control actually "
                    "runs before the handler mutates state."
                ),
                confidence="medium",
                tags=["exposed-endpoint", "auth-missing", "state-changing"],
                attack_techniques=[
                    AttackTechnique(
                        technique_id="T1190",
                        name="Exploit Public-Facing Application",
                        tactic="Initial Access",
                        url="https://attack.mitre.org/techniques/T1190/",
                    )
                ],
            )
        )

    findings.extend(_webhook_exposure_findings(scan, surfaces, content_cache))
    return findings


def _declared_anonymous_evidence(route: Route) -> str:
    where = f"{route.file}:{route.line}" if route.line else route.file
    source = f" by {route.source_analyzer}" if route.source_analyzer else ""
    basis = f" ({route.guard_evidence})" if route.guard_evidence else ""
    return f"{route.method} {route.path} ({where}) — declared anonymous{source}{basis}"


def _read(root: Path, rel: str, cache: dict[str, str | None]) -> str | None:
    if rel not in cache:
        try:
            cache[rel] = read_repo_text(root, rel, errors="replace")
        except OSError:
            cache[rel] = None
    return cache[rel]


def _resolve_control(route: Route, content: str, java_global_auth: bool) -> str | None:
    """Return a short description of the control guarding `route`, or None."""
    suffix = Path(route.file).suffix.lower()
    lines = content.splitlines()
    if suffix in _JS_SUFFIXES:
        return _resolve_js(route, content, lines)
    if suffix in _PY_SUFFIXES:
        return _resolve_py(route, lines)
    if suffix in _JAVA_SUFFIXES:
        return _resolve_java(route, lines, java_global_auth)
    return None


def _line_index(route: Route) -> int | None:
    return (route.line - 1) if route.line else None


def _resolve_js(route: Route, content: str, lines: list[str]) -> str | None:
    # Global middleware: app.use(requireAuth) / router.use(passport...).
    for m in re.finditer(r"\b(?:app|router|server)\s*\.\s*use\s*\(([^)]*)\)", content):
        if _JS_AUTH_TOKEN.search(m.group(1)):
            return f"global middleware: {m.group(0).strip()[:80]}"

    idx = _line_index(route)
    if idx is None:
        return None
    # The route registration may span a few lines; take up to the start of the
    # handler body so we inspect the middleware list, not the handler code.
    region = "\n".join(lines[idx : idx + 4])
    handler_start = re.search(r"=>|function\b|\(\s*req\b|\(\s*request\b", region)
    mw_region = region[: handler_start.start()] if handler_start else region
    # Drop the path string literal so a path like '/authenticate' can't match.
    mw_region = re.sub(r"""(['"`])(?:\\.|(?!\1).)*\1""", "", mw_region, count=1)
    if _JS_AUTH_TOKEN.search(mw_region):
        return f"route middleware on {route.path}"
    return None


def _resolve_py(route: Route, lines: list[str]) -> str | None:
    idx = _line_index(route)
    if idx is None:
        return None
    # Decorators can sit above or below the route decorator; scan a small
    # window above, then the handler signature below.
    start = max(0, idx - 4)
    # Find the handler `def`/`async def` at or after the route decorator, then
    # read through the end of its signature (the line with the closing `):`).
    def_line = None
    for i in range(idx, min(len(lines), idx + 6)):
        if re.match(r"\s*(?:async\s+)?def\s+\w+\s*\(", lines[i]):
            def_line = i
            break
    sig_end = def_line if def_line is not None else idx
    if def_line is not None:
        depth = 0
        for i in range(def_line, min(len(lines), def_line + 30)):
            depth += lines[i].count("(") - lines[i].count(")")
            sig_end = i
            if depth <= 0 and "(" in "".join(lines[def_line : i + 1]):
                break
    window = "\n".join(lines[start : sig_end + 1])
    if _PY_AUTH_DECORATOR.search(window):
        return f"auth decorator on {route.path}"
    if _PY_DEPENDS_AUTH.search(window) or _PY_SECURITY_CALL.search(window):
        return f"auth dependency on {route.path} handler"
    # In-handler authentication gate (AM038): a handler body that checks the
    # caller's identity and rejects with 401/403 before mutating state is a
    # control — decorators are not the only place Flask/FastAPI enforce auth.
    body = _py_handler_body(lines, sig_end)
    if _IN_HANDLER_IDENTITY_RE.search(body) and _IN_HANDLER_REJECT_RE.search(body):
        return f"in-handler auth gate on {route.path}"
    # Router-level dependency (applies to every route on the router).
    return _py_router_dependency(lines)


def _py_handler_body(lines: list[str], sig_end: int) -> str:
    """The handler's body text: from the end of its signature to the next
    top-level decorator / def / class (or a bounded cap)."""
    end = min(len(lines), sig_end + 1 + _IN_HANDLER_BODY_MAX_LINES)
    for i in range(sig_end + 1, end):
        if re.match(r"@(?:[\w.]+)|(?:async\s+)?def\s|class\s", lines[i]):
            end = i
            break
    return "\n".join(lines[sig_end + 1 : end])


def _py_router_dependency(lines: list[str]) -> str | None:
    text = "\n".join(lines)
    for m in re.finditer(r"(?:APIRouter|include_router)\s*\(([^)]*)\)", text, re.DOTALL):
        if "dependencies" in m.group(1) and _PY_DEPENDS_AUTH.search(m.group(1)):
            return "router-level auth dependency"
    return None


def _resolve_java(route: Route, lines: list[str], java_global_auth: bool) -> str | None:
    if java_global_auth:
        return "global Spring Security policy requires authentication"
    idx = _line_index(route)
    if idx is None:
        return None
    # Method-level annotations sit just above the mapping (after any preceding
    # method's closing brace). Only scan up to that boundary so a *different*
    # method's @PreAuthorize doesn't leak onto this route.
    method_start = 0
    for i in range(idx - 1, -1, -1):
        if "}" in lines[i] or re.search(r"\b(?:public|private|protected)\b.*\)", lines[i]):
            method_start = i + 1
            break
    window = "\n".join(lines[method_start : idx + 1])
    if _JAVA_AUTH_ANNOTATION.search(window):
        return f"method security annotation on {route.path}"
    # Class-level annotations: only those directly above the class declaration.
    for i, line in enumerate(lines):
        if re.search(r"\b(?:class|interface)\s+\w+", line):
            class_head = "\n".join(lines[max(0, i - 6) : i])
            if _JAVA_AUTH_ANNOTATION.search(class_head):
                return "class-level security annotation"
            break
    return None


def _repo_has_java_global_auth(
    scan: ScanResult, root: Path, cache: dict[str, str | None]
) -> bool:
    """True when a Spring Security config requires auth for every request —
    then per-route method annotations aren't needed and routes aren't flagged."""
    java_files = {r.file for r in scan.routes if Path(r.file).suffix.lower() in _JAVA_SUFFIXES}
    # Config usually lives elsewhere; check route files plus any *Security*.java.
    candidates = set(java_files)
    for path in (p for p in walk_repo(root) if p.suffix == ".java" and "Security" in p.name):
        try:
            candidates.add(str(path.relative_to(root)))
        except ValueError:
            continue
    for rel in candidates:
        content = _read(root, rel, cache)
        if content and "anyRequest" in content and _JAVA_GLOBAL_AUTH.search(content):
            # Require an explicit authenticated()/hasRole() to avoid matching a
            # config that permits all.
            if re.search(r"\.(?:authenticated|hasRole|hasAuthority|hasAnyRole|fullyAuthenticated)\s*\(", content):
                return True
    return False


def _chain_evidence(route: Route, content: str) -> str:
    """Describe what the control-chain resolution found (i.e. nothing)."""
    loc = f"{route.file}:{route.line}" if route.line else route.file
    suffix = Path(route.file).suffix.lower()
    if suffix in _JS_SUFFIXES:
        has_any = bool(_JS_AUTH_TOKEN.search(content))
    elif suffix in _PY_SUFFIXES:
        has_any = bool(_PY_AUTH_DECORATOR.search(content) or _PY_DEPENDS_AUTH.search(content))
    elif suffix in _JAVA_SUFFIXES:
        has_any = bool(_JAVA_AUTH_ANNOTATION.search(content))
    else:
        has_any = False
    tail = (
        "auth controls exist in the file but none guard this route"
        if has_any
        else "no authentication/authorization control found on the route's chain"
    )
    return f"{route.method} {route.path} in {loc} — {tail}"


def _internal_chain_evidence(route: Route, content: str, surface: AttackSurface) -> str:
    """Chain evidence for an internal-named mutating route: honest that the
    path name does not establish a network boundary, and explicit about the
    observed state-change evidence that qualifies the route."""
    base = _chain_evidence(route, content)
    observed = (
        "datastore write" if surface.data_store_interaction else "outbound call"
    )
    return (
        f"{base} (internal-style path; no network boundary is established "
        f"statically, but a route-linked chain reaches a {observed})"
    )


def resolve_route_control(route: Route, content: str) -> str | None:
    """Public wrapper over the per-route control resolution, so other core
    passes (authz) can ask "is an authentication control resolved on this
    route's chain?" without re-deriving the framework rules.

    Java global Spring Security config is *not* consulted here (the caller
    would need the repo-wide scan); callers restrict use to JS/Python routes
    or accept that a global Java policy is resolved only by the fusion pass.
    """
    return _resolve_control(route, content, java_global_auth=False)


# --- webhook exposure (AM038) ------------------------------------------------


def _is_webhook_style_path(path: str) -> bool:
    """True for paths with a webhook-ish segment: `webhook(s)`, `hook(s)`,
    `callback(s)` — routes that accept inbound events from another service."""
    segments = [seg for seg in path.split("?", 1)[0].split("/") if seg]
    return any(_WEBHOOK_PATH_SEGMENTS.search(seg) for seg in segments)


def _handler_region(route: Route, routes: list[Route], lines: list[str]) -> str:
    """The route's own handler region text: from its registration line to the
    next route registration in the same file (or EOF). Region-scoped so a
    *sibling* handler's signature verification (or lack of it) never decides
    this route."""
    if route.line is None:
        return "\n".join(lines)
    later = sorted(
        r.line for r in routes
        if r.file == route.file and r.line is not None and r.line > route.line
    )
    end = (min(later) - 1) if later else len(lines)
    return "\n".join(lines[route.line - 1 : end])


def _webhook_exposure_findings(
    scan: ScanResult,
    surfaces: list[AttackSurface],
    content_cache: dict[str, str | None],
) -> list[Finding]:
    """Webhook-style routes that accept inbound events with no signature
    verification (AM038).

    Complements the route-linked (taint-backed) `public-webhook` finding in
    ``threat_model``: that one needs attacker-controlled data to reach a sink,
    which a webhook that merely *records* events never shows. This pass fires
    on observed same-file datastore/outbound activity instead — and never for
    a route the taint-backed finding already covers, so the two cannot
    duplicate each other.
    """
    root = Path(scan.root)
    db_files = {db.file for db in scan.databases}
    outbound_files = {call.file for call in scan.external_calls}
    strong_auth = {"jwt", "oauth", "authorization", "service_auth"}

    flagged: list[AttackSurface] = []
    notes: list[str] = []
    for surface in surfaces:
        if surface.method not in _WEBHOOK_MUTATING:
            continue
        if not _is_webhook_style_path(surface.route):
            continue
        if surface.exposure != "public":
            continue
        if surface.auth == "required":
            continue
        if any(signal in strong_auth for signal in surface.auth_signals):
            continue
        # Route-linked interaction on a *webhook-category* route means the
        # taint-backed `public-webhook` finding in threat_model already covers
        # it. Webhook-style paths outside that category (e.g. `/hooks/*`, which
        # never get it) are never covered there, interaction or not.
        if (
            surface.category == "webhook"
            and (surface.data_store_interaction or surface.outbound_integration)
        ):
            continue
        # Observed processing evidence in the same file (a datastore hint or an
        # outbound call) — a webhook route with nothing observed stays quiet.
        if surface.file not in db_files and surface.file not in outbound_files:
            continue
        content = _read(root, surface.file, content_cache)
        if content is None:
            continue
        region = _handler_region(
            next(
                (r for r in scan.routes if r.file == surface.file and r.path == surface.route
                 and r.method == surface.method),
                Route(path=surface.route, method=surface.method, file=surface.file, line=surface.line),
            ),
            scan.routes,
            content.splitlines(),
        )
        if _SIGNATURE_VERIFY_MARKERS.search(region):
            continue  # verification control present — not exposed
        flagged.append(surface)
        note = "no signature-verification code found in its handler"
        if _SECRET_READ_RE.search(region):
            note += " although a webhook secret is read there"
        notes.append(
            f"{surface.method} {surface.route} in "
            f"{surface.file}:{surface.line or '?'} — {note}; "
            f"same-file {'datastore' if surface.file in db_files else 'outbound'} activity observed"
        )

    if not flagged:
        return []
    return [
        Finding(
            title="Public webhook endpoint may trust attacker-controlled events",
            rule_id="public-webhook",
            severity="high",
            evidence=notes[:10],
            locations=[
                FindingLocation(file=s.file, line=s.line) for s in flagged[:10]
            ],
            mitigation=(
                "Require signature verification before processing webhook payloads, "
                "reject replays, and keep any downstream state change behind strict "
                "validation."
            ),
            confidence="medium",
            tags=["exposed-endpoint", "auth-missing"],
        )
    ]
