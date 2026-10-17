"""Cross-repo contract linking — cross-repo phase 2 (#146b).

Given a fleet of independently-scanned repos (#146a), link one repo's **outbound
HTTP calls** to another repo's **routes** — the client↔server seam. This is the
one linking dimension that reuses signals both sides already produce
(`ExternalCall.target`/`.method` and `Route.path`/`.method`); the richer
dimensions (RPC callers, shared schemas, queues, DB tables, token iss/aud) are
new extraction deferred to later work.

Matching is by **normalized path template + method**, cross-repo only, and a
match becomes an **observed** link only when the call's destination authority
positively identifies the server repo (C28):

- The call's URL path and the route's path are each normalized to a segment
  tuple with concrete ids and path params collapsed to ``*`` (so
  ``/users/123`` ↔ ``/users/{id}`` ↔ ``/users/:id`` align).
- A link requires the normalized paths to be **equal** and the methods
  compatible (equal, or either side unknown/``ANY``).
- Destination resolution: the call's host must equal the server repo's fleet id
  or root directory name — no truncation, so ``auth-api`` and ``auth-worker``
  stay distinct — or a **declared deployment alias** must positively name the
  server (below); DNS-suffixed or unknown hosts, relative targets, ambiguous
  identities, and explicit ports keep the match as a **candidate** link that
  never supports an observed trust path.
- Precision guards: the path must carry at least one **static** segment (a bare
  ``/{id}`` won't link), infra/static routes are excluded, and client and
  server must be **different** repos.

Deployment aliases (AM040/C28): a fleet may *declare* hostname → repo mappings
via ``DeploymentAliases`` — exact public names (``auth.bsky.social`` →
``auth-api``), DNS-suffix namespaces (``.internal`` strips to a repo identity),
and explicit ``host:port`` bindings (the only way an explicitly-ported call
resolves). Declarations are positive only — never inferred by name similarity —
and a host an alias maps to more than one repo (including collisions with
another repo's own identity) keeps the affected links candidates.

Pure and deterministic — takes ``(repo_id, ScanResult)`` primitives so it stays
unit-testable without a real scan and imports nothing from the CLI/fleet layer.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .models import ExternalCall, Route, ScanResult
from .srcpaths import is_infra_route, is_test_file, is_vendored_file

# A path segment that is a concrete instance id rather than a static resource
# name: an explicit path param (`{id}`, `:id`, `<id>`), an all-digits segment,
# a uuid, or a long hex blob. Collapsed to `*` so caller and server templates
# align regardless of how each side writes the variable part.
_PARAM_SEG = re.compile(r"^([{:<].*|.*[}>]|\d+|[0-9a-fA-F-]{16,}|[0-9a-fA-F]{8,})$")
_PLACEHOLDER = "*"


@dataclass(frozen=True)
class ContractLink:
    """A matched client→server seam across two repos.

    ``resolution`` separates an *observed* trust path (the call's destination
    authority positively identifies the server repo) from a *candidate* (path
    and method align but the destination is absent, unresolved, ambiguous, or
    carries an explicit port no server side is known to answer). Only observed
    links may support trust-path findings (C28).
    """

    client_repo: str
    server_repo: str
    method: str  # the route's method (the served contract)
    path_template: str  # normalized template, e.g. "users/*"
    client_target: str  # the raw outbound URL as written in the caller
    client_file: str
    client_line: int | None
    server_route_path: str  # the route path as declared on the server
    server_file: str
    server_line: int | None
    # The caller's concrete verb — retained so a state-changing call to a
    # method-unspecified (`ANY`) server route (e.g. XRPC surfaces) isn't lost by
    # downstream trust-gap analysis (#146d). `None` when unknown (config URL).
    client_method: str | None = None
    # Destination identity (C28): normalized ``host[:port]`` from the call
    # target when one is present; ``None`` for relative/variable targets.
    destination: str | None = None
    resolution: str = "observed"  # "observed" | "candidate"
    resolution_reason: str = ""  # "" | no_destination | unresolved_host | ambiguous_identity | explicit_port


@dataclass(frozen=True)
class DeploymentAliases:
    """Explicit deployment-seam declarations (C28/AM040): hostname → repo
    mappings a fleet operator knows to be true. Positive declarations only —
    nothing is inferred by name similarity.

    - ``hosts``: an exact hostname answering for one repo, e.g. a public DNS
      name (``auth.bsky.social`` → ``auth-api``).
    - ``dns_suffixes``: namespace suffixes (``".internal"``) under which a host
      strips to a repo identity — ``feed-generator.internal`` → repo
      ``feed-generator`` — with the stripped name matched whole (no
      truncation). Undeclared suffixes never strip.
    - ``host_ports``: exact ``host:port`` → repo bindings — the only way an
      explicitly-ported call resolves, because a port may route where a bare
      hostname declaration cannot vouch.

    Alias values address a repo by any of its identities (fleet id or root
    directory name, case-insensitive) and may name repos outside the current
    fleet, in which case they never match. A host declared or stripped to more
    than one repo — including collisions with another repo's own identity —
    keeps every affected link a candidate, never an observed trust path.
    """

    hosts: Mapping[str, str] = field(default_factory=dict)
    host_ports: Mapping[str, str] = field(default_factory=dict)
    dns_suffixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "hosts", _declared_hosts(self.hosts))
        object.__setattr__(self, "host_ports", _declared_host_ports(self.host_ports))
        object.__setattr__(self, "dns_suffixes", _declared_suffixes(self.dns_suffixes))


def _declared_hosts(mapping: Mapping[str, str]) -> dict[str, str]:
    """Normalize exact-host declarations: bare lowercased hostnames, non-empty
    on both sides. A key carrying a port, scheme, or path is rejected — the
    declarer means ``host_ports``, and a silently dead key hides a config
    mistake."""
    out: dict[str, str] = {}
    for host, repo in mapping.items():
        h, r = str(host).strip().lower(), str(repo).strip().lower()
        if not h or not r:
            raise ValueError(f"host alias {host!r} -> {repo!r} needs a non-empty host and repo")
        if any(c in h for c in ":/?#"):
            raise ValueError(f"host alias {host!r} must be a bare hostname (bind host:port via host_ports)")
        out[h] = r
    return out


def _declared_host_ports(mapping: Mapping[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for binding, repo in mapping.items():
        host, _, port = str(binding).strip().lower().rpartition(":")
        r = str(repo).strip().lower()
        if not host or not port.isdigit() or not r:
            raise ValueError(
                f"host:port alias {binding!r} -> {repo!r} must be 'host:port' -> repo with a numeric port"
            )
        out[f"{host}:{port}"] = r
    return out


def _declared_suffixes(suffixes: tuple[str, ...]) -> tuple[str, ...]:
    out: dict[str, None] = {}
    for suffix in suffixes:
        s = str(suffix).strip().lower()
        s = s[1:] if s.startswith("*") else s
        if not s.startswith(".") or len(s) < 2:
            raise ValueError(f"dns suffix {suffix!r} must be a dotted suffix like '.internal'")
        out[s] = None
    return tuple(out)


_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def destination_authority(target: str) -> tuple[str, bool] | None:
    """Normalized ``host[:port]`` of an outbound target, and whether the port
    was written explicitly.

    Handles absolute URLs and scheme-less ``host[:port]/path`` forms. Returns
    ``None`` when the target carries no usable authority (relative path,
    variable interpolation, or an empty host).
    """
    text = target.strip()
    if not text or "{" in text or "<" in text or "$" in text or "%" in text:
        return None
    if _SCHEME.match(text):
        parts = urlsplit(text)
        host = (parts.hostname or "").lower()
        if not host:
            return None
        return (f"{host}:{parts.port}" if parts.port is not None else host), parts.port is not None
    # Scheme-less: split the authority off the path by hand.
    authority = text.split("/", 1)[0]
    if not authority or authority.startswith("."):
        return None
    host, _, port = authority.rpartition(":")
    if not host:
        host, port = authority, ""
    if not host or not host.replace(".", "").replace("-", "").replace("_", "").isalnum():
        return None
    if port:
        if not port.isdigit():
            return None
        return f"{host.lower()}:{port}", True
    return host.lower(), False


def _repo_identities(repo_id: str, scan: ScanResult) -> set[str]:
    """Names a repo answers to at the deployment seam: its fleet id and its
    root directory name (both lowered). No truncation — ``auth-api`` and
    ``auth-worker`` stay distinct (C28)."""
    names = {repo_id.lower()}
    root = (scan.root or "").replace("\\", "/").rstrip("/")
    if root:
        names.add(root.rsplit("/", 1)[-1].lower())
    return {name for name in names if name}


def _host_repos(host: str, identities: dict[str, set[str]], aliases: DeploymentAliases) -> set[str]:
    """Repos a portless destination host positively identifies: a repo identity
    (fleet id / root basename), an exact alias declaration, or a declared
    DNS-suffix namespace stripping to a repo identity. The union is deliberate —
    a host named by more than one source is ambiguous, not resolved (C28)."""
    repos = {rid for rid, names in identities.items() if host in names}
    declared = aliases.hosts.get(host)
    if declared is not None:
        repos.update(rid for rid, names in identities.items() if declared in names)
    for suffix in aliases.dns_suffixes:
        if len(host) > len(suffix) and host.endswith(suffix):
            base = host[: -len(suffix)]
            repos.update(rid for rid, names in identities.items() if base in names)
    return repos


def _normalize_path(path: str, *, client: bool = False) -> tuple[str, ...] | None:
    """Normalize a URL/route path to a segment tuple with instance ids collapsed
    to ``*``. Returns ``None`` when there is nothing linkable (no path, or only a
    root / all-variable path with no static segment to anchor on).

    ``client=True`` handles the concatenation idiom: an outbound URL built as
    ``base + "/api/orders/" + oid`` is captured only up to the trailing slash, so
    a client path ending in ``/`` is treated as having a dynamic final segment
    (``api/orders/`` → ``("api","orders","*")``) — which then aligns with the
    server template ``/api/orders/{id}`` while still separating from the bare
    collection route ``/api/orders``."""
    if not path:
        return None
    # A full URL (client side) — take just the path component.
    if "://" in path:
        path = urlsplit(path).path
    else:
        path = path.split("?", 1)[0].split("#", 1)[0]
    trailing_slash = path.endswith("/") and path.strip() not in {"", "/"}
    segments = [s for s in path.split("/") if s]
    if not segments:
        return None
    norm = [_PLACEHOLDER if _PARAM_SEG.match(s) else s.lower() for s in segments]
    if client and trailing_slash:
        norm.append(_PLACEHOLDER)  # the concatenated dynamic segment
    # Require at least one static segment — a bare `/{id}` or `/*/*` is too
    # generic to link on without producing spurious cross-repo edges.
    if all(s == _PLACEHOLDER for s in norm):
        return None
    return tuple(norm)


def _method_compatible(call_method: str | None, route_method: str) -> bool:
    """Methods match when they're equal, or either side is unknown/ANY."""
    rm = (route_method or "ANY").upper()
    if call_method is None or rm in {"", "ANY"}:
        return True
    return call_method.upper() == rm


def _excluded_source(rel_file: str) -> bool:
    """Test/spec/fixture and vendored/generated files are not production
    architecture — a cross-repo link anchored on one is noise. Honors the same
    `ATTACKMAP_INCLUDE_TESTS`/`_VENDORED` opt-ins as the rest of the scanner."""
    return is_test_file(rel_file) or is_vendored_file(rel_file)


def _linkable_calls(scan: ScanResult) -> list[tuple[ExternalCall, tuple[str, ...]]]:
    out: list[tuple[ExternalCall, tuple[str, ...]]] = []
    for call in scan.external_calls:
        if _excluded_source(call.file):
            continue
        norm = _normalize_path(call.target, client=True)
        if norm is None:
            continue
        if is_infra_route("/" + "/".join(norm)):
            continue
        out.append((call, norm))
    return out


def _linkable_routes(scan: ScanResult) -> list[tuple[Route, tuple[str, ...]]]:
    out: list[tuple[Route, tuple[str, ...]]] = []
    for route in scan.routes:
        if _excluded_source(route.file):
            continue
        if is_infra_route(route.path):
            continue
        norm = _normalize_path(route.path)
        if norm is None:
            continue
        out.append((route, norm))
    return out


def link_contracts(
    repo_scans: list[tuple[str, ScanResult]], aliases: DeploymentAliases | None = None
) -> list[ContractLink]:
    """Return the client→server contract links across a fleet of repos.

    For every ordered pair of *distinct* repos (A as client, B as server), match
    A's linkable outbound calls to B's linkable routes by normalized path +
    method. A match is an **observed** link only when the call's destination
    authority positively identifies B (C28) — through B's own identities or a
    declared deployment alias; otherwise the match survives as a **candidate**
    — inspectable, but never an observed trust path. ``aliases`` defaults to no
    declarations (identity-only resolution). Deterministic; deduped on the full
    link identity.
    """
    aliases = aliases or DeploymentAliases()
    calls_by_repo = {rid: _linkable_calls(scan) for rid, scan in repo_scans}
    routes_by_repo = {rid: _linkable_routes(scan) for rid, scan in repo_scans}
    identities = {rid: _repo_identities(rid, scan) for rid, scan in repo_scans}

    def resolve(call_target: str, server_id: str) -> tuple[str | None, str, str]:
        """(destination, resolution, reason) for a call toward *server_id*."""
        authority = destination_authority(call_target)
        if authority is None:
            return None, "candidate", "no_destination"
        destination, explicit_port = authority
        host = destination.rsplit(":", 1)[0] if explicit_port else destination
        host_repos = _host_repos(host, identities, aliases)
        if explicit_port:
            # A port routes where a bare hostname cannot vouch: only an
            # equally explicit host:port declaration resolves it (C28). The
            # portless view still names the most informative candidate reason.
            bound = aliases.host_ports.get(destination)
            repos = (
                {rid for rid, names in identities.items() if bound in names}
                if bound is not None
                else set()
            )
            if server_id not in repos:
                if server_id not in host_repos:
                    return destination, "candidate", "unresolved_host"
                if len(host_repos) > 1:
                    return destination, "candidate", "ambiguous_identity"
                return destination, "candidate", "explicit_port"
        else:
            repos = host_repos
            if server_id not in repos:
                return destination, "candidate", "unresolved_host"
        if len(repos) > 1:
            return destination, "candidate", "ambiguous_identity"
        return destination, "observed", ""

    links: list[ContractLink] = []
    seen: set[tuple] = set()
    for client_id, _client_scan in repo_scans:
        for call, call_norm in calls_by_repo[client_id]:
            for server_id, _server_scan in repo_scans:
                if server_id == client_id:
                    continue
                for route, route_norm in routes_by_repo[server_id]:
                    if call_norm != route_norm:
                        continue
                    if not _method_compatible(call.method, route.method):
                        continue
                    key = (
                        client_id,
                        server_id,
                        call.file,
                        call.line,
                        route.file,
                        route.method,
                        route.path,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    destination, resolution, reason = resolve(call.target, server_id)
                    links.append(
                        ContractLink(
                            client_repo=client_id,
                            server_repo=server_id,
                            method=(route.method or "ANY").upper(),
                            path_template="/".join(call_norm),
                            client_target=call.target,
                            client_file=call.file,
                            client_line=call.line,
                            server_route_path=route.path,
                            server_file=route.file,
                            server_line=route.line,
                            client_method=(call.method.upper() if call.method else None),
                            destination=destination,
                            resolution=resolution,
                            resolution_reason=reason,
                        )
                    )
    links.sort(
        key=lambda link: (link.client_repo, link.server_repo, link.path_template, link.method)
    )
    return links


def route_template(path: str) -> str | None:
    """Public helper: the normalized template for a route path (instance ids
    collapsed to ``*``), or ``None`` if too generic to key on. Used by the
    cross-repo anomaly cohorting (#146d) to group the *same* resource route
    across repos."""
    norm = _normalize_path(path)
    return "/".join(norm) if norm is not None else None


__all__ = ["ContractLink", "DeploymentAliases", "link_contracts", "route_template"]
