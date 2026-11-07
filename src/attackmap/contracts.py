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
and explicit ``host:port`` bindings. Declarations are positive only — never
inferred by name similarity — and a host an alias maps to more than one repo
(including collisions with another repo's own identity) keeps the affected
links candidates.

Further C28 service-resolution declarations: a service may declare its listen
port (``service_ports`` — with ``host_ports``, the only ways an
explicitly-ported call resolves) and the scheme it serves
(``service_protocols`` — a call whose URL scheme contradicts the declaration
stays a candidate, so the same host on a different scheme never silently
resolves). A declared ``proxies`` hostname fronting one repo resolves a call to
it as ``observed_via_proxy`` — the logical seam is positively declared, but no
direct service-to-service edge is claimed and no trust-path finding rides it.
Every alias-resolved observed link records which declaration vouched for it in
``alias_provenance``; declarations extracted from config files additionally
carry their declaring file via ``source_files``.

Pure and deterministic — takes ``(repo_id, ScanResult)`` primitives so it stays
unit-testable without a real scan and imports nothing from the CLI/fleet layer.
"""

from __future__ import annotations

import re
import ntpath
import posixpath
from pathlib import PurePosixPath
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
    and method align but the destination is absent, unresolved, ambiguous,
    carries an explicit port no declaration vouches for, or contradicts the
    server's declared protocol). ``observed_via_proxy`` is an observed logical
    seam that dials a declared proxy rather than the server directly — it never
    renders as a direct edge and never supports trust-path findings (C28).
    Only directly observed links may support trust-path findings.
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
    resolution: str = "observed"  # "observed" | "observed_via_proxy" | "candidate"
    resolution_reason: str = ""  # "" | no_destination | unresolved_host | unresolved_namespace | ambiguous_identity | explicit_port | scheme_mismatch | unsupported_protocol
    # The call target's URL scheme (``http``/``https``/…) when it carries one;
    # `None` for scheme-less authorities and relative targets (C28 protocol
    # modeling).
    scheme: str | None = None
    # Which deployment declaration resolved the destination, e.g.
    # "hosts:auth.bsky.social", "dns_suffix:.internal", "host_ports:h:p",
    # "service_ports:repo:port", "proxies:edge.internal". `None` when the
    # destination resolved by repo identity alone (C28 alias provenance). On a
    # scheme_mismatch candidate it instead names the protocol declaration the
    # call's scheme contradicted ("service_protocols:repo:scheme") — the
    # declaration that kept the match a candidate.
    alias_provenance: str | None = None
    # The declared proxy hostname the call dials on an ``observed_via_proxy``
    # link; `None` on every other resolution (C28 proxy modeling).
    proxy_host: str | None = None
    server_namespace: str | None = None
    server_service_name: str | None = None
    declaration_refs: tuple[DeclarationSource, ...] = ()
    # These describe the explicitly owned backend Service, not the client URL
    # or the ingress listener represented by destination/scheme.
    server_port: int | None = None
    server_protocol: str | None = None


def _repository_root_identity(value: str) -> str:
    """Compare captured repository roots without touching their live trees."""
    if ntpath.splitdrive(value)[0]:
        if not ntpath.isabs(value):
            raise ValueError("Scoped service ownership requires an absolute repository root")
        return ntpath.normcase(ntpath.normpath(value))
    if not posixpath.isabs(value):
        raise ValueError("Scoped service ownership requires an absolute repository root")
    return posixpath.normpath(value)


@dataclass(frozen=True)
class DeclarationSource:
    """An exact config origin; capture/hash verification belongs to consumers."""

    repository_root: str
    file: str
    line: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, str) or any(ord(c) < 32 for c in self.repository_root):
            raise ValueError("Declaration source requires an absolute repository root")
        object.__setattr__(self, "repository_root", _repository_root_identity(self.repository_root))
        if not isinstance(self.file, str) or not self.file or any(ord(c) < 32 for c in self.file):
            raise ValueError("Declaration source requires a safe relative file")
        path = self.file.replace("\\", "/")
        if PurePosixPath(path).is_absolute() or ":" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ValueError("Declaration source requires a safe relative file")
        object.__setattr__(self, "file", path)
        if self.line is not None and (type(self.line) is not int or self.line < 1):
            raise ValueError("Declaration source line must be positive or unknown")


@dataclass(frozen=True)
class ScopedServiceBinding:
    """An explicitly owned Kubernetes Service, not an inferred DNS alias."""

    repository_root: str
    port: int | None = None
    protocol: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository_root, str) or any(ord(c) < 32 for c in self.repository_root):
            raise ValueError("Scoped service ownership requires a repository root")
        object.__setattr__(self, "repository_root", _repository_root_identity(self.repository_root))
        if self.port is not None and (type(self.port) is not int or not 1 <= self.port <= 65535):
            raise ValueError("Scoped service port must be an integer between 1 and 65535")
        if self.protocol is not None and self.protocol not in ("http", "https"):
            raise ValueError("Scoped service protocol must be http or https; unsupported protocols need a negative fact")


_NAMESPACE_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _scoped_service_key(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Scoped service identity requires namespace/service text")
    parts = value.split("/")
    if len(parts) != 2 or any(_NAMESPACE_LABEL.fullmatch(part) is None for part in parts):
        raise ValueError("Scoped service identity requires explicit namespace/service DNS labels")
    return value


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
    - ``host_ports``: exact ``host:port`` → repo bindings — with a repo's own
      declared listen port (``service_ports``) the only ways an
      explicitly-ported call resolves, because a port may route where a bare
      hostname declaration cannot vouch.
    - ``proxies``: a bare hostname that fronts exactly one repo. A call to the
      proxy resolves as ``observed_via_proxy`` carrying the proxy identity —
      never a direct service-to-service edge and never a trust-path finding.
      A host declared as both a direct alias and a proxy is rejected (the two
      claim different topologies).
    - ``service_ports``: repo identity → its declared listen port.
    - ``service_protocols``: repo identity → the scheme the service serves
      (``http``/``https``); a call whose URL scheme contradicts it stays a
      candidate. Config extraction sources it only from positive declarations:
      a k8s Service port's ``appProtocol``, an nginx ``proxy_pass`` scheme, or
      an Ingress ``backend-protocol`` annotation.
    - ``source_files``: provenance key → the config file that declared it
      (config-file extraction, C28), e.g. ``service_ports:auth-api:8443`` →
      ``auth-api/k8s/service.yaml``. Surfaced by appending the file to the
      link's ``alias_provenance``; CLI declarations carry none.
    - ``unresolved_proxies``: normalized hosts with unmodeled/conflicting proxy
      routing. These negative facts prevent any direct or proxy identity
      fallback from claiming an observed contract for that host.
    - ``scoped_services``: internal ``namespace/service`` keys bound to exact
      repository roots. These declarations do not create cluster DNS aliases.
    - ``scoped_proxies``: concrete ingress hostname → explicit scoped Service.
      Only an exact owned Service may establish this logical proxy seam.
    - ``unresolved_service_protocols``: service identities or scoped keys whose
      explicit protocol was unsupported or conflicting. Discarding a positive
      declaration must never turn that negative evidence into an unknown.

    Alias values address a repo by any of its identities (fleet id or root
    directory name, case-insensitive) and may name repos outside the current
    fleet, in which case they never match. A host declared or stripped to more
    than one repo — including collisions with another repo's own identity —
    keeps every affected link a candidate, never an observed trust path.
    """

    hosts: Mapping[str, str] = field(default_factory=dict)
    host_ports: Mapping[str, str] = field(default_factory=dict)
    dns_suffixes: tuple[str, ...] = ()
    proxies: Mapping[str, str] = field(default_factory=dict)
    service_ports: Mapping[str, int] = field(default_factory=dict)
    service_protocols: Mapping[str, str] = field(default_factory=dict)
    source_files: Mapping[str, str] = field(default_factory=dict)
    # Negative config evidence must survive alias merges: removing a proxy
    # alone could expose an unsupported direct repo-identity/alias fallback.
    unresolved_proxies: tuple[str, ...] = ()
    # These internal keys never become inferred .svc or cluster-domain aliases.
    scoped_services: Mapping[str, ScopedServiceBinding] = field(default_factory=dict)
    scoped_proxies: Mapping[str, str] = field(default_factory=dict)
    unresolved_service_protocols: tuple[str, ...] = ()
    declaration_sources: Mapping[str, tuple[DeclarationSource, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        hosts = _declared_hosts(self.hosts)
        object.__setattr__(self, "hosts", hosts)
        object.__setattr__(self, "host_ports", _declared_host_ports(self.host_ports))
        object.__setattr__(self, "dns_suffixes", _declared_suffixes(self.dns_suffixes))
        object.__setattr__(self, "proxies", _declared_proxies(self.proxies, hosts))
        object.__setattr__(self, "service_ports", _declared_service_ports(self.service_ports))
        object.__setattr__(self, "service_protocols", _declared_service_protocols(self.service_protocols))
        object.__setattr__(self, "source_files", _declared_sources(self.source_files))
        unresolved = _declared_hosts({str(host).strip().rstrip("."): "unresolved"
                                      for host in self.unresolved_proxies})
        object.__setattr__(self, "unresolved_proxies", tuple(sorted(unresolved)))
        services = {}
        for key, binding in self.scoped_services.items():
            _scoped_service_key(key)
            if not isinstance(binding, ScopedServiceBinding):
                raise ValueError("Scoped service declarations require typed ownership bindings")
            services[key] = binding
        proxies = {}
        for host, key in self.scoped_proxies.items():
            normalized = host.lower().rstrip(".")
            if not normalized or any(_NAMESPACE_LABEL.fullmatch(label) is None for label in normalized.split(".")):
                raise ValueError("Scoped proxy requires a concrete hostname")
            _scoped_service_key(key)
            if normalized in proxies and proxies[normalized] != key:
                raise ValueError("Conflicting scoped proxy declarations")
            proxies[normalized] = key
        object.__setattr__(self, "scoped_services", services)
        object.__setattr__(self, "scoped_proxies", proxies)
        negative_protocols = set()
        for identity in self.unresolved_service_protocols:
            if not isinstance(identity, str) or not identity or any(ord(c) < 32 for c in identity):
                raise ValueError("Unresolved protocol identities must be nonempty strings")
            if "/" in identity:
                _scoped_service_key(identity)
            negative_protocols.add(identity.lower())
        object.__setattr__(self, "unresolved_service_protocols", tuple(sorted(negative_protocols)))
        declarations = {}
        for key, sources in self.declaration_sources.items():
            if not isinstance(key, str) or not key.startswith(_SOURCE_KEY_PREFIXES):
                raise ValueError("Declaration source key must name a modeled declaration")
            if not isinstance(sources, tuple) or any(not isinstance(source, DeclarationSource) for source in sources):
                raise ValueError("Declaration sources require a tuple of typed origins")
            declarations[key] = tuple(sorted(set(sources), key=lambda source: (
                source.repository_root, source.file, source.line or 0)))
        object.__setattr__(self, "declaration_sources", declarations)


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
        if h in out and out[h] != r:
            raise ValueError(f"conflicting host alias {host!r}")
        out[h] = r
    return out


def _declared_host_ports(mapping: Mapping[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for binding, repo in mapping.items():
        host, _, port = str(binding).strip().lower().rpartition(":")
        r = str(repo).strip().lower()
        if (not host or any(c in host for c in "/?#@") or not port.isascii()
                or not port.isdigit() or not 1 <= int(port) <= 65535 or not r):
            raise ValueError(
                f"host:port alias {binding!r} -> {repo!r} must be 'host:port' -> repo with a numeric port"
            )
        key = f"{host}:{int(port)}"
        if key in out and out[key] != r:
            raise ValueError(f"conflicting host:port alias {binding!r}")
        out[key] = r
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


def _declared_proxies(mapping: Mapping[str, str], hosts: Mapping[str, str]) -> dict[str, str]:
    """Normalize proxy declarations: a bare hostname fronting exactly one repo.
    One backend per proxy host — a proxy with unknown routing is not modeled.
    A host declared as both a direct alias and a proxy is rejected: the two
    declarations claim different topologies for the same traffic, and a
    silently ignored one hides a config mistake."""
    out: dict[str, str] = {}
    for host, repo in mapping.items():
        h, r = str(host).strip().lower(), str(repo).strip().lower()
        if not h or not r:
            raise ValueError(f"proxy declaration {host!r} -> {repo!r} needs a non-empty proxy host and repo")
        if any(c in h for c in ":/?#"):
            raise ValueError(f"proxy declaration {host!r} must be a bare hostname (no port, scheme, or path)")
        if h in hosts:
            raise ValueError(f"host {host!r} is declared both as a direct alias and as a proxy")
        out[h] = r
    return out


def _declared_service_ports(mapping: Mapping[str, int]) -> dict[str, int]:
    """Normalize listen-port declarations: repo identity → TCP port 1..65535."""
    out: dict[str, int] = {}
    for repo, port in mapping.items():
        r, text = str(repo).strip().lower(), str(port).strip()
        if not r or not text.isdigit() or not 1 <= int(text) <= 65535:
            raise ValueError(
                f"service port {repo!r}={port!r} must be REPO=PORT with a port between 1 and 65535"
            )
        out[r] = int(text)
    return out


def _declared_service_protocols(mapping: Mapping[str, str]) -> dict[str, str]:
    """Normalize service-protocol declarations: repo identity → http|https.
    Other protocols are rejected — the linker cannot compare against them, and
    a silently ignored declaration hides a config mistake."""
    out: dict[str, str] = {}
    for repo, scheme in mapping.items():
        r, s = str(repo).strip().lower(), str(scheme).strip().lower()
        if not r or s not in {"http", "https"}:
            raise ValueError(f"service protocol {repo!r}={scheme!r} must be REPO=http or REPO=https")
        out[r] = s
    return out


# Provenance-key prefixes source_files entries are keyed by — the same strings
# link_contracts records in ContractLink.alias_provenance (C28).
_SOURCE_KEY_PREFIXES = (
    "hosts:",
    "host_ports:",
    "dns_suffix:",
    "service_ports:",
    "proxies:",
    "service_protocols:",
    "scoped_services:",
    "scoped_proxies:",
    "unresolved_service_protocols:",
)


def _declared_sources(mapping: Mapping[str, str]) -> dict[str, str]:
    """Normalize declaration provenance: provenance key → non-empty file path.
    Keys must carry a known declaration prefix — an unrecognized one can never
    match a link's provenance and would silently hide a config mistake."""
    out: dict[str, str] = {}
    for key, path in mapping.items():
        k, p = str(key).strip(), str(path).strip()
        if not k or not p:
            raise ValueError(
                f"declaration source {key!r} -> {path!r} needs a provenance key and a file path"
            )
        if not k.startswith(_SOURCE_KEY_PREFIXES):
            raise ValueError(
                f"declaration source key {key!r} must start with one of: "
                f"{', '.join(_SOURCE_KEY_PREFIXES)}"
            )
        if k.startswith("host_ports:"):
            binding = k[len("host_ports:"):]
            normalized = _declared_host_ports({binding: "source"})
            k = "host_ports:" + next(iter(normalized))
        if k in out and out[k] != p:
            raise ValueError(f"conflicting declaration source {key!r}")
        out[k] = p
    return out


def _sourced(aliases: DeploymentAliases, provenance: str | None) -> str | None:
    """Append the declaring file to a provenance string when the declaration
    carried one (config-file extraction, C28); CLI declarations carry none and
    keep the bare key."""
    if provenance is None:
        return None
    source = aliases.source_files.get(provenance)
    return f"{provenance} ({source})" if source else provenance


_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def destination_authority(target: str) -> tuple[str, bool] | None:
    """Normalized ``host[:port]`` of an outbound target, and whether the port
    was written explicitly.

    Handles absolute URLs and scheme-less ``host[:port]/path`` forms. Returns
    ``None`` when the target carries no usable authority (relative path,
    variable interpolation, or an empty host).
    """
    text = target.strip()
    if (not text or any(ord(c) < 32 for c in text)
            or "{" in text or "<" in text or "$" in text or "%" in text):
        return None
    if _SCHEME.match(text):
        try:
            parts = urlsplit(text)
            host = (parts.hostname or "").lower()
            port = parts.port
        except ValueError:
            return None
        if not host or parts.netloc.endswith(":"):
            return None
        if port is not None and not 1 <= port <= 65535:
            return None
        return (f"{host}:{port}" if port is not None else host), port is not None
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
        if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
            return None
        return f"{host.lower()}:{int(port)}", True
    return host.lower(), False


def _target_scheme(target: str) -> str | None:
    """The call target's URL scheme (``http``, ``https``, …) when it carries
    one; ``None`` for scheme-less authorities and relative targets (C28
    protocol modeling — an absent scheme declares nothing)."""
    m = _SCHEME.match(target.strip())
    return m.group(0)[: -len("://")].lower() if m else None


def _repo_identities(repo_id: str, scan: ScanResult) -> set[str]:
    """Names a repo answers to at the deployment seam: its fleet id and its
    root directory name (both lowered). No truncation — ``auth-api`` and
    ``auth-worker`` stay distinct (C28)."""
    names = {repo_id.lower()}
    root = (scan.root or "").replace("\\", "/").rstrip("/")
    if root:
        names.add(root.rsplit("/", 1)[-1].lower())
    return {name for name in names if name}


def _host_repos(
    host: str, identities: dict[str, set[str]], aliases: DeploymentAliases
) -> tuple[set[str], str | None]:
    """Repos a portless destination host positively identifies: a repo identity
    (fleet id / root basename), an exact alias declaration, or a declared
    DNS-suffix namespace stripping to a repo identity. The union is deliberate —
    a host named by more than one source is ambiguous, not resolved (C28).
    Returns the repos plus the alias declaration that vouched when identity
    alone did not (``hosts:…`` / ``dns_suffix:…``), else ``None`` — identity
    matches carry no alias provenance."""
    identity_repos = {rid for rid, names in identities.items() if host in names}
    repos = set(identity_repos)
    host_alias_repos: set[str] = set()
    declared = aliases.hosts.get(host)
    if declared is not None:
        host_alias_repos = {rid for rid, names in identities.items() if declared in names}
    suffix_repos: set[str] = set()
    matched_suffix: str | None = None
    for suffix in aliases.dns_suffixes:
        if len(host) > len(suffix) and host.endswith(suffix):
            base = host[: -len(suffix)]
            hit = {rid for rid, names in identities.items() if base in names}
            if hit:
                suffix_repos |= hit
                matched_suffix = matched_suffix or suffix
    repos |= host_alias_repos | suffix_repos
    provenance: str | None = None
    if not identity_repos and repos:
        if host_alias_repos:
            provenance = f"hosts:{host}"
        elif suffix_repos and matched_suffix is not None:
            provenance = f"dns_suffix:{matched_suffix}"
    return repos, provenance


def _declared_listening_ports(
    repo_id: str, identities: dict[str, set[str]], aliases: DeploymentAliases
) -> set[int]:
    """The listen ports a repo declared under any of its identity names."""
    return {
        aliases.service_ports[name]
        for name in identities.get(repo_id, ())
        if name in aliases.service_ports
    }


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
        try:
            path = urlsplit(path).path
        except ValueError:
            return None
    else:
        path = path.split("?", 1)[0].split("#", 1)[0]
    trailing_slash = path.endswith("/") and path.strip() not in {"", "/"}
    segments = [s for s in path.split("/") if s]
    if not segments:
        return None
    # URL paths remain case-sensitive even though DNS authorities do not.
    norm = [_PLACEHOLDER if _PARAM_SEG.match(s) else s for s in segments]
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
    declared deployment alias — and the call's scheme does not contradict B's
    declared protocol; a call to a declared proxy fronting B resolves as
    **observed_via_proxy** (logical seam, no direct edge); otherwise the match
    survives as a **candidate** — inspectable, but never an observed trust
    path. Explicit non-HTTP(S) schemes remain candidates: matching an HTTP
    route does not establish another protocol's contract. ``aliases`` defaults
    to no declarations (identity-only resolution).
    Deterministic; deduped on the full link identity.
    """
    aliases = aliases or DeploymentAliases()
    calls_by_repo = {rid: _linkable_calls(scan) for rid, scan in repo_scans}
    routes_by_repo = {rid: _linkable_routes(scan) for rid, scan in repo_scans}
    identities = {rid: _repo_identities(rid, scan) for rid, scan in repo_scans}
    roots: dict[str, str] = {}
    for rid, scan in repo_scans:
        try:
            roots[rid] = _repository_root_identity(scan.root)
        except ValueError:
            pass  # Legacy relative roots cannot establish scoped ownership.
    scoped_roots = {binding.repository_root for binding in aliases.scoped_services.values()}

    def unresolved_namespace(host: str, destination: str, server_id: str) -> bool:
        if roots.get(server_id) not in scoped_roots:
            return False
        names = identities[server_id]
        # Explicit operator bindings may confirm an abstract seam, but never
        # assign a caller's Kubernetes namespace. Extracted bare backends do not.
        if aliases.hosts.get(host) in names and f"hosts:{host}" not in aliases.source_files:
            return False
        if aliases.host_ports.get(destination) in names and f"host_ports:{destination}" not in aliases.source_files:
            return False
        if aliases.proxies.get(host) in names and f"proxies:{host}" not in aliases.source_files:
            return False
        for suffix in aliases.dns_suffixes:
            if host.endswith(suffix) and host[:-len(suffix)] in names and f"dns_suffix:{suffix}" not in aliases.source_files:
                return False
        return True

    def scheme_contradiction(scheme: str | None, server_id: str) -> str | None:
        """The provenance key of the protocol declaration a call's scheme
        contradicts (C28), ``""`` when a contradiction exists but no single
        declaration vouches for it, and ``None`` when there is no
        contradiction. Either side undeclared declares nothing. Not applied to
        via-proxy links — a proxy decouples the client→proxy leg from the
        protocol the backend serves."""
        if scheme is None:
            return None
        declarations = {
            name: aliases.service_protocols[name]
            for name in identities[server_id]
            if name in aliases.service_protocols
        }
        schemes = set(declarations.values())
        if not schemes:
            return None
        if len(schemes) > 1:
            return ""  # identities disagree: contradicted, but nothing to cite
        if scheme in schemes:
            return None
        declared = next(iter(schemes))
        name = min(n for n, s in declarations.items() if s == declared)
        return f"service_protocols:{name}:{declared}"

    def resolve(
        call_target: str, server_id: str
    ) -> tuple[str | None, str, str, str | None, str | None]:
        """(destination, resolution, reason, alias_provenance, proxy_host) for
        a call toward *server_id*."""
        authority = destination_authority(call_target)
        if authority is None:
            return None, "candidate", "no_destination", None, None
        destination, explicit_port = authority
        host = destination.rsplit(":", 1)[0] if explicit_port else destination
        scheme = _target_scheme(call_target)
        host_repos, host_provenance = _host_repos(host, identities, aliases)
        scoped_key = aliases.scoped_proxies.get(host.rstrip("."))
        binding = aliases.scoped_services.get(scoped_key) if scoped_key is not None else None
        scoped_owners = {rid for rid, root in roots.items() if binding is not None and root == binding.repository_root}

        if host.rstrip(".") in aliases.unresolved_proxies:
            # Unmodeled proxy routing cannot become a direct observed edge
            # merely because a repo identity or another alias also names it.
            # Compare DNS root-dot equivalents to the normalized negative fact,
            # while preserving destination spelling and positive alias origins.
            declared = aliases.host_ports.get(destination) if explicit_port else aliases.proxies.get(host)
            implicated = server_id in host_repos or declared in identities[server_id]
            reason = "ambiguous_identity" if implicated else "unresolved_host"
            return destination, "candidate", reason, None, None

        legacy_backend = aliases.proxies.get(host)
        protocol_negatives = set(aliases.unresolved_service_protocols) & identities[server_id]
        if protocol_negatives and (server_id in host_repos or legacy_backend in identities[server_id]
                                   or server_id in scoped_owners):
            source = f"unresolved_service_protocols:{min(protocol_negatives)}"
            return destination, "candidate", "unsupported_protocol", _sourced(aliases, source), None

        if scoped_key is not None:
            # The explicit namespace selects a concrete Service owner, never a
            # basename, inferred cluster DNS name or unrelated matching route.
            if server_id not in scoped_owners:
                return destination, "candidate", "unresolved_host", None, None
            if len(scoped_owners) != 1:
                return destination, "candidate", "ambiguous_identity", None, None
            if scoped_key in aliases.unresolved_service_protocols:
                source = f"unresolved_service_protocols:{scoped_key}"
                return destination, "candidate", "unsupported_protocol", _sourced(aliases, source), None
            canonical_host = host.rstrip(".")
            conflicting_host = any(name.rstrip(".") == canonical_host for name in (*aliases.hosts, *aliases.proxies))
            conflicting_port = explicit_port and any(
                name.rsplit(":", 1)[0].rstrip(".") == canonical_host
                and name.rsplit(":", 1)[1] == destination.rsplit(":", 1)[1]
                for name in aliases.host_ports)
            if host_repos or conflicting_host or conflicting_port:
                return destination, "candidate", "ambiguous_identity", None, None
            if explicit_port:
                # Backend Service.port does not declare the ingress listener.
                return destination, "candidate", "explicit_port", None, None
            if scheme is not None and scheme not in {"http", "https"}:
                return destination, "candidate", "unsupported_protocol", None, None
            return destination, "observed_via_proxy", "", _sourced(aliases, f"scoped_proxies:{host.rstrip('.')}"), host

        # Declared proxy (C28): the call dials the proxy, which positively
        # fronts exactly one repo. The logical seam is observed, but never as a
        # direct service-to-service edge and never a trust-path finding — the
        # proxy is an intermediary whose own controls core does not model.
        backend = aliases.proxies.get(host)
        bound = aliases.host_ports.get(destination) if explicit_port else None
        if backend is not None and bound is not None:
            # A direct host:port binding and a proxy declaration describe
            # conflicting topologies; the port binding cannot bypass the proxy.
            implicated_repos = {
                rid for rid, names in identities.items()
                if backend in names or bound in names
            }
            if server_id in implicated_repos:
                return destination, "candidate", "ambiguous_identity", None, None
        if backend is not None and not explicit_port:
            backend_repos = {rid for rid, names in identities.items() if backend in names}
            if host_repos:
                # The same hostname is both a declared proxy and a repo name —
                # the declarations conflict, so nothing resolves.
                return destination, "candidate", "ambiguous_identity", None, None
            if server_id not in backend_repos:
                return destination, "candidate", "unresolved_host", None, None
            if len(backend_repos) > 1:
                return destination, "candidate", "ambiguous_identity", None, None
            if scheme is not None and scheme not in {"http", "https"}:
                return destination, "candidate", "unsupported_protocol", None, None
            if unresolved_namespace(host, destination, server_id):
                return destination, "candidate", "unresolved_namespace", None, None
            return destination, "observed_via_proxy", "", _sourced(aliases, f"proxies:{host}"), host

        if explicit_port:
            # A port routes where a bare hostname cannot vouch: only equally
            # explicit declarations resolve it (C28) — a host:port binding, or
            # the server's own declared listen port when the host already
            # identifies it. The portless view still names the most
            # informative candidate reason.
            port = int(destination.rsplit(":", 1)[1])
            repos: set[str] = set()
            provenance: str | None = None
            bound = aliases.host_ports.get(destination)
            if bound is not None:
                repos.update(rid for rid, names in identities.items() if bound in names)
                if repos:
                    provenance = f"host_ports:{destination}"
            listening_repos = {
                rid for rid in host_repos
                if port in _declared_listening_ports(rid, identities, aliases)
            }
            repos.update(listening_repos)
            if server_id in listening_repos:
                if provenance is None:
                    declared_as = sorted(
                        n for n in identities[server_id]
                        if aliases.service_ports.get(n) == port
                    )
                    provenance = f"service_ports:{declared_as[0]}:{port}"
            if server_id not in repos:
                if server_id not in host_repos:
                    return destination, "candidate", "unresolved_host", None, None
                if len(host_repos) > 1:
                    return destination, "candidate", "ambiguous_identity", None, None
                return destination, "candidate", "explicit_port", None, None
        else:
            repos = host_repos
            provenance = host_provenance
            if server_id not in repos:
                return destination, "candidate", "unresolved_host", None, None
        if len(repos) > 1:
            return destination, "candidate", "ambiguous_identity", None, None
        # Protocol agreement (C28): the destination resolves to exactly this
        # server, so the client's URL scheme describes the leg into it — a
        # contradiction with the server's declared protocol means the same
        # host on a different scheme is a different endpoint, and the match
        # stays a candidate citing the declaration it contradicted.
        contradiction = scheme_contradiction(scheme, server_id)
        if contradiction is not None:
            return destination, "candidate", "scheme_mismatch", _sourced(aliases, contradiction) or None, None
        if scheme is not None and scheme not in {"http", "https"}:
            return destination, "candidate", "unsupported_protocol", None, None
        if unresolved_namespace(host, destination, server_id):
            return destination, "candidate", "unresolved_namespace", None, None
        return destination, "observed", "", _sourced(aliases, provenance), None

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
                        # Keep distinct destination legs and caller verbs while
                        # collapsing instance URLs on the same declared seam.
                        destination_authority(call.target),
                        _target_scheme(call.target),
                        call.method.upper() if call.method else None,
                        route.file,
                        route.method,
                        route.path,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    destination, resolution, reason, provenance, proxy_host = resolve(call.target, server_id)
                    scoped_key = None
                    if resolution == "observed_via_proxy" or reason in {"unsupported_protocol", "explicit_port"}:
                        authority = destination_authority(call.target)
                        if authority is not None:
                            target, has_port = authority
                            host = target.rsplit(":", 1)[0] if has_port else target
                            key = aliases.scoped_proxies.get(host.rstrip("."))
                            binding = aliases.scoped_services.get(key) if key is not None else None
                            if binding is not None and roots.get(server_id) == binding.repository_root:
                                owners = [rid for rid, root in roots.items() if root == binding.repository_root]
                                if len(owners) == 1:
                                    scoped_key = key
                    namespace, service_name = scoped_key.split("/") if scoped_key is not None else (None, None)
                    declaration_keys = []
                    if scoped_key is not None:
                        declaration_keys.extend((f"scoped_services:{scoped_key}",
                                                 f"scoped_proxies:{host.rstrip('.')}"))
                    if reason == "unsupported_protocol":
                        negatives = set(aliases.unresolved_service_protocols) & identities[server_id]
                        if scoped_key in aliases.unresolved_service_protocols:
                            negatives.add(scoped_key)
                        declaration_keys.extend(f"unresolved_service_protocols:{name}" for name in sorted(negatives))
                    declaration_refs = {source for key in declaration_keys
                                        for source in aliases.declaration_sources.get(key, ())}
                    scoped_binding = aliases.scoped_services.get(scoped_key) if scoped_key is not None else None
                    protocol_unresolved = (scoped_key in aliases.unresolved_service_protocols
                        or bool(set(aliases.unresolved_service_protocols) & identities[server_id]))
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
                            scheme=_target_scheme(call.target),
                            alias_provenance=provenance,
                            proxy_host=proxy_host,
                            server_namespace=namespace,
                            server_service_name=service_name,
                            declaration_refs=tuple(sorted(declaration_refs, key=lambda source: (
                                source.repository_root, source.file, source.line or 0))),
                            server_port=scoped_binding.port if scoped_binding is not None else None,
                            server_protocol=(scoped_binding.protocol if scoped_binding is not None
                                             and not protocol_unresolved else None),
                        )
                    )
    links.sort(
        key=lambda link: (
            link.client_repo, link.server_repo, link.path_template, link.method,
            link.destination or "", link.scheme or "", link.client_method or "",
            link.client_file, link.client_line if link.client_line is not None else -1,
            link.server_file, link.server_line if link.server_line is not None else -1,
        )
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
