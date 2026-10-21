"""Config-file scanner (#43).

YAML / TOML / JSON / INI / .env files often carry the real DB
connection strings, service URLs, and — connecting to #39 — hard-coded
credentials the source code hasn't yet inlined. `scan_repo`
intentionally covers only source, so this module fills the config gap
with the same regex-based, dependency-free approach: text-scan the
files, emit `DatabaseHint` / `ExternalCall` / `SecretHint` records
into a `ScanResult`, and let the merge pipeline dedup as usual.

Deliberately no YAML / TOML / JSON *parsers* — the goal is broad,
resilient extraction that works on malformed files too. Callers who
want structural analysis can extend on top; this layer stays regex-only.

The one structural exception is deployment-seam extraction (C28):
`extract_deployment_aliases` reads k8s / docker-compose / nginx configs
with a real YAML parse and brace-matched nginx blocks, because port, scheme,
and upstream declarations must be exact — a regex guess would either miss
or invent seams. Malformed or ambiguous configs are skipped with an
explicit note, never guessed.
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path

from .srcpaths import SKIP_DIRS, in_skipped_dir, is_skipped_dir
from .redact import mask_secret
from .safe_fs import max_file_bytes, walk_repo
from .models import DatabaseHint, ExternalCall, ResourceLimitEvent, ScanResult, SecretHint
from .scanner import _append_hardcoded_secret_hints, _line_snippet

# Config files larger than this are skipped — at that size they're invariably
# generated (lock files, minified bundles, or AttackMap's own JSON reports)
# rather than hand-written config, and scanning multi-megabyte text for URL /
# secret regexes is pointlessly slow.
_MAX_CONFIG_BYTES = 5_000_000


class _LineIndex:
    """O(log n) line-number lookups for a file's text.

    `scanner._line_of` counts newlines from the start on every call — O(n) each,
    which degrades to O(n^2) when a large file yields many matches (the cause of
    a scan hang on multi-megabyte JSON). Precomputing the line-start offsets once
    and binary-searching keeps extraction linear.
    """

    __slots__ = ("_starts",)

    def __init__(self, content: str) -> None:
        starts = [0]
        find = content.find
        idx = find("\n")
        while idx != -1:
            starts.append(idx + 1)
            idx = find("\n", idx + 1)
        self._starts = starts

    def line_of(self, offset: int) -> int:
        """1-indexed line number for a character offset."""
        if offset <= 0:
            return 1
        return bisect.bisect_right(self._starts, offset)


CONFIG_SUFFIXES = {".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".env"}
# Also match dotfiles like `.env.example`, `.env.sample`, `sample.env` —
# handled via filename check rather than suffix.
_CONFIG_FILENAME_HINTS = ("env",)  # substring in stem for `.env`-family files


# Filenames excluded even when they have a matching suffix. These carry
# inventory / build state, not application config.
CONFIG_EXCLUDE_FILENAMES = frozenset({
    # Generated AttackMap artifacts are identified by walk_repo, using their
    # manifest or legacy structure. Their basenames remain valid user config.
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "cargo.lock",
    "poetry.lock",
    "uv.lock",
    "tsconfig.json",
    "jsconfig.json",
    ".eslintrc.json",
    ".prettierrc.json",
    "renovate.json",
    "package.json",  # noisy: `scripts:` values look like URLs and DB strings
})

_SKIP_DIRS = SKIP_DIRS  # shared set (#215)

# Credential dotfiles (#252): registry / VCS / SSH credentials that neither
# the source pass (skips dotfiles) nor the suffix match above would read.
# Symlinked ones are still skipped by walk_repo (#234).
CREDENTIAL_FILENAMES = frozenset({
    ".npmrc", ".pypirc", ".netrc", "_netrc", ".dockercfg", ".git-credentials",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})
# `.netrc`: `machine host login user password SECRET`.
_NETRC_PASSWORD_RE = re.compile(r"\bpassword\s{1,20}(?P<value>\S{4,256})")


# --- DB URL extraction --------------------------------------------------------

# `postgresql://user:pass@host:5432/db`, `mysql://...`, `mongodb://...`,
# `redis://...`, `sqlite:///path`. Scheme drives the `kind` value.
_DB_URL_PATTERN = re.compile(
    r"""(?P<scheme>postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite)
        ://
        (?P<userinfo>[^@\s"'/]*@)?          # optional user[:pass]@
        [^\s"']*                             # host + path
    """,
    re.IGNORECASE | re.VERBOSE,
)
_DB_SCHEME_TO_KIND = {
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mongodb": "mongodb",
    "mongodb+srv": "mongodb",
    "redis": "redis",
    "sqlite": "sqlite",
}

# HTTPS URLs targeting real external hosts. Skip common non-target hosts
# (localhost, example.com, github.com CI links, cdn.jsdelivr, etc.) so
# `homepage:` and `repository:` config fields don't flood ExternalCall.
_HTTP_URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9._-]+(?::\d+)?(?:/[^\s\"'`]*)?")
_URL_HOST_SKIP = re.compile(
    r"^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|(?:.*\.)?(?:example\.com|invalid|"
    r"github\.com|githubusercontent\.com|jsdelivr\.net|unpkg\.com|w3\.org|"
    r"schemastore\.org|npmjs\.com))(?::\d+)?$",
    re.IGNORECASE,
)


# --- Secret KV extraction -----------------------------------------------------

# Keys that mark a secret-bearing config field. Match on the KEY side of
# a `key: value` / `key = value` pair.
_SECRET_KEY_RE = re.compile(
    # start-of-line or dict/list intro. (`-` is not a start char: YAML's
    # `- key:` already starts at the space, and allowing it made every `-` in
    # a long dashed token a new start — #236.)
    r"(?:^|[\s,{\[])"
    r"['\"]?(?P<key>[a-zA-Z0-9_.-]{0,64}"             # optional key prefix (bounded, #236)
    r"(?:password|passwd|secret|token|api[_-]?key|priv[_-]?key|private[_-]?key|apikey|_pass|_pwd))"
    r"['\"]?"
    r"\s*[:=]\s*"
    r"(?:['\"](?P<value>[^'\"\n]{4,})['\"]|(?P<bare>[^\s#'\",]{4,}))",
    re.IGNORECASE | re.MULTILINE,
)

# Values that look like placeholders / template interpolation / dev
# defaults — must NOT be flagged as real secrets. Case-insensitive
# comparison against the trimmed literal.
_PLACEHOLDER_LITERALS = frozenset({
    "changeme", "change-me", "change_me",
    "example", "example-value",
    "your-secret", "your-secret-here", "your_secret", "your_secret_here",
    "your-token-here", "your_token_here",
    "your-api-key", "your-api-key-here", "your_api_key", "your_api_key_here",
    "your-password", "your-password-here", "your_password", "your_password_here",
    "placeholder", "todo", "fixme",
    "xxx", "yyy", "zzz",
    "null", "none", "false", "true",
    "n/a", "na", "tbd",
    "root", "admin",  # noisy default usernames masquerading as passwords
})


def _is_placeholder(value: str) -> bool:
    trimmed = value.strip()
    lower = trimmed.lower()
    if lower in _PLACEHOLDER_LITERALS:
        return True
    # Template interpolation — `${ENV_VAR}`, `{{ .Values.foo }}`, `<value>`.
    if trimmed.startswith(("${", "{{", "<")):
        return True
    # Repeating single character — `xxxxxxxx`, `----`, `********`.
    if len(set(trimmed)) <= 1:
        return True
    # Environment variable substitution shape `$VAR`.
    if re.fullmatch(r"\$[A-Z_][A-Z0-9_]*", trimmed):
        return True
    # File path — probably a keyfile pointer, not the key itself.
    if trimmed.startswith(("/", "./", "../")) or trimmed.endswith((".pem", ".key", ".crt")):
        return True
    return False


def _redact(value: str) -> str:
    return mask_secret(value)


# --- Public entry points ------------------------------------------------------


def should_scan_config_file(path: Path) -> bool:
    """True if the file is a config file this module should extract from."""
    name = path.name.lower()
    if name in CREDENTIAL_FILENAMES or (name.startswith("id_") and name.split(".")[0] in CREDENTIAL_FILENAMES and not name.endswith(".pub")):
        return True
    if name in CONFIG_EXCLUDE_FILENAMES:
        return False
    if path.suffix.lower() in CONFIG_SUFFIXES:
        return True
    # .env, .env.example, sample.env, etc.
    return any(hint in name for hint in _CONFIG_FILENAME_HINTS) and name.startswith(".env") or name.endswith(".env") or ".env." in name


def scan_config_repo(root: str | Path, index: object | None = None) -> ScanResult:
    """Walk `root`, extract config-shaped signals, return a ScanResult
    that merges naturally with source-scanner output via the standard
    merge pipeline."""
    repo = Path(root).resolve()
    result = ScanResult(root=str(repo), scanned_files=[], resource_limit_reporting="complete",
                        resource_limit_scopes=["config_scanner.file_bytes"])
    if not repo.exists() or not repo.is_dir():
        return result

    if index is not None:
        result.resource_limit_events.extend(getattr(index, "resource_limit_events", ()))
        result.resource_limit_scopes = sorted(set(result.resource_limit_scopes) | set(getattr(index, "resource_limit_scopes", ())))
        if getattr(index, "resource_limit_reporting", "unknown") != "complete":
            result.resource_limit_reporting = "partial"
        candidates = []
        config_limit = min(_MAX_CONFIG_BYTES, max_file_bytes())
        for item in getattr(index, "files", ()):
            if not should_scan_config_file(Path(item.rel)) or in_skipped_dir(Path(item.rel)):
                continue
            if len(item.text.encode("utf-8")) > config_limit:
                result.resource_limit_events.append(ResourceLimitEvent.skipped_file(
                    producer="config_scanner", category="file_bytes", relative=item.rel,
                    limit=config_limit))
                continue
            candidates.append((Path(item.rel), item.text))
        for rel_path, content in candidates:
            result.files_scanned += 1
            relative = rel_path.as_posix()
            result.scanned_files.append(relative)
            _extract_db_urls(content, relative, result)
            _extract_http_targets(content, relative, result)
            _extract_secret_kvs(content, relative, result)
            if rel_path.name.lower() in {".netrc", "_netrc"}:
                _extract_netrc(content, relative, result)
            _append_hardcoded_secret_hints(result, relative, content, entropy=False, generic=False)
        result.scanned_files = sorted(set(result.scanned_files))
        result.files_scanned = len(result.scanned_files)
        return result

    for path in walk_repo(repo, prune=is_skipped_dir):
        if in_skipped_dir(path.relative_to(repo)):
            continue
        if not should_scan_config_file(path):
            continue
        try:
            size = path.stat().st_size
            config_limit = min(_MAX_CONFIG_BYTES, max_file_bytes())
            if size > config_limit:
                result.resource_limit_events.append(ResourceLimitEvent.skipped_file(
                    producer="config_scanner", category="file_bytes", relative=path.relative_to(repo).as_posix(),
                    limit=config_limit, observed_bytes=size))
                continue
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        result.files_scanned += 1
        relative = str(path.relative_to(repo)).replace("\\", "/")
        result.scanned_files.append(relative)
        _extract_db_urls(content, relative, result)
        _extract_http_targets(content, relative, result)
        _extract_secret_kvs(content, relative, result)
        if path.name.lower() in {".netrc", "_netrc"}:
            _extract_netrc(content, relative, result)
        # Provider-shaped tokens, URL passwords and GCP service-account keys
        # (#252). No entropy fallback or keyword rule here: config already
        # has the key/value pass, and the entropy fallback is noisy on data.
        _append_hardcoded_secret_hints(result, relative, content, entropy=False, generic=False)
    result.scanned_files = sorted(set(result.scanned_files))
    result.files_scanned = len(result.scanned_files)
    return result


def _extract_netrc(content: str, relative: str, result: ScanResult) -> None:
    index = _LineIndex(content)
    for match in _NETRC_PASSWORD_RE.finditer(content):
        value = match.group("value")
        if _is_placeholder(value):
            continue
        result.secret_hints.append(
            SecretHint(
                name=_redact(value),
                file=relative,
                line=index.line_of(match.start()),
                evidence_text=_line_snippet(content, match.start()).replace(value, _redact(value)),
                confidence=1.0,
                kind="netrc_password",
            )
        )


def _extract_db_urls(content: str, relative: str, result: ScanResult) -> None:
    seen: set[str] = {(h.kind, h.file) for h in result.databases if h.file == relative}
    index = _LineIndex(content)
    for match in _DB_URL_PATTERN.finditer(content):
        scheme = match.group("scheme").lower()
        kind = _DB_SCHEME_TO_KIND.get(scheme, scheme)
        key = (kind, relative)
        if key not in seen:
            result.databases.append(
                DatabaseHint(
                    kind=kind,
                    file=relative,
                    line=index.line_of(match.start()),
                    evidence_text=_line_snippet(content, match.start()),
                )
            )
            seen.add(key)
        # DB URL with embedded userinfo → password in the URL is a real secret.
        userinfo = match.group("userinfo")
        if userinfo and ":" in userinfo:
            # userinfo shape is `user:pass@`; strip the trailing `@`
            user_pass = userinfo.rstrip("@")
            _, _, password = user_pass.partition(":")
            if password and not _is_placeholder(password):
                result.secret_hints.append(
                    SecretHint(
                        name=_redact(password),
                        file=relative,
                        line=index.line_of(match.start()),
                        evidence_text=_line_snippet(content, match.start()),
                        confidence=1.0,
                        kind=f"{kind}_url_password",
                    )
                )


def _extract_http_targets(content: str, relative: str, result: ScanResult) -> None:
    seen_targets = {(c.target, c.file) for c in result.external_calls if c.file == relative}
    index = _LineIndex(content)
    for match in _HTTP_URL_PATTERN.finditer(content):
        target = match.group(0)
        # Trim trailing punctuation that looks like URL end
        target = target.rstrip("),;.\"'")
        parsed_host = _extract_host(target)
        if parsed_host and _URL_HOST_SKIP.match(parsed_host):
            continue
        if (target, relative) in seen_targets:
            continue
        result.external_calls.append(
            ExternalCall(
                target=target,
                file=relative,
                line=index.line_of(match.start()),
                evidence_text=_line_snippet(content, match.start()),
            )
        )
        seen_targets.add((target, relative))


def _extract_host(url: str) -> str | None:
    match = re.match(r"https?://([^/:\s]+)", url, re.IGNORECASE)
    return match.group(1) if match else None


def _masked_kv_snippet(content: str, match: re.Match[str], value: str) -> str:
    """The line up to the value, then the masked value. Masking explicitly
    (not via the generic evidence redaction) matters when the line is long:
    a truncated snippet loses the closing quote that redaction keys on, and a
    multi-line value such as a JSON-escaped PEM key would leak (#252)."""
    group = "value" if match.group("value") is not None else "bare"
    start = match.start(group)
    line_start = content.rfind("\n", 0, start) + 1
    head = content[line_start:start].lstrip()
    if len(head) > 120:
        head = "…" + head[-119:]
    quote = content[start - 1] if group == "value" else ""
    return f"{head}{_redact(value)}{quote}"


def _extract_secret_kvs(content: str, relative: str, result: ScanResult) -> None:
    seen: set[tuple[str, int]] = {(h.name, h.line or 0) for h in result.secret_hints if h.file == relative}
    index = _LineIndex(content)
    for match in _SECRET_KEY_RE.finditer(content):
        key = match.group("key")
        value = match.group("value") or match.group("bare") or ""
        if not value or _is_placeholder(value):
            continue
        # Line from the key itself: the pattern's leading `\s` alternative can
        # consume the previous line's newline, so match.start() may sit one
        # line early (#235).
        line = index.line_of(match.start("key"))
        # Store `key` as the SecretHint.name so consumers see WHICH secret
        # was leaked (auth vs stripe vs db). Value itself is redacted into
        # evidence_text via the same helper hardcoded-secret detection uses.
        secret_key = (key, line)
        if secret_key in seen:
            continue
        seen.add(secret_key)
        result.secret_hints.append(
            SecretHint(
                name=key,
                file=relative,
                line=line,
                evidence_text=_masked_kv_snippet(content, match, value),
                confidence=0.9,
                kind="config_literal",
            )
        )


# --- Deployment seam declarations (C28) ---------------------------------------
#
# DeploymentAliases used to be CLI-only. Real deployment configs already state
# much of the surface: k8s Services/Deployments and compose files declare
# listen ports; nginx upstream blocks declare which host fronts which single
# backend; a k8s Service port's `appProtocol`, an nginx `proxy_pass` scheme,
# and an Ingress `backend-protocol` annotation declare the protocol a backend
# serves; a k8s Ingress rule host fronting exactly one backend service
# declares a proxy. extract_deployment_aliases converts those files into
# declarations carrying per-declaration file provenance
# (DeploymentAliases.source_files), so a fleet run without CLI flags still
# resolves declared seams. A Service's port and appProtocol win over a
# same-named Deployment's containerPort (the Service is the seam callers
# dial). Deliberately conservative: only what a config
# positively states is extracted — a port *named* "https" declares nothing,
# an Ingress TLS block describes the client→ingress leg (which no consumer
# models) and is never extracted, ambiguous declarations (multi-port
# services, multi-server upstreams, multi-backend ingress hosts, same-kind
# conflicts) are recorded and skipped, and malformed files are skipped with
# an explicit note instead of guessed.

_COMPOSE_FILENAMES = frozenset({
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
})
# Precedence ranks when several files declare a listen port for one identity:
# a k8s Service is the dial seam, compose declares the container port, and a
# Deployment's containerPort only fills a name nothing better declared.
_RANK_SERVICE, _RANK_COMPOSE, _RANK_DEPLOYMENT = 2, 1, 0
# Parallel ranks for protocol declarations: the Service's own `appProtocol`
# outranks the leg an edge declares it dials (`proxy_pass` scheme), which
# outranks a controller annotation on an Ingress.
_RANK_APP_PROTOCOL, _RANK_PROXY_PASS, _RANK_INGRESS_ANNOTATION = 2, 1, 0
_HOST_TOKEN = re.compile(r"^[a-zA-Z0-9._-]+$")
_MODELED_SCHEMES = frozenset({"http", "https"})


def _deployment_config_kind(path: Path) -> str | None:
    """'k8s' | 'compose' | 'nginx' for files that may declare deployment seams."""
    name = path.name.lower()
    if name in _COMPOSE_FILENAMES:
        return "compose"
    if name in CONFIG_EXCLUDE_FILENAMES:
        return None
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        return "k8s"  # confirmed by a `kind:` pre-filter before parsing
    if suffix == ".conf":
        return "nginx"
    return None


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _declare_port(
    declared: dict[str, tuple[int, str, int]],
    dropped: set[str],
    name: str,
    port: int,
    provenance: str,
    rank: int,
    kind_label: str,
    notes: list[str],
) -> None:
    """Record a service_ports declaration under explicit conflict rules: a
    higher-precedence source overrides, an equal one with a *different* port
    makes the identity ambiguous (dropped, noted), and equal ports dedupe."""
    if name in dropped:
        return
    existing = declared.get(name)
    if existing is None:
        declared[name] = (port, provenance, rank)
        return
    e_port, e_prov, e_rank = existing
    if e_port == port:
        if rank > e_rank:
            declared[name] = (port, provenance, rank)
        return
    if rank == e_rank:
        del declared[name]
        dropped.add(name)
        notes.append(
            f"dropped service port for {name!r}: conflicting {kind_label} ports "
            f"{e_port} ({e_prov}) and {port} ({provenance})"
        )
    elif rank > e_rank:
        notes.append(
            f"service port for {name!r}: {kind_label} port {port} ({provenance}) "
            f"overrides port {e_port} ({e_prov})"
        )
        declared[name] = (port, provenance, rank)


def _declare_protocol(
    declared: dict[str, tuple[str, str, int]],
    dropped: set[str],
    name: str,
    scheme: str,
    provenance: str,
    rank: int,
    kind_label: str,
    notes: list[str],
) -> None:
    """Record a service_protocols declaration under the same conflict rules as
    ``_declare_port``: a higher-precedence source overrides, an equal one with
    a *different* scheme makes the identity ambiguous (dropped, noted), and
    equal schemes dedupe."""
    if name in dropped:
        return
    existing = declared.get(name)
    if existing is None:
        declared[name] = (scheme, provenance, rank)
        return
    e_scheme, e_prov, e_rank = existing
    if e_scheme == scheme:
        if rank > e_rank:
            declared[name] = (scheme, provenance, rank)
        return
    if rank == e_rank:
        del declared[name]
        dropped.add(name)
        notes.append(
            f"dropped service protocol for {name!r}: conflicting {kind_label} schemes "
            f"{e_scheme} ({e_prov}) and {scheme} ({provenance})"
        )
    elif rank > e_rank:
        notes.append(
            f"service protocol for {name!r}: {kind_label} {scheme} ({provenance}) "
            f"overrides {e_scheme} ({e_prov})"
        )
        declared[name] = (scheme, provenance, rank)


def _declare_proxy(
    host: str,
    backend: str,
    provenance: str,
    proxies: dict[str, str],
    proxy_sources: dict[str, str],
    dropped: set[str],
    notes: list[str],
) -> None:
    """Record a proxies declaration (host fronts exactly one backend). A host
    fronting different backends across declarations is ambiguous — dropped
    with a note, never guessed."""
    if host in dropped:
        return
    if host in proxies and proxies[host] != backend:
        prior = proxies.pop(host)
        proxy_sources.pop(host, None)
        dropped.add(host)
        notes.append(
            f"dropped proxy {host!r}: fronting multiple backends across configs "
            f"({prior}, {backend})"
        )
        return
    proxies[host] = backend
    proxy_sources[host] = provenance


def _port_app_protocol(entry: dict, kind: str, name: str, provenance: str, notes: list[str]) -> str | None:
    """The declared ``appProtocol`` of a port entry, when it names a modeled
    scheme. A port *named* "https" is metadata and declares nothing; only the
    explicit appProtocol field does. Unmodeled protocols (grpc, tcp, …) are
    noted and skipped — never silently guessed as http/https."""
    raw = entry.get("appProtocol")
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if value in _MODELED_SCHEMES:
        return value
    notes.append(
        f"skipped appProtocol {raw!r} on {kind} {name} in {provenance}: "
        "only http/https are modeled"
    )
    return None


def _k8s_manifest_port(
    doc: dict, provenance: str, notes: list[str]
) -> tuple[str, int, int, str, str | None] | None:
    """(name, port, rank, kind, appProtocol) for a Service/Deployment declaring
    exactly one listen port, else None — with an explicit note whenever
    something ambiguous or unparsable was skipped. Schemes come only from an
    explicit ``appProtocol``; a port *named* "https" declares nothing."""
    kind = str(doc.get("kind", "")).strip()
    if kind not in {"Deployment", "Service"}:
        return None
    name = str((doc.get("metadata") or {}).get("name") or "").strip().lower()
    if not name:
        notes.append(f"skipped {provenance}: {kind} without metadata.name")
        return None
    ports: list[int] = []
    if kind == "Service":
        entries = (doc.get("spec") or {}).get("ports") or []
        if not isinstance(entries, list) or not entries:
            notes.append(f"skipped {provenance}: Service {name} declares no ports")
            return None
        protocols: list[str | None] = []
        for entry in entries:
            if not isinstance(entry, dict):
                notes.append(f"skipped port entry {entry!r} in {provenance}: not a mapping")
                continue
            port = _int_or_none(entry.get("port"))
            if port is None:
                notes.append(f"skipped port entry {entry!r} in {provenance}: no numeric port")
                continue
            ports.append(port)
            protocols.append(_port_app_protocol(entry, kind, name, provenance, notes))
            target = _int_or_none(entry.get("targetPort"))
            if target is not None and target != port:
                notes.append(
                    f"Service {name} in {provenance}: targetPort {target} differs from "
                    f"port {port}; only the Service port {port} is declared (the dial seam)"
                )
        if not ports:
            return None  # per-entry notes above name what was unparsable
        if len(set(ports)) != 1:
            notes.append(
                f"skipped {provenance}: Service {name} exposes {len(set(ports))} ports; "
                "which one serves the seam is ambiguous"
            )
            return None
        # The single port's appProtocol is the service's own protocol
        # declaration; None when the port entry carries none.
        protocol = protocols[0] if protocols and len(protocols) == 1 else None
        return (name, ports[0], _RANK_SERVICE, "Service", protocol)
    # Deployment: the containerPort the pod listens on.
    containers = ((doc.get("spec") or {}).get("template") or {}).get("spec", {}).get("containers") or []
    if not isinstance(containers, list):
        return None
    for container in containers:
        if not isinstance(container, dict):
            continue
        for entry in container.get("ports") or []:
            if not isinstance(entry, dict):
                continue
            port = _int_or_none(entry.get("containerPort"))
            if port is not None:
                ports.append(port)
    if len(set(ports)) != 1:
        if ports:
            notes.append(
                f"skipped {provenance}: Deployment {name} declares {len(set(ports))} distinct "
                "containerPorts; which one serves the seam is ambiguous"
            )
        return None
    return (name, ports[0], _RANK_DEPLOYMENT, "Deployment", None)


def _k8s_ingress_declarations(
    doc: dict,
    provenance: str,
    proxies: dict[str, str],
    proxy_sources: dict[str, str],
    dropped_proxies: set[str],
    protocols: dict[str, tuple[str, str, int]],
    dropped_protocols: set[str],
    notes: list[str],
) -> None:
    """kind: Ingress → proxy and protocol declarations (C28). A rule host that
    routes to exactly one backend service declares that host a proxy for the
    service; the nginx ingress ``backend-protocol`` annotation declares the
    protocol the controller uses toward every backend of the ingress. Hosts
    routing to several backends (path-split routing) are multi-backend —
    noted and skipped. ``spec.tls`` describes the client→ingress leg, which
    no consumer models, and is never extracted."""
    name = str((doc.get("metadata") or {}).get("name") or "").strip().lower() or "ingress"
    rules = (doc.get("spec") or {}).get("rules") or []
    by_host: dict[str, set[str]] = {}
    hostless = False
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        paths = ((rule.get("http") or {}).get("paths")) or []
        backends: set[str] = set()
        for p in paths if isinstance(paths, list) else []:
            if not isinstance(p, dict):
                continue
            service = (p.get("backend") or {}).get("service")
            svc_name = (
                str(service.get("name") or "").strip().lower()
                if isinstance(service, dict) else ""
            )
            if svc_name and _HOST_TOKEN.match(svc_name):
                backends.add(svc_name)
        if not backends:
            continue
        host = str(rule.get("host") or "").strip().lower().rstrip(".")
        if host and _HOST_TOKEN.match(host):
            by_host.setdefault(host, set()).update(backends)
        else:
            hostless = True  # a catch-all rule has no identity to declare
    for host in sorted(by_host):
        backends = by_host[host]
        if len(backends) != 1:
            notes.append(
                f"skipped host {host!r} in Ingress {name!r} ({provenance}): routes to "
                f"{len(backends)} backend services; multi-backend routing is not modeled"
            )
            continue
        _declare_proxy(
            host, next(iter(backends)), provenance, proxies, proxy_sources, dropped_proxies, notes
        )
    if hostless:
        notes.append(
            f"skipped hostless rule(s) in Ingress {name!r} ({provenance}): "
            "no concrete host to declare"
        )
    annotations = (doc.get("metadata") or {}).get("annotations")
    raw = annotations.get("nginx.ingress.kubernetes.io/backend-protocol") if isinstance(annotations, dict) else None
    if raw is None:
        return
    value = str(raw).strip()
    if ":" in value:
        notes.append(
            f"skipped backend-protocol {value!r} on Ingress {name!r} ({provenance}): "
            "the per-service mapping form is not modeled"
        )
        return
    scheme = value.lower()
    declared_backends = set().union(*by_host.values()) if by_host else set()
    if scheme not in _MODELED_SCHEMES:
        notes.append(
            f"skipped backend-protocol {value!r} on Ingress {name!r} ({provenance}): "
            "only http/https are modeled"
        )
        return
    for backend in sorted(declared_backends):
        _declare_protocol(
            protocols, dropped_protocols, backend, scheme, provenance,
            _RANK_INGRESS_ANNOTATION, "Ingress annotation", notes,
        )


def _compose_container_port(mapping: object) -> int | None:
    """The container (listen) port of a compose `ports` entry, or None when the
    mapping is not a plain tcp host:container binding (long forms with other
    protocols, udp suffixes, or unparsable values stay undeclared). The
    container port is declared — it is the port the service itself listens on;
    a differing published host port is a different seam."""
    if isinstance(mapping, dict):
        if str(mapping.get("protocol", "tcp")).lower() != "tcp":
            return None
        return _int_or_none(mapping.get("target"))
    if isinstance(mapping, str):
        text = mapping.strip()
        if "/" in text:
            text, _, proto = text.partition("/")
            if proto.strip().lower() != "tcp":
                return None
        parts = text.split(":")
        if not 1 <= len(parts) <= 3:
            return None
        return _int_or_none(parts[-1])
    return None


def _extract_compose_ports(
    doc: dict, provenance: str, declared: dict, dropped: set[str], notes: list[str]
) -> None:
    """compose `services.<name>.ports` → service_ports keyed by service name
    (the compose DNS identity)."""
    services = doc.get("services")
    if not isinstance(services, dict):
        return
    for svc_name, svc in services.items():
        if not isinstance(svc, dict) or not isinstance(svc.get("ports"), list):
            continue
        name = str(svc_name).strip().lower()
        ports = {
            port
            for port in (_compose_container_port(m) for m in svc["ports"])
            if port is not None
        }
        if not ports:
            notes.append(
                f"skipped service {svc_name!r} in {provenance}: no parsable tcp port mapping"
            )
            continue
        if len(ports) > 1:
            notes.append(
                f"skipped service {svc_name!r} in {provenance}: {len(ports)} distinct listen "
                "ports; which one serves the seam is ambiguous"
            )
            continue
        port = ports.pop()
        if not 1 <= port <= 65535:
            notes.append(f"skipped service {svc_name!r} in {provenance}: port {port} out of range")
            continue
        _declare_port(declared, dropped, name, port, provenance, _RANK_COMPOSE, "compose", notes)


def _nginx_blocks(text: str, keyword: str) -> list[tuple[str, str, int, int]]:
    """(header, body, start, end) for each ``keyword … { … }`` block with
    balanced braces. Hand-rolled brace matching because nginx conf is not YAML
    and nested blocks (location inside server) defeat flat regexes."""
    blocks: list[tuple[str, str, int, int]] = []
    for m in re.finditer(rf"(?<![\w.-]){keyword}\b([^{{}}]*)\{{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        if depth == 0:
            blocks.append((m.group(1).strip(), text[m.end(): i - 1], m.start(), i))
    return blocks


def _extract_nginx_proxies(
    text: str,
    provenance: str,
    proxies: dict[str, str],
    proxy_sources: dict[str, str],
    dropped: set[str],
    protocols: dict[str, tuple[str, str, int]],
    dropped_protocols: set[str],
    notes: list[str],
) -> None:
    """nginx upstream-backed server blocks → proxies and backend protocols
    (C28). The proxy host is the ``server_name``; the backend is the single
    ``server`` host of the upstream it ``proxy_pass``es to. Multi-server
    upstreams route to more than one backend — unmodeled (recorded and
    skipped, never guessed), as are proxy_pass targets that are not a defined
    single-backend upstream. A ``proxy_pass`` scheme (``http``/``https``)
    declares the protocol that edge dials the backend with."""
    upstreams: dict[str, str] = {}
    blank = list(text)
    for header, body, start, end in _nginx_blocks(text, "upstream"):
        name = header.split()[0].strip().lower() if header.split() else ""
        hosts = []
        endpoints = set()
        for entry in re.findall(r"(?<![\w.-])server\s+([^;{}]+);", body):
            tokens = entry.strip().split()
            if not tokens:
                continue
            endpoint = tokens[0].lower()
            host = endpoint.split(":")[0].strip()
            if host:
                hosts.append(host)
                endpoints.add(endpoint)
        for i in range(start, end):
            blank[i] = " "  # hide upstream bodies: their `server` entries are not server blocks
        if not name:
            continue
        if len(endpoints) == 1 and len(set(hosts)) == 1:
            upstreams[name] = hosts[0]
        else:
            notes.append(
                f"skipped upstream {name!r} in {provenance}: {len(endpoints)} backends "
                "(multi-backend proxy routing is not modeled)"
            )

    for _header, body, _s, _e in _nginx_blocks("".join(blank), "server"):
        # The proxy_pass scheme declares the leg into the backend — recorded
        # even when the block has no usable server_name (the protocol fact
        # does not depend on naming the proxy host).
        backends = set()
        for scheme, target in re.findall(r"(?<![\w.-])proxy_pass\s+(\w+)://([^/;\s]+)", body):
            host = target.split(":")[0].strip().lower()
            backend = upstreams.get(host)
            if backend is None:
                continue  # not a defined single-backend upstream: out of scope
            backends.add(backend)
            if scheme.lower() in _MODELED_SCHEMES:
                _declare_protocol(
                    protocols, dropped_protocols, backend, scheme.lower(), provenance,
                    _RANK_PROXY_PASS, "nginx proxy_pass", notes,
                )
            else:
                notes.append(
                    f"skipped proxy_pass {scheme}:// in {provenance}: "
                    "only http/https backends are modeled"
                )
        name_m = re.search(r"(?<![\w.-])server_name\s+([^;]+);", body)
        if not name_m:
            if backends:
                notes.append(f"skipped server block in {provenance}: no concrete server_name")
            continue
        hosts = {n.strip().lower().rstrip(".") for n in name_m.group(1).split()}
        valid = {h for h in hosts if _HOST_TOKEN.match(h) and h not in {"_", "*"}}
        if not valid:
            notes.append(f"skipped server block in {provenance}: no concrete server_name")
            continue
        if not backends:
            continue  # not upstream-backed (or a skipped upstream): out of scope
        if len(backends) > 1:
            notes.append(
                f"skipped proxy {sorted(valid)[0]!r} in {provenance}: proxy_pass targets "
                "multiple backends"
            )
            continue
        backend = backends.pop()
        for host in sorted(valid):
            _declare_proxy(host, backend, provenance, proxies, proxy_sources, dropped, notes)


def extract_deployment_aliases(repo_roots: list[Path]) -> tuple["DeploymentAliases", list[str]]:
    """Extract deployment-seam declarations from each repo's config files (C28).

    Returns ``(aliases, notes)``: the aliases carry ``source_files`` provenance
    (``repo-dir/rel-path``) for every extracted declaration, and the notes name
    every skipped or conflicting extraction with its reason. Extracted surface:
    ``service_ports`` (k8s Service/Deployment container ports, compose container
    ports), ``proxies`` (nginx single-backend upstream server blocks; k8s
    Ingress rule hosts fronting exactly one backend service), and
    ``service_protocols`` (a Service port's ``appProtocol``, an nginx
    ``proxy_pass`` scheme, an Ingress ``backend-protocol`` annotation — never a
    port *name*). No host aliases are guessed.
    """
    from .contracts import DeploymentAliases
    import yaml  # type: ignore[import-untyped]  # core dependency (suppress.py et al.)

    declared: dict[str, tuple[int, str, int]] = {}
    dropped_ports: set[str] = set()
    protocols: dict[str, tuple[str, str, int]] = {}
    dropped_protocols: set[str] = set()
    proxies: dict[str, str] = {}
    proxy_sources: dict[str, str] = {}
    dropped_proxies: set[str] = set()
    notes: list[str] = []

    for root in repo_roots:
        repo = Path(root).resolve()
        from .index import PassSources
        sources = PassSources.for_root(repo)
        if not sources.is_dir(repo):
            continue
        label = repo.name
        for path in sources.iter_files(prune=is_skipped_dir):
            if in_skipped_dir(path.relative_to(repo)):
                continue
            kind = _deployment_config_kind(path)
            if kind is None:
                continue
            try:
                text = sources.gated_text(path.relative_to(repo).as_posix(), max_bytes=_MAX_CONFIG_BYTES)
                if text is None:
                    continue
            except (UnicodeDecodeError, OSError):
                continue
            provenance = f"{label}/{path.relative_to(repo).as_posix()}"
            if kind == "nginx":
                _extract_nginx_proxies(
                    text, provenance, proxies, proxy_sources, dropped_proxies,
                    protocols, dropped_protocols, notes,
                )
                continue
            if kind == "k8s" and "kind:" not in text:
                continue  # cheap pre-filter: ordinary YAML is not a k8s manifest
            try:
                docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
            except yaml.YAMLError:
                notes.append(f"skipped {provenance}: malformed YAML; no declarations taken")
                continue
            if kind == "compose":
                if docs:
                    _extract_compose_ports(docs[0], provenance, declared, dropped_ports, notes)
                continue
            for doc in docs:
                if str(doc.get("kind", "")).strip() == "Ingress":
                    _k8s_ingress_declarations(
                        doc, provenance, proxies, proxy_sources, dropped_proxies,
                        protocols, dropped_protocols, notes,
                    )
                    continue
                parsed = _k8s_manifest_port(doc, provenance, notes)
                if parsed is None:
                    continue
                name, port, rank, kind_label, protocol = parsed
                if not 1 <= port <= 65535:
                    notes.append(f"skipped {provenance}: {kind_label} {name} port {port} out of range")
                    continue
                _declare_port(declared, dropped_ports, name, port, provenance, rank, kind_label, notes)
                if protocol is not None:
                    _declare_protocol(
                        protocols, dropped_protocols, name, protocol, provenance,
                        _RANK_APP_PROTOCOL, f"{kind_label} appProtocol", notes,
                    )

    source_files = {
        f"service_ports:{name}:{port}": provenance
        for name, (port, provenance, _rank) in declared.items()
    }
    source_files.update({
        f"service_protocols:{name}:{scheme}": provenance
        for name, (scheme, provenance, _rank) in protocols.items()
    })
    source_files.update({f"proxies:{host}": proxy_sources[host] for host in proxies})
    aliases = DeploymentAliases(
        service_ports={name: port for name, (port, _p, _r) in declared.items()},
        service_protocols={name: scheme for name, (scheme, _p, _r) in protocols.items()},
        proxies=proxies,
        source_files=source_files,
    )
    return aliases, notes


__all__ = [
    "scan_config_repo",
    "should_scan_config_file",
    "extract_deployment_aliases",
    "CONFIG_SUFFIXES",
    "CONFIG_EXCLUDE_FILENAMES",
]
