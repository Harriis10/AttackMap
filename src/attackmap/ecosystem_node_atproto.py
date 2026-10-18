"""Thin ATProto / Node-service ecosystem overlay (AM052 / C38).

The broad built-in ``javascript-web`` analyzer scans JS/TS files one at a
time, so it structurally cannot see the things this overlay adds:

- **XRPC surface from lexicons.** A lexicon JSON file *declares* an NSID
  method (``com.example.foo`` of type query / procedure / subscription);
  the surface it declares never appears as an Express ``app.get(...)`` and
  therefore never becomes a route. The overlay parses lexicon files and
  emits ``/xrpc/<nsid>`` routes, then links each declaration to its
  ``server.method('<nsid>', ...)`` handler wiring wherever it lives in the
  repo (cross-file), resolving whether an auth verifier was observed.
- **Identity / signing hotspots.** did:plc / did:web resolution, PLC
  operations (key rotation), signing-key handling, service auth
  (``Authorization: Bearer`` on a service DID), and session / refresh
  token flows.
- **Service boundaries.** DID-document ``service`` entries
  (``#atproto_pds``, ``BskyFeedGenerator``, …), service URL identifiers,
  inter-service HTTP calls to ``/xrpc/`` endpoints, repo event stream
  (``subscribeRepos`` firehose) subscriptions, and blob upload endpoints.
- **Cross-file framework wiring.** Express auth middleware mounted under
  one file and applied to routes defined elsewhere.

Analyzer-contract rules this module obeys (see docs/external-analyzers.md):

- extraction only — no findings, no severity, no report rendering; every
  signal carries file + line + evidence text, and "observed" facts use
  higher confidence than "inferred" ones;
- no network access, no subprocess, read-only, no global state;
- applicability detection is conservative (``looks_like_atproto_repo``)
  so the overlay stays silent on non-ATProto repositories — enforced both
  in ``detect()`` and again at the top of ``scan_node_atproto``;
- coverage enumeration stays with the broad per-file analyzers:
  ``files_scanned`` is 0 and ``scanned_files`` is None (this overlay only
  enriches; the JS/TS files it reads are already reported by
  ``javascript-web``, and config/manifest files by ``config``).

Hint vocabulary (stable, documented in docs/ecosystem/):

=====================================  ======  =========================================
hint                                   family  meaning
=====================================  ======  =========================================
xrpc_auth_verifier:<nsid>              auth    auth verifier observed on the wiring (strength)
xrpc_no_auth_observed:<nsid>           auth    wired handler with no observed auth (inferred)
node:auth_middleware_mount:<mw>        auth    express auth middleware mount (observed, cross-file)
atproto:did_reference                  auth    did:plc:/did:web: literal reference
atproto:did_resolution                 auth    did:plc / did:web resolution code
atproto:plc_operation                  auth    PLC operations (key rotation / plc client)
atproto:signing_key                    auth    repo signing-key handling
atproto:service_auth                   auth    service-auth JWT / Bearer construction
atproto:session_flow                   auth    createSession / refreshSession flows
atproto:did_service:<kind>             service DID-doc service entry (pds/appview/feedgen/chat)
atproto:service_url:<kind>             service named service endpoint (pdsUrl, relayHost…)
atproto:repo_event_stream              service repo sync / firehose subscription
atproto:feed_generator                 service feed generator surface
atproto:service_call:<kind>            edge    outbound call to a named service kind
atproto:blob_upload                    protocol blob upload endpoint usage
atproto:app_bsky_namespace             protocol app.bsky.* namespace usage
atproto:xrpc_unwired:<nsid>            protocol lexicon declared but never wired (inferred)
atproto:xrpc_no_lexicon:<nsid>         protocol wired method with no lexicon file (inferred)
=====================================  ======  =========================================

Maturity: detectors are experimental pending the C27 labeled-corpus
policy (human label review); see docs/ecosystem/node-atproto-capabilities.md.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config_scanner import _LineIndex
from .models import (
    AuthHint,
    EdgeHint,
    ExternalCall,
    FrameworkHint,
    ProtocolHint,
    Route,
    ScanResult,
    ServiceHint,
)
from .scanner import _line_snippet
from .safe_fs import max_file_bytes, walk_repo
from .srcpaths import (
    JS_TS_SUFFIXES,
    in_skipped_dir,
    is_skipped_dir,
    is_test_file,
    is_vendored_file,
)

# The overlay reads the same file sizes the source scanner tolerates; larger
# files are skipped with an explicit resource-limit event, never guessed from.
_MAX_FILE_BYTES = 1_000_000
_PRODUCER = "ecosystem_node_atproto"

# NSID shape: at least three dotted segments (authority.name.method).
# Mixed case is allowed to match real-world official lexicons
# (`com.atproto.repo.describeRepo`, `app.bsky.feed.getFeedSkeleton`); the
# detection contexts (lexicon `id` fields, `.method('…')` registrations)
# are narrow enough that the dotted shape stays the discriminator.
# Segments are bounded to the ATProto-spec maximum of 63 chars: an
# unbounded ``[a-zA-Z0-9-]*`` backtracks quadratically on hostile
# dash/space runs (tests/test_regex_budget.py).
_NSID_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,62}(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,62}){2,}")


def _is_nsid(value: str) -> bool:
    return bool(_NSID_RE.fullmatch(value))


# --- Applicability detection -------------------------------------------------

# Marker tokens whose presence in a non-test JS/TS source file makes the repo
# ATProto-shaped. Deliberately specific: a plain Express app contains none of
# these. `@atproto/` covers SDK imports; `did:plc:` / `did:web:` cover DID
# literals; `com.atproto.` / `app.bsky.` cover NSID strings.
_SOURCE_MARKER_RE = re.compile(
    r"@atproto/|did:plc:|did:web:|com\.atproto\.|app\.bsky\.",
)

# package.json dependency names / keywords that mark an ATProto service.
_PACKAGE_MARKER_RE = re.compile(r"@atproto/|\batproto\b|\bbluesky\b|\bbsky\b", re.IGNORECASE)

# Directories that conventionally hold lexicon definitions.
_LEXICON_DIR_NAMES = frozenset({"lexicons", "lexicon"})


def looks_like_atproto_repo(root: str | Path) -> bool:
    """Conservative applicability check (the analyzer's ``detect()``).

    True when any of:
    - a ``package.json`` declares an atproto-ish dependency / keyword / name,
    - a directory named ``lexicons``/``lexicon`` holds at least one JSON file,
    - a non-test, non-vendored JS/TS source contains an ATProto marker token.

    Test / vendored / generated trees (SKIP_DIRS, ``*.test.ts``, …) never
    count toward applicability, so a repo that merely *tests* against
    ATProto stays silent.
    """
    repo = Path(root)
    if not repo.exists() or not repo.is_dir():
        return False
    try:
        for path in walk_repo(repo, prune=is_skipped_dir):
            rel = path.relative_to(repo)
            if in_skipped_dir(rel) or is_test_file(rel.as_posix()) or is_vendored_file(rel.as_posix()):
                continue
            if path.name == "package.json":
                try:
                    if path.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                if _package_markers(text):
                    return True
                continue
            in_lexicon_dir = any(
                segment.lower() in _LEXICON_DIR_NAMES for segment in rel.parts[:-1]
            )
            if in_lexicon_dir and path.suffix == ".json":
                return True
            if path.suffix in JS_TS_SUFFIXES:
                try:
                    if path.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                if _SOURCE_MARKER_RE.search(text):
                    return True
    except OSError:
        return False
    return False


def _package_markers(package_json_text: str) -> bool:
    """True when a package.json's name/keywords/dependency names look ATProto."""
    try:
        doc = json.loads(package_json_text)
    except json.JSONDecodeError:
        return False
    if not isinstance(doc, dict):
        return False
    candidates: list[str] = [str(doc.get("name") or "")]
    keywords = doc.get("keywords")
    if isinstance(keywords, list):
        candidates.extend(str(kw) for kw in keywords if isinstance(kw, str))
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = doc.get(section)
        if isinstance(deps, dict):
            candidates.extend(str(name) for name in deps)
    return any(_PACKAGE_MARKER_RE.search(candidate) for candidate in candidates)


# --- Extraction state ---------------------------------------------------------


@dataclass
class _LexiconMethod:
    """One NSID method declared by a lexicon file (observed)."""

    nsid: str
    type: str  # query | procedure | subscription
    file: str
    line: int


@dataclass
class _WiredMethod:
    """One NSID method registered on an XRPC server in source (observed)."""

    nsid: str
    file: str
    line: int
    guard: str | None = None  # auth token observed in the registration config


@dataclass
class _MiddlewareMount:
    """An express middleware mounted at a path prefix (observed)."""

    mount: str
    middleware: str
    file: str
    line: int


@dataclass
class _Overlay:
    """Per-scan extraction state."""

    result: ScanResult
    sources: dict[str, str] = field(default_factory=dict)  # rel -> text (JS/TS)
    lexicons: dict[str, _LexiconMethod] = field(default_factory=dict)
    wired: dict[str, _WiredMethod] = field(default_factory=dict)
    mounts: list[_MiddlewareMount] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)  # every file read


# --- File collection ----------------------------------------------------------


def _file_bytes_limit() -> int:
    return min(_MAX_FILE_BYTES, max_file_bytes())


def _collect_lexicon_methods(rel: str, text: str, overlay: _Overlay) -> None:
    """Parse one lexicon JSON into NSID method declarations.

    Malformed JSON or shapes that are not lexicons are skipped with an
    explicit limitation note — never guessed from.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        overlay.result.limitations.append(f"{_PRODUCER}: skipped malformed lexicon JSON {rel}")
        return
    if not isinstance(doc, dict):
        return
    if doc.get("lexicon") is None:
        return  # ordinary JSON, not a lexicon
    nsid = doc.get("id")
    if not isinstance(nsid, str) or not _is_nsid(nsid):
        overlay.result.limitations.append(f"{_PRODUCER}: skipped lexicon {rel} with invalid id")
        return
    defs = doc.get("defs")
    main = defs.get("main") if isinstance(defs, dict) else None
    method_type = main.get("type") if isinstance(main, dict) else None
    if method_type not in {"query", "procedure", "subscription"}:
        # record/object/patch lexicons are data schemas, not XRPC methods
        return
    index = _LineIndex(text)
    id_offset = text.find(f'"{nsid}"')
    overlay.lexicons[nsid] = _LexiconMethod(
        nsid=nsid,
        type=str(method_type),
        file=rel,
        line=index.line_of(id_offset if id_offset >= 0 else 0),
    )


def _is_lexicon_candidate(rel_path: Path) -> bool:
    """A JSON file that lives under a conventional lexicons directory."""
    return rel_path.suffix == ".json" and any(
        segment.lower() in _LEXICON_DIR_NAMES for segment in rel_path.parts[:-1]
    )


def _read_file(path: Path, limit: int) -> tuple[str | None, int | None]:
    try:
        size = path.stat().st_size
        if size > limit:
            return None, size
        return path.read_text(encoding="utf-8"), size
    except (UnicodeDecodeError, OSError):
        return None, None


def _collect_files(repo: Path, index: object | None, overlay: _Overlay) -> None:
    limit = _file_bytes_limit()

    def wanted(rel: Path) -> str | None:
        if in_skipped_dir(rel):
            return None
        posix = rel.as_posix()
        if is_test_file(posix) or is_vendored_file(posix):
            return None
        if rel.name == "package.json" or _is_lexicon_candidate(rel):
            return "meta"
        if rel.suffix in JS_TS_SUFFIXES:
            return "source"
        return None

    # Oversized files are skipped with an explicit limitation note — never a
    # silent drop. (A dedicated ResourceLimitScope literal would live in
    # models.py, which this overlay deliberately does not touch, so the note
    # is the honest channel and no completeness scope is claimed.)
    if index is not None:
        for item in getattr(index, "files", ()):
            rel_path = Path(item.rel)
            kind = wanted(rel_path)
            if kind is None:
                continue
            text = item.text
            if len(text.encode("utf-8")) > limit:
                overlay.result.limitations.append(
                    f"{_PRODUCER}: skipped oversized file {item.rel} (>{limit} bytes)"
                )
                continue
            overlay.files[rel_path.as_posix()] = text
    else:
        for path in walk_repo(repo, prune=is_skipped_dir):
            rel_path = path.relative_to(repo)
            if wanted(rel_path) is None:
                continue
            text, size = _read_file(path, limit)
            if text is None:
                if size is not None:
                    overlay.result.limitations.append(
                        f"{_PRODUCER}: skipped oversized file {rel_path.as_posix()} ({size} bytes)"
                    )
                continue
            overlay.files[rel_path.as_posix()] = text


# --- Per-source extraction ----------------------------------------------------

# `server.method('com.example.foo', cfg, handler)` — the @atproto/xrpc-server
# registration call. The NSID is validated afterwards.
_XRPC_REGISTRATION_RE = re.compile(
    r"\.\s*(?:method|xrpcMethod)\s*\(\s*['\"]([a-zA-Z0-9][a-zA-Z0-9.-]{2,200})['\"]"
)

# Auth tokens inside a registration's *config object*: `auth: authVerifier`
# (the @atproto/xrpc-server convention) or a standalone verifier token.
_AUTH_KEY_VALUE_RE = re.compile(r"\bauth\s*:\s*([A-Za-z_]\w*)")
_AUTH_COMPOUND_TOKEN_RE = re.compile(
    r"\b(?:authVerifier|verifyAuth|verifyServiceAuth|verifyAccessJwt|verifyRefreshJwt"
    r"|requireAuth|authenticate)\b"
)

# `app.use('/xrpc', sessionAuth)` — a middleware mounted at a path prefix.
_MIDDLEWARE_MOUNT_RE = re.compile(
    r"\b\w+\.use\s*\(\s*['\"](?P<mount>/[^'\"]*)['\"]\s*,\s*(?P<mw>[A-Za-z_]\w*)\s*\)"
)
_AUTHISH_NAME_RE = re.compile(r"[Aa]uth|[Gg]uard|[Pp]assport|[Vv]erifier|[Tt]oken")

# Registration-call bound: the balanced-paren scan never runs longer than this.
_REGISTRATION_MAX_CHARS = 2000

# Identity / signing / auth hotspots (observed). A bare did:plc:/did:web:
# literal is a DID *reference*; resolution code is the stronger claim.
_DID_REFERENCE_RE = re.compile(r"\bdid:(?:plc|web):[^\s'\"`,]+")
_DID_RESOLUTION_RE = re.compile(
    r"\b(?:resolveDid|resolveIdentity|resolveHandle|DidResolver|@atproto/identity)\b"
    r"|\bplc\.directory\b"
)
_PLC_OPERATION_RE = re.compile(
    r"\b(?:rotateSigningKey|updateDidDocument|plcClient|PlcClient|@atproto/plc)\b"
    r"|\bplc\.directory\b"
)
_SIGNING_KEY_RE = re.compile(
    r"\b(?:Secp256k1Keypair|signOperation|verifyOperationSig|did:key:z[1-9a-km-zA-HJ-NP-Z]{8,64}"
    r"|signJwt|verifyJwt)\b"
)
_SERVICE_AUTH_RE = re.compile(
    r"\b(?:getServiceAuth|serviceAuthJwt|createServiceAuth|verifyServiceAuth)\b"
    r"|\bAuthorization['\"]?\s*[:=]\s*[`'\"]Bearer\b"
)
_SESSION_FLOW_RE = re.compile(
    r"\b(?:createSession|refreshSession|deleteSession|getSession|refreshToken)\b"
    r"|com\.atproto\.server\.(?:create|refresh|delete|get)Session"
)

# Service boundaries (observed). DID-doc service ids and type strings map to
# a shared kind vocabulary so the two extraction paths agree.
_DID_SERVICE_ID_KINDS = {
    "atproto_pds": "pds",
    "bsky_app": "appview",
    "bsky_chat": "chat",
    "feed_generator": "feedgen",
}
_DID_SERVICE_TYPES = {
    "AtprotoPersonalDataServer": "pds",
    "BskyAppView": "appview",
    "BskyFeedGenerator": "feedgen",
    "BskyChatService": "chat",
}
_DID_SERVICE_ID_RE = re.compile(
    r"['\"]?id['\"]?\s*:\s*['\"](?P<ref>[^'\"]*#(?:atproto_pds|bsky_app|bsky_chat|feed_generator))['\"]"
)
_DID_SERVICE_TYPE_RE = re.compile(
    r"['\"]?type['\"]?\s*:\s*['\"](?P<type>AtprotoPersonalDataServer|BskyAppView"
    r"|BskyFeedGenerator|BskyChatService)['\"]"
)
_SERVICE_URL_IDENT_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>pdsUrl|relayHost|relayUrl|appviewUrl|searchUrl|chatUrl"
    r"|modServiceUrl|serviceEndpoint|serviceUrl|didDocUrl)\s*[:=]\s*"
    r"['\"](?P<url>https?://[^'\"]+)['\"]"
)
_SERVICE_URL_KINDS = {
    "pdsurl": "pds",
    "relayhost": "relay",
    "relayurl": "relay",
    "appviewurl": "appview",
    "searchurl": "search",
    "chaturl": "chat",
    "modserviceurl": "moderation",
    "serviceendpoint": "service",
    "serviceurl": "service",
    "diddocurl": "did_document",
}
_EVENT_STREAM_RE = re.compile(
    r"\b(?:subscribeRepos|firehose)\b|com\.atproto\.sync\.subscribeRepos"
    r"|['\"]#commit['\"]|['\"]#account['\"]|['\"]#identity['\"]"
)
_FEEDGEN_RE = re.compile(
    r"\b(?:getFeedSkeleton|feedGenerator|FeedGenerator)\b|app\.bsky\.feed\.getFeedSkeleton"
)

# Protocol-level usage (observed).
_BLOB_RE = re.compile(
    r"\b(?:uploadBlob|putBlob|getBlob|BlobRef|blobRef)\b"
    r"|com\.atproto\.repo\.(?:upload|get)Blob|com\.atproto\.sync\.(?:get|put)Blob"
)
_APP_BSKY_NAMESPACE_RE = re.compile(r"\bapp\.bsky\.[a-z][a-z0-9]*")

# Outbound /xrpc/ HTTP URLs: full literals, or template literals whose host
# is a variable (`${pds}/xrpc/<nsid>`) — the latter emit the /xrpc/ path as
# the target, which cross-repo contract linking matches by method + path.
_XRPC_URL_RE = re.compile(r"https?://[a-zA-Z0-9._:-]+(?::\d+)?/xrpc/[a-zA-Z0-9._-]+")
_XRPC_TEMPLATE_URL_RE = re.compile(r"\$\{[^}`]+\}(/xrpc/[a-zA-Z0-9._-]+)")
_LINE_VERB_RE = re.compile(r"\.\s*(get|post|put|delete|patch)\s*\(", re.IGNORECASE)

# SDK imports for framework enrichment (observed).
_ATPROTO_IMPORT_RE = re.compile(r"['\"]@atproto/([a-z0-9-]+)['\"]")


def _mount_covers(mount: str, path: str) -> bool:
    """Express-style segment-boundary prefix match of a mount against a path."""
    trimmed = mount.rstrip("/") or "/"
    if trimmed == "/":
        return True
    return path == trimmed or path.startswith(trimmed + "/")


def _append_auth_hint(overlay: _Overlay, hint: str, rel: str, line: int, snippet: str,
                      confidence: float) -> None:
    key = (hint, rel)
    if key in {(h.hint, h.file) for h in overlay.result.auth_hints}:
        return
    overlay.result.auth_hints.append(
        AuthHint(hint=hint, file=rel, line=line, evidence_text=snippet, confidence=confidence)
    )


def _registration_config(text: str, match: "re.Match[str]") -> str:
    """The config-object argument of a ``.method(nsid, cfg, handler)`` call.

    Bounded balanced-paren scan from the call's opening paren; the config is
    the text between the first and second *top-level* comma (absent in the
    two-argument ``method(nsid, handler)`` form, which returns ""). Keeping
    the scan inside the call — and to the config argument only — stops the
    next registration, or auth tokens inside the handler body, from leaking
    into this registration's auth resolution.
    """
    open_paren = text.find("(", match.start(), match.end())
    if open_paren < 0:
        return ""
    limit = min(len(text), open_paren + _REGISTRATION_MAX_CHARS)
    depth = 0
    commas: list[int] = []
    for i in range(open_paren, limit):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth <= 0:
                break
        elif ch == "," and depth == 1:
            commas.append(i)
    if len(commas) < 2:
        return ""
    return text[commas[0] + 1: commas[1]]


def _guard_from_config(cfg: str) -> str | None:
    """The auth verifier named in a registration config, if any."""
    keyed = _AUTH_KEY_VALUE_RE.search(cfg)
    if keyed is not None:
        return keyed.group(1)
    compound = _AUTH_COMPOUND_TOKEN_RE.search(cfg)
    if compound is not None:
        return compound.group(0)
    return None


def _extract_wiring(rel: str, text: str, overlay: _Overlay) -> None:
    """XRPC method registrations and auth middleware mounts in one source file."""
    index = _LineIndex(text)
    for match in _XRPC_REGISTRATION_RE.finditer(text):
        nsid = match.group(1)
        if not _is_nsid(nsid):
            continue
        if nsid in overlay.wired:
            continue  # first registration wins; later ones are re-exports
        guard = _guard_from_config(_registration_config(text, match))
        overlay.wired[nsid] = _WiredMethod(
            nsid=nsid, file=rel, line=index.line_of(match.start()), guard=guard
        )

    for match in _MIDDLEWARE_MOUNT_RE.finditer(text):
        middleware = match.group("mw")
        if not _AUTHISH_NAME_RE.search(middleware):
            continue  # body parsers, xrpc handlers, loggers: not auth chains
        line = index.line_of(match.start())
        overlay.mounts.append(
            _MiddlewareMount(mount=match.group("mount"), middleware=middleware, file=rel, line=line)
        )
        # The observed chain itself is a signal (a strength), independent of
        # whether any XRPC route later resolves against it.
        _append_auth_hint(
            overlay, f"node:auth_middleware_mount:{middleware}", rel, line,
            _line_snippet(text, match.start()), 0.9,
        )


def _extract_source_signals(rel: str, text: str, overlay: _Overlay) -> None:
    """Per-file identity / boundary / protocol signals (all observed)."""
    result = overlay.result
    index = _LineIndex(text)

    def emit_once(hints_list, ctor, hint: str, offset: int, confidence: float = 0.9) -> None:
        if (hint, rel) in {(h.hint, h.file) for h in hints_list}:
            return
        hints_list.append(
            ctor(hint=hint, file=rel, line=index.line_of(offset),
                 evidence_text=_line_snippet(text, offset), confidence=confidence)
        )

    for pattern, hint in (
        (_DID_REFERENCE_RE, "atproto:did_reference"),
        (_DID_RESOLUTION_RE, "atproto:did_resolution"),
        (_PLC_OPERATION_RE, "atproto:plc_operation"),
        (_SIGNING_KEY_RE, "atproto:signing_key"),
        (_SERVICE_AUTH_RE, "atproto:service_auth"),
        (_SESSION_FLOW_RE, "atproto:session_flow"),
    ):
        match = pattern.search(text)
        if match:
            _append_auth_hint(overlay, hint, rel, index.line_of(match.start()),
                              _line_snippet(text, match.start()), 0.9)

    for pattern, hint in (
        (_EVENT_STREAM_RE, "atproto:repo_event_stream"),
        (_FEEDGEN_RE, "atproto:feed_generator"),
    ):
        match = pattern.search(text)
        if match:
            emit_once(result.service_hints, ServiceHint, hint, match.start())

    for match in _DID_SERVICE_ID_RE.finditer(text):
        kind = _DID_SERVICE_ID_KINDS[match.group("ref").rsplit("#", 1)[-1]]
        emit_once(result.service_hints, ServiceHint, f"atproto:did_service:{kind}", match.start())
    for match in _DID_SERVICE_TYPE_RE.finditer(text):
        kind = _DID_SERVICE_TYPES[match.group("type")]
        emit_once(result.service_hints, ServiceHint, f"atproto:did_service:{kind}", match.start())

    seen_edges: set[tuple[str, str]] = set()
    for match in _SERVICE_URL_IDENT_RE.finditer(text):
        name, url = match.group("name"), match.group("url")
        kind = _SERVICE_URL_KINDS.get(name.lower(), "service")
        emit_once(result.service_hints, ServiceHint, f"atproto:service_url:{kind}", match.start())
        if (kind, rel) not in seen_edges:
            seen_edges.add((kind, rel))
            result.edge_hints.append(
                EdgeHint(hint=f"atproto:service_call:{kind}", file=rel,
                         line=index.line_of(match.start()),
                         evidence_text=_line_snippet(text, match.start()), confidence=0.8)
            )

    for pattern, hint in (
        (_BLOB_RE, "atproto:blob_upload"),
        (_APP_BSKY_NAMESPACE_RE, "atproto:app_bsky_namespace"),
    ):
        match = pattern.search(text)
        if match:
            emit_once(result.protocol_hints, ProtocolHint, hint, match.start())

    for match in _ATPROTO_IMPORT_RE.finditer(text):
        emit_once(
            result.framework_hints, FrameworkHint,
            f"node:atproto-sdk:{match.group(1)}", match.start(),
        )

    # Outbound /xrpc/ URLs are inter-service calls regardless of host
    # (synthetic fixtures use example.com; the /xrpc/ marker is the signal).
    seen_calls: set[tuple[str, str | None]] = set()

    def _emit_call(target: str, offset: int) -> None:
        line_start = text.rfind("\n", 0, offset) + 1
        verb = _LINE_VERB_RE.search(text, line_start, offset)
        method = verb.group(1).upper() if verb else None
        if (target, method) in seen_calls:
            return
        seen_calls.add((target, method))
        result.external_calls.append(
            ExternalCall(target=target, file=rel, line=index.line_of(offset),
                         method=method, evidence_text=_line_snippet(text, offset))
        )

    for match in _XRPC_URL_RE.finditer(text):
        _emit_call(match.group(0), match.start())
    for match in _XRPC_TEMPLATE_URL_RE.finditer(text):
        # `${pds}/xrpc/<nsid>` — the host is a variable; the /xrpc/ path is
        # the stable, linkable target.
        _emit_call(match.group(1), match.start(1))


# --- Route assembly -----------------------------------------------------------

_LEXICON_TYPE_TO_METHOD = {"query": "GET", "procedure": "POST", "subscription": "GET"}


def _emit_routes(overlay: _Overlay) -> None:
    """Assemble /xrpc/ routes from lexicon declarations + handler wiring.

    A wired method wins over its lexicon declaration (the registration site
    is the more precise evidence and carries the auth resolution). A lexicon
    without wiring still emits its declared route plus an unwired inference;
    a wired method without a lexicon emits its route plus a no-lexicon
    inference. Auth is only marked ``required`` when an auth token was
    observed in the registration config or an auth middleware mount covers
    the path; otherwise the route stays ``unknown`` and an
    ``xrpc_no_auth_observed`` inference is emitted for core to weigh.
    """
    result = overlay.result

    for nsid, wired in sorted(overlay.wired.items()):
        path = f"/xrpc/{nsid}"
        method = _LEXICON_TYPE_TO_METHOD.get(overlay.lexicons[nsid].type, "ANY") \
            if nsid in overlay.lexicons else "ANY"
        guards: list[str] = []
        guard_evidence: str | None = None
        auth = "unknown"

        if wired.guard is not None:
            auth = "required"
            guards = [wired.guard]
            guard_evidence = f"auth verifier '{wired.guard}' in registration ({wired.file}:{wired.line})"
            _append_auth_hint(overlay, f"xrpc_auth_verifier:{nsid}", wired.file, wired.line,
                              guard_evidence, 0.9)
        else:
            covering = next(
                (m for m in overlay.mounts if _mount_covers(m.mount, path)), None
            )
            if covering is not None:
                auth = "required"
                guards = [covering.middleware]
                guard_evidence = (
                    f"inferred: middleware '{covering.middleware}' mounted at "
                    f"'{covering.mount}' ({covering.file}:{covering.line})"
                )
            else:
                _append_auth_hint(
                    overlay, f"xrpc_no_auth_observed:{nsid}", wired.file, wired.line,
                    f"XRPC handler '{nsid}' registered with no observed auth verifier "
                    f"({wired.file}:{wired.line})",
                    0.6,
                )

        if nsid not in overlay.lexicons:
            result.protocol_hints.append(
                ProtocolHint(hint=f"atproto:xrpc_no_lexicon:{nsid}", file=wired.file,
                             line=wired.line,
                             evidence_text=f"XRPC method '{nsid}' registered without a lexicon file",
                             confidence=0.6)
            )

        result.routes.append(
            Route(path=path, method=method, file=wired.file, line=wired.line,
                  auth=auth, guards=guards, guard_evidence=guard_evidence)
        )

    for nsid, lex in sorted(overlay.lexicons.items()):
        if nsid in overlay.wired:
            continue
        result.routes.append(
            Route(path=f"/xrpc/{nsid}", method=_LEXICON_TYPE_TO_METHOD[lex.type],
                  file=lex.file, line=lex.line)
        )
        result.protocol_hints.append(
            ProtocolHint(hint=f"atproto:xrpc_unwired:{nsid}", file=lex.file, line=lex.line,
                         evidence_text=f"lexicon declares '{nsid}' but no handler wiring was found",
                         confidence=0.6)
        )


# --- Public entry point --------------------------------------------------------


def scan_node_atproto(root: str | Path, index: object | None = None) -> ScanResult:
    """Walk an ATProto-shaped repository and emit overlay signals.

    Follows the ``config_scanner.scan_config_repo`` delegation pattern: a
    whole-repo extraction returning a ``ScanResult`` that merges naturally
    through the standard pipeline (routes, hints and external calls dedup by
    their MERGE_SCHEMA keys; core owns all scoring). Stays silent on
    repositories that fail the conservative applicability check.
    """
    repo = Path(root).resolve()
    # No resource-limit scope is claimed (the closed ResourceLimitScope
    # literal belongs to models.py); completeness stays "unknown" honestly
    # and any oversized-file skip is reported via `limitations`.
    result = ScanResult(root=str(repo), scanned_files=None)
    if not repo.exists() or not repo.is_dir():
        return result
    if not looks_like_atproto_repo(repo):
        # Enforced here as well as in detect(): a direct call on a
        # non-ATProto repo must stay silent.
        return result

    overlay = _Overlay(result=result)
    _collect_files(repo, index, overlay)

    for rel, text in sorted(overlay.files.items()):
        if _is_lexicon_candidate(Path(rel)):
            _collect_lexicon_methods(rel, text, overlay)

    for rel, text in sorted(overlay.files.items()):
        if Path(rel).suffix in JS_TS_SUFFIXES:
            _extract_wiring(rel, text, overlay)

    for rel, text in sorted(overlay.files.items()):
        if Path(rel).suffix in JS_TS_SUFFIXES:
            _extract_source_signals(rel, text, overlay)

    _emit_routes(overlay)
    return result


__all__ = ["scan_node_atproto", "looks_like_atproto_repo"]
