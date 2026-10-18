"""Layered PHP / Laminas / Omeka S ecosystem extraction (AM052 / C38).

Three layers, following the layering named in AGENTS.md:

- ``php-web`` — broad language extraction from any ``.php`` source:
  request-input usage, superglobal->sink co-occurrence, include/require
  edges, session/cookie handling, database handles, outbound HTTP.
- ``php-laminas`` — framework enrichment for Laminas / Zend MVC repos:
  module structure, router config, controllers/actions, service-manager
  wiring, middleware pipelines, validators/filters used on input.
- ``omeka-s`` — thin application overlay for Omeka S modules: module
  layout, API adapters vs representations vs admin/site routes, admin
  authentication plugins, media ingestion, view-script output encoding.

Each layer only *enriches*. None of them scores, ranks or renders; every
signal carries file+line evidence and an explicit ``(observed)`` /
``(inferred)`` marker in its hint text. Applicability detection is
conservative — a layer stays silent unless its own markers are present —
so a plain-PHP repo yields no framework signals and a non-Omeka Laminas
app yields no Omeka signals.

Deliberately NOT covered here (owned elsewhere in core):

- composer.json dependency inventory — core's SBOM pass
  (``sbom.analyze_sbom``, run by ``scanner.run_repo_passes``) already
  parses composer manifests and *appends* (no dedup), so re-emitting
  would duplicate entries. This module reads composer.json only for
  applicability detection and framework evidence.
- Laravel / Slim / Symfony route registrations — the generic source scanner
  (``scanner.PHP_ROUTE_PATTERN`` / ``PHP_SYMFONY_ROUTE_PATTERN``) already
  extracts them; the ``php-web`` *analyzer class* below delegates its
  generic pass to ``scanner.scan_files`` so those routes flow through the
  same analyzer, but the layered extraction in this module does not
  re-emit them.
- Taint flow tracing — core's taint pass already treats ``$_GET`` /
  ``$_POST`` / ``php://input`` as sources and PDO / mysqli / header() /
  exec-family calls as sinks. This module records line-level
  co-occurrence observations only; ``inferred`` marks the ones reached
  through simple same-file variable propagation.

Output-encoding and file-upload observations are emitted as
``EntrypointHint`` / ``AuthHint`` records because the extraction protocol
has no dedicated control-signal family; the hint text carries the
semantics and downstream reasoning (controls, review) stays in core.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Iterator

from .analyzer_contracts import AnalyzerMetadata, AnalyzerResult
from .models import (
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
)
from .safe_fs import walk_repo
from .srcpaths import in_skipped_dir, is_skipped_dir, is_test_file, is_vendored_file, line_number

__all__ = [
    "PhpWebAnalyzer",
    "PhpLaminasAnalyzer",
    "OmekaSAnalyzer",
    "scan_php_web_repo",
    "scan_php_laminas_repo",
    "scan_omeka_s_repo",
    "has_php_source",
    "looks_laminas",
    "looks_omeka_s",
]

OBSERVED = "(observed)"
INFERRED = "(inferred)"

PHP_SUFFIX = ".php"
PHTML_SUFFIX = ".phtml"

# PHP superglobals and streams that carry request-controlled input.
_REQUEST_INPUT_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|php://input\b")
_SUPERGLOBAL_ASSIGN_RE = re.compile(
    r"\$(?P<var>\w+)\s*=\s*[^;\n]{0,200}?(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|php://input\b)"
)

# Syntax-level sink calls that are interesting when request input reaches
# them on the same line (or via a propagated variable). Names stay at the
# call-syntax level ("query", not "sql") because the call alone does not
# prove the semantic sink kind.
_SINK_CALLS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("query", re.compile(r"->\s*query\s*\(")),
    ("exec", re.compile(r"->\s*exec\s*\(")),
    ("mysqli-query", re.compile(r"\bmysqli_(?:query|real_query|multi_query)\s*\(")),
    ("header", re.compile(r"\bheader\s*\(")),
    ("system", re.compile(r"\bsystem\s*\(")),
    ("shell-exec", re.compile(r"\bshell_exec\s*\(")),
    ("passthru", re.compile(r"\bpassthru\s*\(")),
    ("exec", re.compile(r"\bexec\s*\(")),
    ("popen", re.compile(r"\bpopen\s*\(")),
    ("proc-open", re.compile(r"\bproc_open\s*\(")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("unserialize", re.compile(r"\bunserialize\s*\(")),
    ("include-require", re.compile(r"\b(?:include|include_once|require|require_once)\b")),
    ("file-write", re.compile(r"\bfile_put_contents\s*\(")),
    ("upload-store", re.compile(r"\bmove_uploaded_file\s*\(")),
)

_INCLUDE_LITERAL_RE = re.compile(
    r"\b(?:include|include_once|require|require_once)\b\s*\(?\s*(?:__DIR__\s*\.\s*)?['\"](?P<target>[^'\"]+)['\"]"
)
_INCLUDE_DYNAMIC_RE = re.compile(
    r"\b(?:include|include_once|require|require_once)\b\s*\(?\s*\$"
)

# Session / cookie / password handling (AuthHint family).
_SESSION_START_RE = re.compile(r"\bsession_start\s*\(")
_SESSION_REGENERATE_RE = re.compile(r"\bsession_regenerate_id\s*\(")
_SESSION_STATE_RE = re.compile(r"\$_SESSION\b")
_SETCOOKIE_RE = re.compile(r"\b(?:setcookie|session_set_cookie_params)\s*\(")
_PASSWORD_HASH_RE = re.compile(r"\bpassword_hash\s*\(")
_PASSWORD_VERIFY_RE = re.compile(r"\bpassword_verify\s*\(")
_COOKIE_FLAGS = (("httponly", "php-cookie-httponly"), ("samesite", "php-cookie-samesite"), ("secure", "php-cookie-secure"))

# Output encoding (EntrypointHint family, labeled controls in hint text).
_OUTPUT_ESCAPE_RE = re.compile(r"\b(?:htmlspecialchars|htmlentities)\s*\(")
_OUTPUT_ECHO_VAR_RE = re.compile(r"\becho\s+\$(?!this\b)\w+")
_PHTML_ECHO_RE = re.compile(r"<\?=\s*\$(?!this\b)(?P<var>\w+)")
_PHTML_ESCAPE_RE = re.compile(r"escapeHtml(?:Attr|Url)?\s*\(")

# Databases and credential literals.
_NEW_PDO_RE = re.compile(r"\bnew\s+PDO\s*\(")
_PDO_DRIVER_RE = re.compile(r"['\"](?P<driver>mysql|sqlite|pgsql|oci|sqlsrv):")
_PDO_DRIVER_KIND = {"mysql": "mysql", "sqlite": "sqlite", "pgsql": "postgresql", "oci": "oracle", "sqlsrv": "sqlserver"}
_MYSQLI_RE = re.compile(r"\bnew\s+mysqli\s*\(|\bmysqli_connect\s*\(")
_PDO_LITERAL_CREDS_RE = re.compile(
    r"\bnew\s+PDO\s*\([^)]{0,200}?,\s*['\"](?P<user>[^'\"]{3,})['\"]\s*,\s*['\"](?P<pass>[^'\"]{3,})['\"]"
)

# Outbound HTTP (only literal URLs at the call site — never invented targets).
_CURL_URL_RE = re.compile(r"\bcurl_init\s*\(\s*['\"](?P<url>https?://[^'\"]+)['\"]")
_CURLOPT_URL_RE = re.compile(r"CURLOPT_URL\s*,\s*['\"](?P<url>https?://[^'\"]+)['\"]")
_FILE_GET_HTTP_RE = re.compile(r"\bfile_get_contents\s*\(\s*['\"](?P<url>https?://[^'\"]+)['\"]")
_CURL_ANY_RE = re.compile(r"\bcurl_(?:init|exec)\s*\(")

# --- Laminas layer -----------------------------------------------------------

_LAMINAS_IMPORT_RE = re.compile(r"\buse\s+(?:const\s+|function\s+)?(?:Laminas|Zend)\\(?P<component>\w+)")
_LAMINAS_CONTROLLER_CLASS_RE = re.compile(
    r"class\s+(?P<name>\w*Controller)\s+extends\s+"
    r"(?:AbstractActionController|AbstractRestfulController|AbstractConsoleController)"
)
_LAMINAS_CLASS_RE = re.compile(r"\bclass\s+(?P<name>\w+)")
_LAMINAS_ACTION_RE = re.compile(r"public\s+function\s+(?P<action>\w+)Action\s*\(")
_LAMINAS_REQUEST_INPUT_RE = re.compile(r"->\s*from(?P<kind>Query|Post|Route|Files|Header)\s*\(")
_LAMINAS_FORM_CLASS_RE = re.compile(r"class\s+(?P<name>\w+)\s+extends\s+Form\b")
_LAMINAS_INPUT_FILTER_RE = re.compile(r"\bInputFilter\b")
_LAMINAS_ISVALID_RE = re.compile(r"->\s*isValid\s*\(")
_LAMINAS_AUTH_RE = re.compile(r"\bLaminas\\Authentication\b|\bAuthenticationService\b")
_LAMINAS_ACL_RE = re.compile(r"\bLaminas\\Permissions\\Acl\b|\bnew\s+Acl\s*\(|\bAcl::class\b")
_LAMINAS_MIDDLEWARE_RE = re.compile(r"\bMiddlewarePipe\b|['\"]middleware['\"]\s*=>")
_LAMINAS_MODULE_MARKER_RE = re.compile(r"\b(?:Laminas|Zend)\\")

# Config-array extraction (module.config.php and friends).
_ROUTE_DEF_RE = re.compile(r"['\"]route['\"]\s*=>\s*['\"](?P<path>[^'\"]+)['\"]")
_SERVICE_MANAGER_RE = re.compile(r"['\"]service_manager['\"]\s*=>")
_CONTROLLERS_CONFIG_RE = re.compile(r"['\"]controllers['\"]\s*=>")
# Bounded: an unbounded ``[\w\\]+`` backtracks quadratically over long
# word-shaped runs before the required ``::class`` (tests/test_regex_budget.py);
# real PHP class references are far shorter than 512 chars.
_CLASS_ENTRY_RE = re.compile(r"(?P<entry>[\w\\]{1,512})::class")
_QUOTED_KEY_RE = re.compile(r"['\"](?P<key>[\w][\w.-]*)['\"]\s*=>")
_MODULES_LIST_RE = re.compile(r"['\"]modules['\"]\s*=>")

# --- Omeka S layer -----------------------------------------------------------

_OMEKA_MODULE_MARKER_RE = re.compile(r"\bOmeka\\Module\\AbstractModule\b")
_OMEKA_MARKER_RE = re.compile(r"\bOmeka\\")
_OMEKA_NAMESPACE_RE = re.compile(r"\bnamespace\s+(?P<ns>\w+)")
_OMEKA_ADAPTER_CLASS_RE = re.compile(
    r"class\s+(?P<name>\w+)\s+extends\s+(?:[\w\\]*AbstractEntityAdapter|[\w\\]*AbstractAdapter)\b"
)
_OMEKA_REPRESENTATION_CLASS_RE = re.compile(
    r"class\s+(?P<name>\w+)\s+extends\s+[\w\\]*(?:AbstractEntityRepresentation|AbstractRepresentation)\b"
)
_OMEKA_IDENTITY_RE = re.compile(r"->\s*identity\s*\(")
_OMEKA_AUTH_PLUGIN_RE = re.compile(r"->\s*auth\s*\(\s*\)")
_OMEKA_API_KEY_RE = re.compile(r"\bOmeka\\Entity\\ApiKey\b|\bapiKey\b")
_OMEKA_API_MANAGER_RE = re.compile(r"\bOmeka\\Api\\Manager\b|\bApiManager\b")
_OMEKA_FILE_STORE_RE = re.compile(r"\bOmeka\\File\\")
_OMEKA_UPLOAD_REQUEST_RE = re.compile(r"->\s*getFileData\s*\(")

_OMEKA_CONFIG_SECTIONS: tuple[tuple[str, str], ...] = (
    ("api_adapters", "omeka-api-adapter"),
    ("media_ingesters", "omeka-media-ingester"),
    ("media_renderers", "omeka-media-renderer"),
)

# Container sub-keys that are structure, not resource names — a quoted-key
# scan of an Omeka config section must not report them as adapters/ingesters.
_CONTAINER_SUBKEYS = frozenset({
    "factories", "invokables", "aliases", "delegators", "initializers",
    "abstract_factories", "lazy_services", "shared",
})


# --- Shared helpers -----------------------------------------------------------


def _iter_source_files(
    root: Path,
    index: object | None,
    suffixes: frozenset[str] | set[str],
) -> Iterator[tuple[str, str]]:
    """Yield ``(repo-relative posix path, text)`` for source files, honoring
    the shared skip/vendored/test policy (``SKIP_DIRS`` + source-quality
    weighting). Uses the prebuilt repo index when core passed one."""
    if index is not None:
        for item in getattr(index, "files", ()):
            rel_path = Path(item.rel)
            if in_skipped_dir(rel_path):
                continue
            if rel_path.suffix.lower() not in suffixes:
                continue
            if is_vendored_file(item.rel) or is_test_file(item.rel):
                continue
            yield rel_path.as_posix(), item.text
        return
    for path in walk_repo(root, prune=is_skipped_dir):
        rel = path.relative_to(root).as_posix()
        if in_skipped_dir(Path(rel)):
            continue
        if path.suffix.lower() not in suffixes:
            continue
        if is_vendored_file(rel) or is_test_file(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        yield rel, text


def _composer_files(root: Path, index: object | None) -> Iterator[tuple[str, str]]:
    """Yield ``(rel, text)`` for every composer.json in the repo."""
    if index is not None:
        for item in getattr(index, "files", ()):
            if Path(item.rel).name == "composer.json" and not in_skipped_dir(Path(item.rel)):
                yield Path(item.rel).as_posix(), item.text
        return
    for path in walk_repo(root, prune=is_skipped_dir):
        if path.name != "composer.json":
            continue
        if in_skipped_dir(path.relative_to(root)):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        yield path.relative_to(root).as_posix(), text


def _composer_require_entries(text: str) -> list[tuple[str, str, int]]:
    """Tolerant ``(section, package, line)`` list for a composer.json.

    A real JSON parse when possible; a regex fallback so a truncated or
    hand-mangled manifest still yields its package evidence."""
    entries: list[tuple[str, str, int]] = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        data = None
    if isinstance(data, dict):
        for section in ("require", "require-dev"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for name in block:
                if not isinstance(name, str):
                    continue
                quoted = name.replace("\\", "\\\\")
                hit = re.search(r"[\"']" + re.escape(quoted) + r"[\"']\s*:", text)
                line = line_number(text, hit.start()) if hit else 1
                entries.append((section, name, line))
        return entries
    for match in re.finditer(r"[\"'](?P<pkg>[\w.-]+/[\w.-]+)[\"']\s*:", text):
        entries.append(("require", match.group("pkg"), line_number(text, match.start())))
    return entries


def _match_bracket(text: str, open_idx: int, max_span: int = 20_000) -> int:
    """Index of the bracket matching ``text[open_idx]`` ('[' or '('), or -1.

    Quote- and escape-aware, capped so a malformed config cannot make this
    walk quadratic. -1 means "no matching bracket" — callers fall back to a
    bounded window."""
    if open_idx < 0 or open_idx >= len(text) or text[open_idx] not in "[(":
        return -1
    close = "]" if text[open_idx] == "[" else ")"
    depth = 0
    quote: str | None = None
    escaped = False
    limit = min(len(text), open_idx + max_span)
    for idx in range(open_idx, limit):
        char = text[idx]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char in "[(":
            depth += 1
        elif char in "])":
            depth -= 1
            if depth == 0 and char == close:
                return idx
    return -1


def _section_window(text: str, match: re.Match[str]) -> str:
    """The array body following a ``'section' =>`` match, best effort."""
    open_idx = text.find("[", match.end() - 1)
    if open_idx == -1 or open_idx > match.end() + 40:
        return text[match.end(): match.end() + 400]
    close_idx = _match_bracket(text, open_idx)
    if close_idx == -1:
        return text[open_idx: open_idx + 4_000]
    return text[open_idx:close_idx]


def _snippet_at(text: str, offset: int, max_chars: int = 200) -> str:
    """The source line at ``offset``, stripped and capped."""
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    line = text[start:end].strip()
    return line[: max_chars - 1] + "…" if len(line) > max_chars else line


# --- Detection ----------------------------------------------------------------


def has_php_source(root: str | Path, index: object | None = None) -> bool:
    """Any non-vendored, non-test ``.php`` file below ``root``."""
    repo = Path(root)
    if not repo.is_dir():
        return False
    for _rel, _text in _iter_source_files(repo, index, {PHP_SUFFIX}):
        return True
    return False


def looks_laminas(root: str | Path, index: object | None = None) -> bool:
    """Composer depends on laminas/ or zendframework/, or a Module.php file
    carries a Laminas/Zend class marker. Conservative by design."""
    repo = Path(root)
    if not repo.is_dir():
        return False
    for _rel, text in _composer_files(repo, index):
        for _section, package, _line in _composer_require_entries(text):
            if package.startswith(("laminas/", "zendframework/")):
                return True
    for rel, text in _iter_source_files(repo, index, {PHP_SUFFIX}):
        if Path(rel).name == "Module.php" and _LAMINAS_MODULE_MARKER_RE.search(text):
            return True
    return False


def looks_omeka_s(root: str | Path, index: object | None = None) -> bool:
    """An Omeka S module marker (``Omeka\\Module\\AbstractModule``) or a
    composer dependency on omeka/*. Conservative by design."""
    repo = Path(root)
    if not repo.is_dir():
        return False
    for _rel, text in _composer_files(repo, index):
        for _section, package, _line in _composer_require_entries(text):
            if package.startswith("omeka/"):
                return True
    for _rel, text in _iter_source_files(repo, index, {PHP_SUFFIX}):
        if _OMEKA_MODULE_MARKER_RE.search(text):
            return True
    return False


# --- Layer 1: php-web -----------------------------------------------------------


def scan_php_web_repo(root: str | Path, index: object | None = None) -> ScanResult:
    """Broad plain-PHP extraction: request input, input->sink co-occurrence,
    include/require edges, session/cookie handling, database handles and
    literal outbound HTTP targets. Merges with other analyzers via the
    standard pipeline."""
    repo = Path(root).resolve()
    result = ScanResult(root=str(repo), scanned_files=[])
    if not repo.is_dir():
        return result
    scanned: list[str] = []
    for rel, text in _iter_source_files(repo, index, {PHP_SUFFIX}):
        scanned.append(rel)
        _extract_php_web(rel, text, result)
    result.scanned_files = sorted(set(scanned))
    result.files_scanned = len(result.scanned_files)
    if result.scanned_files:
        result.languages.append("php")
    return result


def _extract_php_web(rel: str, text: str, result: ScanResult) -> None:
    lines = text.splitlines()

    def hint_at(pattern: re.Pattern[str], factory: Callable[[int, str], None]) -> None:
        match = pattern.search(text)
        if match is not None:
            factory(line_number(text, match.start()), _snippet_at(text, match.start()))

    # --- Request input usage (observed; first occurrence per token) ---
    seen_input_tokens: set[str] = set()
    for match in _REQUEST_INPUT_RE.finditer(text):
        token = match.group(0)
        if token in seen_input_tokens:
            continue
        seen_input_tokens.add(token)
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-http-input:{token} {OBSERVED}",
            file=rel, line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    if re.search(r"\bfilter_input\s*\(", text):
        match = re.search(r"\bfilter_input\s*\(", text)
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-filter-input {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))

    # --- Input -> sink co-occurrence ---
    # Pass 1: variables assigned from request input (file-scoped).
    tainted_vars: set[str] = set()
    for line in lines:
        match = _SUPERGLOBAL_ASSIGN_RE.search(line)
        if match is not None:
            tainted_vars.add(match.group("var"))
    # Pass 2: a sink call on a line that also touches request input —
    # directly (observed) or via one of those variables (inferred).
    best: dict[str, tuple[str, int, str]] = {}
    for lineno, line in enumerate(lines, start=1):
        direct = _REQUEST_INPUT_RE.search(line) is not None
        propagated = any(
            re.search(r"\$" + re.escape(var) + r"\b", line) for var in tainted_vars
        )
        if not (direct or propagated):
            continue
        label = OBSERVED if direct else INFERRED
        for name, pattern in _SINK_CALLS:
            if pattern.search(line) is None:
                continue
            prior = best.get(name)
            if prior is None or (label == OBSERVED and prior[0] != OBSERVED):
                best[name] = (label, lineno, line.strip()[:200])
    for name, (label, lineno, snippet) in best.items():
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-input-to-sink:{name} {label}", file=rel,
            line=lineno, evidence_text=snippet, confidence=0.7 if label == OBSERVED else 0.55,
        ))

    # --- Include / require edges ---
    for match in _INCLUDE_LITERAL_RE.finditer(text):
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-include:{match.group('target')} {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.9,
        ))
    match = _INCLUDE_DYNAMIC_RE.search(text)
    if match is not None:
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-include-dynamic {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.7,
        ))

    # --- Session / cookie / password handling ---
    def _auth(hint: str, line: int, snippet: str, confidence: float) -> None:
        result.auth_hints.append(AuthHint(
            hint=hint, file=rel, line=line, evidence_text=snippet, confidence=confidence,
        ))

    hint_at(_SESSION_START_RE, lambda n, s: _auth(f"php-session-start {OBSERVED}", n, s, 0.8))
    hint_at(_SESSION_REGENERATE_RE, lambda n, s: _auth(f"php-session-regenerate-id {OBSERVED}", n, s, 0.85))
    hint_at(_SESSION_STATE_RE, lambda n, s: _auth(f"php-session-state {OBSERVED}", n, s, 0.7))
    hint_at(_PASSWORD_HASH_RE, lambda n, s: _auth(f"php-password-hash {OBSERVED}", n, s, 0.85))
    hint_at(_PASSWORD_VERIFY_RE, lambda n, s: _auth(f"php-password-verify {OBSERVED}", n, s, 0.85))

    for match in _SETCOOKIE_RE.finditer(text):
        open_idx = text.find("(", match.start())
        close_idx = _match_bracket(text, open_idx) if open_idx != -1 else -1
        window = text[match.start(): close_idx + 1 if close_idx != -1 else match.start() + 400]
        line = line_number(text, match.start())
        snippet = _snippet_at(text, match.start())
        found_flag = False
        for token, hint_name in _COOKIE_FLAGS:
            if re.search(token, window, re.IGNORECASE):
                found_flag = True
                _auth(f"{hint_name} {OBSERVED}", line, snippet, 0.85)
        if not found_flag:
            _auth(f"php-setcookie-no-flags {OBSERVED}", line, snippet, 0.6)

    # --- Databases and inline credentials ---
    for match in _NEW_PDO_RE.finditer(text):
        open_idx = text.find("(", match.start())
        close_idx = _match_bracket(text, open_idx) if open_idx != -1 else -1
        window = text[match.start(): close_idx + 1 if close_idx != -1 else match.start() + 300]
        driver = _PDO_DRIVER_RE.search(window)
        kind = _PDO_DRIVER_KIND[driver.group("driver")] if driver else "sql"
        result.databases.append(DatabaseHint(
            kind=kind, file=rel, line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.9,
        ))
        creds = _PDO_LITERAL_CREDS_RE.search(window)
        if creds is not None:
            result.secret_hints.append(SecretHint(
                name="pdo-password", file=rel, line=line_number(text, match.start()),
                evidence_text=_snippet_at(text, match.start()), confidence=0.8, kind="literal",
            ))
    for match in _MYSQLI_RE.finditer(text):
        result.databases.append(DatabaseHint(
            kind="mysql", file=rel, line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.9,
        ))
    # A standalone DSN literal names the driver even when the PDO call
    # passes it through a variable (observed).
    for match in _PDO_DRIVER_RE.finditer(text):
        result.databases.append(DatabaseHint(
            kind=_PDO_DRIVER_KIND[match.group("driver")], file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.8,
        ))

    # --- Outbound HTTP (literal targets only) ---
    seen_urls: set[str] = set()
    for pattern in (_CURL_URL_RE, _CURLOPT_URL_RE, _FILE_GET_HTTP_RE):
        for match in pattern.finditer(text):
            url = match.group("url")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            result.external_calls.append(ExternalCall(
                target=url, file=rel, line=line_number(text, match.start()),
                method="GET" if pattern is _FILE_GET_HTTP_RE else None,
                evidence_text=_snippet_at(text, match.start()),
            ))
    if _CURL_ANY_RE.search(text) and not seen_urls:
        match = _CURL_ANY_RE.search(text)
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-curl-outbound {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.7,
        ))

    # --- Output encoding ---
    hint_at(_OUTPUT_ESCAPE_RE, lambda n, s: result.entrypoint_hints.append(EntrypointHint(
        hint=f"php-output-escaped {OBSERVED}", file=rel, line=n, evidence_text=s, confidence=0.85,
    )))
    for lineno, line in enumerate(lines, start=1):
        if _OUTPUT_ECHO_VAR_RE.search(line) and not _OUTPUT_ESCAPE_RE.search(line):
            result.entrypoint_hints.append(EntrypointHint(
                hint=f"php-output-unescaped {OBSERVED}", file=rel, line=lineno,
                evidence_text=line.strip()[:200], confidence=0.6,
            ))
            break  # one per file is enough for extraction

    # --- File uploads ---
    match = re.search(r"\bmove_uploaded_file\s*\(", text) or re.search(r"\$_FILES\b", text)
    if match is not None:
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-file-upload {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.8,
        ))


# --- Layer 2: php-laminas --------------------------------------------------------


def scan_php_laminas_repo(root: str | Path, index: object | None = None) -> ScanResult:
    """Laminas / Zend MVC enrichment: module structure, router config,
    controllers/actions, service-manager wiring, middleware pipelines,
    validators/filters. Silent unless laminas markers are present."""
    repo = Path(root).resolve()
    result = ScanResult(root=str(repo), scanned_files=[])
    if not repo.is_dir() or not looks_laminas(repo, index):
        return result
    scanned: list[str] = []
    for rel, text in _composer_files(repo, index):
        for section, package, line in _composer_require_entries(text):
            if package.startswith(("laminas/", "zendframework/")):
                offset = text.find(f'"{package}"')
                result.framework_hints.append(FrameworkHint(
                    hint=f"laminas {OBSERVED}", file=rel, line=line,
                    evidence_text=_snippet_at(text, offset if offset >= 0 else 0), confidence=0.9,
                ))
                break
    for rel, text in _iter_source_files(repo, index, {PHP_SUFFIX}):
        scanned.append(rel)
        _extract_laminas(rel, text, result)
    result.scanned_files = sorted(set(scanned))
    result.files_scanned = len(result.scanned_files)
    if result.scanned_files:
        result.languages.append("php")
    return result


def _extract_laminas(rel: str, text: str, result: ScanResult) -> None:
    is_config = rel.endswith(".config.php") or "/config/" in rel

    # Framework imports (observed).
    seen_components: set[str] = set()
    for match in _LAMINAS_IMPORT_RE.finditer(text):
        component = match.group("component")
        if component in seen_components:
            continue
        seen_components.add(component)
        result.framework_hints.append(FrameworkHint(
            hint=f"laminas-import:{component} {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))

    # Module structure (Module.php with a Laminas marker).
    if Path(rel).name == "Module.php":
        marker = _LAMINAS_MODULE_MARKER_RE.search(text)
        if marker is not None:
            ns = _OMEKA_NAMESPACE_RE.search(text)
            ns_name = ns.group("ns") if ns else Path(rel).parent.name
            result.framework_hints.append(FrameworkHint(
                hint=f"laminas-module:{ns_name} {OBSERVED}", file=rel,
                line=line_number(text, marker.start()),
                evidence_text=_snippet_at(text, marker.start()), confidence=0.85,
            ))

    # Controllers and their actions (observed MVC surface).
    class_spans: list[tuple[int, int, str]] = []
    for match in _LAMINAS_CLASS_RE.finditer(text):
        class_spans.append((match.start(), match.end(), match.group("name")))
    for match in _LAMINAS_CONTROLLER_CLASS_RE.finditer(text):
        name = match.group("name")
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"laminas-controller:{name} {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    for match in _LAMINAS_ACTION_RE.finditer(text):
        owner = next((span[2] for span in reversed(class_spans) if span[0] < match.start()), "?")
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"laminas-action:{owner}/{match.group('action')} {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.8,
        ))

    # Request input through the framework's param plugins (observed).
    for match in _LAMINAS_REQUEST_INPUT_RE.finditer(text):
        kind = match.group("kind").lower()
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"laminas-request-input:{kind} {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))

    # Forms / validators / filters (input-validation controls, observed).
    for match in _LAMINAS_FORM_CLASS_RE.finditer(text):
        result.framework_hints.append(FrameworkHint(
            hint=f"laminas-form:{match.group('name')} {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    if _LAMINAS_INPUT_FILTER_RE.search(text):
        match = _LAMINAS_INPUT_FILTER_RE.search(text)
        result.framework_hints.append(FrameworkHint(
            hint=f"laminas-input-filter {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    if _LAMINAS_ISVALID_RE.search(text):
        match = _LAMINAS_ISVALID_RE.search(text)
        result.framework_hints.append(FrameworkHint(
            hint=f"laminas-form-validation-call {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.8,
        ))

    # Authentication / authorization markers (observed).
    if _LAMINAS_AUTH_RE.search(text):
        match = _LAMINAS_AUTH_RE.search(text)
        result.auth_hints.append(AuthHint(
            hint=f"laminas-authentication-service {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    if _LAMINAS_ACL_RE.search(text):
        match = _LAMINAS_ACL_RE.search(text)
        result.auth_hints.append(AuthHint(
            hint=f"laminas-acl {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.8,
        ))

    # Middleware pipelines (observed).
    if _LAMINAS_MIDDLEWARE_RE.search(text):
        match = _LAMINAS_MIDDLEWARE_RE.search(text)
        result.framework_hints.append(FrameworkHint(
            hint=f"laminas-middleware-pipeline {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.8,
        ))

    if not is_config:
        return

    # --- Config-array extraction ---
    for match in _ROUTE_DEF_RE.finditer(text):
        result.routes.append(Route(
            path=match.group("path"), method="ANY", file=rel,
            line=line_number(text, match.start()),
        ))
    if _SERVICE_MANAGER_RE.search(text):
        match = _SERVICE_MANAGER_RE.search(text)
        result.framework_hints.append(FrameworkHint(
            hint=f"laminas-service-manager {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
        window = _section_window(text, match)
        seen_wiring: set[str] = set()
        for entry_match in _CLASS_ENTRY_RE.finditer(window):
            short = entry_match.group("entry").rsplit("\\", 1)[-1]
            if short in seen_wiring:
                continue
            seen_wiring.add(short)
            result.framework_hints.append(FrameworkHint(
                hint=f"laminas-service-factory:{short} {OBSERVED}", file=rel,
                line=line_number(text, match.start()),
                evidence_text=_snippet_at(text, match.start()), confidence=0.8,
            ))
    if _CONTROLLERS_CONFIG_RE.search(text):
        match = _CONTROLLERS_CONFIG_RE.search(text)
        result.framework_hints.append(FrameworkHint(
            hint=f"laminas-controllers-config {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    modules_match = _MODULES_LIST_RE.search(text)
    if modules_match is not None:
        window = _section_window(text, modules_match)
        for key_match in re.finditer(r"['\"](?P<name>[\w\\]+)['\"]", window):
            result.framework_hints.append(FrameworkHint(
                hint=f"laminas-app-module:{key_match.group('name')} {OBSERVED}", file=rel,
                line=line_number(text, modules_match.start()),
                evidence_text=_snippet_at(text, modules_match.start()), confidence=0.85,
            ))
    elif Path(rel).name == "modules.config.php":
        for key_match in re.finditer(r"['\"](?P<name>[\w\\]+)['\"]", text):
            result.framework_hints.append(FrameworkHint(
                hint=f"laminas-app-module:{key_match.group('name')} {OBSERVED}", file=rel,
                line=line_number(text, key_match.start()),
                evidence_text=_snippet_at(text, key_match.start()), confidence=0.85,
            ))


# --- Layer 3: omeka-s ------------------------------------------------------------


def scan_omeka_s_repo(root: str | Path, index: object | None = None) -> ScanResult:
    """Omeka S application overlay: module layout, API adapters /
    representations, admin vs site vs api routes, admin authentication
    plugins, media ingestion, view-script output encoding. Silent unless
    Omeka S markers are present."""
    repo = Path(root).resolve()
    result = ScanResult(root=str(repo), scanned_files=[])
    if not repo.is_dir() or not looks_omeka_s(repo, index):
        return result
    files = list(_iter_source_files(repo, index, frozenset({PHP_SUFFIX, PHTML_SUFFIX})))

    module_roots: list[str] = []
    scanned: set[str] = set()
    for rel, text in files:
        scanned.add(rel)
        if _OMEKA_MODULE_MARKER_RE.search(text):
            module_roots.append(rel.rsplit("/", 1)[0] if "/" in rel else "")
    for rel, text in _composer_files(repo, index):
        for _section, package, line in _composer_require_entries(text):
            if package.startswith("omeka/"):
                offset = text.find(f'"{package}"')
                result.framework_hints.append(FrameworkHint(
                    hint=f"omeka-s {OBSERVED}", file=rel, line=line,
                    evidence_text=_snippet_at(text, offset if offset >= 0 else 0), confidence=0.9,
                ))
                break

    def in_omeka_scope(rel: str, text: str) -> bool:
        if any(rel.startswith(root + "/") or rel == root for root in module_roots if root):
            return True
        return _OMEKA_MARKER_RE.search(text) is not None

    for rel, text in files:
        if not in_omeka_scope(rel, text):
            continue
        if rel.endswith(PHTML_SUFFIX):
            _extract_phtml(rel, text, result)
            continue
        _extract_omeka(rel, text, result, is_module_config=rel.endswith(".config.php") or "/config/" in rel)

    result.scanned_files = sorted(scanned)
    result.files_scanned = len(result.scanned_files)
    if result.scanned_files:
        result.languages.append("php")
    return result


def _extract_omeka(rel: str, text: str, result: ScanResult, *, is_module_config: bool) -> None:
    # Module identity (observed).
    if _OMEKA_MODULE_MARKER_RE.search(text):
        marker = _OMEKA_MODULE_MARKER_RE.search(text)
        ns = _OMEKA_NAMESPACE_RE.search(text)
        ns_name = ns.group("ns") if ns else Path(rel).parent.name
        result.framework_hints.append(FrameworkHint(
            hint=f"omeka-s-module:{ns_name} {OBSERVED}", file=rel,
            line=line_number(text, marker.start()),
            evidence_text=_snippet_at(text, marker.start()), confidence=0.9,
        ))

    # API surface (observed).
    for match in _OMEKA_ADAPTER_CLASS_RE.finditer(text):
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"omeka-api-adapter-class:{match.group('name')} {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    for match in _OMEKA_REPRESENTATION_CLASS_RE.finditer(text):
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"omeka-api-representation:{match.group('name')} {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    if _OMEKA_API_MANAGER_RE.search(text):
        match = _OMEKA_API_MANAGER_RE.search(text)
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"omeka-api-manager {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))

    # Admin authentication plugins (observed).
    if _OMEKA_IDENTITY_RE.search(text):
        match = _OMEKA_IDENTITY_RE.search(text)
        result.auth_hints.append(AuthHint(
            hint=f"omeka-identity-plugin {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    if _OMEKA_AUTH_PLUGIN_RE.search(text):
        match = _OMEKA_AUTH_PLUGIN_RE.search(text)
        result.auth_hints.append(AuthHint(
            hint=f"omeka-auth-plugin {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
    if _OMEKA_API_KEY_RE.search(text):
        match = _OMEKA_API_KEY_RE.search(text)
        result.auth_hints.append(AuthHint(
            hint=f"omeka-api-key-auth {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.7,
        ))

    # Media / file handling (observed).
    if _OMEKA_FILE_STORE_RE.search(text):
        match = _OMEKA_FILE_STORE_RE.search(text)
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"omeka-file-store {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.8,
        ))
    if _OMEKA_UPLOAD_REQUEST_RE.search(text):
        match = _OMEKA_UPLOAD_REQUEST_RE.search(text)
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"omeka-upload-request {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.8,
        ))

    if not is_module_config:
        return

    # --- module.config.php sections ---
    for section, label in _OMEKA_CONFIG_SECTIONS:
        match = re.search(rf"['\"]{section}['\"]\s*=>", text)
        if match is None:
            continue
        window = _section_window(text, match)
        for key_match in _QUOTED_KEY_RE.finditer(window):
            key = key_match.group("key")
            if key in _CONTAINER_SUBKEYS:
                continue
            result.entrypoint_hints.append(EntrypointHint(
                hint=f"{label}:{key} {OBSERVED}", file=rel,
                line=line_number(text, match.start()),
                evidence_text=_snippet_at(text, match.start()), confidence=0.85,
            ))

    # Route surface classification (admin vs api vs site vs generic).
    for match in _ROUTE_DEF_RE.finditer(text):
        path = match.group("path")
        line = line_number(text, match.start())
        result.routes.append(Route(path=path, method="ANY", file=rel, line=line))
        if path.startswith("/admin"):
            kind = "omeka-admin-route"
        elif path.startswith("/api"):
            kind = "omeka-api-route"
        elif path.startswith("/s/") or ":site-slug" in path:
            kind = "omeka-site-route"
        else:
            kind = "omeka-route"
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"{kind}:{path} {OBSERVED}", file=rel, line=line,
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))


def _extract_phtml(rel: str, text: str, result: ScanResult) -> None:
    """View-script output encoding: escaped output is the observed control;
    a short-echo of a request-derived variable without an escaper is the
    observed contrast."""
    for match in _PHTML_ESCAPE_RE.finditer(text):
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-output-escaped {OBSERVED}", file=rel,
            line=line_number(text, match.start()),
            evidence_text=_snippet_at(text, match.start()), confidence=0.85,
        ))
        break  # one per file is enough for extraction
    for lineno, line in enumerate(text.splitlines(), start=1):
        echo = _PHTML_ECHO_RE.search(line)
        if echo is None or _PHTML_ESCAPE_RE.search(line):
            continue
        result.entrypoint_hints.append(EntrypointHint(
            hint=f"php-output-unescaped {OBSERVED}", file=rel, line=lineno,
            evidence_text=line.strip()[:200], confidence=0.7,
        ))
        break  # one per file is enough for extraction


# --- Analyzer classes (registered in analyzers.py; see the registration patch) ---


class PhpWebAnalyzer:
    """Broad built-in PHP language analyzer (layer 1 of 3).

    ``analyze`` combines the generic per-file scanner pass over ``.php``
    (routes, DB/auth/secret heuristics — the coverage the default analyzer
    used to provide for PHP) with this module's layered extraction, so
    claiming ``.php`` away from the default analyzer never loses signals.
    """

    metadata = AnalyzerMetadata(
        name="php-web",
        display_name="PHP Web Analyzer",
        version="0.1.0",
        description="Built-in analyzer for plain PHP web applications: generic routes plus request input, include chains, session/cookie handling, datastores, outbound HTTP.",
        scope="PHP source files (.php). Framework structure lives in php-laminas; Omeka S specifics in omeka-s.",
        targets=["php"],
        languages=["php"],
        priority=20,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        return has_php_source(root)

    def analyze(self, root: str | Path, index: object | None = None) -> AnalyzerResult:
        from .analyzers import merge_analyzer_results
        from .scanner import scan_files

        base = scan_files(root, suffixes={PHP_SUFFIX}, index=index)
        extra = scan_php_web_repo(root, index=index)
        combined = merge_analyzer_results([base, extra], root=root)
        # Coverage counts the union of files, not the sum of both passes.
        combined.scanned_files = sorted(
            set(base.scanned_files or []) | set(extra.scanned_files or [])
        )
        combined.files_scanned = len(combined.scanned_files)
        return combined


class PhpLaminasAnalyzer:
    """Laminas / Zend MVC framework enrichment (layer 2 of 3)."""

    metadata = AnalyzerMetadata(
        name="php-laminas",
        display_name="PHP Laminas (Zend MVC) Analyzer",
        version="0.1.0",
        description="Framework enrichment for Laminas / Zend MVC: module structure, router config, controllers/actions, service-manager wiring, middleware, validators/filters.",
        scope="Repos with laminas/ or zendframework/ composer dependencies, or Module.php files carrying Laminas/Zend markers.",
        targets=["laminas", "zend-mvc"],
        languages=["php"],
        priority=60,
        experimental=True,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        return looks_laminas(root)

    def analyze(self, root: str | Path, index: object | None = None) -> AnalyzerResult:
        return scan_php_laminas_repo(root, index=index)


class OmekaSAnalyzer:
    """Omeka S application overlay (layer 3 of 3)."""

    metadata = AnalyzerMetadata(
        name="omeka-s",
        display_name="Omeka S Analyzer",
        version="0.1.0",
        description="Application overlay for Omeka S modules: module layout, API adapters vs representations vs routes, admin authentication, media ingestion, view output encoding.",
        scope="Repos with an Omeka S module marker (Omeka\\Module\\AbstractModule) or an omeka/* composer dependency.",
        targets=["omeka-s"],
        languages=["php"],
        priority=160,
        experimental=True,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, root: str | Path) -> bool:
        return looks_omeka_s(root)

    def analyze(self, root: str | Path, index: object | None = None) -> AnalyzerResult:
        return scan_omeka_s_repo(root, index=index)
