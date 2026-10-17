"""Exact references to producer evidence and immutable, redacted source spans.

Reference validity is a mechanical check. It never establishes claim support.
Claim support is assessed separately (:func:`assess_claim_support`), always
deterministically, from a closed set of honest states, and only ever as token
presence in captured evidence — never as semantic verification of a conclusion.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Callable, Iterable, Iterator, Literal

from .safe_fs import contained_file

_COLLECTION_PREFIXES = {
    "attack_surfaces": "surface", "findings": "finding", "attack_paths": "path",
    "taint_chains": "taint", "exploitability": "exploit", "anomalies": "anomaly",
}
_ID = re.compile(r"(?:surface|finding|path|taint|exploit|anomaly):[1-9][0-9]*\Z")
_LOCATION = re.compile(r"\A(?P<path>.+):(?P<line>[1-9][0-9]*)(?:-(?P<end>[1-9][0-9]*))?\Z")
_TOKENS = re.compile(r'''[^\s`\[\](){}<>,;!?"'|=*]+''')


def _looks_like_location(token: str) -> bool:
    """Recognize malformed location tokens without overlapping regex scans.

    Tokens contain no whitespace. A path separator must occur after the previous
    colon and before a colon followed by an ASCII digit; the suffix may be
    malformed, since this predicate rejects rather than authorizes references.
    """
    separator = False
    for index, character in enumerate(token):
        if character in "/.":
            separator = True
        elif character == ":":
            if separator and index + 1 < len(token) and "0" <= token[index + 1] <= "9":
                return True
            separator = False
    return False


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_digest(value) -> str:
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())


def _relative_path(value: str) -> str | None:
    if not isinstance(value, str) or not value or "\0" in value or value.startswith("~"):
        return None
    if PureWindowsPath(value).drive:
        return None
    value = value.replace("\\", "/")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value != path.as_posix():
        return None
    return value


@dataclass(frozen=True)
class SourceSpan:
    evidence_id: str
    path: str
    anchor_line: int
    start_line: int
    end_line: int
    source_sha256: str
    excerpt_sha256: str
    excerpt: str

    @property
    def location(self) -> str:
        return f"{self.path}:{self.anchor_line}"

    @property
    def span_location(self) -> str:
        return f"{self.path}:{self.start_line}-{self.end_line}"

    def metadata(self) -> dict:
        return {"id": self.evidence_id, "path": self.path, "anchor_line": self.anchor_line,
            "start_line": self.start_line, "end_line": self.end_line,
            "source_sha256": self.source_sha256, "excerpt_sha256": self.excerpt_sha256}


def capture_source_spans(root: str | Path, locations: Iterable[tuple[str, int]], *,
                         redact_line: Callable[[str], str], context_lines: int = 3,
                         max_locations: int = 24, max_file_bytes: int = 1_000_000) -> tuple[SourceSpan, ...]:
    """Read each selected file once; retain only hashes and bounded redacted spans.

    These are captured file contents, not a whole-repository atomic snapshot.
    No validation later rereads the live filesystem or guesses line positions.
    """
    if context_lines < 0 or max_locations < 0 or max_file_bytes < 1:
        raise ValueError("Source capture limits must be nonnegative and bounded")
    root = Path(root)
    cache: dict[str, tuple[str, list[str]]] = {}
    spans = []
    seen = set()
    for requested, line in locations:
        rel = _relative_path(requested)
        if rel is None or type(line) is not int or line < 1 or (rel, line) in seen:
            continue
        if len(spans) >= max_locations:
            break
        seen.add((rel, line))
        if rel not in cache:
            cache[rel] = ("", [])
            try:
                path = contained_file(root, rel)
                if path is None:
                    continue
                parts = [path, *path.parents]
                if any(part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction())
                       for part in parts if part != root and part.is_relative_to(root)):
                    continue
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(descriptor, "rb") as stream:
                    raw = stream.read(max_file_bytes + 1)
                if len(raw) > max_file_bytes:
                    continue
                if contained_file(root, rel) != path or path.is_symlink():
                    continue
                cache[rel] = (_digest(raw), raw.decode("utf-8", errors="replace").splitlines())
            except (OSError, ValueError):
                continue
        source_hash, lines = cache[rel]
        if not lines or line > len(lines):
            continue
        lo, hi = max(1, line - context_lines), min(len(lines), line + context_lines)
        excerpt = "\n".join(f"{number}: {redact_line(lines[number - 1])}" for number in range(lo, hi + 1))
        excerpt_hash = _digest(excerpt.encode("utf-8"))
        identity = {"path": rel, "anchor": line, "start": lo, "end": hi,
                    "source_sha256": source_hash, "excerpt_sha256": excerpt_hash}
        spans.append(SourceSpan("source:" + _json_digest(identity), rel, line, lo, hi,
                                source_hash, excerpt_hash, excerpt))
    return tuple(spans)


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    record_sha256: str
    source_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CitationContext:
    repository_root: str
    records: tuple[EvidenceReference, ...]
    spans: tuple[SourceSpan, ...]
    producer_payload_json: str = field(default="{}", repr=False)

    @property
    def context_id(self) -> str:
        return _json_digest({"records": [(r.evidence_id, r.record_sha256, r.source_ids) for r in self.records],
                             "spans": [span.metadata() for span in self.spans]})

    @property
    def excerpts(self) -> dict[str, str]:
        return {span.location: span.excerpt for span in self.spans}

    @property
    def producer_payload(self) -> dict:
        """Return a fresh copy so a later prompt cannot mutate the frozen pack."""
        return json.loads(self.producer_payload_json)

    def metadata(self) -> dict:
        return {"context_id": self.context_id, "reference_validity": "mechanically_checked",
            "claim_support": "not_assessed", "sources": [span.metadata() for span in self.spans],
            "evidence": [{"id": ref.evidence_id, "record_sha256": ref.record_sha256,
                          "source_ids": list(ref.source_ids)} for ref in self.records]}


def reference_tokens(text: str) -> tuple[str, ...]:
    """Whole, case-sensitive tokens only; filenames and ID prefixes never match."""
    return tuple(dict.fromkeys(token.rstrip(".,") for token in _TOKENS.findall(text)))


def context_from_payload(payload: dict, spans: tuple[SourceSpan, ...], *, repository_root: str) -> CitationContext:
    """Allowlist explicit producer IDs from known evidence arrays, never free text."""
    by_location = {span.location: span.evidence_id for span in spans}
    records = []
    seen = set()
    duplicates = set()
    for collection, prefix in _COLLECTION_PREFIXES.items():
        entries = payload.get(collection, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            identity = entry.get("id")
            if not isinstance(identity, str) or not _ID.fullmatch(identity) or not identity.startswith(prefix + ":"):
                continue
            if identity in seen:
                duplicates.add(identity)
                continue
            seen.add(identity)
            sources = set()
            locations = entry.get("locations", [])
            if isinstance(locations, list):
                for location in locations:
                    if isinstance(location, dict) and isinstance(location.get("file"), str) and type(location.get("line")) is int:
                        key = f"{location['file']}:{location['line']}"
                        if key in by_location:
                            sources.add(by_location[key])
            for key in ("sink", "evidence"):
                values = entry.get(key, [])
                if isinstance(values, str):
                    values = [values]
                if isinstance(values, list):
                    for value in values:
                        if isinstance(value, str):
                            sources.update(by_location[token] for token in reference_tokens(value) if token in by_location)
            records.append(EvidenceReference(identity, _json_digest(entry), tuple(sorted(sources))))
    # Duplicate IDs are ambiguous even if their first occurrence looked valid.
    return CitationContext(str(Path(repository_root).absolute()),
        tuple(ref for ref in records if ref.evidence_id not in duplicates), spans,
        json.dumps(payload, sort_keys=True, ensure_ascii=True))


@dataclass(frozen=True)
class CitationValidation:
    reference_validity: Literal["valid", "invalid", "missing"]
    valid_references: tuple[str, ...]
    invalid_references: tuple[str, ...]
    source_spans: tuple[SourceSpan, ...]
    claim_support: Literal["not_assessed"] = "not_assessed"

    @property
    def source_reference_valid(self) -> bool:
        return self.reference_validity == "valid" and bool(self.source_spans)


def validate_references(text: str, context: CitationContext) -> CitationValidation:
    records = {record.evidence_id: record for record in context.records}
    spans = {span.evidence_id: span for span in context.spans}
    locations = {key: span for span in context.spans for key in (span.location, span.span_location)}
    valid, invalid, resolved = [], [], {}
    for token in reference_tokens(text):
        if token in records:
            valid.append(token)
            for source_id in records[token].source_ids:
                if source_id in spans:
                    resolved[source_id] = spans[source_id]
        elif token in spans or token in locations:
            span = spans.get(token) or locations[token]
            valid.append(token)
            resolved[span.evidence_id] = span
        else:
            location = _LOCATION.fullmatch(token)
            if (token.lower().startswith(tuple(prefix + ":" for prefix in _COLLECTION_PREFIXES.values()))
                    or token.lower().startswith("source:") or _looks_like_location(token)
                    or (location and any(c in location["path"] for c in "/."))):
                invalid.append(token)
    return CitationValidation("invalid" if invalid else "valid" if valid else "missing",
                              tuple(valid), tuple(invalid), tuple(resolved.values()))


# --- Claim support (AM016) -------------------------------------------------
#
# Reference validity and claim support stay separate. Support is a closed set:
# "supported_by_cited_evidence" is issued only when a deterministic token check
# passes — a captured span bound to a reference the claim cites contains an
# identifier, route, or secret-kind term the claim itself names. Everything
# else stays "not_assessed"; no state ever asserts a claim is false, and no
# reference can become "supported" merely by being valid.

ClaimSupport = Literal["supported_by_cited_evidence", "not_assessed"]

# Closed vocabulary of secret kinds a claim may name in plain prose.
_SECRET_KIND_TERMS = frozenset({
    "password", "passwd", "passphrase", "secret", "secrets", "token", "tokens",
    "credential", "credentials", "apikey",
})
# Verdict/assessment/review vocabulary. A claim quoting these names an
# assessment state or review label, never an identifier of the analyzed
# system, so hostile text printing them cannot manufacture support.
_NON_TERM_WORDS = frozenset({
    "confirmed", "refuted", "proven", "proves", "verified", "verifies",
    "guaranteed", "guarantees", "supported", "unsupported", "valid", "invalid",
    "supported_by_cited_evidence", "not_assessed", "needs_review", "verdict",
    "verdicts", "hypothesis", "hypotheses", "true", "false", "safe", "unsafe",
    "vulnerable", "exploitable", "compromised", "observed", "inferred",
    "unverified", "static", "runtime", "source", "sink", "evidence", "finding",
    "findings", "surface", "citation", "citations", "reference", "references",
    "assessment", "model", "human", "review", "risk", "severity", "priority",
    "critical", "exploit", "secure", "attack",
})
_QUOTED_TERM = re.compile(r"`([^`\n]{2,64})`|\"([^\"\n]{2,64})\"|'([^'\s]{2,64})'")
_CLAIM_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_CLAIM_ROUTE = re.compile(r"(?<![\w/-])/[A-Za-z0-9_\-./{}]{2,96}")


def _is_reference_shaped(token: str) -> bool:
    return bool(_ID.fullmatch(token) or token.startswith("source:")
                or _LOCATION.fullmatch(token) or _looks_like_location(token))


def claim_terms(claim: str) -> tuple[str, ...]:
    """Deterministic distinctive terms a claim names: quoted literals, routes,
    secret-kind words, and code-shaped identifiers (underscore, dot, digit,
    camelCase, or a short uppercase acronym). Generic prose and review
    vocabulary never qualify, so an ordinary sentence cannot gain support by
    matching common words."""
    terms: list[str] = []
    for match in _QUOTED_TERM.finditer(claim):
        for group in match.groups():
            value = (group or "").strip()
            if (len(value) >= 3 and any(character.isalnum() for character in value)
                    and not _is_reference_shaped(value)):
                terms.append(value)
    for match in _CLAIM_ROUTE.finditer(claim):
        route = match.group(0).rstrip(".,;:")
        if any(character.isalpha() for character in route):
            terms.append(route)
    for match in _CLAIM_WORD.finditer(claim):
        token = match.group(0).rstrip(".")
        lowered = token.lower()
        if len(token) < 3 or _is_reference_shaped(token) or lowered in _NON_TERM_WORDS:
            continue
        letters = [character for character in token if character.isalpha()]
        if len(token) >= 4 and ("_" in token or "." in token or any(character.isdigit() for character in token)):
            terms.append(token)  # code-shaped: request.args, api_key, base64
        elif letters and token.isupper():
            if len(token) <= 8:
                terms.append(token)  # acronym constant: JWT, SSRF, XRPC
        elif any(token[index].isupper() for index in range(1, len(token))) and any(character.islower() for character in letters):
            terms.append(token)  # camelCase identifier: runRequest
        elif lowered in _SECRET_KIND_TERMS:
            terms.append(token)
    return tuple(dict.fromkeys(terms))


def matched_claim_terms(claim: str, evidence_text: str) -> tuple[str, ...]:
    """Terms the claim names that occur in the cited evidence text. Case
    sensitive and boundary checked, so substrings and case variants of an
    identifier never count as a match."""
    matched = []
    for term in claim_terms(claim):
        if re.search(rf"(?<![\w.]){re.escape(term)}(?![\w.])", evidence_text):
            matched.append(term)
    return tuple(matched)


@dataclass(frozen=True)
class ClaimSupportAssessment:
    reference: str
    claim_support: ClaimSupport
    matched_terms: tuple[str, ...] = ()

    def metadata(self) -> dict:
        return {"reference": self.reference, "claim_support": self.claim_support,
                "matched_terms": list(self.matched_terms)}


def assess_claim_support(claim: str, context: CitationContext) -> tuple[ClaimSupportAssessment, ...]:
    """Closed-set claim-support assessment for each valid reference in a claim.

    "supported_by_cited_evidence" requires a captured span bound to the cited
    reference to contain a term the claim names. Valid references without a
    captured span, claims naming no checkable term, and missing matches all
    stay "not_assessed" — absence of a token match is never treated as
    disproof, and support assertions inside analyzed files are ignored because
    assessment vocabulary cannot be a claim term.
    """
    records = {record.evidence_id: record for record in context.records}
    spans = {span.evidence_id: span for span in context.spans}
    locations = {key: span for span in context.spans for key in (span.location, span.span_location)}
    out = []
    for token in validate_references(claim, context).valid_references:
        bound: list[SourceSpan] = []
        if token in records:
            bound = [spans[source_id] for source_id in records[token].source_ids if source_id in spans]
        elif token in spans:
            bound = [spans[token]]
        elif token in locations:
            bound = [locations[token]]
        matched = matched_claim_terms(claim, "\n".join(span.excerpt for span in bound)) if bound else ()
        out.append(ClaimSupportAssessment(token,
            "supported_by_cited_evidence" if matched else "not_assessed", matched))
    return tuple(out)


def claim_support_state(assessments: Iterable[ClaimSupportAssessment]) -> ClaimSupport:
    """Overall closed-set state: supported only when at least one cited
    reference's deterministic token check passed."""
    return ("supported_by_cited_evidence"
            if any(item.claim_support == "supported_by_cited_evidence" for item in assessments)
            else "not_assessed")


_context: ContextVar[CitationContext | None] = ContextVar("attackmap_citation_context", default=None)


def current_citation_context() -> CitationContext | None:
    return _context.get()


@contextmanager
def citation_scope(context: CitationContext) -> Iterator[None]:
    token = _context.set(context)
    try:
        yield
    finally:
        _context.reset(token)
