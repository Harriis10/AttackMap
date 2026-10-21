"""Safe per-file analysis cache for incremental scans (C34/AM048).

The cache is strictly an optimization: a stored entry replays the per-file
extraction ``scanner.scan_files`` would have produced, and ANY doubt —
missing file, unreadable JSON, foreign schema, tampered payload, stale
key material — degrades to a full recompute of that file. Correctness
never depends on the cache being present or intact.

Cache identity (roadmap C34): an entry is reusable only when the file's
content sha256, its suffix, the analyzer set + versions that produce
per-file results, the per-file pass configuration and the source-role
policy are all unchanged. Anything that changes per-file output must
invalidate the entry, so each of those is part of the key.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Bump when the cache file layout or key material changes: existing files
# with a different schema string are discarded wholesale (safe recompute).
CACHE_SCHEMA = "attackmap-incremental/1.0"

# Low-level activation knob for the per-file cache. The CLI ``--incremental``
# flag sets it for one run (fleet worker subprocesses inherit it); it can
# also be set directly, like the other ATTACKMAP_* scan-time knobs.
INCREMENTAL_ENV = "ATTACKMAP_INCREMENTAL"

# Eviction bound (C34/AM048 remainder): the current generation keeps at most
# MAX_CACHE_ENTRIES entries; older entries (by persisted insertion sequence)
# are dropped first at insert time. Entries are keyed per (content, pass,
# policy, engine), so every repo edit mints a NEW entry — without a bound the
# single JSON file would grow with each edit across runs. 50k entries sits far
# above the largest reference corpus (juice-shop ≈ 2k files) while keeping
# load/save cheap; since every scanned file is read on every run, insertion
# order and last-use order coincide in practice.
MAX_CACHE_ENTRIES = 50_000

# Environment knobs that change per-file output at scan time without any
# code change: source-role classification gates routes and the weakness
# passes (srcpaths.is_test_file / is_vendored_file).
_POLICY_ENV = ("ATTACKMAP_INCLUDE_TESTS", "ATTACKMAP_INCLUDE_VENDORED")

# The modules whose code (including declared analyzer versions, which live
# in analyzers.py) produces per-file signals. Hashed at cache-open time so
# any edit to extraction logic, detection rules or analyzer metadata
# versions invalidates every entry — the honest engine-level form of
# "analyzer set + versions" for the built-in per-file pass.
_ENGINE_MODULES = (
    "scanner",
    "analyzers",
    "ecosystem_php",
    "analyzer_contracts",
    "weaknesses",
    "crypto",
    "webhardening",
    "srcpaths",
    "redact",
    "models",
    "sdk/models",
    "recon_models",
    "incremental",
)

# Payload families: cached key -> model class used to validate on replay.
PAYLOAD_MODELS: dict[str, type] = {}


def _register_models() -> None:
    if PAYLOAD_MODELS:
        return
    from .models import (
        AuthHint,
        CodeWeakness,
        CryptoWeakness,
        DatabaseHint,
        ExternalCall,
        Route,
        SecretHint,
        WebHardeningIssue,
    )
    PAYLOAD_MODELS.update({
        "routes": Route,
        "external_calls": ExternalCall,
        "databases": DatabaseHint,
        "auth_hints": AuthHint,
        "secret_hints": SecretHint,
        "crypto_weaknesses": CryptoWeakness,
        "web_hardening_issues": WebHardeningIssue,
        "code_weaknesses": CodeWeakness,
    })


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def engine_identity() -> str:
    """Content hash of every module that contributes per-file results."""
    import attackmap
    import pydantic

    parts: list[str] = [CACHE_SCHEMA, f"python:{sys.version}", f"pydantic:{pydantic.__version__}"]
    package = Path(attackmap.__file__).parent
    for name in _ENGINE_MODULES:
        path = package / f"{name}.py"
        try:
            parts.append(f"{name}:{hashlib.sha256(path.read_bytes()).hexdigest()}")
        except OSError as exc:
            # Frozen/source-less installs need a separately verified code identity.
            # A stable placeholder would incorrectly replay entries after upgrades.
            raise OSError(f"Cannot prove incremental extractor identity: {name}") from exc
    return _sha256(_canonical(parts))


def source_policy_identity() -> str:
    """Identity of the env-driven source-role policy in effect right now."""
    return _sha256(_canonical({name: os.environ.get(name, "") for name in _POLICY_ENV}))


def enabled_by_env() -> bool:
    """Whether per-file cache activation is requested via ``ATTACKMAP_INCREMENTAL=1``."""
    return os.environ.get(INCREMENTAL_ENV, "") == "1"


@dataclass(frozen=True)
class FileCacheKey:
    """Everything a per-file cache entry's validity depends on."""

    rel: str
    suffix: str
    content_sha256: str
    pass_suffixes: frozenset[str] | None
    engine: str
    policy: str

    def identity(self) -> str:
        pass_id = None if self.pass_suffixes is None else sorted(self.pass_suffixes)
        return _sha256(_canonical([
            CACHE_SCHEMA, self.engine, self.policy, pass_id,
            self.rel, self.suffix, self.content_sha256,
        ]))


class PerFileCache:
    """A single-JSON per-file result cache. Optimization only, never a
    correctness dependency: every read path that cannot prove an entry
    fresh and intact returns a miss, and the caller recomputes.

    Storage choice: one JSON file, written atomically (temp file +
    ``os.replace``). Stdlib-only, trivially inspectable, and the whole-file
    write removes partial-state concerns at this corpus scale; SQLite
    (also stdlib) would add a second schema and concurrency story with no
    correctness gain — noted as the follow-up if corpora grow large
    enough that load/save time matters.
    """

    def __init__(self, path: Path, *, engine: str, policy: str,
                 max_entries: int | None = None) -> None:
        self.path = Path(path)
        self.engine = engine
        self.policy = policy
        # Entries of the current generation only survive save(); older
        # engine/policy generations are dropped so the file cannot grow
        # without bound across upgrades.
        self.generation = _sha256(_canonical([CACHE_SCHEMA, engine, policy]))
        self.max_entries = MAX_CACHE_ENTRIES if max_entries is None else max(1, int(max_entries))
        self._entries: dict[str, dict] = self._load()
        # Insertion sequence for eviction order; continues across runs so an
        # entry's age survives reopen. Entries from an older layout without a
        # "seq" count as the oldest possible.
        seqs = [entry.get("seq") for entry in self._entries.values()]
        self._seq = max((s for s in seqs if isinstance(s, int) and s >= 0), default=0)
        self._dirty = False
        # Reopening restores the bound even for a file written under a larger
        # one (e.g. after MAX_CACHE_ENTRIES is lowered, or max_entries passed).
        self._evict_to_bound()

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def open(cls, path: str | Path, *, engine: str | None = None,
             policy: str | None = None, max_entries: int | None = None) -> "PerFileCache":
        return cls(
            Path(path),
            engine=engine if engine is not None else engine_identity(),
            policy=policy if policy is not None else source_policy_identity(),
            max_entries=max_entries,
        )

    def _load(self) -> dict[str, dict]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict) or raw.get("schema") != CACHE_SCHEMA:
            return {}
        entries = raw.get("entries")
        if not isinstance(entries, dict):
            return {}
        # Keep only well-formed entries of our own generation; anything
        # else is stale by construction.
        return {
            str(key): entry for key, entry in entries.items()
            if isinstance(entry, dict) and entry.get("gen") == self.generation
        }

    def save(self) -> bool:
        """Atomically persist current-generation entries. Best effort."""
        if not self._dirty:
            return True
        document = {"schema": CACHE_SCHEMA, "generation": self.generation, "entries": self._entries}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(document, ensure_ascii=True, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            return False
        self._dirty = False
        return True

    # -- entry access ------------------------------------------------------

    def get(self, key: FileCacheKey) -> dict | None:
        """The cached payload for ``key``, or None (recompute) on any doubt."""
        entry = self._entries.get(key.identity())
        if not isinstance(entry, dict):
            return None
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            return None
        if entry.get("checksum") != _sha256(_canonical(payload)):
            return None  # tampered or corrupt payload
        if not _payload_shape_ok(payload):
            return None
        return payload

    def put(self, key: FileCacheKey, payload: dict) -> None:
        self._seq += 1
        self._entries[key.identity()] = {
            "gen": self.generation,
            "seq": self._seq,
            "payload": payload,
            "checksum": _sha256(_canonical(payload)),
        }
        self._dirty = True
        self._evict_to_bound()

    def _evict_to_bound(self) -> None:
        """Drop the oldest-inserted entries beyond ``max_entries``."""
        excess = len(self._entries) - self.max_entries
        if excess <= 0:
            return
        oldest = sorted(self._entries.items(), key=lambda kv: kv[1].get("seq") or 0)
        for identity, _entry in oldest[:excess]:
            del self._entries[identity]
        self._dirty = True

    @property
    def entry_count(self) -> int:
        return len(self._entries)


def _payload_shape_ok(payload: dict) -> bool:
    """Structural check before model validation (cheap miss gate)."""
    if not isinstance(payload.get("csrf_protected"), bool):
        return False
    _register_models()
    for family, model in PAYLOAD_MODELS.items():
        items = payload.get(family)
        if not isinstance(items, list):
            return False
        for item in items:
            if not isinstance(item, dict):
                return False
            try:
                model.model_validate(item)
            except Exception:
                return False
    return True


def dump_payload(signals: dict[str, list], csrf_protected: bool) -> dict:
    """Serialize one file's extraction output for storage."""
    _register_models()
    payload: dict[str, object] = {
        family: [item.model_dump() for item in signals.get(family, [])]
        for family in PAYLOAD_MODELS
    }
    payload["csrf_protected"] = bool(csrf_protected)
    return payload


def load_payload(payload: dict) -> tuple[dict[str, list], bool] | None:
    """Validate and rebuild one file's cached output, or None on any error."""
    _register_models()
    rebuilt: dict[str, list] = {}
    for family, model in PAYLOAD_MODELS.items():
        items = payload.get(family)
        if not isinstance(items, list):
            return None
        try:
            rebuilt[family] = [model.model_validate(item) for item in items]
        except Exception:
            return None
    csrf = payload.get("csrf_protected")
    if not isinstance(csrf, bool):
        return None
    return rebuilt, csrf


def default_cache_dir(root: str | Path) -> Path | None:
    """A per-repository cache location outside the analyzed repository.

    Derived under the system temp dir, keyed by the resolved repo root. If
    the repo itself lives somewhere that makes the derived path fall inside
    it (a repo under %TMP%), returns None: caching disables rather than
    ever writing an artifact into the scanned tree.
    """
    try:
        root_path = Path(root).resolve()
    except OSError:
        return None
    digest = _sha256(str(root_path))[:16]
    candidate = Path(tempfile.gettempdir()) / "attackmap-incremental" / digest
    try:
        candidate_resolved = candidate.resolve()
        root_resolved = root_path.resolve()
    except OSError:
        return None
    if candidate_resolved == root_resolved or root_resolved in candidate_resolved.parents:
        return None  # would land inside the scanned repo
    return candidate_resolved
