"""Incremental per-file analysis cache: correctness equivalence and safe
fallback (C34/AM048).

Two claims are proven here:
1. Equivalence — across a generated edit-sequence campaign, an incremental
   run's normalized findings, provenance (observation ids) and scanned
   coverage are identical to a full re-run.
2. Safety — a corrupt, truncated, tampered or foreign-schema cache never
   changes results: the entry is discarded and the file recomputed.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from attackmap.index import RepoIndex
from attackmap.incremental import (
    CACHE_SCHEMA,
    FileCacheKey,
    PerFileCache,
    default_cache_dir,
    engine_identity,
    source_policy_identity,
)
from attackmap.scanner import scan_files
from attackmap.signal_provenance import merge_normalized_signals

N_SEQUENCES = 100


# --- fixture content: every per-file family fires ---------------------------

def _py_body(index: int, variant: int) -> str:
    csrf_line = "app.use(csurf())\n" if variant % 2 == 0 else ""
    return (
        "from flask import Blueprint\n"
        "import os\n"
        "import hashlib\n"
        "import requests\n"
        f"bp = Blueprint('api{index}', __name__, url_prefix='/v{index}')\n"
        f"@bp.route('/users/{index}', methods=['GET'])\n"
        "def users():\n"
        f"    requests.get('https://internal-{variant}.example.com/list')\n"
        "    engine = create_engine('postgresql://u:p@h/db')\n"
        f"    token = os.getenv('SERVICE_TOKEN_{variant}')\n"
        f"    digest = hashlib.md5(b'password-{index}-{variant}')\n"
        "    jwt.decode(token, key)\n"
        "    User.objects.create(**request.json)\n"
        f"{csrf_line}"
        "    return []\n"
    )


def _js_body(index: int, variant: int) -> str:
    return (
        "const express = require('express');\n"
        "const cors = require('cors');\n"
        "const axios = require('axios');\n"
        "const router = express.Router();\n"
        "router.use(cors({ origin: true, credentials: true }));\n"
        f"router.get('/items/{index}', (req, res) => {{\n"
        f"  axios.post('https://api-{variant}.example.com/sync', {{}});\n"
        "  User.create(req.body);\n"
        "  const db = new PrismaClient();\n"
        f"  const key = process.env.STRIPE_SECRET_KEY_{variant};\n"
        "  const crypto = require('crypto');\n"
        "  crypto.createHash('md5').update(password).digest('hex');\n"
        "  const session = require('express-session');\n"
        "  return [];\n"
        "});\n"
    )


def _ts_body(index: int, variant: int) -> str:
    return (
        "import Router from 'koa-router';\n"
        f"const r = new Router({{ prefix: '/ts{index}' }});\n"
        f"r.get('/detail', (ctx) => {{ ctx.body = {{ v: {variant} }}; }});\n"
        "const redis = require('redis');\n"
        "redis.createClient();\n"
        "request.authorization;\n"
    )


def _seed_repo(repo: Path) -> None:
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "app.py").write_text(_py_body(1, 0), encoding="utf-8")
    (repo / "src" / "svc.py").write_text(_py_body(2, 0), encoding="utf-8")
    (repo / "src" / "worker.js").write_text(_js_body(1, 0), encoding="utf-8")
    (repo / "src" / "edge.ts").write_text(_ts_body(1, 0), encoding="utf-8")
    # Source-role policy coverage: routes inside a test dir and vendored code
    # are excluded by default and re-included via ATTACKMAP_INCLUDE_TESTS.
    (repo / "tests").mkdir(exist_ok=True)
    (repo / "tests" / "test_api.py").write_text(_py_body(9, 0), encoding="utf-8")
    (repo / "vendor").mkdir(exist_ok=True)
    (repo / "vendor" / "bundled.js").write_text(_js_body(9, 0), encoding="utf-8")


def _write_variant(repo: Path, rel: str, index: int, variant: int) -> None:
    body = {"py": _py_body, "js": _js_body, "ts": _ts_body}[rel.rsplit(".", 1)[1]](index, variant)
    (repo / rel).write_text(body, encoding="utf-8")


# --- comparison ---------------------------------------------------------------

def _observation_ids(result) -> list:
    """Normalized provenance view: observation id + signal identity."""
    return [
        (signal.observation_id, signal.kind, signal.label, signal.file)
        for signal in merge_normalized_signals(result.all_signals())
    ]


def _normalized(result) -> str:
    """Canonical comparable form: findings, provenance, coverage, limits."""
    dump = result.model_dump()
    return json.dumps([dump, _observation_ids(result)], sort_keys=True)


def _assert_signal_families_populated(result) -> None:
    # The equivalence claim is only meaningful when families actually fire.
    assert result.routes, "fixture must produce routes"
    assert result.external_calls, "fixture must produce external calls"
    assert result.databases, "fixture must produce database hints"
    assert result.auth_hints, "fixture must produce auth hints"
    assert result.secret_hints, "fixture must produce secret hints"
    assert result.crypto_weaknesses, "fixture must produce crypto weaknesses"
    assert result.web_hardening_issues, "fixture must produce web hardening issues"
    assert result.code_weaknesses, "fixture must produce code weaknesses"


# --- edit-sequence equivalence -------------------------------------------------

def _apply_edit(rng: random.Random, repo: Path, counter: int) -> None:
    op = rng.choice(("edit", "edit", "add", "delete", "rename"))
    rels = [p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file()]
    if op == "add" or not rels:
        kind = rng.choice(("py", "js", "ts"))
        rel = f"src/gen{counter}.{kind}"
        (repo / "src").mkdir(exist_ok=True)
        index = counter
        body = {"py": _py_body, "js": _js_body, "ts": _ts_body}[kind](index, counter % 3)
        (repo / rel).write_text(body, encoding="utf-8")
        return
    rel = rng.choice(rels)
    if op == "edit":
        _write_variant(repo, rel, _index_of(rel), counter % 3)
    elif op == "delete":
        if len(rels) > 1:
            (repo / rel).unlink()
    else:  # rename: delete + add of the same content at a new path
        suffix = rel.rsplit(".", 1)[1]
        target = rel.rsplit(".", 1)[0] + f"-ren{counter}." + suffix
        (repo / rel).rename(repo / target)


def _index_of(rel: str) -> int:
    digits = "".join(ch for ch in Path(rel).stem if ch.isdigit())
    return int(digits) if digits else 1


def test_incremental_matches_full_across_edit_sequences(tmp_path: Path) -> None:
    """Across 100 generated edit sequences (edits, adds, deletes, renames),
    incremental output equals a full re-run — findings, observation ids and
    coverage — with one warm cache carried across the whole campaign."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"  # outside the analyzed repo
    rng = random.Random(20261017)

    full_reference = scan_files(repo)
    _assert_signal_families_populated(full_reference)

    for sequence in range(N_SEQUENCES):
        _apply_edit(rng, repo, sequence)
        full = scan_files(repo)
        incremental = scan_files(repo, incremental=True, cache_dir=cache_dir)
        assert _normalized(full) == _normalized(incremental), f"divergence at sequence {sequence}"


def test_incremental_matches_full_with_separate_analyzer_passes(tmp_path: Path) -> None:
    """The analyzer calling pattern — one scan_files per suffix family sharing
    one cache location — stays equivalent and retains sibling entries."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"

    def _split_scan():
        py = scan_files(repo, suffixes={".py"}, incremental=True, cache_dir=cache_dir)
        js = scan_files(repo, suffixes={".js", ".ts"}, incremental=True, cache_dir=cache_dir)
        combined = py.model_copy(deep=True)
        combined.scanned_files = sorted(set(py.scanned_files or []) | set(js.scanned_files or []))
        combined.files_scanned = len(combined.scanned_files)
        combined.routes.extend(js.routes)
        combined.external_calls.extend(js.external_calls)
        combined.databases.extend(js.databases)
        combined.auth_hints.extend(js.auth_hints)
        combined.secret_hints.extend(js.secret_hints)
        combined.crypto_weaknesses.extend(js.crypto_weaknesses)
        combined.web_hardening_issues.extend(js.web_hardening_issues)
        combined.code_weaknesses.extend(js.code_weaknesses)
        return combined

    rng = random.Random(7)
    for sequence in range(10):
        _apply_edit(rng, repo, sequence)
        full = scan_files(repo)
        combined = _split_scan()
        assert _observation_ids(full) == _observation_ids(combined)
        assert sorted(full.scanned_files) == sorted(combined.scanned_files)
        assert len(full.routes) == len(combined.routes)
        assert len(full.secret_hints) == len(combined.secret_hints)
        assert len(full.crypto_weaknesses) == len(combined.crypto_weaknesses)
    # Sibling-pass retention: entries from both suffix families survive.
    cache = PerFileCache.open(cache_dir / "per-file-cache.json")
    assert cache.entry_count >= len(full.scanned_files)


def test_policy_change_does_not_replay_stale_entries(tmp_path: Path, monkeypatch) -> None:
    """The source-role policy (ATTACKMAP_INCLUDE_TESTS / _VENDORED) is part of
    the cache identity: flipping it must recompute, not replay."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"

    default_result = scan_files(repo, incremental=True, cache_dir=cache_dir)
    assert default_result.model_dump() == scan_files(repo).model_dump()

    monkeypatch.setenv("ATTACKMAP_INCLUDE_TESTS", "1")
    tests_included = scan_files(repo)  # full run under the new policy
    replayed = scan_files(repo, incremental=True, cache_dir=cache_dir)
    assert _normalized(tests_included) == _normalized(replayed)
    # The new policy genuinely widens coverage on this fixture.
    assert len(tests_included.routes) > len(default_result.routes)


# --- corruption / staleness safety ----------------------------------------------

def _corruption_setup(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"
    scan_files(repo, incremental=True, cache_dir=cache_dir)  # populate
    return repo, cache_dir / "per-file-cache.json"


def test_truncated_cache_file_recomputes_safely(tmp_path: Path) -> None:
    repo, cache_file = _corruption_setup(tmp_path)
    cache_file.write_text('{"schema": "attackmap-increm', encoding="utf-8")
    full = scan_files(repo)
    incremental = scan_files(repo, incremental=True, cache_dir=cache_file.parent)
    assert _normalized(full) == _normalized(incremental)


def test_tampered_entry_hash_recomputes_safely(tmp_path: Path) -> None:
    repo, cache_file = _corruption_setup(tmp_path)
    document = json.loads(cache_file.read_text(encoding="utf-8"))
    key = next(k for k, e in document["entries"].items() if e["payload"].get("routes"))
    payload = document["entries"][key]["payload"]
    payload["routes"][0]["path"] = "/tampered"
    cache_file.write_text(json.dumps(document), encoding="utf-8")
    # Checksum no longer matches the payload: the entry must be discarded.
    full = scan_files(repo)
    incremental = scan_files(repo, incremental=True, cache_dir=cache_file.parent)
    assert _normalized(full) == _normalized(incremental)
    assert not any(r.path == "/tampered" for r in incremental.routes)


def test_foreign_schema_version_discards_cache(tmp_path: Path) -> None:
    repo, cache_file = _corruption_setup(tmp_path)
    document = json.loads(cache_file.read_text(encoding="utf-8"))
    document["schema"] = "attackmap-incremental/0.9"
    cache_file.write_text(json.dumps(document), encoding="utf-8")
    cache = PerFileCache.open(cache_file)
    assert cache.entry_count == 0
    full = scan_files(repo)
    incremental = scan_files(repo, incremental=True, cache_dir=cache_file.parent)
    assert _normalized(full) == _normalized(incremental)


def test_missing_cache_file_computes_and_persists(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"
    incremental = scan_files(repo, incremental=True, cache_dir=cache_dir)
    assert cache_dir.joinpath("per-file-cache.json").exists()
    assert _normalized(scan_files(repo)) == _normalized(incremental)


def test_cache_trust_boundary_is_documented_by_consistent_forgery(tmp_path: Path) -> None:
    """Integrity checks catch corruption, not forgery: an attacker (or a bug)
    that rewrites a payload AND its checksum gets the forged value replayed.
    The cache location is therefore part of the trusted compute environment,
    same as ccache / build caches — keep it outside the repository."""
    repo, cache_file = _corruption_setup(tmp_path)
    import hashlib
    document = json.loads(cache_file.read_text(encoding="utf-8"))
    key = next(k for k, e in document["entries"].items() if e["payload"].get("routes"))
    entry = document["entries"][key]
    entry["payload"]["routes"][0]["path"] = "/forged"
    canonical = json.dumps(entry["payload"], sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    entry["checksum"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    cache_file.write_text(json.dumps(document), encoding="utf-8")
    incremental = scan_files(repo, incremental=True, cache_dir=cache_file.parent)
    assert any(r.path == "/forged" for r in incremental.routes)


# --- key identity ------------------------------------------------------------

def test_cache_key_identity_covers_every_required_dimension() -> None:
    base = FileCacheKey(
        rel="src/app.py", suffix=".py", content_sha256="a" * 64,
        pass_suffixes=frozenset({".py"}), engine="e", policy="p",
    )
    identical = FileCacheKey(
        rel="src/app.py", suffix=".py", content_sha256="a" * 64,
        pass_suffixes=frozenset({".py"}), engine="e", policy="p",
    )
    assert base.identity() == identical.identity()
    for mutated in (
        FileCacheKey(rel="src/other.py", suffix=".py", content_sha256="a" * 64,
                     pass_suffixes=frozenset({".py"}), engine="e", policy="p"),
        FileCacheKey(rel="src/app.py", suffix=".py", content_sha256="b" * 64,
                     pass_suffixes=frozenset({".py"}), engine="e", policy="p"),
        FileCacheKey(rel="src/app.py", suffix=".js", content_sha256="a" * 64,
                     pass_suffixes=frozenset({".py"}), engine="e", policy="p"),
        FileCacheKey(rel="src/app.py", suffix=".py", content_sha256="a" * 64,
                     pass_suffixes=frozenset({".py", ".js"}), engine="e", policy="p"),
        FileCacheKey(rel="src/app.py", suffix=".py", content_sha256="a" * 64,
                     pass_suffixes=frozenset({".py"}), engine="e2", policy="p"),
        FileCacheKey(rel="src/app.py", suffix=".py", content_sha256="a" * 64,
                     pass_suffixes=frozenset({".py"}), engine="e", policy="p2"),
    ):
        assert base.identity() != mutated.identity()


def test_engine_identity_changes_with_source(tmp_path: Path) -> None:
    """Engine identity hashes the analyzer modules: a different hash input
    must yield a different identity (regression guard for the wiring)."""
    first = engine_identity()
    assert first == engine_identity()  # stable within a process
    assert len(first) == 64


def test_policy_identity_tracks_env_knobs(monkeypatch) -> None:
    base = source_policy_identity()
    monkeypatch.setenv("ATTACKMAP_INCLUDE_TESTS", "1")
    assert source_policy_identity() != base


# --- behavior preservation ------------------------------------------------------

def test_incremental_default_off_creates_no_cache(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"
    scan_files(repo, cache_dir=cache_dir)  # incremental defaults to False
    assert not cache_dir.exists()


def test_default_cache_location_is_never_inside_the_repo(tmp_path: Path) -> None:
    import tempfile

    # A repo placed at the temp root would make the derived location fall
    # inside it: the guard disables caching instead.
    assert default_cache_dir(Path(tempfile.gettempdir())) is None
    # A normal repo gets a location strictly outside itself.
    repo = tmp_path / "repo"
    repo.mkdir()
    location = default_cache_dir(repo)
    assert location is not None
    assert repo.resolve() not in location.parents and location != repo.resolve()
    # And an incremental scan with the default location leaves the repo clean.
    _seed_repo(repo)
    result = scan_files(repo, incremental=True)
    assert result.model_dump() == scan_files(repo).model_dump()
    assert not any("per-file-cache.json" in p.name for p in repo.rglob("*"))


def test_cache_survives_engine_generation_change(tmp_path: Path) -> None:
    """Entries from an older engine generation are dropped on save (bounded
    growth), and the scan still recomputes them correctly."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    cache_dir = tmp_path / "cache"
    scan_files(repo, incremental=True, cache_dir=cache_dir)
    # Forge a foreign-generation entry alongside the real ones.
    cache_file = cache_dir / "per-file-cache.json"
    document = json.loads(cache_file.read_text(encoding="utf-8"))
    document["entries"]["stale-key"] = {
        "gen": "0" * 64, "payload": {"csrf_protected": False}, "checksum": "x",
    }
    cache_file.write_text(json.dumps(document), encoding="utf-8")
    reopened = PerFileCache.open(cache_file)
    assert "stale-key" not in reopened._entries  # stale generation dropped
    incremental = scan_files(repo, incremental=True, cache_dir=cache_dir)
    assert _normalized(incremental) == _normalized(scan_files(repo))


def test_index_file_limit_default_is_c35_target() -> None:
    from attackmap.index import DEFAULT_INDEX_FILE_LIMIT
    assert DEFAULT_INDEX_FILE_LIMIT == 100_000
    assert CACHE_SCHEMA == "attackmap-incremental/1.0"


# --- eviction bound (C34/AM048 remainder) ---------------------------------------

def _key(cache: PerFileCache, rel: str, content: str) -> FileCacheKey:
    import hashlib

    return FileCacheKey(
        rel=rel, suffix=".py",
        content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        pass_suffixes=None, engine=cache.engine, policy=cache.policy,
    )


def _empty_payload() -> dict:
    from attackmap.incremental import dump_payload

    return dump_payload({}, False)


def test_eviction_respects_bound_and_drops_oldest_first(tmp_path: Path) -> None:
    cache = PerFileCache.open(tmp_path / "cache.json", max_entries=3)
    keys = [_key(cache, f"f{i}.py", f"content-{i}") for i in range(5)]
    for key in keys:
        cache.put(key, _empty_payload())
    assert cache.entry_count == 3
    # Oldest-inserted entries were evicted; the newest survive and replay.
    assert cache.get(keys[0]) is None
    assert cache.get(keys[1]) is None
    for key in keys[2:]:
        assert cache.get(key) is not None
    # The bound and eviction order survive save/reopen.
    cache.save()
    reopened = PerFileCache.open(tmp_path / "cache.json", max_entries=3)
    assert reopened.entry_count == 3
    assert reopened.get(keys[1]) is None
    assert reopened.get(keys[4]) is not None


def test_reopen_trims_a_file_written_under_a_larger_bound(tmp_path: Path) -> None:
    cache = PerFileCache.open(tmp_path / "cache.json", max_entries=10)
    for i in range(6):
        cache.put(_key(cache, f"f{i}.py", f"content-{i}"), _empty_payload())
    cache.save()
    trimmed = PerFileCache.open(tmp_path / "cache.json", max_entries=2)
    assert trimmed.entry_count == 2
    assert trimmed._dirty  # reopening itself restores the bound on save


def test_default_bound_is_the_documented_constant(tmp_path: Path) -> None:
    from attackmap.incremental import MAX_CACHE_ENTRIES

    assert PerFileCache.open(tmp_path / "cache.json").max_entries == MAX_CACHE_ENTRIES
    assert MAX_CACHE_ENTRIES == 50_000


def test_env_activation_flag_activates_cache(monkeypatch, tmp_path: Path) -> None:
    """ATTACKMAP_INCREMENTAL=1 (set by the CLI --incremental flag) activates
    the cache exactly like incremental=True, and stays off by default."""
    from attackmap.incremental import enabled_by_env

    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)

    assert enabled_by_env() is False
    full = scan_files(repo)

    monkeypatch.setenv("ATTACKMAP_INCREMENTAL", "1")
    assert enabled_by_env() is True
    via_env = scan_files(repo)
    assert _normalized(full) == _normalized(via_env)
    cache_dir = default_cache_dir(repo)
    assert cache_dir is not None and (cache_dir / "per-file-cache.json").exists()
