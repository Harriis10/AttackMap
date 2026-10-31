"""Auditable source-only WP033 campaign; no provider, GUI or performance claim.

Each seed is an independent warm-cache sequence with three generated mutations.
The built-in source-upgrade case changes disposable identity bytes and the real
declared producer version; it does not pretend to install a different plugin.
Set ATTACKMAP_WP033_EVIDENCE_DIR to retain per-seed comparison records.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from pathlib import Path

import pytest

import attackmap
import attackmap.incremental as cache_mod
import attackmap.scanner as scanner_mod
from attackmap.analyzers import (
    BuiltinConfigAnalyzer,
    BuiltinJavaScriptWebAnalyzer,
    BuiltinPythonWebAnalyzer,
    analyze_repository,
)
from attackmap.index import RepoIndex, clear_pinned_index
from attackmap.recon_to_analysis import translate_recon

SEED_BASE = 2026103100
MUTATIONS = ("edit", "add", "rename", "delete", "dependency", "config",
             "policy", "analyzer_upgrade", "corruption")


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sha(value) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _app(route: str) -> str:
    return (
        "from flask import Blueprint, request\nimport hashlib\nimport requests\n"
        "bp = Blueprint('api', __name__)\n"
        f"@bp.route('{route}', methods=['GET'])\n"
        "def handle(item_id=None):\n"
        "    requests.get('https://internal.example.com/list')\n"
        "    engine = create_engine('postgresql://u:p@h/db')\n"
        "    digest = hashlib.md5(b'password')\n"
        "    cursor.execute('SELECT * FROM items WHERE id = %s' % item_id)\n"
        "    return []\n"
    )


def _seed(repo: Path, sequence: int) -> dict:
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src/app.py").write_text(_app(f"/items/{sequence}/<item_id>"), encoding="utf-8")
    (repo / "src/spare.py").write_text(_app(f"/spare/{sequence}"), encoding="utf-8")
    (repo / "src/worker.js").write_text(
        "const express = require('express');\nconst router = express.Router();\n"
        "router.post('/hooks', (req, res) => {\n"
        "  Object.assign(config, req.body);\n"
        "  require('crypto').createHash('md5').update(password);\n"
        "  res.end();\n});\n", encoding="utf-8")
    (repo / "tests/test_api.py").write_text(_app("/fixture-only"), encoding="utf-8")
    (repo / "package.json").write_text(_canonical({
        "name": f"wp033-{sequence}", "dependencies": {"express": "^4.18.0"}}), encoding="utf-8")
    (repo / "config.yaml").write_text("database: postgresql://db.example.com/app\n", encoding="utf-8")
    return {"spare": "src/spare.py", "sequence": sequence}


def _record(name: str, value: dict) -> None:
    requested = os.environ.get("ATTACKMAP_WP033_EVIDENCE_DIR")
    if requested:
        output = Path(requested).resolve()
        output.mkdir(parents=True, exist_ok=True)
        (output / f"{name}.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _identity_copy(tmp_path: Path, monkeypatch) -> Path:
    """Do not mutate production extractor files to exercise source identities."""
    source = Path(attackmap.__file__).parent
    package = tmp_path / "identity-only" / "attackmap"
    for module in cache_mod._ENGINE_MODULES:
        target = package / f"{module}.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / f"{module}.py").read_bytes())
    monkeypatch.setattr(attackmap, "__file__", str(package / "__init__.py"))
    return package


def _run(repo: Path, incremental: bool):
    index = RepoIndex.build(repo)
    scan = analyze_repository(repo, analyzers=[BuiltinPythonWebAnalyzer(),
        BuiltinJavaScriptWebAnalyzer(), BuiltinConfigAnalyzer()],
        index=index, incremental=incremental, strict=True)
    analysis = translate_recon(scan, index=index)
    # The ledger contains wall-clock observations. Its deterministic signal
    # counts remain indirectly checked by the complete signals/scan comparison.
    value = {
        "scan": scan.model_dump(mode="json", exclude={"analyzer_run_ledger"}),
        "findings": [item.model_dump(mode="json") for item in analysis.findings],
        "attack_surfaces": [item.model_dump(mode="json") for item in analysis.attack_surfaces],
        "attack_paths": [item.model_dump(mode="json") for item in analysis.attack_paths],
        "provenance": [item.model_dump(mode="json") for item in scan.all_signals()],
    }
    assert value["findings"], "a parity campaign with no actual findings is vacuous"
    assert value["provenance"] and all(item["observation_id"] for item in value["provenance"])
    assert scan.scanned_files and scan.files_scanned == len(scan.scanned_files)
    assert not scan.analyzer_errors
    return value, scan


def _compare(repo: Path, calls: list[str], name: str) -> tuple[dict, object]:
    calls.clear()
    full, reference = _run(repo, False)
    full_calls = list(calls)
    assert full_calls, "full reference must execute real per-file extraction"
    calls.clear()
    incremental, result = _run(repo, True)
    fresh = list(calls)
    assert _canonical(full) == _canonical(incremental), name
    assert reference.scan_snapshot.snapshot_id == result.scan_snapshot.snapshot_id
    return {
        "checkpoint": name, "full_sha256": _sha(full), "incremental_sha256": _sha(incremental),
        "findings_sha256": _sha(full["findings"]), "provenance_sha256": _sha(full["provenance"]),
        "coverage_sha256": _sha(full["scan"]["scanned_files"]),
        "findings": len(full["findings"]), "observations": len(full["provenance"]),
        "scanned_files": list(result.scanned_files), "snapshot_id": result.scan_snapshot.snapshot_id,
        "full_extractor_calls": full_calls, "incremental_extractor_calls": fresh,
    }, result


def _mutate(kind: str, repo: Path, cache: Path, state: dict, step: int, monkeypatch) -> dict:
    sequence = state["sequence"]
    suffix = f"{sequence}-{step}"
    details = {"kind": kind, "step": step}
    if kind == "edit":
        (repo / "src/app.py").write_text(_app(f"/changed/{suffix}/<item_id>"), encoding="utf-8")
    elif kind == "add":
        (repo / f"src/added{step}.py").write_text(_app(f"/added/{suffix}"), encoding="utf-8")
    elif kind == "rename":
        old = state["spare"]
        if not (repo / old).exists():
            (repo / old).write_text(_app(f"/spare-restored/{suffix}"), encoding="utf-8")
        new = f"src/renamed{step}.py"
        (repo / old).rename(repo / new)
        state["spare"] = new
        details.update(old=old, new=new)
    elif kind == "delete":
        path = repo / state["spare"]
        assert path.is_file()
        path.unlink()
        details["deleted"] = state["spare"]
    elif kind == "dependency":
        package = json.loads((repo / "package.json").read_text(encoding="utf-8"))
        dependency = f"wp033-dependency-{sequence}"
        package["dependencies"][dependency] = f"1.{step}.0"
        (repo / "package.json").write_text(_canonical(package), encoding="utf-8")
        details["dependency"] = dependency
    elif kind == "config":
        (repo / "config.yaml").write_text(f"cache: redis://cache-{suffix}.example.com:6379/0\n", encoding="utf-8")
    elif kind == "policy":
        monkeypatch.setenv("ATTACKMAP_INCLUDE_TESTS", "1")
        details["policy"] = "ATTACKMAP_INCLUDE_TESTS=1"
    elif kind == "analyzer_upgrade":
        before = cache_mod.engine_identity()
        package = _identity_copy(cache.parent, monkeypatch)
        target = package / "analyzers.py"
        with target.open("a", encoding="utf-8") as stream:
            stream.write(f"\n# WP033 disposable source identity upgrade {suffix}\n")
        monkeypatch.setattr(BuiltinPythonWebAnalyzer, "metadata",
            BuiltinPythonWebAnalyzer.metadata.model_copy(update={"version": f"wp033.{sequence}.{step}"}))
        after = cache_mod.engine_identity()
        assert before != after
        details.update(old_engine=before, new_engine=after,
            qualification="disposable source-byte identity plus actual declared producer-version change; no plugin installation")
    elif kind == "corruption":
        document = json.loads(cache.read_text(encoding="utf-8"))
        assert document["entries"]
        mode = (sequence // len(MUTATIONS)) % 4
        details["corruption"] = ("truncated_json", "foreign_schema", "bad_checksum", "invalid_payload")[mode]
        if mode == 0:
            cache.write_text('{"schema":', encoding="utf-8")
        else:
            if mode == 1:
                document["schema"] = "attackmap-incremental/foreign"
            else:
                # Corrupt every current entry so a recompute is measurable.
                for entry in document["entries"].values():
                    if mode == 2:
                        entry["checksum"] = "0" * 64
                    else:
                        entry["payload"]["routes"] = "invalid-list"
                        entry["checksum"] = hashlib.sha256(_canonical(entry["payload"]).encode()).hexdigest()
            cache.write_text(_canonical(document), encoding="utf-8")
    return details


@pytest.mark.parametrize("sequence", range(100), ids=lambda value: f"seed-{SEED_BASE + value}")
def test_wp033_generated_full_incremental_sequences(tmp_path: Path, monkeypatch, sequence: int) -> None:
    for name in (*cache_mod._POLICY_ENV, cache_mod.INCREMENTAL_ENV,
                 "ATTACKMAP_INDEX_BYTE_BUDGET", "ATTACKMAP_INDEX_FILE_LIMIT", "ATTACKMAP_MAX_FILE_BYTES"):
        monkeypatch.delenv(name, raising=False)
    repo = tmp_path / "repo"
    state = _seed(repo, sequence)
    cache = tmp_path / "cache" / "per-file-cache.json"
    monkeypatch.setattr(cache_mod, "default_cache_dir", lambda root: cache.parent)
    calls = []
    original = scanner_mod._analyze_indexed_file

    def counted(item):
        calls.append(item.rel)
        return original(item)

    monkeypatch.setattr(scanner_mod, "_analyze_indexed_file", counted)
    rng = random.Random(SEED_BASE + sequence)
    first = MUTATIONS[sequence % len(MUTATIONS)]
    others = rng.sample([item for item in MUTATIONS if item != first], 2)
    mutations = [first, *others]
    audit = {"sequence": sequence, "seed": SEED_BASE + sequence, "mutations": mutations,
             "runtime_engine_identity": cache_mod.engine_identity(), "checkpoints": []}
    try:
        cold, _ = _compare(repo, calls, "cold")
        assert cold["incremental_extractor_calls"] == cold["full_extractor_calls"]
        audit["checkpoints"].append(cold)
        warm, _ = _compare(repo, calls, "warm")
        assert warm["incremental_extractor_calls"] == [], "equal results alone do not prove warm reuse"
        audit["checkpoints"].append(warm)
        previous_snapshot = warm["snapshot_id"]
        for step, kind in enumerate(mutations, 1):
            mutation = _mutate(kind, repo, cache, state, step, monkeypatch)
            checkpoint, scan = _compare(repo, calls, f"mutation-{step}-{kind}")
            checkpoint["mutation"] = mutation
            if kind in {"corruption", "analyzer_upgrade", "policy"}:
                assert checkpoint["incremental_extractor_calls"], f"{kind} must cause real cache misses"
            if kind in {"edit", "add", "rename", "delete", "dependency", "config"}:
                assert checkpoint["snapshot_id"] != previous_snapshot
            if kind == "dependency":
                assert mutation["dependency"] in {item.name for item in scan.dependencies}
            elif kind == "config":
                assert any(item.kind == "redis" and item.file == "config.yaml" for item in scan.databases)
                assert not any(item.kind == "postgresql" and item.file == "config.yaml" for item in scan.databases)
            elif kind == "policy":
                assert any(item.file == "tests/test_api.py" for item in scan.routes)
            elif kind in {"rename", "delete"}:
                gone = mutation.get("old", mutation.get("deleted"))
                assert gone not in scan.scanned_files
                assert not any(item.file == gone for item in scan.all_signals())
            elif kind == "analyzer_upgrade":
                assert len(checkpoint["incremental_extractor_calls"]) == len(checkpoint["full_extractor_calls"])
                assert any(origin.analyzer_version == f"wp033.{sequence}.{step}"
                    for item in scan.all_signals() for origin in item.origins)
            previous_snapshot = checkpoint["snapshot_id"]
            audit["checkpoints"].append(checkpoint)
        final, _ = _compare(repo, calls, "final-warm")
        assert final["incremental_extractor_calls"] == []
        audit["checkpoints"].append(final)
        audit["status"] = "PASS"
    finally:
        clear_pinned_index()
        _record(f"sequence-{sequence:03d}", audit)
