"""CLI ``--incremental`` flag (C34/AM048 remainder).

Proves the user-facing contract of the per-file incremental cache:
  (a) flag OFF (default) -> no cache files are created anywhere;
  (b) flag ON twice      -> the second run replays cached entries (zero
                            fresh per-file computations) with identical
                            findings;
  (c) corrupt cache + ON -> safe recompute, identical findings, cache
                            rebuilt;
  plus fleet-worker argv propagation and env hygiene for the
  ATTACKMAP_INCREMENTAL activation knob the flag sets.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from typer.testing import CliRunner

import attackmap.scanner as scanner_mod
from attackmap import incremental
from attackmap.cli import app
from attackmap.incremental import default_cache_dir
from attackmap.scan_service import ScanRequest, _run_fleet_repo_argv

APP_PY = (
    "from flask import Blueprint\n"
    "import os\n"
    "import hashlib\n"
    "bp = Blueprint('api', __name__, url_prefix='/v1')\n"
    "@bp.route('/users/<user_id>', methods=['GET'])\n"
    "def users(user_id):\n"
    "    import requests\n"
    "    requests.get('https://internal.example.com/list')\n"
    "    engine = create_engine('postgresql://u:p@h/db')\n"
    "    token = os.getenv('SERVICE_TOKEN')\n"
    "    digest = hashlib.md5(b'password')\n"
    "    cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)\n"
    "    return []\n"
)

APP_JS = (
    "const express = require('express');\n"
    "const router = express.Router();\n"
    "router.post('/hooks', (req, res) => {\n"
    "  Object.assign(config, req.body);\n"
    "  const key = process.env.STRIPE_SECRET_KEY;\n"
    "  res.end();\n"
    "});\n"
)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text(APP_PY, encoding="utf-8")
    (repo / "src" / "hooks.js").write_text(APP_JS, encoding="utf-8")
    return repo


def _cache_file(repo: Path) -> Path:
    location = default_cache_dir(repo)
    assert location is not None, "fixture repo must get a default cache location"
    return location / "per-file-cache.json"


def _reset_cache(repo: Path) -> None:
    cache = _cache_file(repo)
    shutil.rmtree(cache.parent, ignore_errors=True)


def _analyze(repo: Path, out: Path, *extra: str):
    return CliRunner().invoke(
        app,
        ["analyze", str(repo), "-o", str(out), "--format", "json", "--no-progress", *extra],
    )


def _findings(out: Path) -> list:
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    return report.get("findings", [])


def _entry_count(cache: Path) -> int:
    document = json.loads(cache.read_text(encoding="utf-8"))
    return len(document.get("entries", {}))


# --- (a) default off ------------------------------------------------------------

def test_flag_off_creates_no_cache_and_is_stable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(incremental.INCREMENTAL_ENV, raising=False)
    repo = _repo(tmp_path)
    out = tmp_path / "out"
    cache = _cache_file(repo)
    _reset_cache(repo)

    first = _analyze(repo, out)
    assert first.exit_code == 0, first.output
    findings = _findings(out)
    assert findings, "fixture must produce findings for the identity checks"
    assert not cache.parent.exists(), "cache must stay off by default"

    second = _analyze(repo, out)
    assert second.exit_code == 0, second.output
    assert _findings(out) == findings
    assert not cache.parent.exists()


# --- (b) flag on, second run reuses entries --------------------------------------

def test_flag_on_twice_second_run_reuses_entries(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(incremental.INCREMENTAL_ENV, raising=False)
    repo = _repo(tmp_path)
    out = tmp_path / "out"
    cache = _cache_file(repo)
    _reset_cache(repo)

    calls = {"fresh": 0}
    real = scanner_mod._analyze_indexed_file

    def _counting(item):
        calls["fresh"] += 1
        return real(item)

    monkeypatch.setattr(scanner_mod, "_analyze_indexed_file", _counting)

    cold = _analyze(repo, out, "--incremental")
    assert cold.exit_code == 0, cold.output
    assert calls["fresh"] > 0, "cold run must compute every file freshly"
    assert cache.exists(), "--incremental must persist the default-location cache"
    warm_findings = _findings(out)
    assert warm_findings
    entries_after_cold = _entry_count(cache)

    calls["fresh"] = 0
    warm = _analyze(repo, out, "--incremental")
    assert warm.exit_code == 0, warm.output
    assert calls["fresh"] == 0, "unchanged files must replay from the cache, not recompute"
    assert _findings(out) == warm_findings
    assert _entry_count(cache) == entries_after_cold
    # And the accelerated findings equal the uncached run's findings.
    monkeypatch.undo()
    _reset_cache(repo)
    uncached = _analyze(repo, tmp_path / "out-uncached")
    assert uncached.exit_code == 0, uncached.output
    assert _findings(tmp_path / "out-uncached") == warm_findings


# --- (c) corrupt cache + flag on -> safe recompute -------------------------------

def test_corrupt_cache_with_flag_on_recomputes_safely(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(incremental.INCREMENTAL_ENV, raising=False)
    repo = _repo(tmp_path)
    out = tmp_path / "out"
    cache = _cache_file(repo)
    _reset_cache(repo)

    first = _analyze(repo, out, "--incremental")
    assert first.exit_code == 0, first.output
    findings = _findings(out)
    assert findings
    assert cache.exists()

    cache.write_text('{"schema": "attackmap-increm', encoding="utf-8")  # truncated garbage

    second = _analyze(repo, out, "--incremental")
    assert second.exit_code == 0, second.output
    assert _findings(out) == findings
    # The cache was rebuilt (valid JSON again, entries restored).
    assert _entry_count(cache) > 0


# --- activation knob hygiene ------------------------------------------------------

def test_flag_does_not_leak_activation_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(incremental.INCREMENTAL_ENV, raising=False)
    repo = _repo(tmp_path)
    result = _analyze(repo, tmp_path / "out", "--incremental")
    assert result.exit_code == 0, result.output
    assert os.environ.get(incremental.INCREMENTAL_ENV) is None, (
        "flag activation must not leak into later in-process invocations"
    )


def test_operator_env_activates_without_flag(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(incremental.INCREMENTAL_ENV, "1")
    repo = _repo(tmp_path)
    out = tmp_path / "out"
    _reset_cache(repo)
    result = _analyze(repo, out)  # no flag: the low-level knob still applies
    assert result.exit_code == 0, result.output
    assert _cache_file(repo).exists()


# --- fleet propagation -------------------------------------------------------------

def test_fleet_worker_argv_propagates_the_flag(tmp_path: Path) -> None:
    on = ScanRequest(repo_paths=[tmp_path / "a", tmp_path / "b"], output=tmp_path / "out",
                     incremental=True)
    argv = _run_fleet_repo_argv(on, tmp_path / "a", tmp_path / "out" / "a", [])
    assert "--incremental" in argv

    off = ScanRequest(repo_paths=[tmp_path / "a", tmp_path / "b"], output=tmp_path / "out")
    assert "--incremental" not in _run_fleet_repo_argv(off, tmp_path / "a", tmp_path / "out" / "a", [])
