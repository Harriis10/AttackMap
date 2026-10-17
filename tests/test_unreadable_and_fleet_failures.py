"""Unreadable files and failing fleet repos don't abort the run (#217)."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap import cli
from attackmap.cli import app
from attackmap.scanner import scan_repo

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
APP = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ok')\ndef ok():\n    return 'ok'\n"
needs_chmod = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="chmod 000 is not enforced on Windows or for root",
)


def _flat(text: str) -> str:
    return " ".join(_ANSI.sub("", text).split())


@needs_chmod
def test_unreadable_file_is_skipped_and_reported(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    locked = tmp_path / "locked.py"
    locked.write_text("x = 1\n", encoding="utf-8")
    locked.chmod(0)
    try:
        scan = scan_repo(tmp_path)
        assert [r.path for r in scan.routes] == ["/ok"]
        assert any(l.startswith("unreadable file skipped") and l.endswith("locked.py") for l in scan.limitations)
        assert scan.scanned_files == ["app.py"]
        result = runner.invoke(app, ["analyze", str(tmp_path), "-o", str(tmp_path.parent / "o"), "--format", "json"])
        assert result.exit_code == 0, result.output
        flat = _flat(result.output)
        # Other analyzers can add coverage warnings before this category.
        assert re.search(r"(?:Not analyzed: |, )1 unreadable file skipped(?:, | \()", flat), flat
        from attackmap.artifact_publisher import current_generation
        generation = current_generation(tmp_path.parent / "o")
        assert generation is not None
        saved = json.loads((generation / "attackmap-report.json").read_text(encoding="utf-8"))["scan"]
        unreadable = [note for note in saved["limitations"] if note.startswith("unreadable file skipped")]
        assert unreadable == ["unreadable file skipped (PermissionError): locked.py"]
        if saved["scanned_files"] is None:
            assert any(note.startswith("Unique-file coverage unavailable:") for note in saved["limitations"])
        else:
            assert saved["scanned_files"] == ["app.py"]
    finally:
        locked.chmod(0o644)


def test_fleet_continues_past_a_failing_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good, bad = tmp_path / "good", tmp_path / "bad"
    for d in (good, bad):
        d.mkdir()
        (d / "app.py").write_text(APP, encoding="utf-8")
    import attackmap.pipeline as pipeline

    real = pipeline.analyze_repository

    def flaky(root, **kwargs):
        if Path(root).name == "bad":
            raise RuntimeError("analyzer blew up")
        return real(root, **kwargs)

    monkeypatch.setattr(pipeline, "analyze_repository", flaky)
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(bad), str(good), "-o", str(out)])
    assert result.exit_code == 1, result.output
    flat = _flat(result.output)
    assert "bad failed and was skipped — RuntimeError: analyzer blew up" in flat
    from attackmap.artifact_publisher import current_generation
    assert current_generation(out) is None
    partial = next(path for path in out.iterdir()
                   if path.is_dir() and (path / "fleet-summary.json").is_file())
    assert (out / "diagnostics" / partial.name / "terminal-diagnostic.json").is_file()
    summary = json.loads((partial / "fleet-summary.json").read_text(encoding="utf-8"))
    assert [r["repo_id"] for r in summary["repos"]] == ["good"]
    assert summary["failed"][0]["repo_id"] == "bad"
    assert "analyzer blew up" in (partial / "fleet-summary.md").read_text(encoding="utf-8")
    assert current_generation(partial / "good") is not None


@pytest.mark.parametrize("workers", [1, 2])
def test_usage_errors_still_stop_the_fleet(tmp_path: Path, workers: int) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        d.mkdir()
        (d / "app.py").write_text(APP, encoding="utf-8")
    result = runner.invoke(app, [
        "analyze", str(a), str(b), "-o", str(tmp_path / "out"),
        "--fleet-workers", str(workers), "--suppress-file", str(tmp_path / "missing.yaml"),
    ])
    assert result.exit_code == 2
    assert not (tmp_path / "out" / "fleet-summary.json").exists()
