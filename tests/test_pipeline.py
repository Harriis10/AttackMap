"""RunState pipeline and run-manifest.json — report JSON keys stay locked."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from attackmap import __version__
from attackmap.cli import app
from attackmap.pipeline import AnalyzeOptions, run_scan

runner = CliRunner()

_APP = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return {'id': user_id}\n"
)

REPORT_JSON_KEYS = {
    "scan",
    "architecture_summary",
    "attack_surface_summary",
    "defensive_review",
    "defensive_review_json",
    "review_context_pack",
    "attack_surfaces",
    "findings",
    "suppressed_findings",
    "attack_paths",
    "exploitability",
}

MANIFEST_KEYS = {
    "engine_version",
    "analyzers",
    "stages",
    "files_scanned",
    "analyzer_errors",
    "limitation_count",
    "findings_by_severity",
    "llm_usage",
}


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(_APP, encoding="utf-8")
    return repo


def test_analyze_report_json_keys_locked(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path)), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert set(report) == REPORT_JSON_KEYS


def test_run_manifest_always_written_including_markdown_format(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["analyze", str(_repo(tmp_path)), "-o", str(out), "--format", "markdown"]
    )
    assert result.exit_code == 0, result.output
    manifest_path = out / "run-manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert MANIFEST_KEYS <= set(manifest)
    assert manifest["engine_version"] == __version__
    assert isinstance(manifest["stages"], list)
    assert all("name" in s and "milliseconds" in s for s in manifest["stages"])
    dumped = json.dumps(manifest)
    assert "evidence_text" not in dumped
    assert "defensive_review" not in dumped


def test_run_scan_returns_state_without_typer(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    out = tmp_path / "reports"
    state = run_scan(
        AnalyzeOptions(
            repo_path=repo,
            output=out,
            output_format="json",
            progress_format="none",
            no_progress=True,
        )
    )
    assert state.scan is not None
    assert state.scan.files_scanned >= 1
    assert (out / "run-manifest.json").exists()
    assert (out / "attackmap-report.json").exists()
    assert state.exit_code == 0
