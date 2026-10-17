"""Options are validated before any scanning starts (#229)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap import cli
from attackmap.cli import app

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _flat(text: str) -> str:
    return " ".join(_ANSI.sub("", text).replace("│", " ").split())


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def no_scan(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fail the test if a scan starts: validation must come first."""
    started: list[str] = []

    def boom(*args, **kwargs):
        started.append("scan")
        raise AssertionError("scan started before option validation")

    monkeypatch.setattr(cli, "execute_scan_request", boom)
    return started


@pytest.mark.parametrize(
    "args, message",
    [
        (["--llm-backend", "bogus", "--triage"], "--llm-backend must be one of: auto, api, cli (got 'bogus')"),
        (["--llm-effort", "huge", "--llm"], "--llm-effort must be one of: low, medium, high, xhigh, max"),
        (["--llm-provider", "gemini"], "--llm-provider must be one of: claude, openai"),
        (["--llm-speed", "warp"], "--llm-speed must be one of: standard, fast"),
        (["--progress-format", "bar"], "--progress-format must be one of: auto, tty, json, none"),
        (["--verify"], "--verify only applies with --hunt"),
        (["--verify-votes", "5", "--hunt-rounds", "2"], "--verify-votes, --hunt-rounds only apply with --hunt"),
        (["--diff-output", "d.md"], "--diff-output requires --baseline"),
        (["--hunt", "--verify-votes", "0"], "--verify-votes must be at least 1"),
        (["--hunt", "--hunt-lenses", "-2"], "--hunt-lenses must be between 1 and"),
        (["--hunt", "--hunt-lenses", "99"], "--hunt-lenses must be between 1 and"),
        (["--hunt", "--hunt-rounds", "0"], "--hunt-rounds must be at least 1"),
        (["--hunt", "--hunt-budget", "-1"], "--hunt-budget must be 0 (no cap) or more"),
    ],
)
def test_bad_options_fail_before_scanning(repo: Path, no_scan: list[str], args: list[str], message: str) -> None:
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(repo.parent / "out"), *args])
    assert result.exit_code == 2, result.output
    assert message in _flat(result.output)
    assert no_scan == []


def test_fleet_mode_validates_too(tmp_path: Path, no_scan: list[str]) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    result = runner.invoke(app, ["analyze", str(a), str(b), "--progress-format", "bar"])
    assert result.exit_code == 2
    assert no_scan == []


def test_help_lists_tty() -> None:
    result = runner.invoke(app, ["analyze", "--help"], env={"COLUMNS": "300"})
    assert "'tty'" in _flat(result.output)


def test_defaults_and_valid_combinations_still_run(repo: Path) -> None:
    out = repo.parent / "out-ok"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out), "--progress-format", "tty",
                                 "--llm-backend", "cli", "--llm-effort", "low", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert (out / "attackmap-report.json").exists()


def test_module_preflight_diagnostic_is_generic_and_preserves_previous(repo, tmp_path, monkeypatch):
    import json
    from artifact_fixture import write_generation
    from attackmap.artifact_publisher import generation_dir, publish_generation, current_generation
    out = tmp_path / "out"
    previous = generation_dir(out, "previous")
    write_generation(previous)
    publish_generation(out, "previous")
    before = (out / "current-generation.json").read_bytes()
    def fail(*args, **kwargs):
        raise ValueError("sentinel-provider-credential-detail")
    monkeypatch.setattr(cli, "select_requested_analyzers", fail)
    result = runner.invoke(app, ["analyze", str(repo), "--output", str(out), "--module", "synthetic-missing", "--run-id", "startup-failed"])
    assert result.exit_code == 2
    assert "sentinel-provider-credential-detail" in _flat(result.output)
    diagnostic = out / "diagnostics/startup-failed/terminal-diagnostic.json"
    text = diagnostic.read_text()
    doc = json.loads(text)
    assert doc["error"] == "Requested analyzer configuration unavailable."
    assert doc["state"] == "failed" and doc["artifact_readiness"] == "unavailable"
    assert "sentinel" not in text and "scan_timing" not in doc
    assert (out / "current-generation.json").read_bytes() == before
    assert current_generation(out) == previous


@pytest.mark.parametrize("direct", [False, True])
def test_module_preflight_storage_failure_keeps_original_usage_error(repo, tmp_path, monkeypatch, direct):
    def fail(*args, **kwargs):
        raise ValueError("original module configuration error")
    monkeypatch.setattr(cli, "select_requested_analyzers", fail)
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(args)
        raise PermissionError("storage error must not replace module error")
    monkeypatch.setattr("attackmap.artifact_publisher.write_diagnostic", unavailable)
    monkeypatch.setattr(cli, "execute_scan_request", lambda *_a, **_k: pytest.fail("scan must not start"))
    argv = ["analyze", str(repo), "--output", str(tmp_path / "out"), "--module", "synthetic-missing"]
    if direct:
        argv.append("--direct-generation-output")
    result = runner.invoke(app, argv)
    assert result.exit_code == 2
    assert "original module configuration error" in _flat(result.output)
    assert "storage error" not in result.output
    assert bool(calls) is not direct
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("direct", [False, True])
def test_fleet_module_preflight_generic_diagnostic_and_direct_suppression(tmp_path, monkeypatch, direct):
    import json
    from artifact_fixture import write_generation
    from attackmap.artifact_publisher import generation_dir, publish_generation, current_generation
    repos = [tmp_path / "repo one", tmp_path / "služba dvě"]
    for repo in repos:
        repo.mkdir()
        (repo / "app.py").write_text("print('synthetic')")
    out = tmp_path / "out"
    previous = generation_dir(out, "previous")
    write_generation(previous)
    publish_generation(out, "previous")
    before = (out / "current-generation.json").read_bytes()
    def fail(*args, **kwargs):
        raise ValueError("fleet-sentinel-credential-detail")
    monkeypatch.setattr(cli, "select_requested_analyzers", fail)
    argv = ["analyze", *map(str, repos), "--output", str(out), "--module", "synthetic-missing", "--run-id", "fleet-startup"]
    if direct:
        argv.append("--direct-generation-output")
    result = runner.invoke(app, argv)
    assert result.exit_code == 2
    assert "fleet-sentinel-credential-detail" in _flat(result.output)
    diagnostic = out / "diagnostics/fleet-startup/terminal-diagnostic.json"
    assert diagnostic.exists() is not direct
    if not direct:
        doc = json.loads(diagnostic.read_text())
        assert doc["error"] == "Requested analyzer configuration unavailable."
        assert "sentinel" not in diagnostic.read_text()
        assert doc["state"] == "failed" and "scan_timing" not in doc
    assert (out / "current-generation.json").read_bytes() == before
    assert current_generation(out) == previous
