"""Fleet parallelism: bounded per-repo worker pool."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from attackmap import scan_service
from attackmap.pipeline import AnalyzeOptions, RunState
from attackmap.scan_service import ScanRequest, execute_scan_request


def _make_state(options: AnalyzeOptions) -> RunState:
    state = RunState(options=options)
    from attackmap.models import ScanResult

    state.scan = ScanResult(root=str(options.repo_path), files_scanned=1)
    report_path = Path(options.output) / "attackmap-report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text('{"files_scanned": 1}', encoding="utf-8")
    return state


def test_fleet_default_runs_serially(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    calls: list[Path] = []

    def fake_run(options: AnalyzeOptions) -> RunState:
        calls.append(options.repo_path)
        return _make_state(options)

    monkeypatch.setattr(scan_service, "run_scan", fake_run)
    summary = execute_scan_request(
        ScanRequest(repo_paths=[a, b], output=tmp_path / "out", output_format="json")
    )
    assert calls == [a, b]
    assert summary.exit_code == 0
    assert summary.fleet_summary_path is not None


def test_fleet_parallel_spawns_subprocesses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()

    commands: list[list[str]] = []

    def fake_run(
        argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        # Write a minimal report in the output directory encoded in argv.
        out = Path(argv[argv.index("--output") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "attackmap-report.json").write_text(
            '{"root": "", "files_scanned": 1}', encoding="utf-8"
        )
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scan_service.subprocess, "run", fake_run)
    summary = execute_scan_request(
        ScanRequest(
            repo_paths=[a, b],
            output=tmp_path / "out",
            output_format="json",
            max_workers=2,
        )
    )
    assert len(commands) == 2
    assert summary.exit_code == 0
    assert summary.fleet_summary_path is not None
    for argv in commands:
        assert "analyze" in argv


def test_fleet_workers_cap_limits_concurrency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repos = []
    for name in "abc":
        d = tmp_path / name
        d.mkdir()
        repos.append(d)

    active = {"n": 0}
    max_active = {"n": 0}

    def fake_run(
        argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        active["n"] += 1
        max_active["n"] = max(max_active["n"], active["n"])
        time.sleep(0.1)
        out = Path(argv[argv.index("--output") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "attackmap-report.json").write_text(
            '{"root": "", "files_scanned": 1}', encoding="utf-8"
        )
        active["n"] -= 1
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scan_service.subprocess, "run", fake_run)
    execute_scan_request(
        ScanRequest(
            repo_paths=repos,
            output=tmp_path / "out",
            output_format="json",
            max_workers=2,
        )
    )
    assert max_active["n"] <= 2


def test_fleet_parallel_reports_failed_repo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()

    def fake_run(
        argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        out = Path(argv[argv.index("--output") + 1])
        repo = argv[argv.index("--output") - 1]
        if "a" in repo:
            return subprocess.CompletedProcess(args=argv, returncode=1, stdout="", stderr="boom")
        out.mkdir(parents=True, exist_ok=True)
        (out / "attackmap-report.json").write_text(
            '{"root": "", "files_scanned": 1}', encoding="utf-8"
        )
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scan_service.subprocess, "run", fake_run)
    summary = execute_scan_request(
        ScanRequest(
            repo_paths=[a, b],
            output=tmp_path / "out",
            output_format="json",
            max_workers=2,
        )
    )
    assert summary.exit_code == 1
    assert summary.fleet_summary_path is not None


def test_cli_fleet_workers_spawns_parallel_subprocesses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The --fleet-workers CLI option is wired into the shared fleet runner."""
    from typer.testing import CliRunner

    from attackmap.cli import app

    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    commands: list[list[str]] = []

    def fake_run(
        argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        out = Path(argv[argv.index("--output") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "attackmap-report.json").write_text(
            '{"root": "", "files_scanned": 1}', encoding="utf-8"
        )
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scan_service.subprocess, "run", fake_run)
    result = CliRunner().invoke(
        app,
        [
            "analyze",
            str(a),
            str(b),
            "-o",
            str(tmp_path / "out"),
            "--fleet-workers",
            "2",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert len(commands) == 2
    for argv in commands:
        assert "analyze" in argv
