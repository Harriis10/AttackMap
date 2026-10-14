"""Shared scan orchestration used by CLI and GUI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from attackmap import scan_service
from attackmap.pipeline import AnalyzeOptions, RunState
from attackmap.scan_service import ScanRequest, ScanRequestError, execute_scan_request


def _make_state(options: AnalyzeOptions) -> RunState:
    state = RunState(options=options)
    from attackmap.models import ScanResult

    state.scan = ScanResult(root=str(options.repo_path), files_scanned=1)
    # write a minimal report so the summary sees it
    report_path = Path(options.output) / "attackmap-report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text('{"findings": [], "exploitability": []}', encoding="utf-8")
    return state


def test_single_repo_runs_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    calls: list[AnalyzeOptions] = []

    def fake_run(options: AnalyzeOptions) -> RunState:
        calls.append(options)
        return _make_state(options)

    monkeypatch.setattr(scan_service, "run_scan", fake_run)
    summary = execute_scan_request(ScanRequest(repo_paths=[repo], output=tmp_path / "out"))
    assert len(calls) == 1
    assert summary.exit_code == 0
    assert summary.report_path is not None


def test_modules_passed_as_resolved_analyzers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    resolved = [object()]  # opaque analyzer placeholders
    calls: list[AnalyzeOptions] = []

    def fake_select(modules: Any, *, auto_install: bool = False) -> list:
        assert modules == ["php-web"]
        return resolved

    def fake_run(options: AnalyzeOptions) -> RunState:
        calls.append(options)
        return _make_state(options)

    monkeypatch.setattr(scan_service, "select_requested_analyzers", fake_select)
    monkeypatch.setattr(scan_service, "run_scan", fake_run)
    execute_scan_request(
        ScanRequest(repo_paths=[repo], output=tmp_path / "out", modules=["php-web"])
    )
    assert len(calls) == 1
    assert calls[0].analyzers is resolved


def test_pre_resolved_analyzers_skip_module_lookup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    resolved = [object()]
    select_called = False

    def fake_select(*args: Any, **kwargs: Any) -> list:
        nonlocal select_called
        select_called = True
        return []

    def fake_run(options: AnalyzeOptions) -> RunState:
        return _make_state(options)

    monkeypatch.setattr(scan_service, "select_requested_analyzers", fake_select)
    monkeypatch.setattr(scan_service, "run_scan", fake_run)
    execute_scan_request(
        ScanRequest(
            repo_paths=[repo],
            output=tmp_path / "out",
            modules=["php-web"],
            analyzers=resolved,
        )
    )
    assert not select_called


def test_fleet_runs_all_repos(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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


def test_fleet_rejects_single_repo_only_flags(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    with pytest.raises(ScanRequestError, match="not yet supported in multi-repo mode"):
        execute_scan_request(
            ScanRequest(repo_paths=[a, b], output=tmp_path / "out", baseline="foo.json")
        )


def test_bad_module_raises_scan_request_error(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ScanRequestError):
        execute_scan_request(
            ScanRequest(repo_paths=[repo], output=tmp_path / "out", modules=["not-real"])
        )
