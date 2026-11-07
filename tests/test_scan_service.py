"""Shared scan orchestration used by CLI and GUI."""

from __future__ import annotations

import json

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
    from artifact_fixture import write_generation
    from attackmap.artifact_publisher import generation_dir, publish_generation
    folder = generation_dir(Path(options.output), "fixture-run")
    write_generation(folder, {"scan": state.scan.model_dump(mode="json")})
    publish_generation(Path(options.output), folder.name)
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


@pytest.mark.parametrize("run_id", ["startup-failed", None])
def test_analyzer_startup_failure_writes_redacted_diagnostic_preserving_current(tmp_path, monkeypatch, run_id):
    import json
    from artifact_fixture import write_generation
    from attackmap.artifact_publisher import generation_dir, publish_generation, current_generation
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out"
    previous = generation_dir(out, "previous")
    write_generation(previous)
    publish_generation(out, "previous")
    before = (out / "current-generation.json").read_bytes()
    def fail(*args, **kwargs):
        raise ValueError("sentinel-credential-provider-detail")
    monkeypatch.setattr(scan_service, "select_requested_analyzers", fail)
    with pytest.raises(ScanRequestError, match="sentinel-credential-provider-detail"):
        execute_scan_request(ScanRequest(repo_paths=[repo], output=out, modules=["missing"], run_id=run_id))
    diagnostics = list((out / "diagnostics").glob("*/terminal-diagnostic.json"))
    assert len(diagnostics) == 1
    data = json.loads(diagnostics[0].read_text())
    assert data["state"] == "failed" and data["artifact_readiness"] == "unavailable"
    assert data["error"] == "Requested analyzer configuration unavailable."
    assert "sentinel" not in diagnostics[0].read_text()
    assert "scan_timing" not in data  # Analysis has not started.
    if run_id:
        assert data["run_id"] == run_id
    assert (out / "current-generation.json").read_bytes() == before
    assert current_generation(out) == previous


def test_analyzer_startup_invalid_run_identity_cannot_escape_output(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("missing analyzer")
    monkeypatch.setattr(scan_service, "select_requested_analyzers", fail)
    out = tmp_path / "out"
    with pytest.raises(ScanRequestError, match="missing analyzer"):
        execute_scan_request(ScanRequest(repo_paths=[tmp_path], output=out, modules=["missing"], run_id="../escape"))
    assert not (tmp_path / "escape").exists()
    assert not list(out.glob("**/terminal-diagnostic.json"))


def test_fleet_deployment_aliases_resolve_observed_links(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ScanRequest.deployment_aliases flows into link resolution (C28/AM040)."""
    from attackmap.contracts import DeploymentAliases
    from attackmap.models import ExternalCall, Route, ScanResult

    a, b = tmp_path / "web", tmp_path / "auth-api"
    a.mkdir()
    b.mkdir()

    def fake_run(options: AnalyzeOptions) -> RunState:
        state = RunState(options=options)
        if options.repo_path == a:
            state.scan = ScanResult(
                root=str(a), files_scanned=1,
                external_calls=[ExternalCall(target="http://auth.bsky.social/users/1", method="GET", file="c.py", line=1)],
            )
        else:
            state.scan = ScanResult(
                root=str(b), files_scanned=1,
                routes=[Route(path="/users/{id}", method="GET", file="s.py", line=1)],
            )
        from artifact_fixture import write_generation
        from attackmap.artifact_publisher import generation_dir, publish_generation
        folder = generation_dir(Path(options.output), "fixture-run")
        write_generation(folder, {"scan": state.scan.model_dump(mode="json")})
        publish_generation(Path(options.output), folder.name)
        return state

    monkeypatch.setattr(scan_service, "run_scan", fake_run)
    out = tmp_path / "out"
    summary = execute_scan_request(
        ScanRequest(repo_paths=[a, b], output=out, output_format="json")
    )
    assert summary.exit_code == 0
    data = json.loads(summary.fleet_summary_path.read_text(encoding="utf-8"))
    links = data["cross_repo_links"]
    assert len(links) == 1
    assert links[0]["resolution"] == "candidate"
    assert links[0]["resolution_reason"] == "unresolved_host"

    out2 = tmp_path / "out2"
    summary2 = execute_scan_request(
        ScanRequest(repo_paths=[a, b], output=out2, output_format="json",
                    deployment_aliases=DeploymentAliases(hosts={"auth.bsky.social": "auth-api"}))
    )
    assert summary2.exit_code == 0
    data2 = json.loads(summary2.fleet_summary_path.read_text(encoding="utf-8"))
    links2 = data2["cross_repo_links"]
    assert len(links2) == 1
    assert links2[0]["resolution"] == "observed"
    assert links2[0]["destination"] == "auth.bsky.social"
