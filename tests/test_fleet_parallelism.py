"""Fleet parallelism: bounded per-repo worker pool."""

from __future__ import annotations

import subprocess
import json
import time
from pathlib import Path
from typing import Any

import pytest

from attackmap import scan_service
from attackmap.pipeline import AnalyzeOptions, RunState
from attackmap.scan_service import ScanRequest, execute_scan_request
from artifact_fixture import write_generation
from attackmap.artifact_publisher import current_generation, publish_generation


def test_supervised_worker_cancel_waits_for_verified_cleanup(monkeypatch):
    import attackmap.execution as execution
    calls = []

    class Supervisor:
        running = True
        cancelled = False

        def start(self, argv, *, on_done, timeout=None):
            self.done = on_done
            calls.append("start")
            return True

        def wait(self, timeout):
            assert timeout == 0.1
            calls.append("wait")
            if calls.count("wait") < 3:
                return False
            assert self.cancelled
            self.done(1, "bounded tail")
            self.running = False
            return True

        def request_cancel(self):
            self.cancelled = True
            calls.append("cancel")
            return True

    monkeypatch.setattr(execution, "ProcessSupervisor", Supervisor)
    checks = iter([False, True, True])
    result = scan_service._run_supervised_worker(["worker"], lambda: next(checks))
    assert result.returncode == 130 and result.stdout == ""
    assert result.stderr == "bounded tail"
    assert calls == ["start", "wait", "cancel", "wait", "cancel", "wait"]


def test_supervised_worker_pre_cancel_does_not_launch(monkeypatch):
    import attackmap.execution as execution

    def unexpected():
        raise AssertionError("Cancelled worker must not launch")

    monkeypatch.setattr(execution, "ProcessSupervisor", unexpected)
    result = scan_service._run_supervised_worker(["worker"], lambda: True)
    assert result.returncode == 130


@pytest.mark.parametrize("exception_type", [RuntimeError, KeyboardInterrupt])
def test_supervised_worker_checker_exception_cleans_up_before_reraising(monkeypatch, exception_type):
    import attackmap.execution as execution
    calls = []

    class Supervisor:
        running = True
        cancelled = False

        def start(self, argv, *, on_done, timeout=None):
            calls.append("start")
            self.done = on_done
            return True

        def request_cancel(self):
            calls.append("cancel")
            self.cancelled = True
            return True

        def wait(self, timeout):
            calls.append("wait")
            if calls.count("wait") < 3:
                return False
            assert self.cancelled
            self.done(1, "")
            self.running = False
            return True

    checks = 0

    def check():
        nonlocal checks
        checks += 1
        if checks > 1:
            raise exception_type("fixture interruption")
        return False

    monkeypatch.setattr(execution, "ProcessSupervisor", Supervisor)
    with pytest.raises(exception_type, match="fixture interruption"):
        scan_service._run_supervised_worker(["worker"], check)
    assert calls == ["start", "wait", "cancel", "wait", "wait"]


def test_serial_fleet_pre_cancel_admits_no_repository(monkeypatch, tmp_path):
    def unexpected(*args, **kwargs):
        raise AssertionError("Cancelled serial fleet must not admit a repository")

    monkeypatch.setattr(scan_service, "run_scan", unexpected)
    request = ScanRequest(repo_paths=[tmp_path / "a", tmp_path / "b"],
                          output=tmp_path / "out", output_format="json", cancel_check=lambda: True)
    summary = execute_scan_request(request)
    assert summary.exit_code == 130
    assert current_generation(request.output) is None
    assert not (request.output / "fleet-summary.json").exists()
    diagnostic = next((request.output / "diagnostics").glob("*/terminal-diagnostic.json"))
    assert json.loads(diagnostic.read_text())["state"] == "cancelled"


@pytest.mark.parametrize("workers", [1, 2])
def test_sibling_failure_preserves_previous_fleet_pointer_and_exports(monkeypatch, tmp_path, workers):
    repos = [tmp_path / "good", tmp_path / "bad"]
    for repo in repos:
        repo.mkdir()
    fail = False

    def fake_scan(options):
        if fail and options.repo_path.name == "bad":
            state = RunState(options=options)
            state.exit_code = 1
            return state
        return _make_state(options)

    def fake_worker(argv, **kwargs):
        if fail and Path(argv[argv.index("--output") - 1]).name == "bad":
            return subprocess.CompletedProcess(argv, 1, "", "fixture failed sibling")
        _write_worker_payload(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(scan_service, "run_scan", fake_scan)
    monkeypatch.setattr(scan_service, "_run_supervised_worker", fake_worker)
    base = tmp_path / "out"
    prior = execute_scan_request(ScanRequest(repo_paths=repos, output=base, run_id="prior",
                                            output_format="json", max_workers=workers))
    assert prior.exit_code == 0
    previous = current_generation(base)
    pointer = (base / "current-generation.json").read_bytes()
    exports = {path.relative_to(base): path.read_bytes() for path in base.glob("*.json")}
    immutable = {path.relative_to(previous): path.read_bytes() for path in previous.rglob("*") if path.is_file()}
    fail = True
    partial = execute_scan_request(ScanRequest(repo_paths=repos, output=base, run_id="partial",
                                              output_format="json", max_workers=workers))
    assert partial.exit_code == 1
    assert current_generation(base) == previous
    assert (base / "current-generation.json").read_bytes() == pointer
    assert all((base / name).read_bytes() == data for name, data in exports.items())
    assert {path.relative_to(previous): path.read_bytes() for path in previous.rglob("*") if path.is_file()} == immutable
    assert partial.fleet_summary_path == base / "partial" / "fleet-summary.json"
    summary = json.loads(partial.fleet_summary_path.read_text())
    assert [item["repo_id"] for item in summary["repos"]] == ["good"]
    assert current_generation(base / "partial" / "good") is not None
    assert (base / "diagnostics" / "partial" / "terminal-diagnostic.json").is_file()


def _write_child_generation(base, scan):
    folder = base / "fixture-run"
    write_generation(folder, {"scan": scan})
    publish_generation(base, folder.name)


def _write_worker_payload(argv):
    repo = Path(argv[argv.index("--output") - 1])
    scan = {"root": str(repo), "files_scanned": 1}
    _write_child_generation(Path(argv[argv.index("--output") + 1]), scan)
    Path(argv[argv.index("--fleet-result") + 1]).write_text(json.dumps(scan), encoding="utf-8")


def _make_state(options: AnalyzeOptions) -> RunState:
    state = RunState(options=options)
    from attackmap.models import ScanResult

    state.scan = ScanResult(root=str(options.repo_path), files_scanned=1)
    _write_child_generation(Path(options.output), state.scan.model_dump(mode="json"))
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


@pytest.mark.parametrize("output_format", ["all", "json", "markdown"])
def test_fleet_real_workers_match_serial(tmp_path: Path, output_format: str) -> None:
    """Interchange preserves models even when no JSON presentation is emitted."""
    repos = [tmp_path / "service one", tmp_path / "služba dvě"]
    for repo in repos:
        repo.mkdir()
        (repo / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n"
            "@app.route('/health')\ndef health():\n    return 'ok'\n", encoding="utf-8",
        )
    fleets = []
    original_finalize = scan_service._finalize_fleet

    def capture(request, fleet, output_root):
        fleets.append(fleet)
        return original_finalize(request, fleet, output_root)

    from unittest.mock import patch
    with patch.object(scan_service, "_finalize_fleet", capture):
        for workers in (1, 2):
            summary = execute_scan_request(ScanRequest(
                repo_paths=repos, output=tmp_path / f"out-{workers}",
                output_format=output_format, max_workers=workers, no_progress=True,
            ))
            assert summary.exit_code == 0
    for serial, parallel in zip(fleets[0].results, fleets[1].results):
        assert serial.repo_id == parallel.repo_id
        assert serial.scan.model_dump(mode="json") == parallel.scan.model_dump(mode="json")
        assert [f.model_dump(mode="json") for f in serial.findings] == [f.model_dump(mode="json") for f in parallel.findings]
        assert [p.model_dump(mode="json") for p in serial.attack_paths] == [p.model_dump(mode="json") for p in parallel.attack_paths]
        assert serial.suppressed_count == parallel.suppressed_count
        if output_format == "markdown":
            assert not (tmp_path / "out-2" / parallel.repo_id / "attackmap-report.json").exists()
            assert current_generation(Path(parallel.report_dir)) is not None


def test_frozen_worker_launch_uses_executable_directly(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scan_service.sys, "frozen", True, raising=False)
    monkeypatch.setattr(scan_service.sys, "executable", "C:/Program Files/AttackMap/attackmap.exe")
    request = ScanRequest(repo_paths=[tmp_path], output=tmp_path / "out")
    argv = scan_service._run_fleet_repo_argv(request, tmp_path, request.output, [])
    assert argv[:2] == [scan_service.sys.executable, "analyze"]
    assert "-m" not in argv


@pytest.mark.parametrize("workers", [1, 2])
@pytest.mark.parametrize("failure", ["exception", "exit_code"])
def test_fleet_preserves_sibling_after_repository_failure(monkeypatch, tmp_path: Path, workers: int, failure: str) -> None:
    repos = [tmp_path / "good", tmp_path / "bad"]
    for repo in repos:
        repo.mkdir()

    def fake_scan(options):
        if options.repo_path.name == "bad":
            if failure == "exception":
                raise scan_service.AnalysisExit(2)
            state = RunState(options=options)
            state.exit_code = 1
            return state
        return _make_state(options)

    def fake_child(argv, **kwargs):
        repo = Path(argv[argv.index("--output") - 1])
        if repo.name == "bad":
            return subprocess.CompletedProcess(argv, 1, "", "invalid repository suppression")
        _write_worker_payload(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(scan_service, "run_scan", fake_scan)
    monkeypatch.setattr(scan_service, "_run_supervised_worker", fake_child)
    summary = execute_scan_request(ScanRequest(
        repo_paths=repos, output=tmp_path / "out", output_format="json", max_workers=workers,
    ))
    assert summary.exit_code == 1
    assert summary.fleet_summary_path.parent != tmp_path / "out"
    assert current_generation(tmp_path / "out") is None
    assert not (tmp_path / "out" / "fleet-summary.json").exists()
    assert list((tmp_path / "out" / "diagnostics").glob("*/terminal-diagnostic.json"))
    assert current_generation(summary.fleet_summary_path.parent / "good") is not None
    assert summary.fleet_summary_path.is_file()
    assert current_generation(summary.fleet_summary_path.parent / "bad") is None
    data = json.loads(summary.fleet_summary_path.with_name("fleet-summary.json").read_text())
    assert [repo["repo_id"] for repo in data["repos"]] == ["good"]
    assert [repo["repo_id"] for repo in data["failed"]] == ["bad"]


@pytest.mark.parametrize("payload", [None, "not-json"])
def test_worker_missing_or_malformed_interchange_ignores_stale_report(monkeypatch, tmp_path: Path, payload: str | None) -> None:
    repo_out = tmp_path / "out" / "repo"
    repo_out.mkdir(parents=True)
    (repo_out / "attackmap-report.json").write_text('{"root":"old", "files_scanned":1}')
    result_paths = []

    def fake_child(argv, **kwargs):
        result_path = Path(argv[argv.index("--fleet-result") + 1])
        result_paths.append(result_path)
        if payload is not None:
            result_path.write_text(payload)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(scan_service, "_run_supervised_worker", fake_child)
    request = ScanRequest(repo_paths=[tmp_path], output=tmp_path / "out")
    with pytest.raises(scan_service._FleetRepoError, match="failed to load report"):
        scan_service._run_fleet_repo_worker(request, "repo", tmp_path, request.output, [])
    assert not result_paths[0].parent.exists()


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
        _write_worker_payload(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scan_service, "_run_supervised_worker", fake_run)
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
        _write_worker_payload(argv)
        active["n"] -= 1
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scan_service, "_run_supervised_worker", fake_run)
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
        if Path(repo).name == "a":
            return subprocess.CompletedProcess(args=argv, returncode=1, stdout="", stderr="boom")
        out.mkdir(parents=True, exist_ok=True)
        _write_worker_payload(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scan_service, "_run_supervised_worker", fake_run)
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
        _write_worker_payload(argv)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(scan_service, "_run_supervised_worker", fake_run)
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

