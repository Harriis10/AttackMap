"""Diagnostic producers retain observed context without private source material."""
import io
import json
import threading

import pytest
import typer

from attackmap import cli, desktop_worker, scan_service
from attackmap.artifact_publisher import write_diagnostic
from attackmap.diagnostics import DiagnosticContext, DiagnosticStage, scan_diagnostic, startup_diagnostic
from attackmap.fleet import FleetRepoResult
from attackmap.models import ScanResult
from attackmap.run_contract import RunRequest


def diagnostic(base, run_id):
    return json.loads((base / "diagnostics" / run_id / "terminal-diagnostic.json").read_text(encoding="utf-8"))


def test_cli_selection_failure_has_actual_stage_duration_and_no_private_input(tmp_path, monkeypatch):
    def fail(*args):
        raise typer.BadParameter("PRIVATE_SOURCE_SENTINEL")
    monkeypatch.setattr(cli, "_select_modules", fail)
    with pytest.raises(typer.BadParameter, match="PRIVATE_SOURCE_SENTINEL"):
        cli._select_modules_for_output(["PRIVATE_SOURCE_SENTINEL"], False, tmp_path, "cli")
    result = diagnostic(tmp_path, "cli")
    assert "PRIVATE_SOURCE_SENTINEL" not in json.dumps(result)
    context = result["diagnostic_context"]
    assert context["stages"][0]["stage_id"] == "select_analyzers"
    assert type(context["stages"][0]["duration_milliseconds"]) is int
    assert context["analyzers"]["requested_count"] == 1
    assert context["coverage"]["status"] == "not_started"
    assert context["coverage"]["accepted_file_count"] is None


def test_service_selection_failure_preserves_typed_error_and_unknown_coverage(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("PRIVATE_CONFIGURATION_SENTINEL")
    monkeypatch.setattr(scan_service, "select_requested_analyzers", fail)
    request = scan_service.ScanRequest(repo_paths=[tmp_path], output=tmp_path / "out", run_id="service", modules=["missing"])
    with pytest.raises(scan_service.ScanRequestError, match="PRIVATE_CONFIGURATION_SENTINEL"):
        scan_service.execute_scan_request(request)
    result = diagnostic(request.output, "service")
    assert "PRIVATE_CONFIGURATION_SENTINEL" not in json.dumps(result)
    assert result["diagnostic_context"]["analyzers"]["items"] == []
    assert result["diagnostic_context"]["coverage"]["accepted_file_count"] is None


@pytest.mark.parametrize("engine", [False, True])
def test_desktop_preflight_writes_context_without_exposing_request_path(tmp_path, capsys, engine):
    request = RunRequest(run_id="preflight", repository_id="repo", generation=1, revision=0,
        repository_path=str(tmp_path / "PRIVATE_PATH_SENTINEL"), output_path=str(tmp_path / "out"))
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json(), encoding="utf-8")
    assert desktop_worker.run_request_file(path, engine=engine) == 2
    result = diagnostic(tmp_path / "out", "preflight")
    assert result["schema_version"] == "1.1"
    assert result["diagnostic_context"]["stages"][0]["stage_id"] == "request_validation"
    assert "PRIVATE_PATH_SENTINEL" not in json.dumps(result)
    stdout = capsys.readouterr().out
    assert (json.loads(stdout)["state"] == "failed") if not engine else stdout == ""


@pytest.mark.parametrize("cancel", [False, True])
def test_broker_failure_or_cancel_retains_real_staged_coverage(tmp_path, monkeypatch, cancel):
    base = tmp_path / "out"
    coverage, resources = scan_diagnostic(ScanResult(root=str(tmp_path), scanned_files=["a.py"], files_scanned=1))
    context = DiagnosticContext(stages=[DiagnosticStage(stage_id="scan_and_merge", outcome="completed", duration_milliseconds=12)], coverage=coverage, resource_events=resources)
    threads = []
    class Supervisor:
        def start(self, argv, *, env, on_progress, on_done, timeout=None):
            stage = base / "broker"
            (stage / "run-manifest.json").write_text(json.dumps({"stages": [], "diagnostic_context": context.model_dump(mode="json")}), encoding="utf-8")
            self.cancelled = threading.Event()
            if cancel:
                thread = threading.Thread(target=lambda: (self.cancelled.wait(5), on_done(130)))
                threads.append(thread)
                thread.start()
            else:
                on_done(1)
            return True
        def request_cancel(self):
            self.cancelled.set()
            return True
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    request = RunRequest(run_id="broker", repository_id="repo", generation=1, revision=0,
        repository_path=str(tmp_path), output_path=str(base))
    events = io.StringIO()
    desktop_worker.serve(request, control=io.StringIO("cancel\n" if cancel else ""), events=events)
    for thread in threads:
        thread.join(5)
    result = diagnostic(base, "broker")
    assert result["state"] == ("cancelled" if cancel else "failed")
    assert result["diagnostic_context"]["coverage"]["accepted_file_count"] == 1
    assert result["diagnostic_context"]["stages"][0]["duration_milliseconds"] == 12
    assert json.loads(events.getvalue().splitlines()[-1])["artifact_readiness"] == "unavailable"


def test_broker_preserves_nested_worker_startup_context(tmp_path, monkeypatch):
    base = tmp_path / "out"
    class Supervisor:
        def start(self, argv, *, env, on_progress, on_done, timeout=None):
            write_diagnostic(base / "nested", "nested", state="failed",
                context=startup_diagnostic("select_analyzers", duration_milliseconds=7, requested_analyzers=["missing"]))
            on_done(1)
            return True
        def request_cancel(self):
            return True
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    request = RunRequest(run_id="nested", repository_id="repo", generation=1, revision=0,
        repository_path=str(tmp_path), output_path=str(base))
    desktop_worker.serve(request, control=io.StringIO(""), events=io.StringIO())
    context = diagnostic(base, "nested")["diagnostic_context"]
    assert context["stages"][0]["stage_id"] == "select_analyzers"
    assert context["stages"][0]["duration_milliseconds"] == 7


def test_engine_analyzer_preflight_has_owned_selection_diagnostic(tmp_path, capsys):
    request = RunRequest(run_id="selection", repository_id="repo", generation=1, revision=0,
        repository_path=str(tmp_path), output_path=str(tmp_path / "out"), modules=["not-a-real-official-analyzer"])
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json(), encoding="utf-8")
    assert desktop_worker.run_request_file(path, engine=True) == 2
    context = diagnostic(tmp_path / "out", "selection")["diagnostic_context"]
    assert context["stages"][0]["stage_id"] == "select_analyzers"
    assert context["stages"][0]["duration_milliseconds"] >= 0
    assert context["coverage"]["status"] == "not_started"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("oversized", [False, True])
def test_broker_untrusted_or_oversized_stage_context_falls_back_without_leak(tmp_path, monkeypatch, oversized):
    base = tmp_path / "out"
    class Supervisor:
        def start(self, argv, *, env, on_progress, on_done, timeout=None):
            value = '{"diagnostic_context":{"PRIVATE_SENTINEL":"secret"}}'
            if oversized:
                value = " " * 1_000_001 + value
            (base / "untrusted" / "run-manifest.json").write_text(value, encoding="utf-8")
            on_done(1)
            return True
        def request_cancel(self):
            return True
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    request = RunRequest(run_id="untrusted", repository_id="repo", generation=1, revision=0,
        repository_path=str(tmp_path), output_path=str(base))
    desktop_worker.serve(request, control=io.StringIO(""), events=io.StringIO())
    result = diagnostic(base, "untrusted")
    assert "PRIVATE_SENTINEL" not in json.dumps(result)
    assert result["diagnostic_context"]["coverage"]["accepted_file_count"] is None


def test_partial_fleet_reports_known_child_context_without_paths(tmp_path, monkeypatch):
    repos = [tmp_path / "PRIVATE_REPO_A", tmp_path / "PRIVATE_REPO_B"]
    for repo in repos:
        repo.mkdir()
    def children(request, analyzers, fleet, output):
        fleet.results.append(FleetRepoResult(repo_id="private-repo-a", root=str(repos[0]), report_dir=str(output / "a"),
            scan=ScanResult(root=str(repos[0]), scanned_files=["a.py", "b.py"], files_scanned=2), findings=[]))
        fleet.failed.append({"repo_id": "private-repo-b", "root": str(repos[1]), "error": "PRIVATE_ERROR_SENTINEL"})
    monkeypatch.setattr(scan_service, "_run_fleet_serial", children)
    request = scan_service.ScanRequest(repo_paths=repos, output=tmp_path / "out", run_id="fleet", echo=lambda *a, **k: None)
    assert scan_service.execute_scan_request(request).exit_code == 1
    context = diagnostic(request.output, "fleet")["diagnostic_context"]
    assert "PRIVATE" not in json.dumps(context)
    assert context["fleet"]["requested_count"] == 2
    assert context["fleet"]["completed_count"] == context["fleet"]["failed_count"] == 1
    assert context["fleet"]["children"][0]["coverage"]["accepted_file_count"] == 2
    assert context["fleet"]["children"][1]["coverage"]["accepted_file_count"] is None
    assert context["coverage"]["accepted_file_count"] is None

@pytest.mark.parametrize("case", ["invalid_repo", "diff", "fleet"])
def test_cli_early_semantic_failure_is_diagnostic_without_scanning(tmp_path, monkeypatch, case):
    from typer.testing import CliRunner
    from attackmap.analyzers import TRUSTED_ONLY_ENV
    repo = tmp_path / "repo"
    repo.mkdir()
    second = tmp_path / "second"
    second.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    pointer = output / "current-generation.json"
    pointer.write_text("prior-pointer", encoding="utf-8")
    monkeypatch.delenv(TRUSTED_ONLY_ENV, raising=False)
    monkeypatch.setattr(cli, "execute_scan_request", lambda *_: pytest.fail("scan must not start"))
    args = ["analyze", str(repo), "-o", str(output), "--run-id", "early", "--trusted-analyzers-only"]
    expected = "requires --baseline"
    if case == "invalid_repo":
        args[1] = str(tmp_path / "PRIVATE_PATH_SENTINEL")
        expected = "Path does not exist"
    elif case == "diff":
        args += ["--diff-output", "PRIVATE_PATH_SENTINEL"]
    else:
        args.insert(2, str(second))
        args += ["--baseline", "PRIVATE_PATH_SENTINEL"]
        expected = "not yet supported in multi-repo mode"
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 2
    assert expected in result.output
    envelope = diagnostic(output, "early")
    assert "PRIVATE_PATH_SENTINEL" not in json.dumps(envelope)
    stage = envelope["diagnostic_context"]["stages"][0]
    assert stage["stage_id"] == "request_validation"
    assert type(stage["duration_milliseconds"]) is int
    assert stage["duration_milliseconds"] >= 0
    assert pointer.read_text(encoding="utf-8") == "prior-pointer"
    assert TRUSTED_ONLY_ENV not in __import__("os").environ
    assert len(list(output.rglob("terminal-diagnostic.json"))) == 1


@pytest.mark.parametrize("direct", [False, True])
def test_cli_preflight_storage_failure_preserves_original_error(tmp_path, monkeypatch, direct):
    from typer.testing import CliRunner
    output = tmp_path / "file"
    output.write_text("user-owned", encoding="utf-8")
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(1)
        raise PermissionError("PRIVATE_STORAGE_SENTINEL")
    monkeypatch.setattr("attackmap.artifact_publisher.write_diagnostic", unavailable)
    monkeypatch.setattr(cli, "ensure_output_dir", lambda *_a, **_k: pytest.fail("preliminary output write"))
    args = ["analyze", str(tmp_path), "-o", str(output), "--diff-output", "diff.json"]
    if direct:
        args.append("--direct-generation-output")
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 2
    assert "requires --baseline" in result.output
    assert "PRIVATE_STORAGE_SENTINEL" not in result.output
    assert calls == ([] if direct else [1])
    assert output.read_text(encoding="utf-8") == "user-owned"


@pytest.mark.parametrize("atomic", [False, True])
def test_empty_service_request_preserves_typed_error_and_direct_ownership(tmp_path, atomic):
    request = scan_service.ScanRequest(repo_paths=[], output=tmp_path / "out", run_id="empty", atomic_output=atomic)
    with pytest.raises(scan_service.ScanRequestError, match="At least one repository"):
        scan_service.execute_scan_request(request)
    if atomic:
        assert diagnostic(request.output, "empty")["diagnostic_context"]["stages"][0]["stage_id"] == "request_validation"
    else:
        assert not request.output.exists()

@pytest.mark.parametrize("producer", ["cli", "selection", "service"])
def test_rejected_diagnostic_path_has_no_preliminary_directory_write(tmp_path, monkeypatch, producer):
    from typer.testing import CliRunner
    def reject(*args, **kwargs):
        raise ValueError("unsafe diagnostic destination")
    monkeypatch.setattr("attackmap.artifact_publisher.write_diagnostic", reject)
    monkeypatch.setattr(cli, "ensure_output_dir", lambda *_a, **_k: pytest.fail("preliminary output write"))
    monkeypatch.setattr(scan_service, "ensure_output_dir", lambda *_a, **_k: pytest.fail("preliminary output write"))
    output = tmp_path / "not-created"
    if producer == "cli":
        result = CliRunner().invoke(cli.app, ["analyze", str(tmp_path), "-o", str(output), "--diff-output", "x"])
        assert result.exit_code == 2 and "requires --baseline" in result.output
    elif producer == "selection":
        def fail(*args):
            raise typer.BadParameter("original selection error")
        monkeypatch.setattr(cli, "_select_modules", fail)
        with pytest.raises(typer.BadParameter, match="original selection error"):
            cli._select_modules_for_output(["missing"], False, output, "rejected")
    else:
        with pytest.raises(scan_service.ScanRequestError, match="At least one repository"):
            scan_service.execute_scan_request(scan_service.ScanRequest(repo_paths=[], output=output))
    assert not output.exists()


def test_windows_junction_preflight_does_not_write_redirected_output(tmp_path):
    import os
    import subprocess
    from typer.testing import CliRunner
    if os.name != "nt":
        pytest.skip("Windows junction semantics")
    target = tmp_path / "outside"
    target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)], capture_output=True)
    if created.returncode:
        pytest.skip("Junction creation unavailable on this filesystem")
    try:
        result = CliRunner().invoke(cli.app, ["analyze", str(tmp_path), "-o", str(junction / "reports"), "--diff-output", "x"])
        assert result.exit_code == 2
        assert "requires --baseline" in result.output
        assert list(target.iterdir()) == []
    finally:
        os.rmdir(junction)  # Remove only the exact test-owned junction, never its target.
