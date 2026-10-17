"""Broker transport tests; engine execution and publication use controlled seams."""
import io
import json
import threading

import pytest

from attackmap.desktop_worker import run_request_file, serve
from attackmap.run_contract import RunRequest, parse_run_message


@pytest.fixture
def broker(tmp_path, monkeypatch):
    import attackmap.artifact_publisher as publisher
    import attackmap.execution as execution

    request = RunRequest(run_id="run-test", repository_id="repo-test", generation=2,
                         revision=7, repository_path=str(tmp_path),
                         output_path=str(tmp_path / "reports"))
    generation = tmp_path / "generation"
    generation.mkdir()
    (generation / "attackmap-report.json").write_text(json.dumps({"scan": {"root": str(tmp_path)}}))
    calls = {"published": [], "diagnostics": [], "cancelled": 0}
    calls["exit_state"] = {"exit_code": 0, "status": "succeeded"}
    monkeypatch.setattr(publisher, "generation_dir", lambda *args: generation)
    monkeypatch.setattr(publisher, "validate_generation", lambda *args: {
        "exit_state": calls["exit_state"], "run_identity": {"repo_root": str(tmp_path)}})
    monkeypatch.setattr(publisher, "publish_generation",
                        lambda *args, **kwargs: calls["published"].append(args) or generation)
    monkeypatch.setattr(publisher, "write_diagnostic",
                        lambda *args, **kwargs: calls["diagnostics"].append(kwargs))

    class Supervisor:
        mode = "success"

        def start(self, argv, *, env, on_progress, on_done, timeout=None):
            calls.update(argv=argv, env=env, progress=on_progress, done=on_done)
            if self.mode == "launch-failure":
                calls["exit_state"] = {"exit_code": 1, "status": "failed"}
                on_done(1, "private-secret-tail")
                return False
            if self.mode == "policy-failure":
                calls["exit_state"] = {"exit_code": 2, "status": "policy_failed"}
                on_done(2, "private-secret-tail")
                return True
            if self.mode == "success":
                on_progress({"event": "tick", "done": 1, "total": 3, "label": "First"})
                on_progress({"event": "done", "label": "Subanalyzer finished"})
                on_progress({"event": "tick", "done": 3, "total": 3, "label": "Last"})
                on_done(0, "private-secret-tail")
                on_progress({"event": "tick", "label": "Late callback"})
                on_done(0, "duplicate callback")
            return True

        def request_cancel(self):
            calls["cancelled"] += 1
            calls["done"](1, "private-secret-tail")
            return True

    monkeypatch.setattr(execution, "ProcessSupervisor", Supervisor)
    return request, Supervisor, calls, generation


def messages(events, request):
    payloads = [json.loads(line) for line in events.getvalue().splitlines()]
    assert [item["revision"] for item in payloads] == list(
        range(request.revision + 1, request.revision + 1 + len(payloads)))
    for item in payloads:
        parsed = parse_run_message(item)
        assert parsed.run_id == request.run_id
        assert parsed.repository_id == request.repository_id
        assert parsed.generation == request.generation
    assert "private-secret" not in events.getvalue()
    return payloads



def assert_unknown_worker_diagnostic(calls, state):
    from attackmap.diagnostics import DiagnosticContext

    assert len(calls["diagnostics"]) == 1
    diagnostic = calls["diagnostics"][0]
    assert diagnostic["state"] == state
    assert diagnostic["error"] is None
    context = DiagnosticContext.model_validate(diagnostic["context"])
    assert context.outcome == state
    assert context.policy_outcome == "unknown"
    assert len(context.stages) == 1
    stage = context.stages[0]
    assert stage.stage_id == "worker" and stage.outcome == "unknown"
    assert stage.duration_milliseconds is None
    assert context.analyzers.status == "unknown"
    assert context.analyzers.items == [] and context.analyzers.requested_count is None
    assert context.coverage.status == "unknown"
    assert all(getattr(context.coverage, name) is None for name in (
        "accepted_file_count", "legacy_files_scanned_count", "analyzer_error_count", "limitation_count"))
    assert context.resource_events.status == "unknown"
    assert context.resource_events.items == [] and context.resource_events.scopes == []
    assert not context.resource_events.truncated
    assert context.fleet.status == "not_started" and context.fleet.children == []


def test_success_preserves_identity_revisions_and_ignores_subanalyzer_done(broker, monkeypatch):
    request, _, calls, generation = broker
    monkeypatch.setenv("OPENAI_API_KEY", "private-secret-env")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "private-secret-env")
    events = io.StringIO()
    assert serve(request, control=io.StringIO(""), events=events) == 0
    payloads = messages(events, request)
    assert [item["state"] for item in payloads] == ["queued", "running", "running", "completed"]
    assert [item["stage"] for item in payloads[1:3]] == ["First", "Last"]
    assert payloads[1]["completed_units"] == 1
    assert payloads[1]["total_units"] == 3
    assert payloads[-1]["artifact_readiness"] == "ready"
    assert payloads[-1]["artifact_path"] == str(generation / "attackmap-report.json")
    assert len(calls["published"]) == 1
    assert not calls["diagnostics"] and calls["cancelled"] == 0
    assert "OPENAI_API_KEY" not in calls["env"]
    assert "ANTHROPIC_AUTH_TOKEN" not in calls["env"]
    prepared = RunRequest.model_validate_json((generation / "desktop-request.json").read_text())
    assert prepared.output_path == str(generation)
    assert prepared.repository_path == request.repository_path
    assert "--engine" in calls["argv"]


@pytest.mark.parametrize("control", ["cancel\n", "", "ignored\ncancel\n"])
def test_cancel_or_eof_emits_cancelling_then_verified_terminal(broker, control):
    request, supervisor, calls, _ = broker
    supervisor.mode = "wait-for-control"
    events = io.StringIO()
    assert serve(request, control=io.StringIO(control), events=events) == 0
    payloads = messages(events, request)
    assert [item["state"] for item in payloads] == ["queued", "cancelling", "cancelled"]
    assert payloads[-1]["artifact_readiness"] == "unavailable"
    assert calls["cancelled"] == 1 and not calls["published"]
    assert_unknown_worker_diagnostic(calls, "cancelled")


def test_launch_failure_is_single_generic_terminal(broker):
    request, supervisor, calls, _ = broker
    supervisor.mode = "launch-failure"
    events = io.StringIO()
    assert serve(request, control=io.StringIO(""), events=events) == 1
    payloads = messages(events, request)
    assert [item["state"] for item in payloads] == ["queued", "failed"]
    assert payloads[-1]["artifact_readiness"] == "unavailable"
    assert not calls["published"]
    assert_unknown_worker_diagnostic(calls, "failed")


def test_cancel_acknowledgement_waits_for_verified_worker_completion(broker, monkeypatch):
    request, supervisor, calls, _ = broker
    supervisor.mode = "wait-for-control"
    requested = threading.Event()

    def acknowledge(self):
        requested.set()
        return True

    monkeypatch.setattr(supervisor, "request_cancel", acknowledge)
    events = io.StringIO()
    result = []
    thread = threading.Thread(target=lambda: result.append(
        serve(request, control=io.StringIO("cancel\n"), events=events)), daemon=True)
    thread.start()
    try:
        assert requested.wait(2)
        assert [item["state"] for item in messages(events, request)] == ["queued", "cancelling"]
        assert thread.is_alive() and not calls["published"] and not calls["diagnostics"]
    finally:
        if "done" in calls:
            calls["done"](1, "private-secret-tail")
        thread.join(timeout=2)
    assert not thread.is_alive() and result == [0]
    assert messages(events, request)[-1]["state"] == "cancelled"


def test_publication_error_does_not_expose_exception_or_diagnostics(broker, monkeypatch):
    import attackmap.artifact_publisher as publisher
    request, _, _, _ = broker

    def fail(*args, **kwargs):
        raise OSError("private-secret-publication")

    monkeypatch.setattr(publisher, "publish_generation", fail)
    events = io.StringIO()
    assert serve(request, control=io.StringIO(""), events=events) == 0
    terminal = messages(events, request)[-1]
    assert terminal["state"] == "failed"
    assert terminal["error"] == "Result publication failed; previous results were preserved."
    assert terminal["artifact_readiness"] == "unavailable"
    assert "artifact_path" not in terminal


def test_policy_failure_is_completed_analysis_with_ready_artifacts(broker):
    request, supervisor, calls, _ = broker
    supervisor.mode = "policy-failure"
    events = io.StringIO()
    assert serve(request, control=io.StringIO(""), events=events) == 0
    terminal = messages(events, request)[-1]
    assert terminal["state"] == "completed"
    assert terminal["execution_outcome"] == "succeeded"
    assert terminal["policy_outcome"] == "failed"
    assert terminal["artifact_readiness"] == "ready"
    assert len(calls["published"]) == 1


def test_manifest_exit_mismatch_cannot_publish_ready_artifacts(broker):
    request, _, calls, _ = broker
    calls["exit_state"] = {"exit_code": 2, "status": "policy_failed"}
    events = io.StringIO()
    assert serve(request, control=io.StringIO(""), events=events) == 0
    terminal = messages(events, request)[-1]
    assert terminal["state"] == "failed"
    assert terminal["artifact_readiness"] == "unavailable"
    assert not calls["published"]


def test_policy_failure_publication_error_still_emits_valid_terminal(broker, monkeypatch):
    import attackmap.artifact_publisher as publisher
    request, supervisor, _, _ = broker
    supervisor.mode = "policy-failure"

    def fail(*args, **kwargs):
        raise OSError("private-secret-publication")

    monkeypatch.setattr(publisher, "publish_generation", fail)
    events = io.StringIO()
    assert serve(request, control=io.StringIO(""), events=events) == 0
    terminal = messages(events, request)[-1]
    assert terminal["state"] == "failed"
    assert terminal["policy_outcome"] == "not_evaluated"
    assert terminal["artifact_readiness"] == "unavailable"


def test_invalid_request_reports_generic_error(tmp_path, capsys):
    request = tmp_path / "invalid.json"
    request.write_text('{"private-secret-invalid": true}')
    assert run_request_file(request) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Invalid desktop scan request" in captured.err
    assert "private-secret" not in captured.err
