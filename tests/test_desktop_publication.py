"""Desktop broker exercises the real artifact boundary with fake execution."""
import io
import json
import threading

import pytest

from artifact_fixture import write_generation
from attackmap.artifact_publisher import current_generation, generation_dir, publish_generation
from attackmap.desktop_worker import serve
from attackmap.run_contract import RunRequest
from attackmap.safe_fs import UnsafePathError


def request(tmp_path, output):
    return RunRequest(run_id="new", repository_id="repository-id", generation=2,
        revision=0, repository_path=str(tmp_path), output_path=str(output))


def test_cancel_during_publication_preserves_previous_and_records_cancelled(tmp_path, monkeypatch):
    base = tmp_path / "reports"
    old = generation_dir(base, "old")
    write_generation(old)
    publish_generation(base, "old")
    publication_started = threading.Event()
    cancellation_received = threading.Event()
    callback_threads = []

    class Supervisor:
        def start(self, argv, *, env, on_progress, on_done, timeout=None):
            write_generation(base / "new", {"scan": {"root": str(tmp_path)}})
            thread = threading.Thread(target=lambda: on_done(0))
            callback_threads.append(thread)
            thread.start()
            return True
        def request_cancel(self):
            cancellation_received.set()
            return True

    class Control:
        def readline(self, limit):
            assert publication_started.wait(5)
            return "cancel\n"

    def paused_publish(output_base, run_id, **kwargs):
        def boundary(name):
            if name == "after_validation":
                publication_started.set()
                assert cancellation_received.wait(5), "Control handling blocked during publication"
        return publish_generation(output_base, run_id, boundary=boundary, **kwargs)

    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    monkeypatch.setattr("attackmap.artifact_publisher.publish_generation", paused_publish)
    events = io.StringIO()
    assert serve(request(tmp_path, base), control=Control(), events=events) == 0
    for thread in callback_threads:
        thread.join(5)
        assert not thread.is_alive()
    messages = [json.loads(line) for line in events.getvalue().splitlines()]
    assert cancellation_received.is_set()
    assert [item["state"] for item in messages] == ["queued", "cancelling", "cancelled"]
    assert messages[-1]["artifact_readiness"] == "unavailable"
    assert current_generation(base) == old
    diagnostic = json.loads((base / "diagnostics" / "new" / "terminal-diagnostic.json").read_text())
    assert diagnostic["state"] == "cancelled"


def test_broker_refuses_redirected_output_path_before_writing(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    redirect = tmp_path / "redirect"
    try:
        redirect.symlink_to(victim, target_is_directory=True)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    with pytest.raises(UnsafePathError):
        serve(request(tmp_path, redirect), control=io.StringIO(""), events=io.StringIO())
    assert not list(victim.iterdir())


def test_invalid_worker_result_records_failed_diagnostic_and_keeps_current(tmp_path, monkeypatch):
    base = tmp_path / "reports"
    old = generation_dir(base, "old")
    write_generation(old)
    publish_generation(base, "old")
    class Supervisor:
        def start(self, argv, *, env, on_progress, on_done, timeout=None):
            on_done(0)
            return True
        def request_cancel(self):
            return True
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    events = io.StringIO()
    serve(request(tmp_path, base), control=io.StringIO(""), events=events)
    terminal = json.loads(events.getvalue().splitlines()[-1])
    assert terminal["state"] == "failed"
    assert terminal["artifact_readiness"] == "unavailable"
    assert current_generation(base) == old
    diagnostic = json.loads((base / "diagnostics" / "new" / "terminal-diagnostic.json").read_text())
    assert diagnostic["state"] == "failed"


@pytest.mark.parametrize("foreign", ["manifest", "report"])
def test_foreign_repository_artifacts_never_become_current(tmp_path, monkeypatch, foreign):
    base = tmp_path / "reports"
    old = generation_dir(base, "old")
    write_generation(old)
    publish_generation(base, "old")

    class Supervisor:
        def start(self, argv, *, env, on_progress, on_done, timeout=None):
            folder = base / "new"
            report_root = str(tmp_path / "other") if foreign == "report" else str(tmp_path)
            write_generation(folder, {"scan": {"root": report_root}})
            path = folder / "artifact-manifest.json"
            manifest = json.loads(path.read_text())
            manifest["run_identity"]["repo_root"] = str(tmp_path / "other") if foreign == "manifest" else str(tmp_path)
            path.write_text(json.dumps(manifest), encoding="utf-8")
            on_done(0)
            return True

        def request_cancel(self):
            return True

    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    events = io.StringIO()
    serve(request(tmp_path, base), control=io.StringIO(""), events=events)
    terminal = json.loads(events.getvalue().splitlines()[-1])
    assert terminal["state"] == "failed" and terminal["artifact_readiness"] == "unavailable"
    assert current_generation(base) == old
