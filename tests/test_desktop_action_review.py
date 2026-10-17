"""Integration boundary regressions; fake providers never make network calls."""
import sys
from pathlib import Path
import threading

import pytest
from types import SimpleNamespace

from attackmap.desktop_provider import execute_provider_action
from attackmap.llm_review import _resolve_openai_client
from attackmap.provider_options import ProviderOptions
from attackmap.ui import secrets


def test_local_claude_check_never_loads_or_forwards_cloud_credential(monkeypatch):
    captured = {}
    monkeypatch.setenv("HTTPS_PROXY", "http://outside.invalid:3128")
    monkeypatch.setenv("ATTACKMAP_ACTION_CREDENTIAL", "cloud-secret")
    monkeypatch.setattr(secrets, "load_llm_key", lambda *a, **k: "stored-cloud-secret")
    client = SimpleNamespace(models=SimpleNamespace(list=lambda **k: SimpleNamespace(data=[])), close=lambda: None)
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(
        Anthropic=lambda **kwargs: captured.update(client=kwargs) or client,
        DefaultHttpxClient=lambda **kwargs: captured.update(transport=kwargs) or object()))
    options = ProviderOptions(provider="claude", endpoint="http://127.0.0.1:1234/v1")
    execute_provider_action("provider_check", {"configuration": options.model_dump(mode="json")})
    assert "cloud-secret" not in repr(captured)
    assert captured["transport"] == {"trust_env": False, "follow_redirects": False}


def test_local_claude_child_environment_never_loads_cloud_credential(monkeypatch):
    monkeypatch.setattr(secrets, "load_llm_key", lambda *a, **k: "stored-cloud-secret")
    env = secrets.child_llm_env("claude", "http://127.0.0.1:1234/v1", allow_environment=False)
    assert "stored-cloud-secret" not in repr(env)


def test_desktop_accepted_localhost_isolates_generation_transport(monkeypatch):
    options = ProviderOptions(endpoint="http://localhost:1234/v1")
    monkeypatch.setenv("OPENAI_BASE_URL", options.endpoint)
    monkeypatch.setenv("OPENAI_API_KEY", "lm-studio")
    monkeypatch.setenv("HTTPS_PROXY", "http://outside.invalid:3128")
    captured = {}
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(
        OpenAI=lambda **kwargs: captured.update(client=kwargs) or object(),
        DefaultHttpxClient=lambda **kwargs: captured.update(transport=kwargs) or object()))
    _resolve_openai_client(None, None)
    assert captured.get("transport") == {"trust_env": False, "follow_redirects": False}


def test_action_worker_executes_validated_snapshot_if_original_request_changes(monkeypatch, tmp_path):
    from attackmap import desktop_actions, execution
    original = tmp_path / "request.json"
    request = desktop_actions.ActionRequest(request_id="snapshot-test", operation="provider_save",
        output_path=str(tmp_path / "out"), payload={"sentinel": "validated"})
    original.write_text(request.model_dump_json(), encoding="utf-8")
    executed = []
    monkeypatch.setattr(desktop_actions, "execute_action", lambda req: executed.append(req.payload) or {"status": "saved"})

    class Supervisor:
        def start(self, argv, *, env, on_done, timeout):
            changed = request.model_copy(update={"payload": {"sentinel": "mutated"}})
            original.write_text(changed.model_dump_json(), encoding="utf-8")
            worker_path = Path(argv[argv.index("--request") + 1])
            code = desktop_actions.run_action_file(worker_path, engine=True)
            on_done(code, "")
            return True

        def request_cancel(self):
            pass

    monkeypatch.setattr(execution, "ProcessSupervisor", Supervisor)
    desktop_actions.run_action_file(original)
    assert executed == [{"sentinel": "validated"}]


@pytest.mark.parametrize("boundary", ["fsync", "replace"])
def test_provider_save_failure_preserves_previous_configuration(monkeypatch, tmp_path, boundary):
    from attackmap import desktop_provider
    path = tmp_path / "provider.json"
    previous = b'{"previous": "exact bytes"}\r\n'
    path.write_bytes(previous)
    monkeypatch.setattr(desktop_provider, "configuration_path", lambda: path)
    monkeypatch.delenv("ATTACKMAP_ACTION_CREDENTIAL", raising=False)
    def fail(*args, **kwargs):
        raise OSError("injected failure")
    monkeypatch.setattr(desktop_provider.os, boundary, fail)
    with pytest.raises(OSError):
        execute_provider_action("provider_save", {"configuration": ProviderOptions().model_dump(mode="json")})
    assert path.read_bytes() == previous
    assert not list(tmp_path.glob(".provider-*.tmp"))


def test_outer_action_admission_refuses_concurrent_and_failed_replay(monkeypatch, tmp_path):
    from attackmap import desktop_actions
    path = tmp_path / "request.json"
    request = desktop_actions.ActionRequest(request_id="same-id", operation="provider_save",
        output_path=str(tmp_path / "out"), payload={})
    path.write_text(request.model_dump_json(), encoding="utf-8")
    entered, release = threading.Event(), threading.Event()
    calls = []
    def serve(*args):
        calls.append(args)
        entered.set()
        assert release.wait(5)
        return 1  # Failed or uncertain execution must remain non-replayable.
    monkeypatch.setattr(desktop_actions, "_serve", serve)
    worker = threading.Thread(target=lambda: desktop_actions.run_action_file(path))
    worker.start()
    try:
        assert entered.wait(5)
        assert desktop_actions.run_action_file(path) == 1
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert desktop_actions.run_action_file(path) == 1
    assert len(calls) == 1
    assert (tmp_path / "out" / "same-id.admitted.json").is_file()
