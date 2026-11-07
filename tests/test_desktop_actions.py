import json
from pathlib import Path

from attackmap.desktop_actions import ActionRequest, run_action_file


def request_file(tmp_path, operation="compare", payload=None):
    request = ActionRequest(request_id="action-test", operation=operation,
                            output_path=str(tmp_path / "results"), payload=payload or {})
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json(), encoding="utf-8")
    return path, request


def test_engine_action_preserves_identity(tmp_path, monkeypatch):
    path, request = request_file(tmp_path)
    monkeypatch.setattr("attackmap.desktop_actions.execute_action", lambda value: {"count": 3})
    assert run_action_file(path, engine=True) == 0
    result = json.loads((Path(request.output_path) / "action-test.result.json").read_text())
    assert result["request_id"] == request.request_id
    assert result["operation"] == "compare" and result["result"] == {"count": 3}
    # Action identity is immutable and cannot overwrite a prior receipt.
    assert run_action_file(path, engine=True) == 1


def _staged_generation_base(base: Path):
    from attackmap.artifact_manifest import write_artifact_manifest
    from attackmap.artifact_publisher import generation_dir, publish_generation
    from attackmap.safe_fs import safe_write_text
    base.mkdir(parents=True, exist_ok=True)
    folder = generation_dir(base, "g01")
    report = {"scan": {"root": "repo"}, "findings": [], "attack_paths": [],
              "attack_surfaces": [], "exploitability": [], "suppressed_findings": []}
    safe_write_text(folder, folder / "attackmap-report.json", json.dumps(report))
    safe_write_text(folder, folder / "run-manifest.json", json.dumps({"stages": []}))
    write_artifact_manifest(folder, "g01", "1.0", "repo", "repo", [], 0, "succeeded", report)
    publish_generation(base, "g01")
    return base


def test_pin_unpin_diagnostics_actions(tmp_path):
    from attackmap.desktop_actions import execute_action
    base = _staged_generation_base(tmp_path / "out")
    pinned = execute_action(ActionRequest(request_id="pin-1", operation="pin_generation",
                                          output_path=str(tmp_path / "r"), payload={"output_base": str(base), "run_id": "g01"}))
    assert pinned == {"pinned": ["g01"]}
    preview = execute_action(ActionRequest(request_id="diag-1", operation="diagnostics_preview",
                                           output_path=str(tmp_path / "r"), payload={"output_base": str(base)}))
    assert preview["pinned"] == ["g01"]
    assert preview["current_generation"]["generation"] == "g01"
    target = tmp_path / "bundle.json"
    exported = execute_action(ActionRequest(request_id="diag-2", operation="diagnostics_export",
                                            output_path=str(tmp_path / "r"),
                                            payload={"output_base": str(base), "target_path": str(target)}))
    assert exported["written"] == str(target)
    assert json.loads(target.read_text(encoding="utf-8")) == exported["preview"]
    unpinned = execute_action(ActionRequest(request_id="pin-2", operation="unpin_generation",
                                            output_path=str(tmp_path / "r"), payload={"output_base": str(base), "run_id": "g01"}))
    assert unpinned == {"pinned": []}


def test_pin_action_rejects_unknown_generation_without_leaking(tmp_path, capsys):
    from attackmap.desktop_actions import execute_action
    base = _staged_generation_base(tmp_path / "out")
    request = ActionRequest(request_id="pin-x", operation="pin_generation",
                            output_path=str(tmp_path / "r"), payload={"output_base": str(base), "run_id": "missing"})
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json(), encoding="utf-8")
    assert run_action_file(path, engine=True) == 1
    output = capsys.readouterr()
    assert "missing" not in output.out + output.err


def test_action_failure_never_prints_payload_or_exception(tmp_path, monkeypatch, capsys):
    path, _ = request_file(tmp_path, payload={"local_snapshot": "secret-sentinel"})
    def fail(request):
        raise ValueError("secret-sentinel")
    monkeypatch.setattr("attackmap.desktop_actions.execute_action", fail)
    assert run_action_file(path, engine=True) == 1
    output = capsys.readouterr()
    assert "secret-sentinel" not in output.out + output.err


def test_provider_save_never_serializes_credential(tmp_path, monkeypatch):
    from attackmap.desktop_provider import execute_provider_action, configuration_path, load_configuration
    from attackmap.provider_options import ProviderOptions
    saved = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("ATTACKMAP_ACTION_CREDENTIAL", "secret-sentinel")
    monkeypatch.setattr("attackmap.ui.secrets.save_llm_key", lambda key, provider: saved.append((key, provider)))
    result = execute_provider_action("provider_save", {"configuration": ProviderOptions().model_dump()})
    assert saved == [("secret-sentinel", "openai")]
    assert "secret-sentinel" not in configuration_path().read_text() + json.dumps(result)
    assert not load_configuration().enable_ai


def test_loopback_connection_ignores_cloud_key_and_proxy(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from attackmap.desktop_provider import execute_provider_action
    from attackmap.provider_options import ProviderOptions
    calls = []
    class Client:
        def __init__(self, **kwargs):
            calls.append(kwargs)
            self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[SimpleNamespace(id=ProviderOptions().model)]))
        def close(self):
            calls[0]["http_client"].close()
    monkeypatch.setenv("OPENAI_API_KEY", "cloud-secret-sentinel")
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid")
    monkeypatch.setattr("openai.OpenAI", Client)
    result = execute_provider_action("provider_check", {"configuration": ProviderOptions().model_dump()})
    assert calls[0]["api_key"] == "lm-studio"
    assert calls[0]["http_client"]._trust_env is False
    assert calls[0]["max_retries"] == 0
    assert result["selected_model_listed"]
    assert "cloud-secret-sentinel" not in json.dumps(result)
