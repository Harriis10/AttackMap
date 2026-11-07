"""Desktop options reach the shared engine without enabling network by default."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from attackmap.desktop_worker import run_request_file
from attackmap.run_contract import RunRequest, ScanOptions, ScanOptionsV12


def test_defaults_are_local_and_finite():
    options = ScanOptions()
    assert not options.cve
    assert options.secrets_history == 0
    assert options.timeout_seconds == 600
    assert not options.recall and not options.no_suppress


@pytest.mark.parametrize("fields", [
    {"cve": "true"}, {"recall": 1}, {"timeout_seconds": 0},
    {"timeout_seconds": 86_401}, {"secrets_history": -1},
    {"secrets_history": 10_001},
])
def test_invalid_options_rejected(fields):
    with pytest.raises(ValidationError):
        ScanOptions(**fields)


def test_options_reach_shared_engine(tmp_path, monkeypatch):
    captured = []
    monkeypatch.setattr("attackmap.scan_service.run_scan",
                        lambda options: captured.append(options) or SimpleNamespace(exit_code=0))
    request = RunRequest(run_id="options", repository_id="repo", generation=1,
                         revision=0, repository_path=str(tmp_path),
                         output_path=str(tmp_path / "reports"), options=ScanOptions(
                             recall=True, strict_analyzers=True, no_suppress=True,
                             cve=True, secrets_history=12, timeout_seconds=30))
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json(), encoding="utf-8")
    assert run_request_file(path, engine=True) == 0
    options = captured[0]
    assert options.recall and options.strict_analyzers and options.no_suppress
    assert options.cve and options.secrets_history == 12
    assert not options.llm and not options.hunt
    assert not options.atomic_output


def test_legacy_request_uses_safe_defaults(tmp_path):
    payload = dict(schema_version="1.0", run_id="old", repository_id="repo",
                   generation=1, revision=0, repository_path=str(tmp_path),
                   output_path=str(tmp_path / "reports"))
    request = RunRequest.model_validate(json.loads(json.dumps(payload)))
    assert request.options == ScanOptions()


def test_startup_failure_has_typed_result_and_redacted_diagnostic(tmp_path, capsys):
    request = RunRequest(run_id="startup", repository_id="repo", generation=1,
                         revision=4, repository_path=str(tmp_path / "missing"),
                         output_path=str(tmp_path / "reports"))
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json(), encoding="utf-8")
    assert run_request_file(path) == 2
    captured = capsys.readouterr()
    terminal = json.loads(captured.out)
    assert terminal["kind"] == "terminal" and terminal["state"] == "failed"
    assert terminal["revision"] == 5 and terminal["run_id"] == "startup"
    diagnostic = json.loads((tmp_path / "reports" / "diagnostics" / "startup" /
                             "terminal-diagnostic.json").read_text())
    assert diagnostic["state"] == "failed" and diagnostic["error"] == terminal["error"]


NEW_SENTINELS = {
    "baseline": "C:/parity/baseline.json",
    "suppress_file": "C:/parity/suppressions.yml",
    "fail_on_new_high": True,
    "fail_on_new_suppression": True,
    "strict_suppressions": True,
    "isolated_analyzers": True,
    "time_budget_seconds": 17,
}


def test_every_new_field_has_nondefault_service_and_pipeline_sentinel(tmp_path):
    from attackmap.scan_service import scan_request_from_run, _analyze_options
    assert set(NEW_SENTINELS) == set(ScanOptionsV12.model_fields) - set(ScanOptions.model_fields)
    options = ScanOptionsV12(**NEW_SENTINELS, timeout_seconds=37)
    request = RunRequest(schema_version="1.2", run_id="sentinel", repository_id="opaque-repo",
        generation=2, revision=4, repository_path=str(tmp_path), output_path=str(tmp_path / "reports"),
        options=options)
    decoded = RunRequest.model_validate_json(request.model_dump_json())
    assert decoded == request
    service = scan_request_from_run(decoded)
    pipeline = _analyze_options(service, service.repo_paths[0], service.output, None)
    for name, sentinel in NEW_SENTINELS.items():
        assert sentinel != getattr(ScanOptionsV12(), name)
        assert getattr(decoded.options, name) == sentinel
        assert getattr(service, name) == sentinel
        assert getattr(pipeline, name) == sentinel
        metadata = ScanOptionsV12.model_fields[name].json_schema_extra
        assert metadata["network_impact"] == "none" and metadata["supported"] is True
        assert metadata["unit"]
    assert not service.install_missing and not service.atomic_output
    assert service.run_id == "sentinel"
    assert service.repo_paths == [tmp_path]
    assert pipeline.ai_limits == service.ai_limits


@pytest.mark.parametrize("fields", [
    {"baseline": "relative.json"}, {"suppress_file": "C:relative.yml"},
    {"baseline": "https://example.invalid/baseline.json"},
    {"suppress_file": "//server/share/config.yml"},
    {"baseline": "C:/file\nsecret-sentinel"}, {"time_budget_seconds": 0},
    {"time_budget_seconds": 86_401}, {"time_budget_seconds": True},
    {"timeout_seconds": 20, "time_budget_seconds": 20},
    {"fail_on_new_high": True}, {"fail_on_new_suppression": True},
    {"no_suppress": True, "suppress_file": "C:/parity/suppressions.yml"},
    {"no_suppress": True, "strict_suppressions": True},
    {"isolated_analyzers": 1},
])
def test_v12_paths_ranges_units_and_conflicts_rejected(fields):
    with pytest.raises(ValidationError):
        ScanOptionsV12(**fields)


@pytest.mark.parametrize("schema", ["1.0", "1.1"])
def test_old_versions_keep_exact_frozen_options_and_reject_new_fields(schema, tmp_path):
    request = RunRequest(schema_version=schema, run_id="old", repository_id="repo", generation=1,
        revision=0, repository_path=str(tmp_path), output_path=str(tmp_path / "out"))
    assert type(request.options) is ScanOptions
    assert request.model_dump()["options"] == ScanOptions().model_dump()
    with pytest.raises(ValidationError, match="require schema 1.2"):
        RunRequest.model_validate(request.model_dump() | {"options": {"baseline": "C:/parity/baseline.json"}})


def test_v12_fixture_hashes_and_wire_roundtrip():
    import hashlib
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "tests/fixtures/desktop-options-v12/manifest.json").read_text())
    assert manifest["new_field_sentinels"] == NEW_SENTINELS
    for entry in manifest["entries"]:
        path = root / entry["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
        raw = json.loads(path.read_text())
        assert RunRequest.model_validate(raw).model_dump(mode="json") == raw


def test_v12_worker_reaches_application_service_with_exact_sentinels(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    suppress = tmp_path / "suppressions.yml"
    baseline.write_text("{}")
    suppress.write_text("suppressions: []")
    options = ScanOptionsV12(**(NEW_SENTINELS | {"baseline": str(baseline), "suppress_file": str(suppress)}),
                            timeout_seconds=37)
    request = RunRequest(schema_version="1.2", run_id="mapped", repository_id="repo", generation=1,
        revision=0, repository_path=str(tmp_path), output_path=str(tmp_path / "out"), options=options)
    captured = []
    monkeypatch.setattr("attackmap.scan_service.execute_scan_request",
                        lambda value: captured.append(value) or SimpleNamespace(exit_code=0))
    provider = Mock(side_effect=AssertionError("Provider must not be called"))
    monkeypatch.setattr("attackmap.desktop_provider.execute_provider_action", provider)
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json())
    assert run_request_file(path, engine=True) == 0
    assert len(captured) == 1
    for name in NEW_SENTINELS:
        assert getattr(captured[0], name) == getattr(options, name)
    provider.assert_not_called()


@pytest.mark.parametrize("unsupported", ["incremental", "mode", "fleet", "jury", "max_memory_bytes"])
def test_v12_unwired_fields_fail_before_dispatch_and_preserve_previous(tmp_path, monkeypatch, unsupported):
    from attackmap.desktop_capabilities import validate_desktop_request
    output = tmp_path / "out"
    output.mkdir()
    previous = output / "current.json"
    previous.write_text('{"generation":"prior-kept"}')
    payload = RunRequest(schema_version="1.2", run_id="rejected", repository_id="repo", generation=2,
        revision=0, repository_path=str(tmp_path), output_path=str(output)).model_dump(mode="json")
    payload["options"][unsupported] = "secret-sentinel"
    with pytest.raises(ValueError, match="unsupported or malformed"):
        validate_desktop_request(payload)
    dispatches = [Mock() for _ in range(3)]
    monkeypatch.setattr("attackmap.desktop_worker.serve", dispatches[0])
    monkeypatch.setattr("attackmap.scan_service.execute_scan_request", dispatches[1])
    monkeypatch.setattr("attackmap.desktop_provider.execute_provider_action", dispatches[2])
    path = tmp_path / "request.json"
    path.write_text(json.dumps(payload))
    assert run_request_file(path, engine=True) == 2
    for dispatch in dispatches:
        dispatch.assert_not_called()
    assert previous.read_text() == '{"generation":"prior-kept"}'


@pytest.mark.parametrize("field", ["baseline", "suppress_file"])
def test_missing_v12_input_file_fails_before_service(tmp_path, monkeypatch, field):
    service = Mock()
    monkeypatch.setattr("attackmap.scan_service.execute_scan_request", service)
    request = RunRequest(schema_version="1.2", run_id="missing", repository_id="repo", generation=1,
        revision=0, repository_path=str(tmp_path), output_path=str(tmp_path / "out"),
        options=ScanOptionsV12(**{field: str(tmp_path / "missing-file")}))
    path = tmp_path / "request.json"
    path.write_text(request.model_dump_json())
    assert run_request_file(path, engine=True) == 2
    service.assert_not_called()


@pytest.mark.parametrize("field", ["repository_paths", "repo_paths", "repository_ids", "max_workers",
                                    "llm", "llm_backend", "incremental"])
def test_unwired_top_level_feature_alias_is_not_metadata(field, tmp_path):
    from attackmap.desktop_capabilities import validate_desktop_request
    request = RunRequest(schema_version="1.2", run_id="alias", repository_id="repo", generation=1,
        revision=0, repository_path=str(tmp_path), output_path=str(tmp_path / "out"))
    with pytest.raises(ValueError, match="unsupported or malformed"):
        validate_desktop_request(request.model_dump(mode="json") | {field: "unsupported-sentinel"})


@pytest.mark.parametrize("schema", ["1.0", "1.1", "1.2"])
def test_broker_echoes_request_schema_for_old_and_new_consumers(schema, tmp_path, monkeypatch):
    import io
    from attackmap.desktop_worker import serve
    from attackmap.run_contract import parse_run_message
    class RejectedLaunch:
        def start(self, argv, *, on_done, **kwargs):
            on_done(1, "")
            return False
        def request_cancel(self):
            return True
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", RejectedLaunch)
    monkeypatch.setattr("attackmap.artifact_publisher.write_diagnostic", lambda *args, **kwargs: None)
    request = RunRequest(schema_version=schema, run_id="schema-echo", repository_id="repo", generation=1,
        revision=0, repository_path=str(tmp_path), output_path=str(tmp_path / "out"))
    events = io.StringIO()
    serve(request, control=io.StringIO(""), events=events)
    messages = [json.loads(line) for line in events.getvalue().splitlines()]
    assert messages and messages[0]["state"] == "queued" and messages[-1]["state"] == "failed"
    assert all(message["schema_version"] == schema for message in messages)
    assert all(parse_run_message(message).schema_version == schema for message in messages)
