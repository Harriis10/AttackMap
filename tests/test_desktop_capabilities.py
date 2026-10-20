"""Capability compatibility and raw-request admission; no provider/network calls."""
import json
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.desktop_actions import ActionRequest, execute_action, run_action_file
from attackmap.desktop_capabilities import (
    build_capabilities, executable_identity, module_inventory,
    preflight_capabilities, validate_desktop_request,
)
from attackmap.desktop_worker import run_request_file
from attackmap.run_contract import RunRequest, ScanOptions, ScanOptionsV12, SUPPORTED_SCHEMA_VERSIONS


def request(tmp_path, schema="1.1"):
    return RunRequest(schema_version=schema, run_id="preflight-1", repository_id="repo",
                      generation=1, revision=0, repository_path=str(tmp_path),
                      output_path=str(tmp_path / "results")).model_dump(mode="json")


@pytest.fixture
def caps():
    return build_capabilities(app, metadata=[])


def test_cli_and_action_share_capabilities_and_module_inventory(monkeypatch):
    from attackmap.analyzers import get_available_modules
    expected_modules = module_inventory(get_available_modules())
    cli = CliRunner().invoke(app, ["capabilities"])
    assert cli.exit_code == 0, cli.output
    actual = execute_action(ActionRequest(request_id="caps", operation="capabilities",
                                         output_path="unused", payload={}))
    assert json.loads(cli.output) == actual
    assert actual["schema"] == 1
    assert actual["modules"] == expected_modules
    assert actual["desktop"]["scan_options"] == sorted(ScanOptionsV12.model_fields)
    assert actual["desktop"]["scan_options_by_schema"]["1.1"] == sorted(ScanOptions.model_fields)
    assert actual["desktop"]["schema_versions"] == list(SUPPORTED_SCHEMA_VERSIONS)
    assert actual["analyze"]["multi_repo"] is True
    assert actual["desktop"]["multi_repo"] is False
    modules = CliRunner().invoke(app, ["modules", "--json"])
    assert modules.exit_code == 0
    assert json.loads(modules.output) == expected_modules


@pytest.mark.parametrize("schema", ["1.0", "1.1"])
def test_supported_request_preflight(caps, tmp_path, schema):
    payload = request(tmp_path, schema)
    assert validate_desktop_request(payload).schema_version == schema
    assert preflight_capabilities(caps, request=payload) == {"supported": True, "status": "compatible"}


@pytest.mark.parametrize("mutation,status", [
    (lambda c: c.pop("desktop"), "legacy_engine_unsupported"),
    (lambda c: c.update(schema=99), "incompatible_capabilities_schema"),
    (lambda c: c.update(schema="1"), "malformed"),
    (lambda c: c.update(commands=[{}]), "malformed"),
    (lambda c: c["desktop"].update(schema_versions=["99.0"]), "incompatible_run_schema"),
    (lambda c: c.update(commands=["analyze"]), "missing_desktop_commands"),
    (lambda c: c["desktop"].update(scan_options=None), "malformed"),
])
def test_legacy_future_malformed_and_missing_command_are_deterministic(caps, mutation, status):
    mutation(caps)
    assert preflight_capabilities(caps) == {"supported": False, "status": status}


def test_identity_replacement_invalidates_cache_even_same_path_and_size(tmp_path, caps):
    candidate = tmp_path / "attackmap.exe"
    candidate.write_bytes(b"first-engine")
    identity = executable_identity(candidate)
    candidate.write_bytes(b"other-engine")
    replacement = executable_identity(candidate)
    assert identity["path"] == replacement["path"]
    assert identity["size_bytes"] == replacement["size_bytes"]
    assert identity["sha256"] != replacement["sha256"]
    assert preflight_capabilities(caps, expected_identity=replacement)["status"] == "engine_changed"
    with pytest.raises(ValueError, match="identity is unavailable"):
        executable_identity(tmp_path / "missing.exe")


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(schema_version="99.0"),
    lambda p: p["options"].update(mode="hunt"),
    lambda p: p["options"].update(suppress_file="secret-sentinel"),
    lambda p: p["options"].update(unknown_requested_feature=True),
    lambda p: p.update(fleet=["secret-sentinel"]),
    lambda p: p.update(llm_mode="remediate"),
    lambda p: p["options"]["provider"].update(backend="cli"),
    lambda p: p["options"]["provider"].update(provider="unsupported"),
])
@pytest.mark.parametrize("engine", [False, True])
def test_unsupported_request_fails_before_any_scan_or_provider(tmp_path, monkeypatch, capsys, mutation, engine):
    payload = request(tmp_path)
    mutation(payload)
    path = tmp_path / "request.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    dispatches = [Mock(side_effect=AssertionError("Unsupported request reached dispatch or provider"))
                  for _ in range(3)]
    monkeypatch.setattr("attackmap.desktop_worker.serve", dispatches[0])
    monkeypatch.setattr("attackmap.pipeline.run_scan", dispatches[1])
    monkeypatch.setattr("attackmap.desktop_provider.execute_provider_action", dispatches[2])
    assert run_request_file(path, engine=engine) == 2
    for dispatch in dispatches:
        dispatch.assert_not_called()
    captured = capsys.readouterr()
    assert "secret-sentinel" not in captured.out + captured.err
    assert not (tmp_path / "results").exists()


def test_additive_envelope_metadata_preserved_but_not_feature_options(tmp_path):
    payload = request(tmp_path)
    payload["client_metadata"] = {"version": "future additive metadata"}
    assert validate_desktop_request(payload).schema_version == "1.1"


@pytest.mark.parametrize("schema", ["1.0", "1.1"])
def test_valid_source_request_reaches_existing_broker(tmp_path, monkeypatch, schema):
    payload = request(tmp_path, schema)
    path = tmp_path / "request.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    called = []
    monkeypatch.setattr("attackmap.desktop_worker.serve", lambda value, **kwargs: called.append(value) or 0)
    assert run_request_file(path) == 0
    assert called[0].schema_version == schema


@pytest.mark.parametrize("frozen", [False, True])
@pytest.mark.parametrize("operation", ["capabilities", "preflight"])
def test_read_only_action_source_and_frozen_transport_no_provider(tmp_path, monkeypatch, frozen, operation):
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setenv("ATTACKMAP_ACTION_CREDENTIAL", "secret-sentinel")
    def forbidden(*args, **kwargs):
        pytest.fail("Capability discovery invoked provider")
    monkeypatch.setattr("attackmap.desktop_provider.execute_provider_action", forbidden)
    value = ActionRequest(request_id="probe", operation=operation, output_path=str(tmp_path / "out"),
                          payload={} if operation == "capabilities" else {"request": request(tmp_path)})
    path = tmp_path / "action.json"
    path.write_text(value.model_dump_json(), encoding="utf-8")
    assert run_action_file(path, engine=True) == 0
    raw = (tmp_path / "out/probe.result.json").read_text(encoding="utf-8")
    assert "secret-sentinel" not in raw
    result = json.loads(raw)["result"]
    if operation == "preflight":
        assert result["supported"] is True
    else:
        assert result["engine_identity"]["runtime_kind"] == ("Frozen" if frozen else "Python")


def test_remote_document_does_not_authorize_unsupported_local_mode(caps, tmp_path):
    payload = request(tmp_path)
    caps["desktop"]["modes"].append("hunt")
    payload["options"]["mode"] = "hunt"
    assert preflight_capabilities(caps, request=payload)["status"] == "unsupported_request"
    caps["desktop"]["modes"] = []
    payload["options"].pop("mode")
    assert preflight_capabilities(caps, request=payload)["status"] == "unsupported_request"


def test_explicit_unavailable_module_is_rejected(caps, tmp_path):
    payload = request(tmp_path)
    payload["modules"] = ["missing-analyzer"]
    assert preflight_capabilities(caps, request=payload)["status"] == "unsupported_request"
