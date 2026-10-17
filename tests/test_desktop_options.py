"""Desktop options reach the shared engine without enabling network by default."""
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from attackmap.desktop_worker import run_request_file
from attackmap.run_contract import RunRequest, ScanOptions


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
    monkeypatch.setattr("attackmap.pipeline.run_scan",
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
