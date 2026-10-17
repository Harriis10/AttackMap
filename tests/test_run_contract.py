import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from attackmap.run_contract import (
    RunArtifact, RunArtifactManifest, RunProgress, RunRequest, RunTerminal,
    accepts_update, import_legacy_report, parse_run_message,
)

BASE = dict(run_id="r1", repository_id="repo1", generation=1, revision=1)
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("path", sorted((ROOT / "fixtures/run-contract").glob("*.json")))
def test_shared_golden_messages(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    message = parse_run_message(payload)
    assert message.schema_version in {"1.0", "1.1"}
    assert "future_additive_field" not in message.model_dump()


@pytest.mark.parametrize("version", ["2.0", "1.2", "0.9", "garbage"])
def test_unsupported_versions_actionable(version):
    with pytest.raises(ValidationError, match="Upgrade the consumer"):
        RunProgress(**BASE, schema_version=version, state="running")


def test_schema_less_is_explicit_import_only():
    with pytest.raises(ValueError, match="import_legacy_report"):
        parse_run_message({"kind": "terminal"})
    legacy = {"scan": {"root": "C:/sample"}, "findings": []}
    terminal, original = import_legacy_report(legacy, run_id="import", repository_id="repo", generation=1)
    assert terminal.policy_outcome == "not_evaluated"
    assert terminal.artifact_readiness == "unavailable"
    assert terminal.limitations and original is legacy
    with pytest.raises(ValueError, match="Unsupported legacy"):
        import_legacy_report({}, run_id="r", repository_id="p", generation=1)


def test_policy_failure_is_completed_execution():
    terminal = RunTerminal(**BASE, state="completed", execution_outcome="succeeded", policy_outcome="failed", artifact_readiness="ready")
    assert terminal.state == "completed"
    with pytest.raises(ValidationError):
        RunTerminal(**BASE, state="failed", execution_outcome="succeeded")
    with pytest.raises(ValidationError):
        RunTerminal(**BASE, state="cancelled", execution_outcome="cancelled", artifact_readiness="ready")


def test_identity_ordering_and_terminal_are_authoritative():
    current = RunProgress(**BASE, state="running")
    assert not accepts_update(current, current)
    for changed in ({"run_id":"other"}, {"repository_id":"other"}, {"generation":2}):
        assert not accepts_update(current, RunProgress(**(BASE | changed | {"revision":2}), state="running"))
    assert not accepts_update(current, RunProgress(**(BASE | {"revision":2}), state="queued"))
    cancelling = RunProgress(**(BASE | {"revision":2}), state="cancelling")
    assert accepts_update(current, cancelling)
    assert not accepts_update(cancelling, RunProgress(**(BASE | {"revision":3}), state="running"))
    terminal = RunTerminal(**(BASE | {"revision":3}), state="cancelled", execution_outcome="cancelled")
    assert accepts_update(cancelling, terminal)
    assert not accepts_update(terminal, RunProgress(**(BASE | {"revision":4}), state="running"))


def test_progress_never_infers_whole_run_done():
    with pytest.raises(ValidationError):
        RunProgress(**BASE, state="completed")
    with pytest.raises(ValidationError):
        RunProgress(**BASE, state="running", completed_units=3,total_units=2)
    assert RunProgress(**BASE,state="running").total_units is None
    with pytest.raises(ValidationError):
        RunProgress(**(BASE | {"revision": True}),state="running")


@pytest.mark.parametrize("path", ["../outside", "C:/outside", "a/../b", "a\\b", "/outside"])
def test_manifest_paths_cannot_escape_generation(path):
    with pytest.raises(ValidationError):
        RunArtifact(path=path,media_type="application/json",sha256="0"*64,size_bytes=1)


@pytest.mark.parametrize("name,model", [("request",RunRequest),("progress",RunProgress),("terminal",RunTerminal),("manifest",RunArtifactManifest)])
def test_published_schemas_match_models(name,model):
    actual = json.loads((ROOT / f"schemas/run-{name}.schema.json").read_text(encoding="utf-8"))
    expected = model.model_json_schema()
    expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    expected["properties"]["schema_version"]["enum"] = ["1.0","1.1"]
    assert actual == expected


def test_manifest_rejects_duplicate_artifacts():
    item = RunArtifact(path="report.json",media_type="application/json",sha256="0"*64,size_bytes=1)
    with pytest.raises(ValidationError, match="unique"):
        RunArtifactManifest(**BASE,artifacts=[item,item])


def test_failed_execution_cannot_claim_policy_result():
    with pytest.raises(ValidationError, match="Only a completed"):
        RunTerminal(**BASE,state="failed",execution_outcome="failed",policy_outcome="passed")
