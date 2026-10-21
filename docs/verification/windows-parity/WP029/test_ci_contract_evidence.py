"""Lightweight CI helper contract tests; no analyzer scan or build."""
import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("ci_contract_evidence", ROOT / "tools/ci_contract_evidence.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def test_inapplicable_is_failure_even_when_fixture_emits_data():
    with pytest.raises(ValueError, match="inapplicable"):
        helper.require_exercised("required", False, {"routes": 1}, [])


def test_errors_and_empty_output_are_not_passes():
    for counts, errors in (({}, []), ({"routes": 0}, []), ({"routes": 1}, ["failed"])):
        with pytest.raises(ValueError, match="failed or emitted no"):
            helper.require_exercised("required", True, counts, errors)


def test_applicable_structured_output_is_required():
    helper.require_exercised("required", True, {"routes": 1}, [])


def test_byte_identity_invalidates_on_fixture_change(tmp_path):
    target = tmp_path / "fixture"
    target.mkdir()
    source = target / "app.py"
    source.write_bytes(b"first\r\n")
    before = helper.hashed_inventory(tmp_path, ["fixture"])
    source.write_bytes(b"first\n")
    after = helper.hashed_inventory(tmp_path, ["fixture"])
    assert before["sha256"] != after["sha256"]
    assert list(before["files"]) == ["fixture/app.py"]


def test_missing_input_is_failure(tmp_path):
    with pytest.raises(ValueError, match="missing"):
        helper.hashed_inventory(tmp_path, ["absent"])


def test_generated_outputs_do_not_change_identity(tmp_path):
    (tmp_path / "consumer").mkdir()
    (tmp_path / "consumer/Program.cs").write_text("source")
    before = helper.hashed_inventory(tmp_path, ["consumer"])
    (tmp_path / "consumer/obj").mkdir()
    (tmp_path / "consumer/obj/output").write_text("build")
    assert before == helper.hashed_inventory(tmp_path, ["consumer"])


def test_workflow_has_separate_real_consumers_and_no_allow_failure():
    import yaml
    workflow = yaml.load((ROOT / ".github/workflows/client-contract-fixtures.yml").read_text(encoding="utf-8-sig"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"push", "pull_request", "workflow_dispatch"}
    assert "paths" not in workflow["on"]["pull_request"]
    jobs = workflow["jobs"]
    assert jobs["windows-consumer"]["runs-on"] == "windows-latest"
    assert jobs["client-fixture-suites"]["runs-on"] == "ubuntu-latest"
    assert {row["group"] for row in jobs["analyzer-fixtures"]["strategy"]["matrix"]["include"]} == set(helper.GROUPS)
    assert "continue-on-error" not in json_text(workflow)
    for job in jobs.values():
        checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        assert checkout["with"]["ref"] == "${{ github.sha }}"


def json_text(value):
    import json
    return json.dumps(value)


def test_foreign_core_import_cannot_borrow_checkout_identity(tmp_path, monkeypatch):
    from types import ModuleType
    import sys
    foreign = ModuleType("attackmap")
    foreign.__file__ = str(tmp_path / "stale-snapshot/attackmap/__init__.py")
    monkeypatch.setitem(sys.modules, "attackmap", foreign)
    with pytest.raises(ValueError, match="not the checkout"):
        helper.assert_core_origin()
    with pytest.raises(ValueError, match="preloaded core may be stale"):
        helper.require_fresh_core_import()


def test_output_inside_hashed_inputs_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "input_paths", lambda root: ["inputs"])
    with pytest.raises(ValueError, match="outside"):
        helper.assert_output_scope(tmp_path / "inputs/result.json", tmp_path)
    helper.assert_output_scope(tmp_path / "evidence/result.json", tmp_path)


def test_changed_inputs_during_execution_prevent_evidence_write(tmp_path, monkeypatch):
    import sys
    output = tmp_path / "result.json"
    monkeypatch.setattr(sys, "argv", ["helper", "--mode", "analyzers", "--group", "node", "--output", str(output)])
    monkeypatch.setattr(helper, "assert_output_scope", lambda path: None)
    monkeypatch.setattr(helper, "require_fresh_core_import", lambda: None)
    monkeypatch.setattr(helper, "assert_core_origin", lambda: None)
    monkeypatch.setattr(helper, "evidence_identity", lambda: {"input_identity": {"sha256": "before", "files": {}}})
    monkeypatch.setattr(helper, "exercise", lambda group: {"scope": "injected transport test only"})
    monkeypatch.setattr(helper, "hashed_inventory", lambda *args: {"sha256": "after", "files": {}})
    with pytest.raises(ValueError, match="changed during execution"):
        helper.main()
    assert not output.exists()
