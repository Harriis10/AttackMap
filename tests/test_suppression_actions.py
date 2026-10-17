import copy
import json
from pathlib import Path

import pytest
import yaml

from attackmap.finding_identity import finding_id, legacy_finding_id
from attackmap.safe_fs import UnsafePathError
from attackmap.suppression_actions import (
    apply_suppression_action, execute_suppression_action, preview_suppression_action,
    recover_suppression_action, undo_suppression_action,
)
from attackmap.suppress import apply_suppressions, collect_suppressions
from attackmap.models import Finding, FindingLocation


@pytest.fixture
def finding():
    return Finding(title="Authorization check missing", rule_id="missing-authorization",
        severity="high", mitigation="Review authorization", locations=[FindingLocation(file="app.py", line=2)])


def preview(root, finding, **kwargs):
    return preview_suppression_action(root, finding, reason="Accepted risk tracked by engineering", **kwargs)


def test_preview_is_readonly_and_apply_undo_new_file_roundtrips_engine(tmp_path, finding):
    plan = preview(tmp_path, finding, owner="security-team", ticket="SEC-123", report_run_id="run-1")
    target = tmp_path / ".attackmap-suppress.yaml"
    assert not target.exists()
    assert plan["entry"]["id"] == finding_id(finding)
    assert plan["can_apply"] is True
    assert "+" in plan["diff"]
    receipt = apply_suppression_action(json.loads(json.dumps(plan)))
    document = yaml.safe_load(target.read_text())
    assert document["suppress"][0]["reason"] == "Accepted risk tracked by engineering"
    assert document["suppress"][0]["owner"] == "security-team"
    assert document["suppress"][0]["provenance"]["report_run_id"] == "run-1"
    configured, _ = collect_suppressions(tmp_path, [finding])
    result = apply_suppressions([finding], configured)
    assert result.count == 1
    assert result.suppressed[0].reason == "Accepted risk tracked by engineering"
    assert undo_suppression_action(json.loads(json.dumps(receipt)))["status"] == "undone"
    assert not target.exists()


def test_existing_reason_provenance_unknown_settings_and_exact_undo_bytes_are_preserved(tmp_path, finding):
    target = tmp_path / ".attackmap-suppress.yaml"
    original = b"# team-owned config\r\nversion: 1\r\nteam_setting: keep\r\nsuppress:\r\n- id: 0123456789abcdef\r\n  reason: old accepted reason\r\n  provenance:\r\n    owner_note: retained\r\n"
    target.write_bytes(original)
    before = yaml.safe_load(original)
    receipt = apply_suppression_action(preview(tmp_path, finding))
    after = yaml.safe_load(target.read_bytes())
    assert after["team_setting"] == before["team_setting"]
    assert after["suppress"][0] == before["suppress"][0]
    undo_suppression_action(receipt)
    assert target.read_bytes() == original


def test_stable_identity_survives_title_and_line_changes(tmp_path, finding):
    renamed = finding.model_copy(update={"title": "New display title", "locations": [FindingLocation(file="app.py", line=99)]})
    assert preview(tmp_path, finding)["entry"]["id"] == preview(tmp_path, renamed)["entry"]["id"]


def test_legacy_reference_requires_explicit_review_and_writes_current_stable_id(tmp_path, finding):
    record = finding.model_dump(mode="json")
    record["id"] = legacy_finding_id(finding.title)
    plan = preview(tmp_path, record)
    assert plan["identity_review"]["legacy_review_required"]
    assert not plan["can_apply"]
    with pytest.raises(ValueError, match="explicit review"):
        apply_suppression_action(plan)
    reviewed = preview(tmp_path, record, legacy_reviewed=True)
    receipt = apply_suppression_action(reviewed)
    assert receipt["plan"]["entry"]["id"] == finding_id(finding)
    assert receipt["plan"]["entry"]["provenance"]["recorded_id"] == record["id"]


def test_ruleless_legacy_finding_is_not_silently_mapped(tmp_path):
    finding = {"title": "Legacy plugin finding"}
    plan = preview(tmp_path, finding)
    assert plan["identity_review"]["identity_scheme"] == "legacy-title/v1"
    assert not plan["can_apply"]
    assert preview(tmp_path, finding, legacy_reviewed=True)["can_apply"]


def test_unknown_recorded_identity_is_refused(tmp_path, finding):
    record = finding.model_dump(mode="json")
    record["id"] = "unknown-reference"
    with pytest.raises(ValueError, match="Unrecognized finding"):
        preview(tmp_path, record)


@pytest.mark.parametrize("reason", ["", "  ", None, "x\0y", "x" * 2001])
def test_mandatory_bounded_reason(tmp_path, finding, reason):
    with pytest.raises(ValueError):
        preview_suppression_action(tmp_path, finding, reason=reason)


@pytest.mark.parametrize("field,value", [("after_text", "malicious"), ("before_text", "invented"),
    ("after_sha256", "0" * 64), ("relative_path", "../outside.yaml"), ("diff", "innocent preview"),
    ("can_apply", False), ("action_id", "injected")])
def test_tampered_plan_is_refused_before_writes(tmp_path, finding, field, value):
    plan = preview(tmp_path, finding)
    plan[field] = value
    with pytest.raises(ValueError):
        apply_suppression_action(plan)
    assert not (tmp_path / ".attackmap-suppress.yaml").exists()


def test_apply_and_undo_refuse_changed_files(tmp_path, finding):
    plan = preview(tmp_path, finding)
    target = tmp_path / ".attackmap-suppress.yaml"
    target.write_text("version: 1\nsuppress: []\n")
    with pytest.raises(ValueError, match="changed"):
        apply_suppression_action(plan)
    target.unlink()
    receipt = apply_suppression_action(plan)
    target.write_text(target.read_text() + "manual_setting: retained\n")
    changed = target.read_bytes()
    with pytest.raises(ValueError, match="changed"):
        undo_suppression_action(receipt)
    assert target.read_bytes() == changed
    assert recover_suppression_action(plan)["status"] == "review_required"


def test_postcommit_exception_can_recover_receipt_from_durable_plan(tmp_path, finding, monkeypatch):
    import attackmap.suppression_actions as module
    plan = preview(tmp_path, finding)
    original = module.os.replace
    def interrupted(source, target):
        original(source, target)
        raise OSError("process exited before result delivery")
    monkeypatch.setattr(module.os, "replace", interrupted)
    with pytest.raises(OSError):
        apply_suppression_action(plan)
    recovery = recover_suppression_action(json.loads(json.dumps(plan)))
    assert recovery["status"] == "applied"
    assert execute_suppression_action("suppression_undo", {"plan": plan})["status"] == "undone"


def test_apply_retry_is_idempotent_without_duplicate_entries(tmp_path, finding):
    plan = preview(tmp_path, finding)
    receipt = apply_suppression_action(plan)
    repeated = apply_suppression_action(plan)
    assert repeated == receipt
    assert len(yaml.safe_load((tmp_path / ".attackmap-suppress.yaml").read_text())["suppress"]) == 1


def test_replace_failure_preserves_original(tmp_path, finding, monkeypatch):
    target = tmp_path / ".attackmap-suppress.yaml"
    target.write_text("version: 1\nsuppress: []\n")
    before = target.read_bytes()
    plan = preview(tmp_path, finding)
    def fail(*args):
        raise OSError("replace failed")
    monkeypatch.setattr("attackmap.suppression_actions.os.replace", fail)
    with pytest.raises(OSError):
        apply_suppression_action(plan)
    assert target.read_bytes() == before
    assert recover_suppression_action(plan)["status"] == "not_applied"
    assert not list(tmp_path.glob(".attackmap-suppression-*.tmp"))


def test_file_mutation_during_flush_is_not_overwritten(tmp_path, finding, monkeypatch):
    import attackmap.suppression_actions as module
    plan = preview(tmp_path, finding)
    target = tmp_path / ".attackmap-suppress.yaml"
    original = module.os.fsync
    def mutate(descriptor):
        target.write_text("manual source change")
        original(descriptor)
    monkeypatch.setattr(module.os, "fsync", mutate)
    with pytest.raises(ValueError, match="changed"):
        apply_suppression_action(plan)
    assert target.read_text() == "manual source change"


def test_symlink_target_and_repository_are_refused(tmp_path, finding):
    repo = tmp_path / "repo"; repo.mkdir()
    victim = tmp_path / "victim.yaml"; victim.write_text("version: 1\nsuppress: []\n")
    try:
        (repo / ".attackmap-suppress.yaml").symlink_to(victim)
        (tmp_path / "redirect").symlink_to(repo, target_is_directory=True)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    with pytest.raises(UnsafePathError):
        preview(repo, finding)
    with pytest.raises(UnsafePathError):
        preview(tmp_path / "redirect", finding)
    assert victim.read_text() == "version: 1\nsuppress: []\n"


def test_existing_yml_is_used_but_new_higher_priority_yaml_blocks_stale_preview(tmp_path, finding):
    (tmp_path / ".attackmap-suppress.yml").write_text("version: 1\nsuppress: []\n")
    plan = preview(tmp_path, finding)
    assert plan["relative_path"] == ".attackmap-suppress.yml"
    (tmp_path / ".attackmap-suppress.yaml").write_text("version: 1\nsuppress: []\n")
    with pytest.raises(ValueError, match="higher-priority"):
        apply_suppression_action(plan)


@pytest.mark.parametrize("content", ["version: 99\nsuppress: []", "[]", "suppress: not-a-list", "suppress: [not-an-object]", "[invalid YAML"])
def test_invalid_existing_configuration_is_preserved(tmp_path, finding, content):
    target = tmp_path / ".attackmap-suppress.yaml"; target.write_text(content)
    with pytest.raises(ValueError):
        preview(tmp_path, finding)
    assert target.read_text() == content


def test_json_bridge_preview_apply_undo_and_strict_payloads(tmp_path, finding):
    result = execute_suppression_action("suppression_preview", {"repo_root": str(tmp_path),
        "finding": finding.model_dump(mode="json"), "reason": "Reviewed risk", "report_run_id": "run-1"})
    assert result["status"] == "preview"
    applied = execute_suppression_action("suppression_apply", {"plan": result["plan"]})
    assert applied["status"] == "applied"
    undone = execute_suppression_action("suppression_undo", {"receipt": applied["receipt"]})
    assert undone["status"] == "undone"
    with pytest.raises(ValueError):
        execute_suppression_action("suppression_apply", {"plan": result["plan"], "confirmed": True})
