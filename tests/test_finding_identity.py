"""Stable aggregate identity, exact legacy migration, and collision visibility."""
import json

import pytest

from attackmap.diff import FindingSnapshot, diff_findings, load_baseline, render_diff_markdown
from attackmap.finding_identity import dependency_entity_id, finding_id, legacy_finding_id, legacy_id_aliases
from attackmap.models import Finding, FindingLocation, ScanResult, Vulnerability
from attackmap.report import write_reports
from attackmap.suppress import Suppression, SuppressionSet, apply_suppressions


def finding(title="Old title", **changes):
    return Finding(title=title, rule_id="test-stable-rule", severity="high", mitigation="Fix it",
                   **changes)


def test_title_recommendation_severity_and_location_addition_do_not_replace_aggregate():
    before = finding(locations=[FindingLocation(file="a.py", line=1, fingerprint="one")])
    after = before.model_copy(update={"title": "Clearer title", "mitigation": "Better recommendation",
                                     "severity": "low", "locations": [*before.locations,
                                         FindingLocation(file="b.py", line=2, fingerprint="two")]})
    assert finding_id(before) == finding_id(after)
    diff = diff_findings([FindingSnapshot.from_finding(before)], [FindingSnapshot.from_finding(after)])
    assert not diff.new and not diff.resolved
    assert diff.persisted[0].title == "Clearer title"
    assert diff.new_instances[0][1] == ["b.py:2"]


def test_same_title_distinct_rules_have_distinct_ids():
    assert finding_id(finding()) != finding_id(finding().model_copy(update={"rule_id": "other-rule"}))


def test_same_rule_distinct_explicit_entities_do_not_collide():
    first = finding(entity_id="service:a")
    second = finding(entity_id="service:b")
    assert finding_id(first) != finding_id(second)
    diff = diff_findings([], [FindingSnapshot.from_finding(first), FindingSnapshot.from_finding(second)])
    assert len(diff.new) == 2


def test_dependency_entity_key_never_serializes_source_credentials():
    source = "https://user:private-sentinel-password@example.invalid/private-sentinel-version"
    entity = dependency_entity_id("npm", "package", source)
    assert entity.startswith("dependency/v1:")
    assert len(entity.removeprefix("dependency/v1:")) == 64
    assert "private-sentinel" not in entity and "user" not in entity and "https" not in entity
    assert entity == dependency_entity_id("npm", "package", source)
    assert entity != dependency_entity_id("npm", "package", source + "changed")
    current = finding(entity_id=entity)
    assert "private-sentinel" not in json.dumps(current.model_dump())


def test_explicit_rule_rename_remains_new_and_resolved_without_guessed_mapping():
    old = finding()
    new = old.model_copy(update={"rule_id": "renamed-rule"})
    diff = diff_findings([FindingSnapshot.from_finding(old)], [FindingSnapshot.from_finding(new)])
    assert len(diff.new) == len(diff.resolved) == 1 and not diff.persisted


def test_file_rename_is_visible_as_new_instance_without_guessed_mapping(tmp_path):
    from attackmap.fingerprint import assign_fingerprints
    for name in ("before.py", "after.py"):
        (tmp_path / name).write_text("run(value)\n")
    old = finding(locations=[FindingLocation(file="before.py", line=1)])
    new = finding("Clearer title", locations=[FindingLocation(file="after.py", line=1)])
    assign_fingerprints([old, new], tmp_path)
    diff = diff_findings([FindingSnapshot.from_finding(old)], [FindingSnapshot.from_finding(new)])
    assert len(diff.persisted) == 1
    assert diff.new_instances[0][1] == ["after.py:1"]


def test_core_dependency_emitter_has_distinct_stable_entities_and_legacy_adapter():
    from attackmap.threat_model import generate_findings
    scan = ScanResult(root="fixture", vulnerabilities=[
        Vulnerability(id="CVE-fixture-a", ecosystem="npm", package_name=name,
                      package_version="1.0.0", severity="high", summary="Fixture")
        for name in ("@scope/one", "two")
    ])
    findings = [f for f in generate_findings(scan) if f.rule_id == "vulnerable-dependency"]
    assert len(findings) == 2
    assert len({f.entity_id for f in findings}) == len({finding_id(f) for f in findings}) == 2
    for current in findings:
        legacy = current.model_dump(exclude={"entity_id"})
        legacy["id"] = legacy_finding_id(current.title)
        assert finding_id(legacy) == finding_id(current)
        assert legacy_id_aliases([legacy]).aliases[legacy["id"]] == finding_id(current)
        renamed = current.model_copy(update={"title": "New title", "mitigation": "New recommendation"})
        assert finding_id(renamed) == finding_id(current)
    diff = diff_findings([FindingSnapshot.from_finding(f) for f in findings],
                         [FindingSnapshot.from_finding(f.model_copy(update={"title": "Reworded"})) for f in findings])
    assert len(diff.persisted) == 2 and not diff.new and not diff.resolved


def test_unrecoverable_legacy_dependency_is_retained_for_review():
    record = {"rule_id": "vulnerable-dependency", "title": "Edited old prose", "severity": "high"}
    snapshot = FindingSnapshot.from_dump(record)
    assert snapshot.id == legacy_finding_id(record["title"])
    diff = diff_findings([snapshot], [])
    assert diff.resolved == [snapshot]
    assert "no recoverable package entity" in render_diff_markdown(diff)
    assert legacy_id_aliases([record]).aliases == {}


def test_existing_baseline_with_old_title_id_migrates_using_recorded_rule(tmp_path):
    old = finding()
    record = {"id": legacy_finding_id(old.title), **old.model_dump()}
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"findings": [record]}))
    new = finding("New title")
    diff = diff_findings(load_baseline(path), [FindingSnapshot.from_finding(new)])
    assert len(diff.persisted) == 1 and not diff.new and not diff.resolved


def test_legacy_suppression_reference_matches_unchanged_title_with_migration_notice():
    current = finding()
    outcome = apply_suppressions([current], SuppressionSet([
        Suppression(id=legacy_finding_id(current.title), reason="reviewed")]))
    assert outcome.suppressed[0].id == finding_id(current)
    assert "legacy title-based reference" in outcome.notices[0]


def test_baseline_adapter_migrates_old_suppression_across_title_edit():
    old = finding()
    migration = legacy_id_aliases([old.model_dump()])
    assert not migration.notices
    current = finding("New title")
    outcome = apply_suppressions([current], SuppressionSet([
        Suppression(id=legacy_finding_id(old.title), reason="reviewed")], id_aliases=migration.aliases))
    assert not outcome.active and len(outcome.suppressed) == 1
    assert outcome.suppressed[0].id == finding_id(current)


def test_unmappable_and_ambiguous_records_never_get_guessed_aliases():
    records = [finding().model_dump(), finding().model_copy(update={"rule_id": "other"}).model_dump(),
               {"title": "No recorded rule"}, {"title": "Foreign", "rule_id": "test", "id": "foreign"}]
    migration = legacy_id_aliases(records)
    assert migration.aliases == {}
    assert len(migration.notices) == 3


def test_unmapped_legacy_suppression_remains_visible_and_does_not_hide_renamed_finding():
    outcome = apply_suppressions([finding("New title")], SuppressionSet([
        Suppression(id=legacy_finding_id("Old title"), reason="reviewed")]))
    assert len(outcome.active) == 1 and not outcome.suppressed
    assert "matched no findings" in outcome.notices[0]


def test_ambiguous_legacy_title_selector_cannot_hide_two_distinct_rules():
    first = finding()
    second = first.model_copy(update={"rule_id": "other-rule"})
    outcome = apply_suppressions([first, second], SuppressionSet([
        Suppression(id=legacy_finding_id(first.title), reason="legacy")]))
    assert len(outcome.active) == 2 and not outcome.suppressed
    assert any("matches multiple rules" in notice for notice in outcome.notices)


def test_ruleless_baseline_is_retained_and_visible_for_review():
    old = FindingSnapshot.from_dump({"title": "Legacy", "severity": "high"})
    diff = diff_findings([old], [])
    assert diff.resolved == [old]
    assert "Legacy baseline" in render_diff_markdown(diff)


@pytest.mark.parametrize("data", [[None], {"findings": ["unmappable"]}, {"findings": "unmappable"}, 42])
def test_malformed_baseline_records_are_reported_instead_of_silently_dropped(tmp_path, data):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unmappable"):
        load_baseline(path)


@pytest.mark.parametrize("side", ["baseline", "current", "suppressed"])
def test_duplicate_rule_identity_fails_visibly_instead_of_overwriting(side):
    snapshots = [FindingSnapshot.from_finding(finding()), FindingSnapshot.from_finding(finding("Another title"))]
    args = {"baseline": [], "current": [], "suppressed": []}
    args[side] = snapshots
    with pytest.raises(ValueError, match="Ambiguous finding identity"):
        diff_findings(**args)


@pytest.mark.parametrize("with_location", [False, True])
def test_json_baseline_suppression_and_sarif_identity_survive_prose_edits(tmp_path, with_location):
    old = finding(locations=[FindingLocation(file="app.py", line=2, fingerprint="fixed-instance")] if with_location else [])
    new = old.model_copy(update={"title": "New title", "mitigation": "New recommendation"})
    reports = []
    for index, current in enumerate([old, new]):
        folder = tmp_path / str(index)
        report = write_reports(folder, ScanResult(root="fixture"), "", "", "", [], [current], [], output_format="json")
        assert report["findings"][0]["id"] == finding_id(current)
        assert report["findings"][0]["identity_scheme"] == "rule-aggregate/v2"
        assert FindingSnapshot.from_dump(report["findings"][0]).id == finding_id(current)
        reports.append(json.loads((folder / "attackmap-report.sarif").read_text())["runs"][0]["results"][0])
    assert reports[0]["ruleId"] == reports[1]["ruleId"] == old.rule_id
    assert reports[0]["partialFingerprints"] == reports[1]["partialFingerprints"]
