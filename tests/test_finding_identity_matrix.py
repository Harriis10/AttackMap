"""C13 finding-identity matrix: paired saved-report fixtures through the real
comparison and suppression paths.

All fixtures under ``tests/fixtures/finding-identity/`` are SYNTHETIC paired
reports; ids inside them were computed with the shipped identity functions, so
the fixtures state exactly what a pre-migration and a current report record.

Moved-file semantics stated honestly here (verified by the moved-file pair):
the per-instance fingerprint is ``sha256(rule | file | normalized source line |
occurrence)`` — the line number is excluded (line drift is invisible) but the
file path is included, so a moved file yields a NEW instance fingerprint at the
new path while the aggregate identity (rule + entity) is unchanged. The removed
old instance is not separately reported: a move surfaces as "new instance",
never as a resolved finding, and no rename inference is attempted.
"""

import json
from pathlib import Path

import pytest

from attackmap.comparison import compare_report_files, compare_reports
from attackmap.diff import FindingSnapshot
from attackmap.finding_identity import finding_id, legacy_finding_id, legacy_id_aliases
from attackmap.models import Finding
from attackmap.suppress import apply_suppressions, collect_suppressions

FIXTURES = Path(__file__).parents[1] / "tests" / "fixtures" / "finding-identity"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def compare_pair(stem):
    return compare_report_files(FIXTURES / f"{stem}-baseline.json", FIXTURES / f"{stem}-current.json")


def test_title_and_recommendation_edit_is_persisted_not_new_or_resolved():
    result = compare_pair("title-edit")
    baseline, current = load("title-edit-baseline.json"), load("title-edit-current.json")
    assert result["counts"] == {"new": 0, "persisted": 1, "resolved": 0, "new_instances": 0,
                                "newly_suppressed": 0, "resolution_uncertain": 0}
    row = result["changes"]["persisted"][0]
    assert row["title"] == current["findings"][0]["title"] != baseline["findings"][0]["title"]
    assert row["id"] == baseline["findings"][0]["id"] == current["findings"][0]["id"]


def test_nearby_line_insertion_drifts_line_numbers_but_not_instance_identity():
    result = compare_pair("line-drift")
    assert result["counts"]["new"] == result["counts"]["resolved"] == 0
    assert result["counts"]["persisted"] == 1
    # Same fingerprint at drifted line 10 -> 14: no new instance, nothing resolved.
    assert result["counts"]["new_instances"] == 0
    assert not result["changes"]["new_instances"]


def test_duplicate_routes_keep_one_identity_and_surface_only_the_new_location():
    result = compare_pair("duplicate-routes")
    baseline, current = load("duplicate-routes-baseline.json"), load("duplicate-routes-current.json")
    orders_before, orders_after = baseline["findings"][0], current["findings"][0]
    users = current["findings"][1]
    assert finding_id(orders_before) == finding_id(orders_after)
    assert len(orders_after["locations"]) == 2  # one aggregate identity, two routes
    assert finding_id(orders_after) != finding_id(users)  # distinct entities stay distinct
    assert result["counts"] == {"new": 0, "persisted": 2, "resolved": 0, "new_instances": 1,
                                "newly_suppressed": 0, "resolution_uncertain": 0}
    assert result["changes"]["new_instances"][0]["new_instance_locations"] == ["src/routes/admin.py:40"]


def test_moved_file_persists_identity_and_reports_new_instance_not_resolution():
    result = compare_pair("moved-file")
    baseline, current = load("moved-file-baseline.json"), load("moved-file-current.json")
    assert finding_id(baseline["findings"][0]) == finding_id(current["findings"][0])
    assert result["counts"] == {"new": 0, "persisted": 1, "resolved": 0, "new_instances": 1,
                                "newly_suppressed": 0, "resolution_uncertain": 0}
    # The move appears only as an added instance at the new path; the dropped
    # old fingerprint is not reported as a resolution (and never guessed as a
    # rename).
    assert result["changes"]["new_instances"][0]["new_instance_locations"] == ["src/handlers/handler.py:3"]


def test_old_baseline_migrates_via_recorded_rule_and_flags_unmappable_records():
    baseline, current = load("old-baseline.json"), load("old-baseline-current.json")
    result = compare_reports(baseline, current, baseline_path="old", current_path="new")
    counts = result["counts"]
    # The title-edited sql-injection finding persists through its recorded
    # rule+entity; both shared-title findings persist on their distinct rules.
    assert counts["persisted"] == 3 and counts["new"] == 0 and counts["resolved"] == 0
    # The rule-less legacy record cannot be mapped: its disappearance stays
    # uncertain for review instead of being resolved or dropped.
    assert counts["resolution_uncertain"] == 1
    uncertain = result["changes"]["resolution_uncertain"][0]
    assert uncertain["title"] == "Legacy plugin finding without rule"
    assert "no structured source location" in uncertain["resolution_reason"]
    notes = "\n".join(result["notes"])
    assert "Ambiguous legacy finding id" in notes and "74a031af3f0b5f03" in notes
    assert "Legacy finding without title/rule_id cannot be migrated" in notes


def test_foreign_recorded_baseline_id_is_flagged_not_silently_reidentified():
    baseline, current = load("title-edit-baseline.json"), load("title-edit-current.json")
    baseline["findings"][0]["id"] = "deadbeefdeadbeef"  # matches neither old nor new identity
    result = compare_reports(baseline, current)
    assert result["counts"]["persisted"] == 1  # identity is recomputed from rule+entity …
    assert any("Unrecognized finding id 'deadbeefdeadbeef'" in note for note in result["notes"])  # … and flagged


def test_legacy_suppression_round_trips_reason_and_provenance_through_migration(tmp_path):
    baseline, current = load("old-baseline.json"), load("old-baseline-current.json")
    migration = legacy_id_aliases(baseline["findings"])
    assert migration.aliases == {legacy_finding_id("SQL query built from user input"):
                                 finding_id(current["findings"][0])}
    assert not migration.aliases.get("74a031af3f0b5f03")  # ambiguous id never acquires an alias
    findings = [Finding.model_validate(record) for record in current["findings"]]
    suppset, warnings = collect_suppressions(
        tmp_path, findings, explicit_file=FIXTURES / "legacy-suppress.yaml",
        enable_inline=False, id_aliases=migration.aliases)
    assert not warnings
    outcome = apply_suppressions(findings, suppset)
    # The title-edited finding stays suppressed under its new stable id, with
    # the recorded reason and governance provenance intact.
    suppressed = outcome.suppressed[0]
    assert suppressed.id == finding_id(current["findings"][0])
    assert suppressed.reason == "accepted risk, tracked in SEC-1001"
    assert suppressed.matched[0].owner == "appsec"
    assert suppressed.matched[0].ticket == "https://tracker.example/SEC-1001"
    # The ambiguous legacy reference hides neither shared-title finding.
    assert {f.title for f in outcome.active} == {"Shared prose title"}
    assert len(outcome.active) == 2
    notices = "\n".join(outcome.notices)
    assert "legacy title-based reference" in notices
    assert "matches multiple rules" in notices


def test_migration_without_aliases_leaves_title_edited_finding_visible(tmp_path):
    # Without the baseline-derived aliases the legacy id matches nothing after
    # the title edit: the finding reappears for review, it is not hidden.
    current = load("old-baseline-current.json")
    findings = [Finding.model_validate(record) for record in current["findings"]]
    suppset, _ = collect_suppressions(
        tmp_path, findings, explicit_file=FIXTURES / "legacy-suppress.yaml", enable_inline=False)
    outcome = apply_suppressions(findings, suppset)
    assert len(outcome.active) == 3 and not outcome.suppressed


def test_baseline_snapshots_round_trip_finding_ids_from_saved_reports():
    for name in ("title-edit-current.json", "old-baseline.json", "old-baseline-current.json"):
        for record in load(name)["findings"]:
            assert FindingSnapshot.from_dump(record).id == finding_id(record)
