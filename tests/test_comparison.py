"""Coverage-aware comparison is shared core semantics, not a desktop policy."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from attackmap.comparison import compare_report_files, compare_reports
from attackmap.diff import ComparisonCoverage, FindingSnapshot, diff_findings, render_diff_markdown

FIXTURES = Path(__file__).parents[1] / "fixtures" / "desktop-workflows"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_complete_and_partial_golden_comparisons_are_distinct():
    expected = load("expected.json")
    for filename, case in (("current.json", "complete_diff"), ("partial-coverage.json", "partial_diff")):
        before, current = load("previous.json"), load(filename)
        original = copy.deepcopy((before, current))
        result = compare_reports(before, current)
        assert result["comparison_version"] == "1.0"
        for group, keys in expected[case].items():
            assert {row["id"] for row in result["changes"][group]} == {expected["finding_ids"][key] for key in keys}
        assert (before, current) == original
        assert all(row["evidence_basis"] == "unknown" for rows in result["changes"].values() for row in rows)
    uncertain = result["changes"]["resolution_uncertain"][0]
    assert "not included" in uncertain["resolution_reason"]
    assert result["counts"]["resolved"] == result["counts"]["resolution_uncertain"] == 1


@pytest.mark.parametrize("coverage", [None, [], ["wrong-file.ts"], [1]])
def test_unknown_or_uncovered_sources_never_resolve_from_file_count(coverage):
    previous, current = load("previous.json"), load("current.json")
    current["scan"]["scanned_files"] = coverage
    current["scan"]["files_scanned"] = 999999
    result = compare_reports(previous, current)
    assert result["changes"]["resolved"] == []
    assert len(result["changes"]["resolution_uncertain"]) == 1


def test_analyzer_failure_keeps_disappearance_uncertain_even_when_file_scanned():
    previous, current = load("previous.json"), load("current.json")
    current["scan"]["analyzer_errors"] = [{"analyzer": "fixture", "error": "synthetic failure"}]
    result = compare_reports(previous, current)
    assert not result["changes"]["resolved"]
    assert "analyzer failures" in result["changes"]["resolution_uncertain"][0]["resolution_reason"]


def test_missing_structured_location_cannot_prove_resolution():
    previous, current = load("current.json"), load("current.json")
    current["findings"] = [row for row in current["findings"] if row["fixture_key"] != "e"]
    result = compare_reports(previous, current)
    assert not result["changes"]["resolved"]
    assert "no structured source location" in result["changes"]["resolution_uncertain"][0]["resolution_reason"]


def test_legacy_shape_reads_but_coverage_remains_unknown():
    previous = {"scan": {"root": "fixture"}, "findings": [{"title": "Legacy", "severity": "high"}]}
    current = {"scan": {"root": "fixture", "files_scanned": 100}, "findings": []}
    result = compare_reports(previous, current)
    assert result["counts"]["resolution_uncertain"] == 1 and result["counts"]["resolved"] == 0
    assert any("Legacy baseline" in note for note in result["notes"])


def test_selected_file_paths_and_hashes_identify_exact_inputs():
    before, current = FIXTURES / "previous.json", FIXTURES / "current.json"
    result = compare_report_files(before, current)
    for field, path in (("baseline", before), ("current", current)):
        assert result[field]["report_path"] == str(path.resolve())
        assert result[field]["report_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_cross_repository_comparison_fails_actionably():
    previous, current = load("previous.json"), load("current.json")
    current["scan"]["root"] = "different-repository"
    with pytest.raises(ValueError, match="different repositories"):
        compare_reports(previous, current)


def test_versioned_envelope_cannot_be_mistaken_for_saved_report():
    previous, current = load("previous.json"), load("current.json")
    current["schema_version"] = "future-version"
    with pytest.raises(ValueError, match="not saved reports"):
        compare_reports(previous, current)


def test_empty_source_name_cannot_prove_resolution():
    previous, current = load("previous.json"), load("current.json")
    missing = next(row for row in previous["findings"] if row["fixture_key"] == "b")
    missing["locations"] = [{"file": ""}]
    current["scan"]["scanned_files"].append("")
    result = compare_reports(previous, current)
    assert not result["changes"]["resolved"]
    assert "no structured source location" in result["changes"]["resolution_uncertain"][0]["resolution_reason"]


def test_legacy_diff_call_contract_is_unchanged_but_opt_in_renders_uncertainty():
    baseline = [FindingSnapshot.from_dump(row) for row in load("previous.json")["findings"]]
    legacy = diff_findings(baseline, [])
    assert len(legacy.resolved) == 4 and "resolution_uncertain" not in legacy.counts()
    aware = diff_findings(baseline, [], current_coverage=ComparisonCoverage())
    assert not aware.resolved and len(aware.resolution_uncertain) == 4
    assert "Resolution uncertain due to changed coverage" in render_diff_markdown(aware)


def test_added_instances_remain_visible_in_semantic_output():
    previous, current = load("previous.json"), load("previous.json")
    current["findings"][0]["locations"].append({"file": "synthetic/new.ts", "line": 5, "fingerprint": "synthetic-new"})
    result = compare_reports(previous, current)
    assert result["counts"]["new_instances"] == 1
    assert result["changes"]["new_instances"][0]["new_instance_locations"] == ["synthetic/new.ts:5"]
