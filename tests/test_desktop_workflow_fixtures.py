"""Shared C21/C23 golden scenarios; no native or detector policy is invented."""
import hashlib
import json
from pathlib import Path

import pytest

from attackmap.diff import FindingSnapshot, diff_findings, load_baseline
from attackmap.finding_identity import finding_id
from attackmap.models import Finding, ScanResult
from attackmap.suppress import SuppressionSet, apply_suppressions, parse_suppress_text

ROOT = Path(__file__).parents[1] / "fixtures" / "desktop-workflows"
EXPECTED = json.loads((ROOT / "expected.json").read_text(encoding="utf-8"))


def report(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def compare(name):
    current = report(name)
    return diff_findings(load_baseline(ROOT / "previous.json"), load_baseline(ROOT / name),
                         [FindingSnapshot.from_dump(row) for row in current["suppressed_findings"]])


@pytest.mark.parametrize("name", ["previous.json", "current.json", "partial-coverage.json", "suppressed.json"])
def test_canonical_shapes_identity_and_synthetic_evidence_labels(name):
    data = report(name)
    ScanResult.model_validate(data["scan"])
    assert data["fixture"]["synthetic"] is True
    for row in [*data["findings"], *data["suppressed_findings"]]:
        finding = Finding.model_validate(row)
        assert row["id"] == finding_id(finding)
        assert row["evidence_basis"] == "unknown"
        assert row["title"].startswith("SYNTHETIC")
        assert row["observed_controls"] == [] and row["trust_chain"] == []


def test_fixture_byte_hashes_are_fixed():
    for name, digest in EXPECTED["sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("name,scenario", [("current.json", "complete_diff"), ("suppressed.json", "suppressed_diff")])
def test_complete_comparisons_match_core_semantics(name, scenario):
    result = compare(name)
    expected = EXPECTED[scenario]
    for field in ("new", "persisted", "resolved", "newly_suppressed"):
        assert {row.id for row in getattr(result, field)} == {
            EXPECTED["finding_ids"][key] for key in expected[field]}
    assert not result.new_instances


def test_reasoned_suppression_is_reversible_without_mutating_finding():
    warnings = []
    selectors = parse_suppress_text((ROOT / "suppressions.yaml").read_text(), "fixture.yaml", warnings)
    candidate = next(row for row in report("previous.json")["findings"] if row["fixture_key"] == "c")
    finding = Finding.model_validate(candidate)
    suppressed = apply_suppressions([finding], SuppressionSet(selectors))
    assert not warnings and not suppressed.active and len(suppressed.suppressed) == 1
    assert suppressed.suppressed[0].reason == report("suppressed.json")["suppressed_findings"][0]["reason"]
    restored = apply_suppressions([finding], SuppressionSet([]))
    assert restored.active == [finding] and not restored.suppressed
    assert finding_id(restored.active[0]) == candidate["id"]


def test_conflicting_missing_unicode_long_and_source_changed_cases_are_explicit():
    data = report("current.json")
    keyed = {row["fixture_key"]: row for row in data["findings"]}
    assert keyed["a"]["fixture_conflicts"][0]["values"] == ["required", "unknown"]
    assert keyed["e"]["locations"] == [] and "unavailable" in keyed["e"]["uncertainty"][-1]
    path = keyed["d"]["locations"][0]["file"]
    assert len(path) > 260 and "žluťoučký" in path
    source = data["fixture"]["source_snapshot"]
    snapshot = (ROOT / source["snapshot_file"]).read_bytes()
    live = (ROOT / source["live_file"]).read_bytes()
    assert hashlib.sha256(snapshot).hexdigest() == source["snapshot_sha256"]
    assert hashlib.sha256(live).hexdigest() != source["snapshot_sha256"]
    assert source["expected_action"] == "warn live source differs from snapshot"


def test_partial_coverage_removal_is_uncertain_rather_than_resolved():
    from attackmap.comparison import compare_report_files
    data = report("partial-coverage.json")
    assert data["fixture"]["coverage"]["status"] == "partial"
    result = compare_report_files(ROOT / "previous.json", ROOT / "partial-coverage.json")
    uncertain = EXPECTED["finding_ids"]["d"]
    assert uncertain not in {row["id"] for row in result["changes"]["resolved"]}
    assert EXPECTED["finding_ids"]["b"] in {row["id"] for row in result["changes"]["resolved"]}
    assert uncertain in {row["id"] for row in result["changes"]["resolution_uncertain"]}
