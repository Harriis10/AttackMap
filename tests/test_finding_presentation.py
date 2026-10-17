import json
from pathlib import Path

import pytest

from attackmap.finding_presentation import FindingPresentationIndex, MAX_CANDIDATES
from attackmap.models import Finding, ScanResult, Signal
from attackmap.report import write_reports


def finding(**kwargs):
    return Finding(title="Synthetic heuristic", severity="high", mitigation="Review synthetic control", rule_id="synthetic-rule", **kwargs)


def test_missing_support_is_explicit_and_scores_are_not_decomposed():
    context = FindingPresentationIndex(ScanResult(root=".")).for_finding(finding(score=90, exploitability=80))
    assert context["claim"]["runtime_verification"] == "unknown"
    assert context["source"]["role"] == "unknown"
    assert context["observed_controls"]["items"] == []
    assert context["trust_chain"]["status"] == "unknown"
    assert context["priority"]["point_contributions"] == "not_supplied"
    assert all(f["points"] is None for f in context["priority"]["factors"])


def test_exact_location_is_only_candidate_not_control_or_trust_link():
    scan = ScanResult(root=".", signals=[
        Signal(kind="auth", label="Synthetic auth", file="src/a.py", line=7,
               conflicts=[{"field": "auth", "values": ["present", "absent"]}]),
        Signal(kind="auth", label="Other line", file="src/a.py", line=8),
        Signal(kind="auth", label="Other basename", file="other/a.py", line=7),
    ])
    context = FindingPresentationIndex(scan).for_finding(finding(locations=[{"file": "src/a.py", "line": 7}]))
    candidates = context["evidence"]["candidates"]
    assert len(candidates) == 1
    assert candidates[0]["ownership"] == "unknown"
    assert set(candidates[0]["conflicts"][0]["values"]) == {"present", "absent"}
    assert context["observed_controls"]["status"] == "unknown"
    assert context["trust_chain"]["status"] == "unknown"
    assert context["source"]["role"] == "unclassified"


def test_source_policy_and_detector_owned_flow_remain_static():
    context = FindingPresentationIndex(ScanResult(root=".")).for_finding(finding(
        locations=[{"file": "tests/a.py", "line": 1}, {"file": "src/a.py", "line": 1}],
        code_flows=[[{"file": "src/a.py", "line": 1, "kind": "source"}, {"file": "src/a.py", "line": 2, "kind": "sink"}]],
    ), suppression_reason="Synthetic suppression")
    assert context["source"]["role"] == "mixed"
    assert context["source"]["locations"][0]["low_quality_source"]
    assert context["trust_chain"]["status"] == "detector_owned_static_flow"
    assert context["trust_chain"]["trust_boundary_crossing"] == "unknown"
    assert context["claim"]["runtime_verification"] == "unknown"
    assert context["suppression"]["state"] == "suppressed"


def test_candidate_details_are_bounded_and_deterministic():
    signals = [Signal(kind="auth", label=f"Synthetic {i}", file="a.py", line=1) for i in range(20)]
    f = finding(locations=[{"file": "a.py", "line": 1}])
    first = FindingPresentationIndex(ScanResult(root=".", signals=signals)).for_finding(f)
    second = FindingPresentationIndex(ScanResult(root=".", signals=list(reversed(signals)))).for_finding(f)
    assert first == second
    assert len(first["evidence"]["candidates"]) == MAX_CANDIDATES
    assert first["evidence"]["candidates_truncated"]


def test_report_contains_precomputed_context(tmp_path):
    scan = ScanResult(root=".")
    write_reports(tmp_path, scan, "# Synthetic", "# Synthetic", "# Synthetic", [], [finding()], [])
    payload = json.loads((tmp_path / "attackmap-report.json").read_text(encoding="utf-8"))
    row = payload["findings"][0]
    assert row["context"]["finding_id"] == row["id"]
    assert row["context"]["context_version"] == "1.0"


@pytest.mark.parametrize("name", ["previous", "current", "partial-coverage", "suppressed"])
def test_workflow_goldens_never_gain_unowned_associations(name):
    path = Path(__file__).parents[1] / "fixtures" / "desktop-workflows" / f"{name}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    index = FindingPresentationIndex(ScanResult.model_validate(payload["scan"]))
    for row in payload["findings"]:
        context = index.for_finding(Finding.model_validate(row))
        assert context["observed_controls"]["status"] == "unknown"
        assert context["claim"]["runtime_verification"] == "unknown"
        assert context["trust_chain"]["trust_boundary_crossing"] == "unknown"


def test_empty_source_reference_is_unknown():
    context = FindingPresentationIndex(ScanResult(root=".")).for_finding(finding(locations=[{"file": ""}]))
    assert context["source"]["role"] == "unknown"
