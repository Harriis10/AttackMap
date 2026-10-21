import json
from pathlib import Path

import pytest

from attackmap.exploitability import score_exploitability
from attackmap.index import ScanSnapshot
from attackmap.finding_presentation import FindingPresentationIndex, MAX_CANDIDATES
from attackmap.models import AttackSurface, Finding, ScanResult, Signal, TaintChain
from attackmap.report import write_reports


def finding(**kwargs):
    return Finding(title="Synthetic heuristic", severity="high", mitigation="Review synthetic control", rule_id="synthetic-rule", **kwargs)


def _with_fixture_scope(scan):
    # Synthetic fixture identity only; no live paths or RepoIndex are consulted.
    import hashlib
    files = {path: hashlib.sha256(("fixture:" + path).encode()).hexdigest()
             for c in scan.taint_chains for path in [c.route_file, c.sink_file]}
    scan.root = "/synthetic/repository"
    scan.scan_snapshot = ScanSnapshot.from_identity({"files": files}).identity()
    return scan


def test_missing_support_is_explicit_and_scores_are_not_decomposed():
    context = FindingPresentationIndex(ScanResult(root=".")).for_finding(finding(score=90, exploitability=80))
    assert context["claim"]["runtime_verification"] == "unknown"
    assert context["source"]["role"] == "unknown"
    assert context["observed_controls"]["items"] == []
    assert context["trust_chain"]["status"] == "unknown"
    # No factor list was supplied, so nothing may pretend to be decomposed.
    assert context["priority"]["point_contributions"] == "not_supplied"
    assert context["priority"]["decomposition"] == []
    assert all(f["points"] is None for f in context["priority"]["factors"])
    assumptions = " ".join(context["priority"]["unresolved_assumptions"])
    assert "not calibrated probabilities" in assumptions
    assert "factor list was not supplied" in assumptions
    assert "source-quality weighting cannot be applied" in assumptions


def test_ranking_factors_expose_policy_without_rescoring():
    context = FindingPresentationIndex(ScanResult(root=".")).for_finding(finding(confidence="low", locations=[{"file": "src/a.py", "line": 1}]))
    factors = {f["name"]: f for f in context["priority"]["factors"]}
    assert set(factors) == {"severity", "confidence", "exploitability", "source_quality", "trust_boundary_crossing"}
    assert factors["severity"]["kind"] == "ordering_band"
    assert factors["confidence"]["kind"] == "ordering_multiplier"
    assert "0.5" in factors["confidence"]["note"]  # low-confidence multiplier, made visible
    assert factors["exploitability"]["kind"] == "not_applied"
    assert factors["source_quality"]["value"] == "unclassified"
    assert factors["source_quality"]["kind"] == "qualitative_filter"
    assert factors["trust_boundary_crossing"]["kind"] == "not_applied"
    # Exposure is presentation-only: the finding's own numbers pass through unchanged.
    assert context["priority"]["score"] is None


def test_exploitability_decomposition_is_additive_and_corroborated():
    scan = ScanResult(root=".", taint_chains=[TaintChain(
        route_path="/items", route_method="GET", route_file="src/routes/items.py",
        sink_kind="sql_execute", sink_file="src/db/query.py", sink_line=42, hops=1,
        files=["src/routes/items.py", "src/db/query.py"])])
    scan = _with_fixture_scope(scan)
    surfaces = [AttackSurface(route="/items", method="GET", file="src/routes/items.py",
                              category="public_api", exposure="public", risk="high")]
    scores = score_exploitability(scan, surfaces)
    assert scores
    best = scores[0]
    f = finding(score=100, exploitability=best.score, exploitability_tier=best.tier,
                exploitability_reference=best.producer_reference,
                locations=[{"file": "src/db/query.py", "line": 42}])
    context = FindingPresentationIndex(scan, exploitability_scores=scores).for_finding(f)
    assert context["priority"]["point_contributions"] == "supplied"
    decomposition = context["priority"]["decomposition"]
    assert decomposition and decomposition[0]["score"] == best.score
    assert decomposition[0]["match_basis"] == "exact_producer_reference"
    assert decomposition[0]["location_corroborated"] is True
    points = [factor["points"] for factor in decomposition[0]["factors"]]
    assert all(isinstance(p, int) for p in points)
    assert sum(points) == decomposition[0]["raw_score"]
    assert decomposition[0]["sums_to_raw_score"] is True
    names = {factor["name"] for factor in decomposition[0]["factors"]}
    assert any("exposure" in name for name in names)
    assert any("auth" in name for name in names)  # privilege sensitivity at entry
    assert any("reachability" in name for name in names)  # chain depth


def test_legacy_missing_reference_never_invents_decomposition():
    scan = ScanResult(root=".")
    scores = score_exploitability(scan, [])
    f = finding(exploitability=99, exploitability_tier="high")
    context = FindingPresentationIndex(scan, exploitability_scores=scores).for_finding(f)
    # A finding whose score matches nothing gets no invented decomposition.
    assert context["priority"]["decomposition"] == []
    assert context["priority"]["point_contributions"] == "not_supplied"
    assert "factor list was not supplied" in " ".join(context["priority"]["unresolved_assumptions"])


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


def test_report_json_exposes_exploitability_decomposition(tmp_path):
    scan = ScanResult(root=".", taint_chains=[TaintChain(
        route_path="/items", route_method="GET", route_file="src/routes/items.py",
        sink_kind="sql_execute", sink_file="src/db/query.py", sink_line=42, hops=1,
        files=["src/routes/items.py", "src/db/query.py"])])
    scan = _with_fixture_scope(scan)
    surfaces = [AttackSurface(route="/items", method="GET", file="src/routes/items.py",
                              category="public_api", exposure="public", risk="high")]
    best = score_exploitability(scan, surfaces)[0]
    f = finding(score=100, exploitability=best.score, exploitability_tier=best.tier,
                exploitability_reference=best.producer_reference,
                locations=[{"file": "src/db/query.py", "line": 42}])
    write_reports(tmp_path, scan, "# Synthetic", "# Synthetic", "# Synthetic", surfaces, [f], [])
    payload = json.loads((tmp_path / "attackmap-report.json").read_text(encoding="utf-8"))
    priority = payload["findings"][0]["context"]["priority"]
    assert priority["point_contributions"] == "supplied"
    assert priority["decomposition"][0]["score"] == best.score
    assert sum(factor["points"] for factor in priority["decomposition"][0]["factors"]) == priority["decomposition"][0]["raw_score"]
    assert priority["unresolved_assumptions"]
    assert "not calibrated probabilities" in priority["meaning"]


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
