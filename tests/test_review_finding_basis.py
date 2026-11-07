import pytest

from attackmap.models import AttackSurface, Finding, ScanResult
from attackmap.review_json import build_defensive_review_json


@pytest.mark.parametrize("overlap", ["auth", "/unrelated", "other.py"])
@pytest.mark.parametrize("source", ["src/other.py", "tests/other.py", "lexicons/other.json"])
def test_prose_proximity_never_upgrades_finding_or_recommendation(overlap, source):
    finding = Finding(rule_id="synthetic-rule", title=f"Synthetic {overlap}", severity="high", evidence=["other.py"], mitigation="Synthetic recommendation")
    surface = AttackSurface(route="/unrelated", method="GET", file=source, category="auth", exposure="public", risk="high")
    before = build_defensive_review_json(ScanResult(root="."), [], [finding], [])
    after = build_defensive_review_json(ScanResult(root="."), [surface], [finding], [])
    for key in ("weaknesses", "recommendations"):
        a = before["weaknesses_risk_hotspots"][key] if key == "weaknesses" else before[key]
        b = after["weaknesses_risk_hotspots"][key] if key == "weaknesses" else after[key]
        assert a[0]["evidence_basis"] == b[0]["evidence_basis"] == "heuristic_static"
        assert b[0]["surface_association"] == "unknown"
        assert all(item["association"] == "prose_overlap_candidate_only" for item in b[0]["candidate_surfaces"])
    assert after["attack_surface"]["evidence_class_counts"] != before["attack_surface"]["evidence_class_counts"]


def test_title_rewording_and_exact_structured_colocation_do_not_create_ownership():
    surface = AttackSurface(route="/auth", method="GET", file="src/auth.py", line=3, category="auth", risk="high")
    for title in ("Synthetic auth", "Unrelated prose"):
        finding = Finding(title=title, severity="high", mitigation="Review", locations=[{"file": "src/auth.py", "line": 3}])
        result = build_defensive_review_json(ScanResult(root="."), [surface], [finding], [])
        row = result["weaknesses_risk_hotspots"]["weaknesses"][0]
        assert row["evidence_basis"] == "heuristic_static"
        assert row["surface_association"] == "unknown"
        assert row["locations"] == [location.model_dump() for location in finding.locations]


def test_candidate_list_is_bounded_without_dropping_surface_facts():
    surfaces = [AttackSurface(route=f"/auth/{i}", method="GET", file=f"src/{i}.py", category="auth", risk="low") for i in range(12)]
    finding = Finding(title="Synthetic auth", severity="low", mitigation="Review")
    result = build_defensive_review_json(ScanResult(root="."), surfaces, [finding], [])
    row = result["weaknesses_risk_hotspots"]["weaknesses"][0]
    assert len(row["candidate_surfaces"]) == 8
    assert row["candidate_surfaces_truncated"]
    assert len(result["raw_structured_signals"]["attack_surfaces"]) == 12
