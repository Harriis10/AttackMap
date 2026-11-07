from attackmap.defensive_review import _finding_priority, _finding_source_quality, _weaknesses, render_defensive_review
from attackmap.models import AttackPath, AttackSurface, Finding, ScanResult
from attackmap.review_json import build_defensive_review_json


def test_unrelated_surface_and_path_cannot_change_finding_priority_or_basis():
    finding = Finding(title="Synthetic auth /admin src/a.py", severity="high", confidence="high", evidence=["Entry: /admin"], mitigation="Synthetic recommendation")
    surface = AttackSurface(route="/admin", method="POST", file="src/a.py", category="auth", risk="high", exposure="public", data_store_interaction=True, outbound_integration=True)
    path = AttackPath(name=finding.title, steps=["Entry: /admin", "Sink: privileged", "edge", "service"] * 3, impact="Synthetic")
    assert _finding_priority(finding, [], []) == _finding_priority(finding, [surface], [path])
    before = _weaknesses([], [finding], [])
    after = _weaknesses([surface], [finding], [path])
    assert before[:3] == after[:3]
    markdown = render_defensive_review(ScanResult(root="."), [surface], [finding], [path])
    report = build_defensive_review_json(ScanResult(root="."), [surface], [finding], [path])
    assert "[heuristic_static] Synthetic recommendation" in markdown
    assert report["recommendations"][0]["evidence_basis"] == "heuristic_static"
    assert "surface/path association=unknown" in markdown


def test_source_quality_uses_owned_locations_never_evidence_prose():
    finding = Finding(title="Synthetic tests/a.py", severity="high", confidence="high", evidence=["tests/a.py confidence=0.99"], mitigation="Review")
    assert _finding_source_quality(finding) == "unknown"
    plain = finding.model_copy(update={"evidence": [], "title": "Synthetic"})
    assert _finding_priority(finding, [], []) == _finding_priority(plain, [], [])
    owned = Finding.model_validate({**finding.model_dump(), "locations": [{"file": "tests/a.py"}]})
    assert _finding_source_quality(owned) == "low_quality"
    assert _finding_priority(owned, [], [])[0] < _finding_priority(finding, [], [])[0]
    mixed = Finding.model_validate({**finding.model_dump(), "locations": [{"file": "tests/a.py"}, {"file": "src/a.py"}]})
    assert _finding_source_quality(mixed) == "mixed"
