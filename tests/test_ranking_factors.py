"""C12 ranking tests: intended direction of confidence and source quality.

These pin the *documented direction* of the ranking inputs the engine already
uses — not new policy. Scores are ordering keys for triage; they are never
treated as calibrated probabilities (a score of 75 does not mean 75% likely).

- Confidence: within one severity band, higher confidence outranks lower
  (threat_model.compute_finding_score multipliers 1.0 / 0.75 / 0.5). Swapping
  only the confidence flips the rank order.
- Source quality: findings driven by route surfaces exclude low-quality source
  files (tests/fixtures/mocks/examples) entirely — the documented down-weight
  is exclusion from ranked output, not a numeric penalty. The finding context
  states the policy qualitatively.
- Exposure / chain depth: the fused exploitability factors move the score in
  the documented direction (public > unknown > internal exposure; nearer sink
  > farther sink), each factor named and additive.
"""

from __future__ import annotations

from itertools import permutations

from attackmap.analyzer import identify_attack_surfaces
from attackmap.exploitability import score_exploitability
from attackmap.finding_presentation import FindingPresentationIndex
from attackmap.models import AttackSurface, Finding, Route, ScanResult, TaintChain
from attackmap.threat_model import compute_finding_score, generate_findings
from attackmap.triage import rank_findings


def _finding(title: str, severity: str, confidence: str) -> Finding:
    # The pipeline attaches the prioritization score in generate_findings;
    # reproduce that so rank_findings sees what triage really receives.
    return Finding(title=title, severity=severity, confidence=confidence,
                   mitigation="Synthetic mitigation",
                   score=compute_finding_score(severity, confidence))


# --- Confidence direction ----------------------------------------------------


def test_confidence_ordering_direction_is_monotonic() -> None:
    assert compute_finding_score("high", "high") > compute_finding_score("high", "medium")
    assert compute_finding_score("high", "medium") > compute_finding_score("high", "low")
    # Cross-band: severity dominates — the intended direction. The numbers are
    # ordering keys, not likelihoods (a low/high finding is not "less likely",
    # it simply triages after any high-severity finding).
    assert compute_finding_score("low", "high") < compute_finding_score("high", "low")


def test_only_confidence_varies_rank_order_changes_as_documented() -> None:
    a = _finding("Alpha handler", "high", "high")
    b = _finding("Beta handler", "high", "low")
    assert [f.title for f in rank_findings([a, b])] == ["Alpha handler", "Beta handler"]
    # Swap only the confidence values: the rank order must flip.
    a2 = _finding("Alpha handler", "high", "low")
    b2 = _finding("Beta handler", "high", "high")
    assert [f.title for f in rank_findings([a2, b2])] == ["Beta handler", "Alpha handler"]


def test_confidence_ranking_is_input_order_independent() -> None:
    findings = [
        _finding("Alpha handler", "medium", "high"),
        _finding("Beta handler", "medium", "medium"),
        _finding("Gamma handler", "medium", "low"),
    ]
    expected = ["Alpha handler", "Beta handler", "Gamma handler"]
    for order in permutations(range(3)):
        assert [f.title for f in rank_findings([findings[i] for i in order])] == expected


def test_scores_are_ordering_keys_not_probabilities() -> None:
    # Ints in a fixed, small table — the score is a deterministic sort key.
    assert isinstance(compute_finding_score("high", "medium"), int)
    context = FindingPresentationIndex(ScanResult(root=".")).for_finding(
        _finding("Synthetic", "high", "medium")
    )
    assert "not calibrated probabilities" in context["priority"]["meaning"]
    confidence_factor = next(f for f in context["priority"]["factors"] if f["name"] == "confidence")
    assert "not a calibrated probability" in confidence_factor["note"]


# --- Source-quality direction -------------------------------------------------


def _webhook_scan(route_file: str) -> ScanResult:
    return ScanResult(
        root=".",
        routes=[Route(path="/webhook/payments", method="POST", file=route_file, line=4)],
        taint_chains=[
            TaintChain(
                route_path="/webhook/payments",
                route_method="POST",
                route_file=route_file,
                sink_kind="sql_execute",
                sink_file="src/db.py",
                sink_line=9,
                hops=0,
                files=[route_file, "src/db.py"],
            )
        ],
    )


def test_only_source_role_varies_low_quality_is_excluded_from_ranked_findings() -> None:
    production = generate_findings(_webhook_scan("src/app.py"))
    test_code = generate_findings(_webhook_scan("tests/app.py"))
    assert any(f.rule_id == "public-webhook" for f in production)
    # Same route, same chain, same surface shape — only the source role varies.
    # The documented down-weight is exclusion from surface-driven findings.
    assert not any(f.rule_id == "public-webhook" for f in test_code)
    # The exclusion is a source-quality policy, not a claim the route is safe.
    assert identify_attack_surfaces(_webhook_scan("tests/app.py")), "surface modeling still observes the route"


def test_finding_context_states_source_quality_as_qualitative_filter() -> None:
    scan = ScanResult(root=".")
    finding = Finding(title="Synthetic heuristic", severity="high", mitigation="Synthetic",
                      locations=[{"file": "tests/app.py", "line": 4}])
    context = FindingPresentationIndex(scan).for_finding(finding)
    factor = next(f for f in context["priority"]["factors"] if f["name"] == "source_quality")
    assert factor["value"] == "low_quality"
    assert factor["kind"] == "qualitative_filter"
    assert factor["points"] is None, "source quality is a filter, not a numeric multiplier"
    assert any("tests/fixtures/mocks/examples" in note for note in context["uncertainty"])


# --- Fused-factor direction (exposure, chain depth) ---------------------------


def _chain(route_path: str, route_file: str, sink_file: str, hops: int) -> TaintChain:
    return TaintChain(
        route_path=route_path, route_method="GET", route_file=route_file,
        sink_kind="sql_execute", sink_file=sink_file, sink_line=11, hops=hops,
        files=[route_file, sink_file],
    )


def _surface(route_path: str, route_file: str, exposure: str) -> AttackSurface:
    return AttackSurface(route=route_path, method="GET", file=route_file,
                         category="public_api", exposure=exposure, risk="high")


def test_exposure_factor_direction_public_over_unknown_over_internal() -> None:
    scan = ScanResult(root=".", taint_chains=[
        _chain("/pub", "src/pub.py", "src/sink.py", 0),
        _chain("/unk", "src/unk.py", "src/sink2.py", 0),
        _chain("/int", "src/int.py", "src/sink3.py", 0),
    ])
    surfaces = [_surface("/pub", "src/pub.py", "public"),
                _surface("/unk", "src/unk.py", "unknown"),
                _surface("/int", "src/int.py", "internal")]
    by_route = {s.route: s for s in score_exploitability(scan, surfaces)}
    assert by_route["/pub"].score > by_route["/unk"].score > by_route["/int"].score
    for route_file, route_path, expected in (("src/pub.py", "/pub", "public exposure"),
                                             ("src/int.py", "/int", "internal exposure")):
        assert next(f.name for f in by_route[route_path].factors if "exposure" in f.name) == expected


def test_chain_depth_direction_nearer_sink_ranks_higher() -> None:
    scan = ScanResult(root=".", taint_chains=[_chain("/near", "src/near.py", "src/near.py", 0),
                                              _chain("/far", "src/far.py", "src/far_sink.py", 2)])
    surfaces = [_surface("/near", "src/near.py", "public"), _surface("/far", "src/far.py", "public")]
    by_route = {s.route: s for s in score_exploitability(scan, surfaces)}
    assert by_route["/near"].score > by_route["/far"].score
    near_factor = next(f for f in by_route["/near"].factors if "reachability" in f.name)
    far_factor = next(f for f in by_route["/far"].factors if "reachability" in f.name)
    assert near_factor.points > far_factor.points
