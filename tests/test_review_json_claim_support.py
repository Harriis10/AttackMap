"""Closed-set per-claim claim support in the deterministic review JSON (AM016).

`claim_support` on weaknesses and recommendations is a token check: the cited
evidence text must name an identifier, route, or secret-kind the claim (the
finding title) names. It never verifies a conclusion and never asserts a claim
is false.
"""

from attackmap.models import Finding, Route, ScanResult
from attackmap.review_json import build_defensive_review_json


def _payload(*findings: Finding) -> dict:
    scan = ScanResult(
        root=".",
        languages=["python"],
        routes=[Route(path="/admin/reindex", method="POST", file="app.py")],
        files_scanned=3,
    )
    return build_defensive_review_json(scan, [], list(findings), [])


def test_weakness_claim_support_is_supported_only_on_named_identifier_match() -> None:
    payload = _payload(
        Finding(
            title="Hardcoded `api_key` near request handling",
            severity="high",
            evidence=["api_key = ... in app.py:3"],
            mitigation="Move the key to environment configuration.",
            confidence="high",
        ),
        Finding(
            title="Some administrative surfaces lack observed authorization guards",
            severity="medium",
            evidence=["POST /admin/reindex in app.py"],
            mitigation="Require server-side authorization on admin actions.",
            confidence="medium",
        ),
    )
    weaknesses = payload["weaknesses_risk_hotspots"]["weaknesses"]
    states = {item["title"]: item["claim_support"] for item in weaknesses}
    assert states["Hardcoded `api_key` near request handling"] == "supported_by_cited_evidence"
    assert states["Some administrative surfaces lack observed authorization guards"] == "not_assessed"
    supported = next(item for item in weaknesses if item["claim_support"] == "supported_by_cited_evidence")
    assert supported["claim_support_terms"] == ["api_key"]


def test_recommendations_carry_the_same_closed_set_assessment() -> None:
    payload = _payload(
        Finding(
            title="Weak crypto on `password_reset` tokens",
            severity="medium",
            evidence=["password_reset tokens hashed with md5 in app.py:8"],
            mitigation="Use a modern KDF for reset tokens.",
            confidence="medium",
        )
    )
    recommendation = payload["recommendations"][0]
    assert recommendation["claim_support"] == "supported_by_cited_evidence"
    assert "password_reset" in recommendation["claim_support_terms"]
    assert any("claim_support" in note for note in payload["limitations_meta"]["notes"])
