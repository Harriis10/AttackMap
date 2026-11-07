import json

import pytest

from attackmap.analyzer import identify_attack_surfaces, summarize_attack_surface
from attackmap.defensive_review import render_defensive_review
from attackmap.evidence import surface_evidence_basis
from attackmap.models import (
    AttackSurface, AuthHint, DatabaseHint, ExternalCall, Finding, Route,
    ScanResult, ServiceHint, TaintChain,
)
from attackmap.review_json import build_defensive_review_json
from attackmap.review_prompts import render_review_prompts
from attackmap.scanner import scan_files
from attackmap.threat_model import generate_findings


@pytest.mark.parametrize("path", ["/orders", "/internal/jobs", "/debug"])
@pytest.mark.parametrize("field,signal", [
    ("service_hints", ServiceHint(hint="service_role:worker", file="worker.py")),
    ("databases", DatabaseHint(kind="postgresql", file="database.py")),
    ("external_calls", ExternalCall(target="https://vendor.example", file="client.py")),
    ("auth_hints", AuthHint(hint="jwt", file="auth.py")),
    ("auth_hints", AuthHint(hint="handler_visibility:internal", file="worker.py")),
])
def test_unrelated_file_does_not_change_route_facts(path, field, signal):
    scan = ScanResult(root=".", routes=[Route(path=path, file="routes.py", line=10)])
    before = identify_attack_surfaces(scan)[0].model_dump()
    getattr(scan, field).append(signal)
    after = identify_attack_surfaces(scan)[0].model_dump()

    assert after == before
    assert after["auth"] == "unknown"
    assert after["relationship_basis"] == "unknown"
    if path != "/orders":
        assert after["exposure"] == "unknown"


def test_same_file_candidates_do_not_establish_dependency_ownership():
    scan = ScanResult(
        root=".", routes=[Route(path="/orders", file="routes.py", line=10)],
        databases=[DatabaseHint(kind="postgresql", file="routes.py", line=200)],
        external_calls=[ExternalCall(target="https://vendor.example", file="routes.py", line=250)],
        auth_hints=[AuthHint(hint="jwt", file="routes.py", line=15)],
    )
    surface = identify_attack_surfaces(scan)[0]
    assert not surface.data_store_interaction
    assert not surface.outbound_integration
    assert surface.relationship_basis == "unknown"
    assert surface.auth == "unknown"
    assert surface.auth_signals == ["jwt"]
    assert len(surface.context_signals) == 3
    assert all("ownership unknown" in item for item in surface.context_signals)


@pytest.mark.parametrize("field,content", [
    ("databases", "import sqlite3\nconnection = sqlite3.connect('state.db')\n"),
    ("external_calls", "import requests\nrequests.get('https://vendor.example')\n"),
    ("auth_hints", "import jwt\ntoken = jwt.decode(value, key)\n"),
])
def test_adding_an_unrelated_source_file_preserves_all_route_facts(tmp_path, field, content):
    (tmp_path / "routes.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.route('/internal')\ndef internal():\n    return 'ok'\n"
        "@app.route('/debug')\ndef debug():\n    return 'ok'\n",
        encoding="utf-8",
    )
    before = identify_attack_surfaces(scan_files(tmp_path))
    (tmp_path / "unrelated.py").write_text(content, encoding="utf-8")
    changed_scan = scan_files(tmp_path)
    assert getattr(changed_scan, field)
    assert len(before) == 2
    assert identify_attack_surfaces(changed_scan) == before
    assert all(surface.exposure == "unknown" for surface in before)


def _chain(**changes):
    return TaintChain(**{
        "route_path": "/orders", "route_method": "POST", "route_file": "routes.py",
        "sink_kind": "ssrf", "sink_file": "client.py", "hops": 1,
        **changes,
    })


@pytest.mark.parametrize("changes", [
    {"route_path": "/other"}, {"route_method": "GET"},
    {"route_file": "other.py"}, {"speculative": True},
])
def test_dependency_chain_requires_matching_route_identity(changes):
    scan = ScanResult(root=".", routes=[Route(path="/orders", method="POST", file="routes.py")])
    scan.taint_chains = [_chain(**changes)]
    assert not identify_attack_surfaces(scan)[0].outbound_integration
    scan.taint_chains = [_chain()]
    surface = identify_attack_surfaces(scan)[0]
    assert surface.outbound_integration
    assert surface.relationship_basis == "inferred_route_chain"
    assert surface.evidence_class == "static_observed"


def test_unrelated_auth_does_not_suppress_route_integration_finding():
    scan = ScanResult(
        root=".", routes=[Route(path="/orders", method="POST", file="routes.py")],
        taint_chains=[_chain()],
    )
    before = [f.model_dump() for f in generate_findings(scan) if f.rule_id == "unauth-outbound-integration"]
    scan.auth_hints.append(AuthHint(hint="jwt", file="unrelated/auth.py"))
    after = [f.model_dump() for f in generate_findings(scan) if f.rule_id == "unauth-outbound-integration"]
    assert before and before == after


@pytest.mark.parametrize("exposure", ["public", "internal", "unknown"])
@pytest.mark.parametrize("file,expected", [
    ("src/handler.ts", "static_observed"),
    ("src/lexicon_handler.ts", "static_observed"),
    ("lexicons/query.json", "inferred_protocol"),
    ("tests/handler.ts", "low_quality"),
])
def test_surface_classification_is_identical_in_model_json_markdown_and_ai(exposure, file, expected):
    surface = AttackSurface(
        route="/xrpc/com.example.query", method="GET", file=file,
        exposure=exposure, category="public_api", risk="medium",
    )
    scan = ScanResult(root=".")
    report = build_defensive_review_json(scan, [surface], [], [])
    prompt = json.loads(render_review_prompts(scan, [surface], [], []).evidence_json)
    markdown = render_defensive_review(scan, [surface], [], [])
    summary = summarize_attack_surface(scan, [surface])
    assert surface.model_dump()["evidence_class"] == expected
    assert report["raw_structured_signals"]["attack_surfaces"][0]["evidence_class"] == expected
    assert report["attack_surface"]["surfaces"][0]["evidence_class"] == expected
    assert prompt["attack_surfaces"][0]["evidence_class"] == expected
    assert report["attack_surface"]["evidence_class_counts"] == prompt["evidence_counts"]
    assert f"{expected}=100%" in markdown
    assert f"evidence: {expected}" in summary
    assert "observed_runtime" not in json.dumps(report) + json.dumps(prompt) + markdown + summary


def test_unlinked_findings_do_not_borrow_repository_surface_provenance():
    surface = AttackSurface(route="/orders", method="GET", file="routes.py", category="public_api", risk="low")
    finding = Finding(title="Unlinked concern", severity="low", confidence="low", evidence=[], mitigation="Review configuration.")
    report = build_defensive_review_json(ScanResult(root="."), [surface], [finding], [])
    assert report["weaknesses_risk_hotspots"]["weaknesses"][0]["evidence_basis"] == "heuristic_static"
    assert report["recommendations"][0]["evidence_basis"] == "heuristic_static"
    assert report["weaknesses_risk_hotspots"]["weaknesses"][0]["surface_association"] == "unknown"
    assert report["recommendations"][0]["surface_association"] == "unknown"
    fixture = surface.model_copy(update={"file": "tests/routes.py"})
    assert surface_evidence_basis([surface, surface, fixture]) == "mixed"


def test_repository_context_is_retained_separately_from_route_claims():
    scan = ScanResult(
        root=".", routes=[Route(path="/debug", file="routes.py")],
        databases=[DatabaseHint(kind="postgresql", file="unrelated/database.py")],
        external_calls=[ExternalCall(target="https://vendor.example", file="unrelated/client.py")],
    )
    surfaces = identify_attack_surfaces(scan)
    report = build_defensive_review_json(scan, surfaces, [], [])
    assert report["system_overview"]["database_count"] == 1
    assert report["system_overview"]["external_call_count"] == 1
    assert report["raw_structured_signals"]["scan"]["databases"]
    route = report["attack_surface"]["surfaces"][0]
    assert route["exposure"] == "unknown"
    assert route["context_signals"] == []
    assert not route["data_store_interaction"] and not route["outbound_integration"]
