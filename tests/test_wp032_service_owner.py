"""Preserve each consumer's ownership rules while indexing topology hints."""

from dataclasses import asdict

import pytest

from attackmap import threat_model, topology
from attackmap.models import AuthHint, DatabaseHint, EdgeHint, ExternalCall, Route, ScanResult, ServiceHint


FILE = "services/layout/app.py"
FAMILIES = [("auth_hints", AuthHint), ("service_hints", ServiceHint), ("edge_hints", EdgeHint)]
OWNERS = [
    ([], None, None, ()),
    ([""], None, "", ()),
    (["alpha"], "alpha", "alpha", ("alpha",)),
    (["Auth", "auth"], "auth", "auth", ("auth",)),
    (["Auth "], "auth ", "auth ", ("auth ",)),
    ([" "], " ", " ", (" ",)),
    (["alpha", "beta"], "alpha", "beta", ("alpha", "beta")),
    (["beta", "alpha"], "beta", "alpha", ("beta", "alpha")),
    (["", "alpha"], "alpha", "alpha", ("alpha",)),
    (["alpha", ""], "alpha", "", ("alpha",)),
    (["alpha", "beta", "alpha"], "alpha", "beta", ("alpha", "beta")),
    (["", "alpha", ""], "alpha", "alpha", ("alpha",)),
    (["alpha", "", "alpha"], "alpha", "", ("alpha",)),
    (["Straße", "STRASSE"], "straße", "strasse", ("straße", "strasse")),
]


def make_scan(family, hint_class, names, target="https://peer.internal/users"):
    return ScanResult(
        root=".",
        routes=[Route(method="GET", path="/api", file=FILE)],
        databases=[DatabaseHint(kind="postgresql", file=FILE)],
        external_calls=[ExternalCall(target=target, file=FILE)],
        **{family: [hint_class(hint="service_name:" + name, file=FILE) for name in names]},
    )


@pytest.mark.parametrize("family,hint_class", FAMILIES)
@pytest.mark.parametrize("names,first,last,all_names", OWNERS)
def test_consumer_order_empty_and_typed_family_rules(family, hint_class, names, first, last, all_names):
    scan = make_scan(family, hint_class, names)
    assert topology._file_service_map(scan) == ({FILE: first} if first is not None else {})
    assert topology._services_in_file(FILE, scan) == list(all_names)
    expected_threat = last if family != "edge_hints" and names else "layout"
    assert threat_model._file_service_map(scan) == {FILE: expected_threat}
    # Rendering has always stripped names; ownership lookups must not copy it.
    graph = topology.build_service_graph(scan)
    rendered_source = (first if first is not None else "layout").strip()
    assert [(edge.source, edge.target) for edge in graph.edges] == (
        [(rendered_source, "peer")] if rendered_source else []
    )
    assert "layout" in graph.node_names()


@pytest.mark.parametrize("family,hint_class", FAMILIES[:2])
def test_empty_explicit_owner_keeps_complete_lower_confidence_chain(family, hint_class):
    scan = make_scan(family, hint_class, [""])
    assert [asdict(chain) for chain in threat_model._build_service_chains(scan)] == [{
        "route_method": "GET",
        "route_path": "/api",
        "route_file": FILE,
        "entry_service": "layout",
        "next_service": None,
        "sink": "database",
        "confidence": 0.35 + 0.1 + 0.05,
        "evidence": [
            f"route GET /api in {FILE}",
            "entry service inferred from repository layout: layout",
            f"database hint elsewhere in repo: postgresql ({FILE})",
        ],
        "env_risk": None,
    }]


def test_roles_retain_all_conflicting_names_and_exact_file_keys():
    scan = make_scan("service_hints", ServiceHint, ["alpha", "beta", "alpha"])
    scan.auth_hints = [AuthHint(hint="service_role:privileged", file=FILE)]
    scan.service_hints.append(ServiceHint(hint="service_name:other", file=FILE.replace("/", "\\")))
    graph = topology.build_service_graph(scan)
    assert {node.name: node.role for node in graph.nodes} == {
        "alpha": "privileged", "beta": "privileged", "other": "service", "layout": "service", "peer": "service",
    }
    assert topology._services_in_file(FILE, scan) == ["alpha", "beta"]
    assert topology._services_in_file(FILE.replace("/", "\\"), scan) == ["other"]


def test_role_count_does_not_increase_whole_hint_scan_passes(monkeypatch):
    original = topology._iter_hints
    passes = 0

    def counted(scan):
        nonlocal passes
        passes += 1
        yield from original(scan)

    monkeypatch.setattr(topology, "_iter_hints", counted)
    scan = make_scan("service_hints", ServiceHint, ["alpha"])
    scan.auth_hints = [AuthHint(hint="service_role:privileged", file=FILE)]
    expected = topology.build_service_graph(scan)
    one_role_passes = passes
    passes = 0
    scan.auth_hints *= 32
    assert topology.build_service_graph(scan) == expected
    assert passes == one_role_passes
