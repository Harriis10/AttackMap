"""Negative gates for the reference verifier, not analyzer/runtime evidence."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("wp032_reference_verifier", ROOT / "tools/verify_wp032_closeout.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


@pytest.fixture
def sample():
    oracle = verifier.read(verifier.FIXTURE / "expected.json")
    links, edges = [], []
    refs = {}
    nodes = {name: dict(id=name, repo_id="repo:" + name, evidence_refs=[]) for name in ("client", "auth-api", "auth-api-2")}
    repos = [dict(id="repo:" + name, repo_id=name, root=str(verifier.FIXTURE / relative)) for name, relative in zip(oracle["repository_ids"], oracle["roots"])]
    for key, (resolution, reason) in verifier.expected_edges(oracle, "baseline").items():
        client, server, target, client_location, method, route, server_location = key
        call = next(row for row in oracle["calls"] if row["target"] == target)
        authority = urlsplit(target)
        known = server in call["resolved"] or server in call.get("known_scope", [])
        declarations = [dict(repository_root=next(row["root"] for row in repos if row["repo_id"] == server), file=file, line=None)
                        for file in ("service.yaml", "ingress.yaml")] if known else []
        links.append(dict(client_repo=client, server_repo=server, client_target=target, client_location=client_location,
            method=method, server_route_path=route, server_location=server_location,
            resolution=resolution, resolution_reason=reason, proxy_host=target.split('/')[2] if resolution != "candidate" else None,
            alias_provenance=f"scoped_proxies:{authority.hostname} (auth-api/ingress.yaml)" if resolution != "candidate" else None,
            server_namespace=call.get("namespace") if known else None, server_service_name="auth-api" if known else None,
            server_port=8080 if known else None, server_protocol="http" if known else None,
            scheme=authority.scheme, destination=authority.hostname,
            declaration_refs=declarations))
        caller_ref, route_ref = f'call-{call["line"]}', f'route-{server}'
        refs[caller_ref] = dict(id=caller_ref, kind="external_call", core_repo_id=client, file="client.js", line=call["line"])
        refs[route_ref] = dict(id=route_ref, kind="route", core_repo_id=server, file="app.py", line=5)
        declaration_ids = []
        for declaration in declarations:
            identity = f'declaration-{server}-{declaration["file"]}'
            refs[identity] = dict(id=identity, kind="deployment_declaration", core_repo_id=server, file=declaration["file"],
                line=None, snapshot_binding="unverified", location_status="file_only", location_reason="line_not_supplied")
            declaration_ids.append(identity)
        endpoints = [(client, server)]
        if resolution == "observed_via_proxy":
            proxy = "proxy-" + str(call["line"])
            nodes[proxy] = dict(id=proxy, repo_id=None, component_role="proxy", authority=authority.hostname, scheme=authority.scheme, evidence_refs=[])
            endpoints = [(client, proxy), (proxy, server)]
        for source, destination in endpoints:
            edges.append(dict(id=f"edge-{len(edges)}", source=source, target=destination, kind="cross_repo_http_call",
                client_target=target, method=method, server_route_path=route, resolution=resolution, resolution_reason=reason,
                server_namespace=call.get("namespace") if known else None, server_service_name="auth-api" if known else None,
                server_port=8080 if known else None, server_protocol="http" if known else None,
                leg=("client_to_proxy" if source == client else "proxy_to_server") if resolution == "observed_via_proxy" else "direct",
                evidence_refs=[caller_ref, route_ref, *declaration_ids]))
    return oracle, dict(repos=repos, cross_repo_links=links, cross_boundary_flows=[], trust_gaps=[],
        fleet_architecture=dict(repositories=repos, nodes=list(nodes.values()), edges=edges, evidence=list(refs.values())))


def test_valid_gate_transport_fixture_then_exact_graph_tamper_rejected(sample):
    oracle, summary = sample
    assert verifier.verify_edges(summary, oracle, "baseline")["links"] == 16


@pytest.mark.parametrize("mutation", ["namespace", "evidence_owner", "missing_leg", "false_config_verification", "wrong_endpoint", "duplicate_proxy_leg", "backend_port"])
def test_graph_cannot_silently_diverge_from_exact_source_link(sample, mutation):
    oracle, summary = sample
    if mutation == "namespace": summary["fleet_architecture"]["edges"][0]["server_namespace"] = "other"
    elif mutation == "evidence_owner": summary["fleet_architecture"]["evidence"][0]["core_repo_id"] = "unrelated"
    elif mutation == "missing_leg": summary["fleet_architecture"]["edges"].pop(0)
    elif mutation == "false_config_verification":
        next(row for row in summary["fleet_architecture"]["evidence"] if row["kind"] == "deployment_declaration")["snapshot_binding"] = "verified"
    elif mutation == "wrong_endpoint": summary["fleet_architecture"]["edges"][0]["source"] = "auth-api-2"
    elif mutation == "backend_port": summary["fleet_architecture"]["edges"][0]["server_port"] = 9999
    else:
        identity = summary["fleet_architecture"]["edges"][1]["id"]
        summary["fleet_architecture"]["edges"][1] = {**deepcopy(summary["fleet_architecture"]["edges"][0]), "id": identity}
    with pytest.raises(ValueError):
        verifier.verify_edges(summary, oracle, "baseline")


@pytest.mark.parametrize("mutation", ["missing_origin", "wrong_same_basename_root"])
def test_declaration_origins_are_exact_not_filename_only(sample, mutation):
    oracle, summary = sample
    declarations = summary["cross_repo_links"][0]["declaration_refs"]
    if mutation == "missing_origin": declarations.pop()
    else: declarations[0]["repository_root"] = summary["repos"][2]["root"]
    with pytest.raises(ValueError, match="config declaration origin"):
        verifier.verify_edges(summary, oracle, "baseline")


@pytest.mark.parametrize("mutation", ["missing", "extra", "wrong_case", "promote_candidate", "erase_reason", "erase_namespace", "erase_candidate_scope", "wrong_proxy", "unrelated_backend"])
def test_exact_reference_link_mutations_fail_before_any_graph_claim(sample, mutation):
    oracle, summary = sample
    links = summary["cross_repo_links"]
    if mutation == "missing": links.pop()
    elif mutation == "extra": links.append(deepcopy(links[0]))
    elif mutation == "wrong_case": links[0]["server_route_path"] = "/api/users/<id>"
    elif mutation == "promote_candidate":
        target = next(row for row in links if row["client_target"].startswith("http://unknown"))
        target.update(resolution="observed", resolution_reason="")
    elif mutation == "erase_reason":
        next(row for row in links if row["resolution"] == "candidate")["resolution_reason"] = ""
    elif mutation == "erase_namespace": links[0]["server_namespace"] = None
    elif mutation == "erase_candidate_scope":
        next(row for row in links if row["client_target"].startswith("grpc://") and row["server_repo"] == "auth-api")["server_namespace"] = None
    elif mutation == "wrong_proxy": links[0]["proxy_host"] = "unrelated.example"
    else: links[1]["server_port"] = 8080
    with pytest.raises(ValueError):
        verifier.verify_edges(summary, oracle, "baseline")


def test_no_vacuous_finding_reference_acceptance():
    with pytest.raises(ValueError, match="Vacuous"):
        verifier.verify_child_reports([], verifier.read(verifier.FIXTURE / "expected.json"))


def test_protocol_variants_keep_negative_named_scope_in_oracle():
    oracle = verifier.read(verifier.FIXTURE / "expected.json")
    for variant in ("grpc", "conflict"):
        expected = verifier.expected_edges(oracle, variant)
        owned = [value for key, value in expected.items() if key[1] == "auth-api" and key[2] == "http://prod-api.example/Api/Users/42"]
        assert owned == [("candidate", "unsupported_protocol")]
