"""Explicit legacy operator seams + real nginx config; normalized app fixtures."""
from __future__ import annotations

import json
import shutil
from dataclasses import asdict
from pathlib import Path

import pytest

from attackmap.config_scanner import extract_deployment_aliases
from attackmap.contracts import DeploymentAliases, link_contracts
from attackmap.crossrepo import find_cross_boundary_flows, find_trust_gaps
from attackmap.exploitability import score_exploitability
from attackmap.finding_presentation import FindingPresentationIndex
from attackmap.fleet import FleetRepoResult, FleetScan
from attackmap.fleet_architecture import build_fleet_architecture
from attackmap.index import RepoIndex, clear_pinned_index
from attackmap.models import AttackSurface, ExternalCall, Route, ScanResult, TaintChain
from attackmap.threat_model import generate_findings


FIXTURE = Path(__file__).parent / "fixtures" / "wp032_protocol_fleet"
UPPER, LOWER = "/Api/Items/{id}", "/api/items/{id}"


def fixture_scans(root: Path):
    """The configs are real extractor input; these app signals are explicit fixtures."""
    scans = {name: ScanResult(root=str((root / name).resolve())) for name in ("caller", "api", "worker")}
    for name in ("api", "worker"):
        for path, line, sink_line in [(UPPER, 2, 4)] + ([(LOWER, 6, 8)] if name == "api" else []):
            scans[name].routes.append(Route(path=path, method="POST", file="handlers.py", line=line,
                                             source_analyzer="wp032-normalized-fixture"))
            scans[name].taint_chains.append(TaintChain(route_path=path, route_method="POST",
                route_file="handlers.py", route_line=line, sink_kind="sql_execute", sink_file="handlers.py",
                sink_line=sink_line, hops=0, files=["handlers.py"], source_kind="path_param",
                source_file="handlers.py", source_line=line + 1, source_analyzer="wp032-normalized-fixture"))
        index = RepoIndex.build(root / name)
        scans[name].scan_snapshot = index.snapshot.identity()
    clear_pinned_index()
    return scans


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "fleet"
    shutil.copytree(FIXTURE, root)
    scans = fixture_scans(root)
    aliases, notes = extract_deployment_aliases([root / name for name in scans])
    return root, scans, legacy_operator_aliases(aliases), notes


def legacy_operator_aliases(extracted):
    """Namespaces in retained YAML must not leak into this legacy bare-host matrix.

    Its dial ports/protocols are explicit operator declarations. Only proxy
    provenance comes from the real nginx file; scoped config-only matching has
    its own namespace corpus and physical fleet qualification.
    """
    return DeploymentAliases(hosts={"api": "api", "worker": "worker"}, service_ports={"api": 8443, "worker": 9000},
        service_protocols={"api": "https", "worker": "http"}, proxies=extracted.proxies,
        unresolved_proxies=extracted.unresolved_proxies,
        source_files={key: value for key, value in extracted.source_files.items() if key.startswith("proxies:")})


def linked(scans, aliases, target):
    scans["caller"].external_calls = [ExternalCall(target=target, method="POST", file="client.py", line=3,
                                                  source_analyzer="wp032-normalized-fixture")]
    return link_contracts(list(scans.items()), aliases)


@pytest.mark.parametrize("host", ["worker:9000", "worker-edge.internal"])
@pytest.mark.parametrize("scheme", ["grpc", "kafka", "wss", "ftp"])
def test_non_http_scheme_never_supports_http_contract_or_trust_path(corpus, host, scheme):
    _, scans, aliases, _ = corpus
    # Remove the proxy_pass protocol declaration to also cover an unknown backend.
    aliases = DeploymentAliases(service_ports=aliases.service_ports, proxies=aliases.proxies,
                                source_files={key: value for key, value in aliases.source_files.items()
                                              if not key.startswith("service_protocols:")})
    links = linked(scans, aliases, f"{scheme}://{host}/Api/Items/42")
    assert len(links) == 2
    worker = next(link for link in links if link.server_repo == "worker")
    assert (worker.resolution, worker.resolution_reason) == ("candidate", "unsupported_protocol")
    assert worker.proxy_host is None and worker.alias_provenance is None
    assert all(link.resolution == "candidate" for link in links)
    auth = {name: {(r.file, r.method, r.path): False for r in scan.routes} for name, scan in scans.items()}
    assert find_cross_boundary_flows(links, list(scans.items())) == []
    assert find_trust_gaps(links, list(scans.items()), auth) == []


def test_config_alias_origins_and_negative_multi_backend_controls(corpus):
    root, scans, _, _ = corpus
    aliases, notes = extract_deployment_aliases([root / name for name in scans])
    assert aliases.hosts == {} and aliases.host_ports == {} and aliases.dns_suffixes == ()
    assert aliases.service_ports == {}
    assert {key: (binding.port, binding.protocol) for key, binding in aliases.scoped_services.items()} == {
        "production/api": (8443, "https"), "preview/worker": (9000, None)}
    assert aliases.service_protocols == {"api": "https", "worker": "http"}
    assert aliases.proxies == {"api-edge.internal": "api", "worker-edge.internal": "worker"}
    assert aliases.source_files == {
        "scoped_services:production/api": "api/service.yaml",
        "scoped_services:preview/worker": "worker/service.yaml",
        "service_protocols:api:https": "caller/nginx.conf",
        "service_protocols:worker:http": "caller/nginx.conf",
        "proxies:api-edge.internal": "caller/nginx.conf",
        "proxies:worker-edge.internal": "caller/nginx.conf",
    }
    assert len(notes) == 4
    assert sum("2 backends" in note for note in notes) == 2
    assert all("not modeled" in note for note in notes)
    assert sum("host-wide proxy" in note for note in notes) == 2


@pytest.mark.parametrize("host", ["worker:9000", "worker-edge.internal"])
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_http_schemes_keep_existing_matching_without_backend_protocol(corpus, host, scheme):
    _, scans, extracted, _ = corpus
    aliases = DeploymentAliases(service_ports=extracted.service_ports, proxies=extracted.proxies)
    links = linked(scans, aliases, f"{scheme}://{host}/Api/Items/42")
    worker = next(link for link in links if link.server_repo == "worker")
    assert worker.resolution == ("observed" if ":" in host else "observed_via_proxy")
    assert worker.resolution_reason == ""


@pytest.mark.parametrize("target,server,resolution,reason,provenance", [
    ("https://API:08443/Api/Items/42", "api", "observed", "", "service_ports:api:8443"),
    ("http://api:8443/Api/Items/42", "api", "candidate", "scheme_mismatch", "service_protocols:api:https"),
    ("grpc://api:8443/Api/Items/42", "api", "candidate", "scheme_mismatch", "service_protocols:api:https"),
    ("http://worker:9000/Api/Items/42", "worker", "observed", "", "service_ports:worker:9000"),
    ("https://worker:9000/Api/Items/42", "worker", "candidate", "scheme_mismatch", "service_protocols:worker:http"),
    ("http://api-edge.internal/Api/Items/42", "api", "observed_via_proxy", "", "proxies:api-edge.internal (caller/nginx.conf)"),
    ("https://worker-edge.internal/Api/Items/42", "worker", "observed_via_proxy", "", "proxies:worker-edge.internal (caller/nginx.conf)"),
    ("grpc://api-edge.internal/Api/Items/42", "api", "candidate", "unsupported_protocol", None),
    ("http://multi-edge.internal/Api/Items/42", "api", "candidate", "unresolved_host", None),
    ("http://ports-edge.internal/Api/Items/42", "worker", "candidate", "unresolved_host", None),
    ("https://api.production.svc.cluster.local:8443/Api/Items/42", "api", "candidate", "unresolved_host", None),
    ("https://api.preview.svc.cluster.local:8443/Api/Items/42", "api", "candidate", "unresolved_host", None),
    ("http://worker:9001/Api/Items/42", "worker", "candidate", "explicit_port", None),
    ("/Api/Items/42", "api", "candidate", "no_destination", None),
])
def test_explicit_operator_three_repository_identity_matrix(corpus, target, server, resolution, reason, provenance):
    _, scans, aliases, _ = corpus
    links = linked(scans, aliases, target)
    assert len(links) == 2
    selected = next(link for link in links if link.server_repo == server)
    assert (selected.resolution, selected.resolution_reason, selected.alias_provenance) == (resolution, reason, provenance)
    assert all(link.resolution == "candidate" for link in links if link.server_repo != server)
    direct = [link for link in links if link.resolution == "observed"]
    auth = {name: {(r.file, r.method, r.path): False for r in scan.routes} for name, scan in scans.items()}
    flows = find_cross_boundary_flows(links, list(scans.items()))
    gaps = find_trust_gaps(links, list(scans.items()), auth)
    assert len(flows) == len(gaps) == len(direct)
    assert all(item.client_target == target and item.server_repo == server for item in flows + gaps)


def test_route_case_survives_dns_normalization_without_cross_handler_evidence(corpus):
    _, scans, aliases, _ = corpus
    links = linked(scans, aliases, "https://API:8443/api/items/42")
    assert len(links) == 1
    assert links[0].server_route_path == LOWER and links[0].path_template == "api/items/*"
    flow = find_cross_boundary_flows(links, list(scans.items()))
    assert len(flow) == 1 and flow[0].route == LOWER and flow[0].server_line == 8
    assert linked(scans, aliases, "https://API:8443/API/Items/42") == []


def test_declared_namespace_is_exact_and_still_checks_protocol(corpus):
    _, scans, aliases, _ = corpus
    # Explicit suffix opt-in remains separate from namespace-aware config matching.
    aliases = DeploymentAliases(service_ports=aliases.service_ports, service_protocols=aliases.service_protocols,
        dns_suffixes=(".production.svc.cluster.local",), source_files=aliases.source_files)
    target = "https://api.production.svc.cluster.local:8443/Api/Items/42"
    links = linked(scans, aliases, target)
    assert [(link.server_repo, link.resolution) for link in links] == [("api", "observed"), ("worker", "candidate")]
    assert all(link.resolution == "candidate" for link in linked(scans, aliases, target.replace("production", "preview")))
    api = next(link for link in linked(scans, aliases, target.replace("https:", "http:")) if link.server_repo == "api")
    assert api.resolution_reason == "scheme_mismatch"


def test_port_name_does_not_become_tls_declaration(corpus):
    root, _, _, _ = corpus
    aliases, notes = extract_deployment_aliases([root / "worker"])
    assert aliases.service_ports == aliases.service_protocols == {}
    assert aliases.scoped_services["preview/worker"].port == 9000
    assert aliases.scoped_services["preview/worker"].protocol is None
    assert notes == []


def qualification_proof(root: Path) -> dict:
    """Bounded legacy operator seams, actual nginx config and normalized app inputs."""
    scans = fixture_scans(root)
    targets = ["https://api:8443/Api/Items/42", "http://api:8443/Api/Items/42",
               "http://api-edge.internal/Api/Items/42", "grpc://api-edge.internal/Api/Items/42",
               "http://worker:9000/Api/Items/42", "grpc://worker:9000/Api/Items/42",
               "http://multi-edge.internal/Api/Items/42", "http://ports-edge.internal/Api/Items/42",
               "https://api.preview.svc.cluster.local:8443/Api/Items/42",
               "https://api:8443/api/items/42", "https://api:8443/API/Items/42"]
    scans["caller"].external_calls = [ExternalCall(target=target, method="POST", file="client.py", line=3,
        source_analyzer="wp032-normalized-fixture") for target in targets]
    aliases, notes = extract_deployment_aliases([root / name for name in scans])
    aliases = legacy_operator_aliases(aliases)
    links = link_contracts(list(scans.items()), aliases)
    auth = {name: {(r.file, r.method, r.path): False for r in scan.routes} for name, scan in scans.items()}
    flows = find_cross_boundary_flows(links, list(scans.items()))
    gaps = find_trust_gaps(links, list(scans.items()), auth)
    assert len(links) == 19 and len(flows) == len(gaps) == 3
    assert {item.client_target for item in flows} == {targets[0], targets[4], targets[9]}
    results = []
    finding_refs = []
    for name, scan in scans.items():
        surfaces = [AttackSurface(route=r.path, method=r.method, file=r.file,
                    category="public_api", exposure="public", risk="high") for r in scan.routes]
        scores = score_exploitability(scan, surfaces)
        findings = generate_findings(scan, surfaces)
        presentation = FindingPresentationIndex(scan, scores)
        for finding in findings:
            if finding.exploitability_reference is None:
                continue
            priority = presentation.for_finding(finding)["priority"]
            assert priority["score_reference"]["status"] == "resolved"
            finding_refs.append({"repo_id": name, "rule_id": finding.rule_id,
                "reference": finding.exploitability_reference.model_dump(), "priority": priority})
        results.append(FleetRepoResult(name, scan.root, str(root / "reports" / name), scan, findings))
    fleet = FleetScan(results=results, links=links)
    graph = build_fleet_architecture(fleet)
    evidence = {item["id"]: item for item in graph["evidence"]}
    http_edges = [edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call"]
    for edge in http_edges:
        refs = [evidence[ref] for ref in edge["evidence_refs"]]
        assert {item["kind"] for item in refs} == {"external_call", "route"}
        assert {item["file"] for item in refs} == {"client.py", "handlers.py"}
        call_ids = {signal.observation_id for signal in scans["caller"].all_signals()
                    if signal.kind == "external_call" and signal.label == edge["client_target"]}
        assert call_ids & {item["observation_id"] for item in refs if item["kind"] == "external_call"}
        server = next(item["core_repo_id"] for item in refs if item["kind"] == "route")
        route_ids = {signal.observation_id for signal in scans[server].all_signals()
                     if signal.kind == "route" and signal.label == f'{edge["method"]} {edge["server_route_path"]}'}
        assert route_ids & {item["observation_id"] for item in refs if item["kind"] == "route"}
        assert all(item["line"] == 3 and item["core_repo_id"] == "caller" for item in refs if item["kind"] == "external_call")
        assert all(item["line"] == (6 if edge["server_route_path"] == LOWER else 2) for item in refs if item["kind"] == "route")
        assert {item["source_analyzer"] for item in refs} >= {"wp032-normalized-fixture"}
        assert edge["resolution"] == "candidate" or edge["scheme"] in {"http", "https"}
    assert finding_refs
    return {"scope": "three_synthetic_repos_explicit_operator_legacy_seams_actual_nginx_extraction_normalized_app_signals",
        "provider_calls": 0, "aliases": {**asdict(aliases), "dns_suffixes": list(aliases.dns_suffixes),
            "unresolved_proxies": list(aliases.unresolved_proxies),
            "unresolved_service_protocols": list(aliases.unresolved_service_protocols)}, "extraction_notes": notes,
        "links": [{**asdict(link), "declaration_refs": [asdict(ref) for ref in link.declaration_refs]} for link in links],
        "architecture": graph, "finding_score_references": finding_refs,
        "cross_boundary_flows": [asdict(flow) for flow in flows], "trust_gaps": [asdict(gap) for gap in gaps]}


def test_graph_evidence_and_finding_score_references_use_exact_context(corpus):
    root, _, _, _ = corpus
    proof = qualification_proof(root)
    # JSON round trip exercises the existing export contract without changing it.
    assert json.loads(json.dumps(proof)) == proof
    refs = proof["finding_score_references"]
    assert {item["repo_id"] for item in refs} == {"api", "worker"}
    for item in refs:
        assert item["reference"]["repository_root"] == str((root / item["repo_id"]).resolve())
        assert item["reference"]["scope"] == "repository_snapshot"
        assert item["priority"]["decomposition"][0]["producer_reference"] == item["reference"]
