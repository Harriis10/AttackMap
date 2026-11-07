"""Physical config extraction; supplied app observations are static fixtures."""
from __future__ import annotations

import json
import shutil
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from attackmap.config_scanner import extract_deployment_aliases
from attackmap.contracts import DeploymentAliases, link_contracts
from attackmap.crossrepo import find_cross_boundary_flows, find_trust_gaps
from attackmap.fleet import FleetRepoResult, FleetScan
from attackmap.fleet_architecture import build_fleet_architecture
from attackmap.models import ExternalCall, Route, ScanResult, TaintChain
from attackmap.scan_service import ScanRequest, _effective_deployment_aliases


FIXTURE = Path(__file__).parent / "fixtures" / "wp032_multibackend_proxy"
BAD_CASES = ("mixed-upstream.conf", "mixed-ports.conf", "mixed-unknown.conf",
             "mixed-variable.conf", "split.conf", "only-multi.conf", "only-unknown.conf",
             "split.yaml", "mixed-resource.yaml")
TARGET = "edge.production.internal"
ORIGIN = "wp032-multibackend-normalized-fixture"


def materialize(root: Path, cases: tuple[str, ...]) -> dict[str, ScanResult]:
    """Copy real config inputs and keep app evidence explicitly supplied."""
    scans = {}
    for name in ("caller", "api", "worker"):
        shutil.copytree(FIXTURE / name, root / name)
        scans[name] = ScanResult(root=str((root / name).resolve()))
    for number, case in enumerate(cases):
        # The case filename controls actual extractor traversal, not a mock.
        shutil.copyfile(FIXTURE / "cases" / case,
                        root / "caller" / f"case-{number:02d}{Path(case).suffix}")
    for name in ("api", "worker"):
        for route_path, line, sink_line in [("/Api/Items/{id}", 2, 4)] + (
                [("/api/items/{id}", 6, 8)] if name == "api" else []):
            scans[name].routes.append(Route(path=route_path, method="POST", file="handlers.py", line=line,
                                            source_analyzer=ORIGIN))
            scans[name].taint_chains.append(TaintChain(route_path=route_path, route_method="POST",
                route_file="handlers.py", route_line=line, sink_kind="sql_execute", sink_file="handlers.py",
                sink_line=sink_line, hops=0, files=["handlers.py"], source_kind="path_param",
                source_file="handlers.py", source_line=line + 1, source_analyzer=ORIGIN))
    return scans


def resolve(scans, aliases, target):
    scans["caller"].external_calls = [ExternalCall(target=target, method="POST", file="client.py", line=3,
                                                  source_analyzer=ORIGIN)]
    return link_contracts(list(scans.items()), aliases)


def assert_no_direct_trust(scans, links):
    auth = {name: {(route.file, route.method, route.path): False for route in scan.routes}
            for name, scan in scans.items()}
    assert find_cross_boundary_flows(links, list(scans.items())) == []
    assert find_trust_gaps(links, list(scans.items()), auth) == []


@pytest.mark.parametrize("bad_case", BAD_CASES)
@pytest.mark.parametrize("reverse", [False, True], ids=["single-first", "single-last"])
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_unmodeled_routing_cannot_resurrect_a_single_backend(tmp_path, bad_case, reverse, scheme):
    single = "single.yaml" if bad_case.endswith(".yaml") else "single.conf"
    cases = (bad_case, single) if reverse else (single, bad_case)
    root = tmp_path / "fleet"
    scans = materialize(root, cases)
    aliases, notes = extract_deployment_aliases([root / name for name in scans])
    assert aliases.proxies == {"safe.production.internal": "api"}
    assert aliases.unresolved_proxies == (TARGET,)
    assert f"proxies:{TARGET}" not in aliases.source_files
    assert aliases.source_files["proxies:safe.production.internal"] == "caller/safe.conf"
    assert any(TARGET in note and "not modeled" in note for note in notes)
    links = resolve(scans, aliases, f"{scheme}://{TARGET}/Api/Items/42")
    assert len(links) == 2
    assert {(link.resolution, link.resolution_reason) for link in links} == {("candidate", "unresolved_host")}
    assert all(link.alias_provenance is None and link.proxy_host is None for link in links)
    assert_no_direct_trust(scans, links)


@pytest.mark.parametrize("bad_case", BAD_CASES)
def test_multi_or_unknown_config_alone_has_no_modeled_proxy(tmp_path, bad_case):
    root = tmp_path / "fleet"
    scans = materialize(root, (bad_case,))
    aliases, _ = extract_deployment_aliases([root / name for name in scans])
    links = resolve(scans, aliases, f"https://{TARGET}/Api/Items/42")
    assert TARGET not in aliases.proxies
    assert len(links) == 2 and all(link.resolution == "candidate" for link in links)
    assert_no_direct_trust(scans, links)


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("single", ["single.conf", "repeated-single.conf", "single.yaml"])
def test_valid_single_backend_keeps_proxy_semantics_and_origins(tmp_path, scheme, single):
    root = tmp_path / "fleet"
    scans = materialize(root, (single,))
    aliases, notes = extract_deployment_aliases([root / name for name in scans])
    assert notes == []
    if single.endswith(".yaml"):
        assert aliases.proxies == {"safe.production.internal": "api"}
        assert aliases.scoped_proxies == {TARGET: "production/api"}
    else:
        assert aliases.proxies == {TARGET: "api", "safe.production.internal": "api"}
        assert aliases.source_files[f"proxies:{TARGET}"] == f"caller/case-00{Path(single).suffix}"
        raw_links = resolve(scans, aliases, f"{scheme}://EDGE.PRODUCTION.internal/Api/Items/42")
        assert raw_links[0].resolution == "candidate" and raw_links[0].resolution_reason == "unresolved_namespace"
        # An operator can affirm an abstract proxy seam explicitly. Its origin
        # is no longer the unscoped nginx declaration and must not claim one.
        aliases = replace(aliases, source_files={key: value for key, value in aliases.source_files.items()
                                                if key != f"proxies:{TARGET}"})
    links = resolve(scans, aliases, f"{scheme}://EDGE.PRODUCTION.internal/Api/Items/42")
    api, worker = links
    assert api.server_repo == "api" and api.resolution == "observed_via_proxy"
    assert api.proxy_host == TARGET
    prefix = "scoped_proxies" if single.endswith(".yaml") else "proxies"
    expected_origin = f" (caller/case-00{Path(single).suffix})" if single.endswith(".yaml") else ""
    assert api.alias_provenance == f"{prefix}:{TARGET}{expected_origin}"
    assert worker.server_repo == "worker" and worker.resolution_reason == "unresolved_host"
    assert aliases.service_protocols == {"api": "https"}
    assert "worker" not in aliases.service_protocols  # its port is merely named https
    assert_no_direct_trust(scans, links)


@pytest.mark.parametrize("port", ["", ":8443"])
def test_rejected_proxy_cannot_fall_through_to_repository_identity(tmp_path, port):
    root = tmp_path / "fleet"
    scans = materialize(root, ("identity-collision.conf",))
    aliases, _ = extract_deployment_aliases([root / name for name in scans])
    links = resolve(scans, aliases, f"https://API{port}/Api/Items/42")
    api = next(link for link in links if link.server_repo == "api")
    assert (api.resolution, api.resolution_reason) == ("candidate", "ambiguous_identity")
    assert api.alias_provenance is None and api.proxy_host is None
    assert_no_direct_trust(scans, links)


@pytest.mark.parametrize("declaration", ["host", "port", "suffix", "proxy"])
def test_rejected_proxy_remains_candidate_with_other_positive_declarations(tmp_path, declaration):
    root = tmp_path / "fleet"
    scans = materialize(root, ("mixed-upstream.conf",))
    extracted, _ = extract_deployment_aliases([root / name for name in scans])
    kwargs = {"host": {"hosts": {TARGET: "api"}}, "port": {"host_ports": {f"{TARGET}:8443": "api"}},
              "suffix": {"dns_suffixes": (".production.internal",)}, "proxy": {"proxies": {TARGET: "api"}}}[declaration]
    if declaration == "suffix":
        # The declared namespace would normally resolve this full host by repo basename.
        scans["api"].root = str(root / "edge")
    aliases = replace(extracted, **kwargs)
    links = resolve(scans, aliases, f'https://{TARGET}{":8443" if declaration == "port" else ""}/Api/Items/42')
    assert len(links) == 2 and all(link.resolution == "candidate" for link in links)
    assert_no_direct_trust(scans, links)


@pytest.mark.parametrize("mode", ["merge-empty", "merge-host", "merge-negative", "conflict-fallback"])
def test_effective_alias_merge_preserves_negative_proxy_evidence(tmp_path, mode):
    root = tmp_path / "fleet"
    scans = materialize(root, ("identity-collision.conf",))
    kwargs = {"merge-empty": {}, "merge-host": {"hosts": {"api": "api"}},
              "merge-negative": {"unresolved_proxies": (" WORKER. ", "API", "api")},
              "conflict-fallback": {"hosts": {"safe.production.internal": "worker"}}}[mode]
    effective, _ = _effective_deployment_aliases(ScanRequest(
        repo_paths=[root / name for name in scans], output=tmp_path / "reports",
        deployment_aliases=DeploymentAliases(**kwargs)))
    links = resolve(scans, effective, "https://api/Api/Items/42")
    assert all(link.resolution == "candidate" for link in links)
    assert effective.unresolved_proxies == (("api", "worker") if mode == "merge-negative" else ("api",))
    assert_no_direct_trust(scans, links)


def test_effective_aliases_retains_negative_only_config(tmp_path):
    root = tmp_path / "fleet"
    scans = materialize(root, ("identity-collision.conf",))
    for file in (root / "caller/safe.conf", root / "api/service.yaml", root / "worker/service.yaml"):
        file.unlink()
    effective, _ = _effective_deployment_aliases(ScanRequest(
        repo_paths=[root / name for name in scans], output=tmp_path / "reports"))
    links = resolve(scans, effective, "https://api/Api/Items/42")
    assert all(link.resolution == "candidate" for link in links)
    assert effective.unresolved_proxies == ("api",)
    assert_no_direct_trust(scans, links)


@pytest.mark.parametrize("prefix", ["http://", "https://", ""], ids=["http", "https", "scheme-less"])
@pytest.mark.parametrize("declaration", ["host", "proxy", "port"])
@pytest.mark.parametrize("blocked", [True, False], ids=["rejected-host", "unrelated-rejected-host"])
def test_trailing_dot_declarations_cannot_bypass_unresolved_proxy(tmp_path, prefix, declaration, blocked):
    root = tmp_path / "fleet"
    scans = materialize(root, ("mixed-upstream.conf",))
    extracted, _ = extract_deployment_aliases([root / name for name in scans])
    dotted = f"{TARGET}."
    kwargs = {"host": {"hosts": {dotted: "api"}}, "proxy": {"proxies": {dotted: "api"}},
              "port": {"host_ports": {f"{dotted}:8443": "api"}}}[declaration]
    aliases = replace(extracted, **kwargs, service_protocols={},
                      unresolved_proxies=extracted.unresolved_proxies if blocked else ("unrelated.internal",))
    authority = f'{dotted}{":8443" if declaration == "port" else ""}'
    if not prefix:
        # The existing path matcher retains a scheme-less authority as a path
        # segment. Supply that route shape to reach its destination resolver.
        for scan in scans.values():
            for route in scan.routes:
                route.path = f"/{authority}{route.path}"
    links = resolve(scans, aliases, f"{prefix}{authority}/Api/Items/42")
    api = next(link for link in links if link.server_repo == "api")
    assert api.destination == authority  # Preserve the declared authority spelling.
    worker = next(link for link in links if link.server_repo == "worker")
    assert (worker.resolution, worker.resolution_reason) == ("candidate", "unresolved_host")
    if blocked:
        assert (api.resolution, api.resolution_reason) == ("candidate", "ambiguous_identity")
        assert api.alias_provenance is None and api.proxy_host is None
        assert_no_direct_trust(scans, links)
    else:
        assert api.resolution == ("observed_via_proxy" if declaration == "proxy" else "observed")
        field = {"host": "hosts", "proxy": "proxies", "port": "host_ports"}[declaration]
        assert api.alias_provenance == f"{field}:{authority}"
        assert api.proxy_host == (dotted if declaration == "proxy" else None)
        if declaration == "proxy":
            assert_no_direct_trust(scans, links)


@pytest.mark.parametrize("prefix", ["http://", "https://", ""], ids=["http", "https", "scheme-less"])
def test_cli_dotted_host_merge_cannot_override_unresolved_config_proxy(tmp_path, prefix):
    from attackmap.cli import _parse_deployment_aliases

    root = tmp_path / "fleet"
    scans = materialize(root, ("mixed-upstream.conf",))
    dotted = f"{TARGET}."
    cli_aliases = _parse_deployment_aliases([f"{dotted}=api"], [], [], [], [])
    effective, _ = _effective_deployment_aliases(ScanRequest(
        repo_paths=[root / name for name in scans], output=tmp_path / "reports",
        deployment_aliases=cli_aliases))
    assert effective.hosts[dotted] == "api"
    assert effective.unresolved_proxies == (TARGET,)
    if not prefix:
        for scan in scans.values():
            for route in scan.routes:
                route.path = f"/{dotted}{route.path}"
    links = resolve(scans, effective, f"{prefix}{dotted}/Api/Items/42")
    api = next(link for link in links if link.server_repo == "api")
    assert (api.resolution, api.resolution_reason) == ("candidate", "ambiguous_identity")
    assert api.alias_provenance is None and api.proxy_host is None
    assert_no_direct_trust(scans, links)


def qualification_proof(root: Path) -> dict:
    scans = materialize(root, ("single.conf", "mixed-upstream.conf", "single.yaml"))
    aliases, notes = extract_deployment_aliases([root / name for name in scans])
    # This legacy invalidation/reference matrix keeps its direct positive via
    # explicit operator ports, never by stripping namespaces from retained YAML.
    aliases = DeploymentAliases(hosts={"api": "api", "worker": "worker"}, service_ports={"api": 8443, "worker": 9000},
        service_protocols=aliases.service_protocols, proxies=aliases.proxies,
        source_files={key: value for key, value in aliases.source_files.items()
                      if key.startswith(("proxies:", "service_protocols:"))},
        unresolved_proxies=aliases.unresolved_proxies,
        unresolved_service_protocols=aliases.unresolved_service_protocols)
    targets = [f"https://{TARGET}/Api/Items/42", "http://safe.production.internal/Api/Items/42",
               "https://api:8443/Api/Items/42", "http://api:8443/Api/Items/42",
               "grpc://safe.production.internal/Api/Items/42", f"https://{TARGET}/api/items/42",
               f"https://{TARGET}/API/Items/42", "https://api.preview.svc.cluster.local:8443/Api/Items/42"]
    scans["caller"].external_calls = [ExternalCall(target=target, method="POST", file="client.py", line=3,
                                                  source_analyzer=ORIGIN) for target in targets]
    links = link_contracts(list(scans.items()), aliases)
    results = [FleetRepoResult(name, scan.root, str(root / "reports" / name), scan, [])
               for name, scan in scans.items()]
    graph = build_fleet_architecture(FleetScan(results=results, links=links))
    evidence = {item["id"]: item for item in graph["evidence"]}
    edges = [edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call"]
    for edge in edges:
        refs = [evidence[ref] for ref in edge["evidence_refs"]]
        assert {item["kind"] for item in refs} == {"external_call", "route"}
        assert {item["source_analyzer"] for item in refs} >= {ORIGIN}
        assert all(item["core_repo_id"] == "caller" and item["file"] == "client.py" and item["line"] == 3
                   for item in refs if item["kind"] == "external_call")
        for item in refs:
            if item["observation_id"] is not None:
                scan = scans[item["core_repo_id"]]
                assert item["observation_id"] in {signal.observation_id for signal in scan.all_signals()}
        call_ids = {signal.observation_id for signal in scans["caller"].all_signals()
                    if signal.kind == "external_call" and signal.label == edge["client_target"]}
        assert call_ids & {item["observation_id"] for item in refs if item["kind"] == "external_call"}
        route_refs = [item for item in refs if item["kind"] == "route"]
        server = route_refs[0]["core_repo_id"]
        route_ids = {signal.observation_id for signal in scans[server].all_signals()
                     if signal.kind == "route" and signal.label == f'{edge["method"]} {edge["server_route_path"]}'}
        assert route_ids & {item["observation_id"] for item in route_refs}
        if edge["client_target"].startswith(f"https://{TARGET}/"):
            assert edge["resolution"] == "candidate"
            assert edge["provenance"] is None
        if edge["server_route_path"] == "/api/items/{id}":
            assert all(item["line"] == 6 for item in refs if item["kind"] == "route")
    assert len(links) == 13
    assert sum(link.resolution == "observed" for link in links) == 1
    assert sum(link.resolution == "observed_via_proxy" for link in links) == 1
    assert not any(link.client_target.endswith("/API/Items/42") for link in links)
    return {"scope": "physical_proxy_configs_explicit_operator_ports_normalized_app_signals_no_runtime_traffic", "provider_calls": 0,
            "aliases": asdict(aliases), "notes": notes,
            "links": [{**asdict(link), "declaration_refs": [asdict(ref) for ref in link.declaration_refs]} for link in links],
            "architecture": graph}


def test_graph_evidence_case_and_existing_protocol_guards_survive_invalidation(tmp_path):
    proof = qualification_proof(tmp_path / "fleet")
    assert json.loads(json.dumps(proof))["links"] == proof["links"]
