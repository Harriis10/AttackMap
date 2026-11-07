"""Qualified deployment facts must survive orchestration and report projection."""
import pytest

from attackmap.contracts import ContractLink, DeclarationSource, DeploymentAliases, ScopedServiceBinding
from attackmap.fleet import FleetRepoResult, FleetScan, fleet_summary_json
from attackmap.models import ScanResult
from attackmap.scan_service import ScanRequest, _effective_deployment_aliases


def extracted_aliases():
    return DeploymentAliases(
        scoped_services={"prod/api": ScopedServiceBinding("/fleet/prod/api", 8080, "http")},
        scoped_proxies={"edge.example": "prod/api"},
        unresolved_service_protocols=("dev/api",),
        unresolved_proxies=("blocked.example",),
        source_files={"scoped_services:prod/api": "api/service.yaml",
                      "scoped_proxies:edge.example": "api/ingress.yaml"},
        declaration_sources={
            "scoped_services:prod/api": (DeclarationSource("/fleet/prod/api", "k8s/service.yaml"),),
            "scoped_proxies:edge.example": (DeclarationSource("/fleet/prod/api", "k8s/ingress.yaml"),),
        },
    )


def effective(monkeypatch, aliases, cli=None):
    monkeypatch.setattr("attackmap.config_scanner.extract_deployment_aliases",
                        lambda roots: (aliases, []))
    return _effective_deployment_aliases(ScanRequest(
        repo_paths=[], output="/output", deployment_aliases=cli))


@pytest.mark.parametrize("aliases", [
    DeploymentAliases(scoped_services={"prod/api": ScopedServiceBinding("/fleet/prod/api")}),
    DeploymentAliases(unresolved_service_protocols=("api",)),
    DeploymentAliases(service_protocols={"api": "https"}),
])
def test_nonempty_qualified_or_protocol_facts_are_not_discarded(monkeypatch, aliases):
    actual, _ = effective(monkeypatch, aliases)
    assert actual == aliases


def test_unrelated_cli_declaration_preserves_namespace_and_negative_facts(monkeypatch):
    extracted = extracted_aliases()
    cli = DeploymentAliases(hosts={"other.example": "other"},
                            unresolved_service_protocols=("third/api",))
    actual, _ = effective(monkeypatch, extracted, cli)
    assert actual.scoped_services == extracted.scoped_services
    assert actual.scoped_proxies == extracted.scoped_proxies
    assert actual.source_files == extracted.source_files
    assert actual.declaration_sources == extracted.declaration_sources
    assert actual.unresolved_proxies == ("blocked.example",)
    assert actual.unresolved_service_protocols == ("dev/api", "third/api")
    assert extracted.unresolved_service_protocols == ("dev/api",)


@pytest.mark.parametrize("field,key", [
    ("hosts", "edge.example"), ("proxies", "edge.example"),
    ("host_ports", "edge.example:8443"),
])
def test_explicit_operator_override_does_not_inherit_scoped_config_origin(monkeypatch, field, key):
    extracted = extracted_aliases()
    actual, _ = effective(monkeypatch, extracted, DeploymentAliases(**{field: {key: "operator"}}))
    assert actual.scoped_proxies == {}
    assert "scoped_proxies:edge.example" not in actual.source_files
    assert "scoped_proxies:edge.example" not in actual.declaration_sources
    assert actual.declaration_sources["scoped_services:prod/api"] == extracted.declaration_sources["scoped_services:prod/api"]
    assert actual.source_files["scoped_services:prod/api"] == "api/service.yaml"
    assert actual.unresolved_service_protocols == ("dev/api",)
    assert actual.unresolved_proxies == ("blocked.example",)
    assert extracted.scoped_proxies == {"edge.example": "prod/api"}


def test_legacy_conflict_fallback_keeps_protocol_and_proxy_negative_evidence(monkeypatch):
    declarations = (DeclarationSource("/fleet/api", "http.yaml"), DeclarationSource("/fleet/api", "https.yaml"))
    extracted = DeploymentAliases(proxies={"edge.example": "api"},
        unresolved_service_protocols=("api",), unresolved_proxies=("blocked.example",),
        source_files={"unresolved_service_protocols:api": "api/https.yaml"},
        declaration_sources={"unresolved_service_protocols:api": declarations})
    actual, notes = effective(monkeypatch, extracted,
        DeploymentAliases(hosts={"edge.example": "operator"}, unresolved_service_protocols=("other",)))
    assert actual.hosts == {"edge.example": "operator"}
    assert actual.proxies == {}
    assert actual.unresolved_service_protocols == ("api", "other")
    assert actual.unresolved_proxies == ("blocked.example",)
    assert actual.source_files == {"unresolved_service_protocols:api": "api/https.yaml"}
    assert set(actual.declaration_sources["unresolved_service_protocols:api"]) == set(declarations)
    assert any("using CLI declarations only" in note for note in notes)


def test_programmatic_operator_sources_are_retained_without_erasing_negative_origins(monkeypatch):
    configured = DeclarationSource("/fleet/api", "config.yaml")
    supplied = DeclarationSource("/fleet/api", "operator.yaml")
    actual, _ = effective(monkeypatch,
        DeploymentAliases(unresolved_service_protocols=("api",),
                          declaration_sources={"unresolved_service_protocols:api": (configured,)}),
        DeploymentAliases(hosts={"manual.example": "api"},
                          source_files={"hosts:manual.example": "api/operator.yaml"},
                          declaration_sources={"hosts:manual.example": (supplied,),
                                               "unresolved_service_protocols:api": (supplied,)}))
    assert actual.source_files["hosts:manual.example"] == "api/operator.yaml"
    assert actual.declaration_sources["hosts:manual.example"] == (supplied,)
    assert set(actual.declaration_sources["unresolved_service_protocols:api"]) == {configured, supplied}


def test_namespace_facts_reach_fleet_json_and_both_proxy_graph_legs():
    fleet = FleetScan(results=[FleetRepoResult(repo_id=name, root=root,
        report_dir=f"/output/{name}", scan=ScanResult(root=root), findings=[])
        for name, root in (("client", "/fleet/client"), ("api", "/fleet/prod/api"), ("api-2", "/fleet/dev/api"))])
    fleet.links = [ContractLink(client_repo="client", server_repo="api", method="GET",
        path_template="items/*", client_target="http://edge.example/items/1",
        client_file="client.py", client_line=1, server_route_path="/items/{id}",
        server_file="app.py", server_line=2, resolution="observed_via_proxy",
        proxy_host="edge.example", scheme="http", server_namespace="prod", server_service_name="api",
        server_port=8080, server_protocol="https",
        declaration_refs=(DeclarationSource("/fleet/prod/api", "k8s/service.yaml"),
                          DeclarationSource("/fleet/prod/api", "k8s/ingress.yaml")))]
    summary = fleet_summary_json(fleet)
    assert summary["cross_repo_links"][0]["server_namespace"] == "prod"
    assert summary["cross_repo_links"][0]["server_service_name"] == "api"
    assert summary["cross_repo_links"][0]["server_port"] == 8080
    assert summary["cross_repo_links"][0]["server_protocol"] == "https"
    assert summary["cross_repo_links"][0]["scheme"] == "http"
    assert {ref["repository_root"] for ref in summary["cross_repo_links"][0]["declaration_refs"]} == {"/fleet/prod/api"}
    edges = [edge for edge in summary["fleet_architecture"]["edges"]
             if edge["kind"] == "cross_repo_http_call"]
    assert len(edges) == 2
    assert {edge["leg"] for edge in edges} == {"client_to_proxy", "proxy_to_server"}
    assert all(edge["server_namespace"] == "prod" and edge["server_service_name"] == "api"
               and edge["server_port"] == 8080 and edge["server_protocol"] == "https"
               and edge["scheme"] == "http" and edge["resolution"] == "observed_via_proxy" for edge in edges)
    prod_id = next(repo["id"] for repo in summary["fleet_architecture"]["repositories"] if repo["repo_id"] == "api")
    evidence = {ref["id"]: ref for ref in summary["fleet_architecture"]["evidence"]}
    for edge in edges:
        references = [evidence[ref] for ref in edge["evidence_refs"]
                      if evidence[ref]["kind"] == "deployment_declaration"]
        assert {ref["file"] for ref in references} == {"k8s/service.yaml", "k8s/ingress.yaml"}
        assert all(ref["repo_id"] == prod_id and ref["line"] is None
                   and ref["snapshot_binding"] == "unverified" for ref in references)
