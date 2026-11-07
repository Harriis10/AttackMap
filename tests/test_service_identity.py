"""WP032 authority, route identity and ambiguity regression contracts."""
from pathlib import Path

import pytest

from attackmap.config_scanner import extract_deployment_aliases
from attackmap.contracts import DeploymentAliases, destination_authority, link_contracts
from attackmap.models import ExternalCall, Route, ScanResult


def client(target: str) -> ScanResult:
    return ScanResult(root="client", external_calls=[ExternalCall(target=target, method="GET", file="client.py", line=3)])


def server(root: str, path: str = "/Api/Users/{id}") -> ScanResult:
    return ScanResult(root=root, routes=[Route(path=path, method="GET", file="server.py", line=7)])


def test_dns_case_does_not_erase_route_case():
    scans = [("client", client("https://API/Api/Users/42")), ("api", server("api"))]
    links = link_contracts(scans)
    assert len(links) == 1 and links[0].resolution == "observed"
    assert links[0].path_template == "Api/Users/*"
    scans[0] = ("client", client("https://API/api/users/42"))
    assert link_contracts(scans) == []


@pytest.mark.parametrize("target", ["http://api:bad/Api/Users/42", "http://api:65536/Api/Users/42", "http://api:0/Api/Users/42", "http://[invalid/Api/Users/42", "api:65536/Api/Users/42", "api:0/Api/Users/42", "http://api:/Api/Users/42", "http://a\npi/Api/Users/42"])
def test_malformed_authority_never_establishes_an_observed_edge(target):
    assert destination_authority(target) is None
    links = link_contracts([("client",client(target)),("api",server("api"))])
    assert all(link.resolution == "candidate" for link in links)


@pytest.mark.parametrize("binding", ["api:0", "api:65536", "https://api:80", "api/path:80", "user@api:80"])
def test_invalid_explicit_port_declarations_are_rejected(binding):
    with pytest.raises(ValueError):
        DeploymentAliases(host_ports={binding:"api"})


def test_normalized_alias_conflicts_are_not_silently_overwritten():
    with pytest.raises(ValueError, match="conflicting"):
        DeploymentAliases(hosts={"API.internal":"one", "api.internal":"two"})
    with pytest.raises(ValueError, match="conflicting"):
        DeploymentAliases(host_ports={"API.internal:80":"one", "api.internal:080":"two"})


def test_canonical_port_alias_keeps_its_declaring_source():
    aliases = DeploymentAliases(host_ports={"API.internal:08443":"api"},source_files={"host_ports:API.internal:08443":"deploy/edge.yaml"})
    links = link_contracts([("client",client("https://api.internal:8443/Api/Users/42")),("api",server("api"))],aliases)
    assert len(links) == 1 and links[0].resolution == "observed"
    assert links[0].alias_provenance == "host_ports:api.internal:8443 (deploy/edge.yaml)"


def test_explicit_port_does_not_disambiguate_two_services_listening_on_that_port():
    aliases = DeploymentAliases(service_ports={"one":8443,"two":8443})
    links = link_contracts([("client",client("https://api:8443/Api/Users/42")),("one",server("/first/api")),("two",server("/second/api"))],aliases)
    assert len(links) == 2
    assert {link.resolution for link in links} == {"candidate"}
    assert {link.resolution_reason for link in links} == {"ambiguous_identity"}


def test_conflicting_protocol_declarations_cannot_vouch_for_either_scheme():
    aliases = DeploymentAliases(service_protocols={"api":"http","backend":"https"})
    for scheme in ("http","https"):
        links = link_contracts([("client",client(f"{scheme}://api/Api/Users/42")),("api",server("/services/backend"))],aliases)
        assert len(links) == 1 and links[0].resolution == "candidate"
        assert links[0].resolution_reason == "scheme_mismatch"


def test_three_services_config_only_aliases_preserve_provenance_and_negative_edges(tmp_path: Path):
    gateway, api, worker = [tmp_path / name for name in ("gateway","api","worker")]
    for repo in (gateway,api,worker): repo.mkdir()
    (api / "service.yaml").write_text("kind: Service\nmetadata:\n  name: api\nspec:\n  ports:\n    - port: 8443\n      appProtocol: https\n",encoding="utf-8")
    aliases, notes = extract_deployment_aliases([gateway,api,worker])
    scans = [("gateway",client("https://api:8443/Api/Users/42")),("api",server(str(api))),("worker",server(str(worker)))]
    links = link_contracts(scans,aliases)
    observed = [link for link in links if link.resolution == "observed"]
    assert len(observed) == 1 and observed[0].server_repo == "api"
    assert "api/service.yaml" in observed[0].alias_provenance
    assert all(link.resolution == "candidate" for link in links if link.server_repo == "worker")
    scans[0] = ("gateway",client("http://api:8443/Api/Users/42"))
    assert all(link.resolution == "candidate" for link in link_contracts(scans,aliases))


def test_same_host_multiple_upstream_ports_never_collapse_into_single_backend(tmp_path: Path):
    repo = tmp_path / "edge"
    repo.mkdir()
    (repo / "nginx.conf").write_text("upstream backend { server api:8080; server api:9090; }\nserver { server_name edge.internal; location / { proxy_pass http://backend; } }\n",encoding="utf-8")
    aliases, notes = extract_deployment_aliases([repo])
    assert "edge.internal" not in aliases.proxies
    assert any("2 backends" in note for note in notes)
    links = link_contracts([("client",client("http://edge.internal/Api/Users/42")),("api",server("api"))],aliases)
    assert len(links) == 1 and links[0].resolution == "candidate"
