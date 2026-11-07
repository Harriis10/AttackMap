"""Namespace ownership and explicit unsupported deployment protocol safety."""
from dataclasses import fields

import pytest

from attackmap.config_scanner import extract_deployment_aliases
from attackmap.contracts import DeclarationSource, DeploymentAliases, ScopedServiceBinding, link_contracts
from attackmap.models import ExternalCall, Route, ScanResult


@pytest.mark.parametrize("protocols", [("grpc",), ("http", "https")])
def test_extracted_protocol_negative_cannot_become_unknown_http(tmp_path, protocols):
    api = tmp_path / "api"
    api.mkdir()
    for number, protocol in enumerate(protocols):
        (api / f"service-{number}.yaml").write_text(
            "kind: Service\nmetadata:\n  name: api\nspec:\n  ports:\n"
            f"    - port: 8080\n      appProtocol: {protocol}\n", encoding="utf-8")
    aliases, _ = extract_deployment_aliases([api])
    scans = [("client", ScanResult(root=str(tmp_path / "client"), external_calls=[
        ExternalCall(target="http://api:8080/items/1", method="GET", file="client.py", line=1)])),
        ("api", ScanResult(root=str(api), routes=[Route(path="/items/{id}", method="GET", file="api.py", line=1)]))]
    links = link_contracts(scans, aliases)
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason in {"unsupported_protocol", "scheme_mismatch"}


@pytest.mark.parametrize("namespace", [None, "prod"])
def test_unsupported_ingress_backend_protocol_does_not_become_unknown_http(tmp_path, namespace):
    api = tmp_path / "api"
    api.mkdir()
    scope = f"  namespace: {namespace}\n" if namespace is not None else ""
    (api / "service.yaml").write_text(
        f"kind: Service\nmetadata:\n  name: api\n{scope}spec:\n  ports:\n    - port: 8080\n", encoding="utf-8")
    (api / "ingress.yaml").write_text(
        f"kind: Ingress\nmetadata:\n  name: edge\n{scope}  annotations:\n"
        "    nginx.ingress.kubernetes.io/backend-protocol: GRPC\n"
        "spec:\n  rules:\n    - host: edge.example\n      http:\n        paths:\n"
        "          - path: /\n            backend:\n              service:\n                name: api\n"
        "                port:\n                  number: 8080\n",
        encoding="utf-8")
    aliases, _ = extract_deployment_aliases([api])
    scans = [("client", ScanResult(root=str(tmp_path / "client"), external_calls=[
        ExternalCall(target="http://edge.example/items/1", method="GET", file="client.py", line=1)])),
        ("api", ScanResult(root=str(api), routes=[Route(path="/items/{id}", method="GET", file="api.py", line=1)]))]
    links = link_contracts(scans, aliases)
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "unsupported_protocol"


def test_unsupported_nginx_backend_protocol_does_not_support_http_route(tmp_path):
    api = tmp_path / "api"
    api.mkdir()
    (api / "nginx.conf").write_text(
        "upstream backend { server api:8080; }\n"
        "server { server_name edge.example; location / { proxy_pass grpc://backend; } }\n",
        encoding="utf-8")
    aliases, _ = extract_deployment_aliases([api])
    scans = [("client", ScanResult(root=str(tmp_path / "client"), external_calls=[
        ExternalCall(target="http://edge.example/items/1", method="GET", file="client.py", line=1)])),
        ("api", ScanResult(root=str(api), routes=[Route(path="/items/{id}", method="GET", file="api.py", line=1)]))]
    links = link_contracts(scans, aliases)
    assert len(links) == 1
    assert links[0].resolution == "candidate" and links[0].resolution_reason == "unsupported_protocol"


def test_ingress_backend_port_must_match_the_explicit_service_port(tmp_path):
    api = tmp_path / "api"
    api.mkdir()
    (api / "service.yaml").write_text(
        "kind: Service\nmetadata:\n  name: api\n  namespace: prod\nspec:\n  ports:\n    - port: 8080\n",
        encoding="utf-8")
    (api / "ingress.yaml").write_text(
        "kind: Ingress\nmetadata:\n  name: edge\n  namespace: prod\nspec:\n  rules:\n"
        "    - host: edge.example\n      http:\n        paths:\n          - path: /\n"
        "            backend:\n              service:\n                name: api\n"
        "                port:\n                  number: 9999\n", encoding="utf-8")
    aliases, _ = extract_deployment_aliases([api])
    scans = [("client", ScanResult(root=str(tmp_path / "client"), external_calls=[
        ExternalCall(target="http://edge.example/items/1", method="GET", file="client.py", line=1)])),
        ("api", ScanResult(root=str(api), routes=[Route(path="/items/{id}", method="GET", file="api.py", line=1)]))]
    links = link_contracts(scans, aliases)
    assert len(links) == 1
    assert links[0].resolution == "candidate"


def test_external_name_service_does_not_establish_repository_owned_backend(tmp_path):
    api = tmp_path / "api"
    api.mkdir()
    (api / "service.yaml").write_text(
        "kind: Service\nmetadata:\n  name: api\n  namespace: prod\nspec:\n"
        "  type: ExternalName\n  externalName: unrelated.example\n  ports:\n    - port: 8080\n",
        encoding="utf-8")
    (api / "ingress.yaml").write_text(
        "kind: Ingress\nmetadata:\n  name: edge\n  namespace: prod\nspec:\n  rules:\n"
        "    - host: edge.example\n      http:\n        paths:\n          - path: /\n"
        "            backend:\n              service:\n                name: api\n"
        "                port:\n                  number: 8080\n", encoding="utf-8")
    aliases, _ = extract_deployment_aliases([api])
    scans = [("client", ScanResult(root=str(tmp_path / "client"), external_calls=[
        ExternalCall(target="http://edge.example/items/1", method="GET", file="client.py", line=1)])),
        ("api", ScanResult(root=str(api), routes=[Route(path="/items/{id}", method="GET", file="api.py", line=1)]))]
    links = link_contracts(scans, aliases)
    assert len(links) == 1
    assert links[0].resolution == "candidate"


def scoped_links(target="http://edge.example/items/1", **changes):
    aliases = dict(scoped_services={
        "prod/api": ScopedServiceBinding("C:/fleet/prod/api", 8080, "https"),
        "dev/api": ScopedServiceBinding("C:/fleet/dev/api", 8080, "http")},
        scoped_proxies={"edge.example": "prod/api"},
        source_files={"scoped_proxies:edge.example": "prod/api/ingress.yaml"})
    aliases.update(changes)
    scans = [("client", ScanResult(root="C:/fleet/client", external_calls=[
        ExternalCall(target=target, method="GET", file="client.py", line=1)]))]
    scans.extend((repo, ScanResult(root=root, routes=[
        Route(path="/items/{id}", method="GET", file="app.py", line=2)]))
        for repo, root in (("prod-api", "C:/fleet/prod/api"), ("dev-api", "C:/fleet/dev/api")))
    return link_contracts(scans, DeploymentAliases(**aliases))


def test_namespace_proxy_selects_exact_root_and_preserves_facts_without_tls_inference():
    links = scoped_links()
    assert [(link.server_repo, link.resolution) for link in links] == [
        ("dev-api", "candidate"), ("prod-api", "observed_via_proxy")]
    observed = links[1]
    assert (observed.server_namespace, observed.server_service_name) == ("prod", "api")
    assert observed.alias_provenance == "scoped_proxies:edge.example (prod/api/ingress.yaml)"
    assert observed.proxy_host == "edge.example"
    assert (observed.server_port, observed.server_protocol) == (8080, "https")
    assert links[0].server_port is None and links[0].server_protocol is None
    # Backend HTTPS does not declare TLS on the client's HTTP ingress leg.
    assert observed.scheme == "http"


@pytest.mark.parametrize("target,reason", [
    ("grpc://edge.example/items/1", "unsupported_protocol"),
    ("http://edge.example:8080/items/1", "explicit_port"),
])
def test_scoped_backend_port_and_protocol_never_vouch_for_proxy_listener(target, reason):
    links = scoped_links(target)
    assert all(link.resolution == "candidate" for link in links)
    owned = next(link for link in links if link.server_repo == "prod-api")
    assert owned.resolution_reason == reason
    assert (owned.server_namespace, owned.server_service_name) == ("prod", "api")
    assert owned.proxy_host is None
    assert (owned.server_port, owned.server_protocol) == (8080, "https")
    assert next(link for link in links if link.server_repo == "dev-api").server_namespace is None


@pytest.mark.parametrize("target", ["http://edge.example/items/1", "http://edge.example./items/1"])
@pytest.mark.parametrize("declaration", ["hosts", "proxies", "host_ports"])
def test_conflicting_scoped_and_legacy_topology_is_not_resolved(target, declaration):
    key = "edge.example:8080" if declaration == "host_ports" else "edge.example"
    if declaration == "host_ports":
        target = target.replace("/items/", ":8080/items/")
    links = scoped_links(target, **{declaration: {key: "prod-api"}})
    assert all(link.resolution == "candidate" for link in links)
    assert next(link for link in links if link.server_repo == "prod-api").resolution_reason == "ambiguous_identity"


def test_unresolved_proxy_negative_survives_scoped_positive_and_root_dot():
    links = scoped_links("http://edge.example./items/1", unresolved_proxies=("edge.example",))
    assert all(link.resolution == "candidate" and link.alias_provenance is None for link in links)


@pytest.mark.parametrize("negative", ["prod/api", "prod-api", "api"])
def test_explicit_negative_protocol_cannot_soften_to_unknown_for_scoped_proxy(negative):
    links = scoped_links(unresolved_service_protocols=(negative,))
    owned = next(link for link in links if link.server_repo == "prod-api")
    assert owned.resolution == "candidate" and owned.resolution_reason == "unsupported_protocol"
    assert owned.server_namespace == "prod" and owned.server_service_name == "api"
    assert owned.proxy_host is None
    assert owned.server_port == 8080 and owned.server_protocol is None


def test_absent_scoped_owner_cannot_fall_back_to_same_basename():
    links = scoped_links("http://api/items/1", scoped_proxies={"api": "missing/api"})
    assert all(link.resolution == "candidate" and link.proxy_host is None for link in links)


def test_known_namespace_cannot_be_resolved_from_bare_repo_identity_without_operator_binding():
    scans = [("client", ScanResult(root="C:/fleet/client", external_calls=[
        ExternalCall(target="http://api/items/1", method="GET", file="client.py", line=1)])),
        ("api", ScanResult(root="C:/fleet/prod/api", routes=[
            Route(path="/items/{id}", method="GET", file="app.py", line=2)]))]
    service = {"prod/api": ScopedServiceBinding("C:/fleet/prod/api", 8080, "http")}
    links = link_contracts(scans, DeploymentAliases(scoped_services=service))
    assert links[0].resolution == "candidate" and links[0].resolution_reason == "unresolved_namespace"
    assert links[0].server_namespace is None
    explicit = link_contracts(scans, DeploymentAliases(scoped_services=service, hosts={"api": "api"}))
    assert explicit[0].resolution == "observed"
    assert explicit[0].server_namespace is None  # An abstract operator seam is not a Kubernetes default.


@pytest.mark.parametrize("target", ["http://api.prod.svc/items/1", "http://api.prod.svc.cluster.local/items/1"])
def test_scoped_declaration_does_not_create_implicit_dns_alias(target):
    assert all(link.resolution == "candidate" for link in scoped_links(target))


@pytest.mark.parametrize("scope", ["api", "/api", "prod/", "Prod/api", "prod/api/extra", "prod/with.dot"])
def test_invalid_or_missing_namespace_is_not_a_scoped_identity(scope):
    with pytest.raises(ValueError):
        DeploymentAliases(scoped_services={scope: ScopedServiceBinding("C:/fleet/api")})


def test_appended_fields_preserve_legacy_positional_arguments():
    assert [item.name for item in fields(DeploymentAliases)][:8] == [
        "hosts", "host_ports", "dns_suffixes", "proxies", "service_ports",
        "service_protocols", "source_files", "unresolved_proxies"]
    legacy = DeploymentAliases({}, {}, (), {}, {"api": 8080}, {}, {}, ())
    assert legacy.service_ports == {"api": 8080} and not legacy.scoped_services


def test_typed_declarations_distinguish_same_relative_file_and_preserve_negative_origins():
    service = DeclarationSource("C:/fleet/prod/api", "k8s/service.yaml")
    ingress = DeclarationSource("C:/fleet/prod/api", "k8s/ingress.yaml")
    conflict = DeclarationSource("C:/fleet/prod/api", "k8s/conflict.yaml", 9)
    other = DeclarationSource("C:/fleet/dev/api", "k8s/ingress.yaml")
    links = scoped_links(unresolved_service_protocols=("prod/api",), declaration_sources={
        "scoped_services:prod/api": (service,), "scoped_proxies:edge.example": (ingress,),
        "unresolved_service_protocols:prod/api": (service, conflict),
        "scoped_services:dev/api": (other,)})
    owned = next(link for link in links if link.server_repo == "prod-api")
    assert set(owned.declaration_refs) == {service, ingress, conflict}
    assert owned.resolution == "candidate" and owned.proxy_host is None
    assert next(link for link in links if link.server_repo == "dev-api").declaration_refs == ()
    assert service.line is None and ingress != other


@pytest.mark.parametrize("file", ["../service.yaml", "k8s/../service.yaml", "/service.yaml", "C:/service.yaml", "k8s//service.yaml", "k8s/service.yaml:stream"])
def test_typed_declaration_rejects_unsafe_relative_file(file):
    with pytest.raises(ValueError):
        DeclarationSource("C:/fleet/prod/api", file)
