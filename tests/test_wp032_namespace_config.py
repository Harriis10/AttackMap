"""Physical Kubernetes config extraction: explicit scopes and fail-closed seams."""
from pathlib import Path
import os

import pytest
import yaml

from attackmap.config_scanner import extract_deployment_aliases


def service(namespace="blue", protocol="http", *, name="api", port=8080):
    return {"kind": "Service", "metadata": {"name": name, "namespace": namespace},
            "spec": {"ports": [{"port": port, "appProtocol": protocol}]}}


def ingress(namespace="blue", *, backend="api", host="edge.example"):
    metadata = {"name": "edge"}
    if namespace is not None:
        metadata["namespace"] = namespace
    return {"kind": "Ingress", "metadata": metadata, "spec": {"rules": [{"host": host,
        "http": {"paths": [{"backend": {"service": {"name": backend, "port": {"number": 8080}}}}]}}]}}


def write(root: Path, *documents):
    root.mkdir(parents=True, exist_ok=True)
    (root / "seams.yaml").write_text(yaml.safe_dump_all(documents), encoding="utf-8")
    return root


def test_service_scope_is_exact_owned_and_never_a_bare_or_guessed_dns_alias(tmp_path):
    root = write(tmp_path / "api", ingress(), service())
    aliases, _ = extract_deployment_aliases([root])
    binding = aliases.scoped_services["blue/api"]
    assert (binding.repository_root, binding.port, binding.protocol) == (os.path.normcase(str(root.resolve())), 8080, "http")
    assert aliases.scoped_proxies == {"edge.example": "blue/api"}
    assert aliases.service_ports == aliases.service_protocols == aliases.hosts == aliases.proxies == {}
    assert aliases.dns_suffixes == ()
    assert aliases.source_files["scoped_services:blue/api"] == "api/seams.yaml"
    assert aliases.source_files["scoped_proxies:edge.example"] == "api/seams.yaml"


def test_same_service_name_in_different_namespaces_keeps_distinct_exact_owners(tmp_path):
    blue = write(tmp_path / "a" / "api", service("blue"), ingress("blue", host="blue.example"))
    green = write(tmp_path / "b" / "api", service("green"), ingress("green", host="green.example"))
    aliases, _ = extract_deployment_aliases([blue, green])
    assert {key: binding.repository_root for key, binding in aliases.scoped_services.items()} == {
        "blue/api": os.path.normcase(str(blue.resolve())), "green/api": os.path.normcase(str(green.resolve()))}
    assert aliases.scoped_proxies == {"blue.example": "blue/api", "green.example": "green/api"}
    assert not aliases.service_ports
    for namespace, root in (("blue", blue), ("green", green)):
        refs = aliases.declaration_sources[f"scoped_services:{namespace}/api"]
        assert [(ref.repository_root, ref.file, ref.line) for ref in refs] == [
            (os.path.normcase(str(root.resolve())), "seams.yaml", None)]


def test_same_scope_conflicting_repository_owners_cannot_be_recovered_by_file_order(tmp_path):
    roots = [write(tmp_path / part / "api", service(), ingress()) for part in ("a", "b")]
    for ordered in (roots, list(reversed(roots))):
        aliases, notes = extract_deployment_aliases(ordered)
        assert not aliases.scoped_services and not aliases.scoped_proxies
        assert aliases.unresolved_proxies == ("edge.example",)
        assert any("conflicting repository owners" in note for note in notes)


def test_manifest_containment_never_establishes_foreign_service_ownership(tmp_path):
    root = write(tmp_path / "deployment-charts", service(), ingress())
    aliases, notes = extract_deployment_aliases([root])
    assert not aliases.scoped_services and not aliases.scoped_proxies
    assert aliases.unresolved_proxies == ("edge.example",)
    assert any("no exact repository identity ownership" in note for note in notes)


@pytest.mark.parametrize("namespace", [None, "green", "", "BLUE", 7])
def test_ingress_missing_invalid_or_other_namespace_does_not_borrow_known_service(tmp_path, namespace):
    root = write(tmp_path / "api", service(), ingress(namespace))
    aliases, _ = extract_deployment_aliases([root])
    assert set(aliases.scoped_services) == {"blue/api"}
    assert not aliases.scoped_proxies and not aliases.proxies
    assert aliases.unresolved_proxies == ("edge.example",)


def test_ingress_backend_cannot_override_its_namespace(tmp_path):
    edge = ingress()
    edge["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["namespace"] = "green"
    root = write(tmp_path / "api", service(), edge)
    aliases, _ = extract_deployment_aliases([root])
    assert not aliases.scoped_proxies and aliases.unresolved_proxies == ("edge.example",)


def test_deployment_is_not_a_service_and_explicit_namespace_never_leaks_bare_ports(tmp_path):
    deployment = {"kind": "Deployment", "metadata": {"name": "api", "namespace": "blue"},
        "spec": {"template": {"spec": {"containers": [{"ports": [{"containerPort": 8080}]}]}}}}
    root = write(tmp_path / "api", deployment, ingress())
    aliases, notes = extract_deployment_aliases([root])
    assert not aliases.scoped_services and not aliases.service_ports and not aliases.scoped_proxies
    assert aliases.unresolved_proxies == ("edge.example",)
    assert any("Deployment is not a Service" in note for note in notes)


@pytest.mark.parametrize("namespace", ["blue", None])
def test_unsupported_service_protocol_survives_as_negative_fact(tmp_path, namespace):
    doc = service(protocol="grpc")
    if namespace is None:
        del doc["metadata"]["namespace"]
    root = write(tmp_path / "api", doc, ingress(namespace))
    aliases, _ = extract_deployment_aliases([root])
    identity = "blue/api" if namespace else "api"
    assert identity in aliases.unresolved_service_protocols
    assert aliases.source_files[f"unresolved_service_protocols:{identity}"] == "api/seams.yaml"
    if namespace:
        assert aliases.scoped_services[identity].protocol is None
        assert aliases.scoped_proxies == {"edge.example": "blue/api"}
        assert not aliases.unresolved_proxies


def test_conflicting_scoped_protocol_is_not_downgraded_to_positive_unknown(tmp_path):
    root = write(tmp_path / "api", service(protocol="http"), service(protocol="https"), ingress())
    aliases, _ = extract_deployment_aliases([root])
    assert aliases.unresolved_service_protocols == ("blue/api",)
    assert aliases.scoped_services["blue/api"].protocol is None
    assert aliases.scoped_proxies == {"edge.example": "blue/api"}
    assert not aliases.unresolved_proxies


@pytest.mark.parametrize("namespace", ["blue", None])
def test_conflicting_protocols_on_duplicate_dial_port_remain_negative(tmp_path, namespace):
    doc = service()
    doc["spec"]["ports"].append({"port": 8080, "appProtocol": "https"})
    if namespace is None:
        del doc["metadata"]["namespace"]
    root = write(tmp_path / "api", doc)
    aliases, _ = extract_deployment_aliases([root])
    assert aliases.unresolved_service_protocols == (("blue/api" if namespace else "api"),)


def test_agreeing_service_protocol_and_ingress_annotation_keep_same_scoped_port(tmp_path):
    edge = ingress()
    edge["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["port"] = {"number": 8443}
    edge["metadata"]["annotations"] = {"nginx.ingress.kubernetes.io/backend-protocol": "https"}
    root = write(tmp_path / "api", service(protocol="https", port=8443), edge)
    aliases, _ = extract_deployment_aliases([root])
    assert aliases.scoped_services["blue/api"].port == 8443
    assert aliases.scoped_services["blue/api"].protocol == "https"
    assert not aliases.unresolved_service_protocols


@pytest.mark.parametrize("port", [{"number": 9999}, {"number": True}, {"number": "8080"},
    {"number": 0}, {"number": 65536}, {"number": 8080, "name": "web"}, {}, None,
    {"name": "unknown"}, {"name": ""}, {"name": True}])
def test_scoped_ingress_port_must_be_one_exact_service_dial_port(tmp_path, port):
    edge = ingress()
    edge["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["port"] = port
    root = write(tmp_path / "api", service(), edge)
    aliases, _ = extract_deployment_aliases([root])
    assert set(aliases.scoped_services) == {"blue/api"}
    assert not aliases.scoped_proxies and not aliases.proxies
    assert aliases.unresolved_proxies == ("edge.example",)


def test_exact_named_service_port_does_not_infer_tls_from_its_name(tmp_path):
    doc = service(protocol=None)
    doc["spec"]["ports"][0]["name"] = "https"
    edge = ingress()
    edge["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["port"] = {"name": "https"}
    root = write(tmp_path / "api", doc, edge)
    aliases, _ = extract_deployment_aliases([root])
    assert aliases.scoped_proxies == {"edge.example": "blue/api"}
    assert aliases.scoped_services["blue/api"].port == 8080
    assert aliases.scoped_services["blue/api"].protocol is None


@pytest.mark.parametrize("port", [True, "8080"])
def test_scoped_service_port_cannot_be_coerced_from_invalid_yaml_type(tmp_path, port):
    root = write(tmp_path / "api", service(port=port), ingress())
    aliases, _ = extract_deployment_aliases([root])
    assert not aliases.scoped_services and not aliases.scoped_proxies
    assert aliases.unresolved_proxies == ("edge.example",)


def test_one_invalid_port_path_invalidates_the_entire_scoped_host(tmp_path):
    edge = ingress()
    edge["spec"]["rules"][0]["http"]["paths"].append({"backend": {
        "service": {"name": "api", "port": {"number": 9999}}}})
    root = write(tmp_path / "api", service(), edge)
    aliases, _ = extract_deployment_aliases([root])
    assert not aliases.scoped_proxies and aliases.unresolved_proxies == ("edge.example",)


@pytest.mark.parametrize("redirect", [{"type": "ExternalName"}, {"externalName": "unrelated.example"},
                                      {"type": "ClusterIP", "externalName": ""}])
def test_external_name_redirect_is_not_an_owned_service_even_with_matching_port(tmp_path, redirect):
    doc = service()
    doc["spec"].update(redirect)
    root = write(tmp_path / "api", doc, ingress())
    aliases, notes = extract_deployment_aliases([root])
    assert not aliases.scoped_services and not aliases.scoped_proxies and not aliases.service_ports
    assert aliases.unresolved_proxies == ("edge.example",)
    assert any("ExternalName DNS redirection" in note for note in notes)


def test_conflicting_service_and_ingress_backend_protocol_retain_both_exact_origins(tmp_path):
    root = write(tmp_path / "api", service(protocol="https"))
    edge = ingress()
    edge["metadata"]["annotations"] = {"nginx.ingress.kubernetes.io/backend-protocol": "http"}
    (root / "edge.yaml").write_text(yaml.safe_dump(edge), encoding="utf-8")
    aliases, _ = extract_deployment_aliases([root])
    assert aliases.unresolved_service_protocols == ("blue/api",)
    assert aliases.scoped_services["blue/api"].protocol is None
    assert aliases.scoped_proxies == {"edge.example": "blue/api"}
    refs = aliases.declaration_sources["unresolved_service_protocols:blue/api"]
    assert {(ref.repository_root, ref.file, ref.line) for ref in refs} == {
        (os.path.normcase(str(root.resolve())), "edge.yaml", None),
        (os.path.normcase(str(root.resolve())), "seams.yaml", None)}
