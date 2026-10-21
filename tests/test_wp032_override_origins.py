"""Operator declarations must not inherit a config declaration's ownership."""
import pytest

from attackmap.contracts import DeploymentAliases
from attackmap.scan_service import ScanRequest, _effective_deployment_aliases


@pytest.fixture
def config_aliases(monkeypatch):
    extracted = DeploymentAliases(
        service_ports={"auth-api": 8443},
        service_protocols={"auth-api": "https", "auth-api-worker": "https"},
        proxies={"edge.internal": "auth-api"},
        source_files={
            "service_ports:auth-api:8443": "auth/service.yaml",
            "service_protocols:auth-api:https": "auth/service.yaml",
            "service_protocols:auth-api-worker:https": "worker/service.yaml",
            "proxies:edge.internal": "edge/nginx.conf",
        },
    )
    monkeypatch.setattr("attackmap.config_scanner.extract_deployment_aliases",
                        lambda roots: (extracted, ["retained extraction note"]))
    return extracted


@pytest.mark.parametrize("scheme", ["https", "http"])
def test_cli_protocol_redeclaration_loses_file_ownership(tmp_path, config_aliases, scheme):
    effective, notes = _effective_deployment_aliases(ScanRequest(
        repo_paths=[], output=tmp_path,
        deployment_aliases=DeploymentAliases(service_protocols={" AUTH-API ": scheme}),
    ))
    assert effective.service_protocols == {"auth-api": scheme, "auth-api-worker": "https"}
    assert "service_protocols:auth-api:https" not in effective.source_files
    assert "service_protocols:auth-api:http" not in effective.source_files
    assert effective.source_files == {
        "service_ports:auth-api:8443": "auth/service.yaml",
        "service_protocols:auth-api-worker:https": "worker/service.yaml",
        "proxies:edge.internal": "edge/nginx.conf",
    }
    assert effective.service_ports == config_aliases.service_ports
    assert effective.proxies == config_aliases.proxies
    assert notes == ["retained extraction note"]
    assert config_aliases.source_files["service_protocols:auth-api:https"] == "auth/service.yaml"


def test_new_cli_protocol_does_not_claim_an_unrelated_config_file(tmp_path, config_aliases):
    effective, _ = _effective_deployment_aliases(ScanRequest(
        repo_paths=[], output=tmp_path,
        deployment_aliases=DeploymentAliases(service_protocols={"new-service": "http"}),
    ))
    assert effective.source_files == config_aliases.source_files
    assert effective.service_protocols == {**config_aliases.service_protocols, "new-service": "http"}
    assert "service_protocols:new-service:http" not in effective.source_files


def test_port_and_proxy_overrides_keep_their_existing_origin_rules(tmp_path, config_aliases):
    effective, _ = _effective_deployment_aliases(ScanRequest(
        repo_paths=[], output=tmp_path,
        deployment_aliases=DeploymentAliases(service_ports={"auth-api": 9999},
                                             proxies={"edge.internal": "replacement"}),
    ))
    assert effective.service_ports["auth-api"] == 9999
    assert effective.proxies["edge.internal"] == "replacement"
    assert effective.source_files == {
        "service_protocols:auth-api:https": "auth/service.yaml",
        "service_protocols:auth-api-worker:https": "worker/service.yaml",
    }
