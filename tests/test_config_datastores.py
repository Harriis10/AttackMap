"""Physical config extraction through core fleet projection, without a provider."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from attackmap.config_datastores import extract_config_datastores
from attackmap.config_scanner import scan_config_repo
from attackmap.fleet import FleetRepoResult, FleetScan, fleet_summary_json
from attackmap.fleet_resource_identity import extract_shared_datastore_declarations
from attackmap.index import RepoIndex
from attackmap.models import ScanResult
from attackmap.signal_provenance import stamp_scan_provenance

FIXTURES = Path(__file__).parent / "fixtures" / "shared_datastores"
IDENTITY = dict(scope="production-eu", protocol="postgresql", host="db.example.internal",
                port=5432, namespace="public", resource="orders")


def document(**identity):
    return {"attackmap_datastores": {"schema_version": "1.0", "declarations": [
        {"identity": {**IDENTITY, **identity}, "operation": "read"}]}}


def extract(text, relative="config.json"):
    scan = ScanResult(root="C:/service")
    extract_config_datastores(text, relative, scan)
    return scan


def graph(scans):
    return fleet_summary_json(FleetScan(results=[FleetRepoResult(
        f"repo-{i}", scan.root, f"C:/reports/{i}", scan, []) for i, scan in enumerate(scans)]))["fleet_architecture"]


def test_paired_files_emit_exact_sources_and_fleet_association(tmp_path):
    scans = []
    for name, filename, line in (("reader", "config.yaml", 4), ("writer", "config.json", 5)):
        root = tmp_path / name
        shutil.copytree(FIXTURES / name, root)
        scan = scan_config_repo(root)
        assert len(scan.signals) == 1
        signal = scan.signals[0]
        assert (signal.file, signal.line, signal.source_role) == (filename, line, "unknown")
        stamp_scan_provenance(scan, "config", "0.1.0")
        extracted = extract_shared_datastore_declarations(scan.signals, scan.root)
        assert extracted["rejected"] == 0 and len(extracted["declarations"]) == 1
        assert extracted["declarations"][0]["source"]["line"] == line
        scans.append(scan)
    projected = graph(scans)
    edges = [edge for edge in projected["edges"] if edge["kind"] == "shared_datastore"]
    assert len(edges) == 1
    assert edges[0]["resolution"] == "declared" and edges[0]["directed"] is False
    evidence = {row["id"]: row for row in projected["evidence"]}
    assert len(edges[0]["evidence_refs"]) == 2
    assert {evidence[ref]["line"] for ref in edges[0]["evidence_refs"]} == {4, 5}
    assert graph(list(reversed(scans)))["coverage"] == projected["coverage"]


def test_indexed_and_walked_extraction_identical(tmp_path):
    shutil.copytree(FIXTURES / "reader", tmp_path / "app")
    root = tmp_path / "app"
    walked = scan_config_repo(root)
    indexed = scan_config_repo(root, index=RepoIndex.build(root))
    assert walked.signals == indexed.signals
    assert walked.scanned_files == indexed.scanned_files


@pytest.mark.parametrize("field,value", [
    ("scope", "${ENV}"), ("protocol", "sqlite"), ("host", "localhost"),
    ("host", "db"), ("host", "user:password@db.example.internal"),
    ("host", "127.0.0.1"), ("port", "5432"), ("port", True),
    ("port", 0), ("namespace", "unknown"), ("resource", "${TABLE}"),
])
def test_incomplete_or_nonliteral_identity_never_emits(field, value):
    scan = extract(json.dumps(document(**{field: value})))
    assert not scan.signals and len(scan.limitations) == 1
    assert "password" not in json.dumps(scan.model_dump())


@pytest.mark.parametrize("role", ["tests", "__tests__", "fixtures", "mocks", "examples", "generated"])
def test_nonproduction_paths_never_emit(role):
    assert not extract(json.dumps(document()), f"{role}/config.json").signals


@pytest.mark.parametrize("mutation", ["missing", "extra", "credentials", "operation", "version", "partial"])
def test_invalid_declaration_file_is_atomic_and_opaque(mutation):
    data = document()
    container = data["attackmap_datastores"]
    record = container["declarations"][0]
    if mutation == "missing":
        del record["identity"]["scope"]
    elif mutation == "extra":
        record["extra"] = "not admitted"
    elif mutation == "credentials":
        record["identity"]["password"] = "SecretValue42"
    elif mutation == "operation":
        record["operation"] = "unknown"
    elif mutation == "version":
        container["schema_version"] = "2.0"
    elif mutation == "partial":
        container["declarations"].append({"identity": {}, "operation": "read"})
    scan = extract(json.dumps(data))
    assert not scan.signals and scan.limitations
    assert "SecretValue42" not in json.dumps(scan.model_dump())


@pytest.mark.parametrize("text", [
    '{"attackmap_datastores": {}, "attackmap_datastores": {}}',
    'attackmap_datastores: {}\nattackmap_datastores: {}',
    'attackmap_datastores: &a {schema_version: "1.0", declarations: [*a]}',
    'attackmap_datastores: !!python/object:os.system {}',
    'attackmap_datastores: {schema_version: "1.0", declarations: []}\n---\n{}',
    'attackmap_datastores: [',
])
def test_ambiguous_unsafe_malformed_documents_do_not_emit(text):
    scan = extract(text, "config.yaml")
    assert not scan.signals and scan.limitations


def test_size_and_depth_bounds_are_explicit():
    for content in ('attackmap_datastores: {}\n#' + 'x' * 256000,
                    'attackmap_datastores: ' + '[' * 40 + ']' * 40):
        assert extract(content, "config.yaml").limitations


def test_yaml_octal_port_is_not_reinterpreted_as_decimal():
    content = (FIXTURES / "reader" / "config.yaml").read_text().replace("port: 5432", "port: 05432")
    scan = extract(content, "config.yaml")
    assert not scan.signals and scan.limitations


@pytest.mark.parametrize("prefix", ["sk-proj-", "SK-PROJ-"])
def test_secret_shaped_raw_and_canonical_hosts_are_opaque_and_never_emitted(prefix):
    host = prefix + "a" * 30 + ".example.internal"
    scan = extract(json.dumps(document(host=host)))
    assert not scan.signals and len(scan.limitations) == 1
    serialized = scan.model_dump_json()
    assert host not in serialized and host.lower() not in serialized
    assert "sk-proj-" not in serialized.lower()
    assert "rejected" in scan.limitations[0]
    peer = extract(json.dumps(document()))
    peer.root = "C:/other-service"
    projected = graph([scan, peer])
    assert not [row for row in projected["edges"] if row["kind"] == "shared_datastore"]
    assert host.lower() not in json.dumps(projected).lower()


def test_generic_database_settings_and_urls_do_not_become_qualified():
    for data in ({"database": IDENTITY}, {"datastores": [IDENTITY]},
                 {"DATABASE_URL": "postgresql://db.example.internal:5432/orders"}):
        assert not extract(json.dumps(data)).signals


def test_same_line_records_keep_distinct_observation_identity_after_merge():
    data = document()
    data["attackmap_datastores"]["declarations"].append(
        {"identity": {**IDENTITY, "resource": "users"}, "operation": "write"})
    scan = extract(json.dumps(data))
    stamp_scan_provenance(scan, "config", "0.1.0")
    assert len(scan.signals) == 2
    assert len({signal.observation_id for signal in scan.signals}) == 2
    assert not any(signal.conflicts for signal in scan.signals)


@pytest.mark.parametrize("text", [
    'attackmap_datastores: {}',
    '{"attackmap_datastores": {}, "unused": NaN}',
    '{"attackmap_datastores": {}, "unused": 1, "unused": 2}',
])
def test_json_files_require_strict_json(text):
    scan = extract(text)
    assert not scan.signals and scan.limitations


@pytest.mark.parametrize("field,value", [
    ("scope", "staging"), ("protocol", "mysql"), ("host", "other.example.internal"),
    ("port", 5433), ("namespace", "private"), ("resource", "users"),
])
def test_each_identity_dimension_prevents_cross_repo_matching(field, value):
    left = extract(json.dumps(document()))
    right = extract(json.dumps(document(**{field: value})))
    right.root = "C:/other-service"
    assert not [edge for edge in graph([left, right])["edges"] if edge["kind"] == "shared_datastore"]
