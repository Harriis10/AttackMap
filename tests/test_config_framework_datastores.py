"""Literal framework candidates must never masquerade as owner declarations."""
import json

import pytest

from attackmap.config_scanner import scan_config_repo
from attackmap.fleet import FleetRepoResult, FleetScan, fleet_summary_json
from attackmap.fleet_resource_identity import extract_shared_datastore_declarations
from attackmap.index import RepoIndex
from attackmap.signal_provenance import stamp_scan_provenance

CONFIG = """production:
  adapter: postgresql
  host: db.example.internal
  port: 5432
  database: orders
  schema_search_path: public
  replica: false
  username: application
  password: RailsSecret42
"""


def scan(root, content=CONFIG):
    path = root / "config" / "database.yml"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    return scan_config_repo(root)


def graph(scans):
    return fleet_summary_json(FleetScan(results=[FleetRepoResult(
        f"repo-{i}", item.root, f"C:/reports/{i}", item, [])
        for i, item in enumerate(scans)]))["fleet_architecture"]


def test_literal_rails_candidate_preserves_source_and_is_not_owner_assertion(tmp_path):
    result = scan(tmp_path / "writer")
    assert len(result.signals) == 1
    signal = result.signals[0]
    assert (signal.file, signal.line, signal.source_role) == ("config/database.yml", 2, "unknown")
    assert signal.properties["framework_datastore_candidate"] == "1.0"
    assert signal.properties["scope"] == "production"
    assert signal.properties["namespace"] == "public"
    assert signal.properties["resource"] == "orders"
    assert signal.properties["operation"] == "read_write"
    assert "shared_datastore_declaration" not in signal.properties
    assert "RailsSecret42" not in signal.model_dump_json()
    stamp_scan_provenance(result, "config", "0.1.0")
    assert signal.observation_id and signal.origins[0].analyzer == "config"
    assert extract_shared_datastore_declarations(result.signals, result.root) == {"declarations": [], "rejected": 0}
    reader = scan(tmp_path / "reader", CONFIG.replace("replica: false", "replica: true"))
    assert reader.signals[0].properties["operation"] == "read"
    projected = graph([result, reader])
    edges = [edge for edge in projected["edges"] if edge["kind"] == "shared_datastore"]
    assert len(edges) == 1
    edge = edges[0]
    assert edge["resolution"] == "candidate" and edge["directed"] is False
    assert edge["basis"] == "matching_literal_framework_config_context"
    evidence = {item["id"]: item for item in projected["evidence"]}
    assert len(edge["evidence_refs"]) == 2
    assert {evidence[ref]["line"] for ref in edge["evidence_refs"]} == {2}
    assert "RailsSecret42" not in json.dumps(projected)
    coverage = projected["coverage"]["protocols"]["shared_datastore"]
    assert coverage["declaration_count"] == coverage["association_count"] == 0
    assert coverage["framework_static_candidates"]["association_count"] == 1


def test_index_snapshot_and_walk_emit_identical_candidates(tmp_path):
    walked = scan(tmp_path)
    indexed = scan_config_repo(tmp_path, index=RepoIndex.build(tmp_path))
    assert walked.signals == indexed.signals


@pytest.mark.parametrize("before,after", [
    ("db.example.internal", "localhost"),
    ("db.example.internal", "db"),
    ("db.example.internal", "${DB_HOST}"),
    ("db.example.internal", "user:password@db.example.internal"),
    ("db.example.internal", "SK-PROJ-" + "a" * 30 + ".example.internal"),
    ("5432", "05432"),
    ("5432", "\"5432\""),
    ("public", "public,other"),
    ("replica: false", "replica: yes"),
    ("  replica: false\n", ""),
    ("  host: db.example.internal", "  host: db.example.internal\n  host: other.example.internal"),
    ("  host: db.example.internal", "  host: <%= ENV['DB_HOST'] %>"),
    ("production:", "default:"),
])
def test_ambiguous_nonliteral_or_secret_identity_never_emits(tmp_path, before, after):
    result = scan(tmp_path, CONFIG.replace(before, after))
    assert not result.signals and result.limitations
    assert "RailsSecret42" not in json.dumps(result.limitations)


@pytest.mark.parametrize("content", [
    CONFIG + "  url: postgresql://other.example.internal:5432/orders\n",
    CONFIG.replace("production:", "production: &defaults") + "staging: *defaults\n",
    CONFIG + "---\n{}",
    "production: [",
    "production: " + "[" * 40 + "]" * 40,
    CONFIG + "#" + "x" * 256000,
    "production:\n  primary:\n    adapter: postgresql\n",
], ids=["url_override", "alias", "multiple_docs", "malformed", "depth", "size", "nested_database"])
def test_unsupported_shapes_are_atomic_and_opaque(tmp_path, content):
    result = scan(tmp_path, content)
    assert not result.signals and result.limitations
    assert "RailsSecret42" not in json.dumps(result.limitations)


def test_generic_and_nonproduction_config_paths_do_not_qualify(tmp_path):
    for relative in ("database.yml", "tests/config/database.yml", "examples/config/database.yml"):
        root = tmp_path / str(len(relative))
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CONFIG, encoding="utf-8")
        assert not scan_config_repo(root).signals


def test_owner_assertion_and_framework_observation_never_coalesce(tmp_path):
    candidate = scan(tmp_path / "candidate")
    root = tmp_path / "owner"
    root.mkdir()
    document = {"attackmap_datastores": {"schema_version": "1.0", "declarations": [{
        "identity": {"scope": "production", "protocol": "postgresql", "host": "db.example.internal",
                     "port": 5432, "namespace": "public", "resource": "orders"}, "operation": "read_write"}]}}
    (root / "config.json").write_text(json.dumps(document), encoding="utf-8")
    owner = scan_config_repo(root)
    projected = graph([candidate, owner])
    assert not [edge for edge in projected["edges"] if edge["kind"] == "shared_datastore"]
    resources = [item for item in projected["nodes"] if item["kind"] == "datastore" and item.get("qualified_identity")]
    assert len(resources) == 2 and len({item["id"] for item in resources}) == 2
    assert {item["resolution"] for item in resources} == {"declared", "candidate"}


@pytest.mark.parametrize("before,after", [("production:", "staging:"),
    ("db.example.internal", "other.example.internal"), ("5432", "5433"),
    ("orders", "users"), ("public", "private")])
def test_every_literal_identity_dimension_blocks_candidate_match(tmp_path, before, after):
    left = scan(tmp_path / "left")
    right = scan(tmp_path / "right", CONFIG.replace(before, after))
    assert len(right.signals) == 1
    assert not [edge for edge in graph([left, right])["edges"] if edge["kind"] == "shared_datastore"]


def test_identity_text_resembling_id_prefix_is_never_rewritten(tmp_path):
    left = scan(tmp_path / "left", CONFIG.replace("db.example.internal", "datastore-db.example.internal"))
    right = scan(tmp_path / "right", CONFIG.replace("db.example.internal", "datastore-db.example.internal"))
    projected = graph([left, right])
    resources = [item for item in projected["nodes"] if item.get("qualified_identity")]
    assert len(resources) == 1
    assert resources[0]["qualified_identity"]["host"] == "datastore-db.example.internal"
