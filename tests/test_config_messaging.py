"""Bounded owner declarations, not discovery or a runtime message-delivery test."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from attackmap.config_datastores import extract_config_datastores, extract_config_messaging
from attackmap.config_scanner import scan_config_repo
from attackmap.fleet import FleetRepoResult, FleetScan, fleet_summary_json
from attackmap.fleet_architecture import aggregate_fleet_architecture, build_fleet_architecture
from attackmap.fleet_resource_identity import (MAX_MESSAGING_DECLARATIONS,
    MAX_MESSAGING_REPOSITORIES, extract_messaging_declarations, project_producer_consumer)
from attackmap.index import RepoIndex
from attackmap.models import ScanResult, SignalConflict, SignalOrigin
from attackmap.signal_provenance import stamp_scan_provenance

IDENTITY = dict(scope="production-eu", protocol="kafka", transport="tls",
                host="broker.example.internal", port=9093, namespace="orders-cluster", channel="orders.created")
FIXTURES = Path(__file__).parent / "fixtures" / "messaging_declarations"


def document(operation="publish", **identity):
    return {"attackmap_messaging": {"schema_version": "1.0", "declarations": [
        {"identity": {**IDENTITY, **identity}, "operation": operation}]}}


def extract(data=None, *, root="C:/publisher", relative="config.json", text=None):
    scan = ScanResult(root=root)
    extract_config_messaging(text if text is not None else json.dumps(data or document()), relative, scan)
    return scan


def declaration(root="C:/publisher", operation="publish", observation="topic-declaration", **identity):
    return {"schema_version": "1.0", "identity": {**IDENTITY, **identity}, "operation": operation,
            "source": {"repository_root": root, "file": "config.yaml", "line": 4,
                       "observation_id": observation, "source_analyzer": "config"}}


def fleet(scans):
    return FleetScan(results=[FleetRepoResult(f"repo-{i}", scan.root, f"C:/reports/{i}", scan, [])
                              for i, scan in enumerate(scans)])


def assert_references(graph):
    nodes = {item["id"] for item in graph["nodes"]}
    evidence = {item["id"]: item for item in graph["evidence"]}
    for edge in graph["edges"]:
        assert edge["source"] in nodes and edge["target"] in nodes
        assert set(edge["evidence_refs"]) <= evidence.keys()
        for endpoint in edge.get("endpoints", []):
            assert set(endpoint.get("evidence_refs", [])) <= set(edge["evidence_refs"])
    for item in graph.get("producer_consumer_unresolved", []):
        assert set(item["evidence_refs"]) <= evidence.keys()
    return evidence


def test_physical_pair_preserves_both_sources_declared_direction_and_serialization(tmp_path):
    scans = []
    for name in ("publisher", "consumer"):
        root = tmp_path / name
        root.mkdir()
        source = next((FIXTURES / name).iterdir())
        (root / source.name).write_bytes(source.read_bytes())
        scan = scan_config_repo(root)
        indexed = scan_config_repo(root, index=RepoIndex.build(root))
        assert scan.signals == indexed.signals
        assert len(scan.signals) == 1 and scan.signals[0].source_role == "unknown"
        assert (scan.signals[0].file, scan.signals[0].line) == (source.name, 4 if name == "publisher" else 5)
        stamp_scan_provenance(scan, "config", "0.1.0")
        assert len(extract_messaging_declarations(scan.signals, scan.root)["declarations"]) == 1
        scans.append(scan)
    result = fleet(scans)
    graph = fleet_summary_json(result)["fleet_architecture"]
    assert json.loads(json.dumps(graph)) == graph
    edge, = [row for row in graph["edges"] if row["kind"] == "producer_consumer"]
    assert edge["resolution"] == "declared" and edge["directed"] is True
    assert edge["direction_basis"] == "declared_publish_to_consume"
    roots = {row["id"]: row["root"] for row in graph["repositories"]}
    assert roots[edge["source"]].endswith("/publisher") and roots[edge["target"]].endswith("/consumer")
    assert [endpoint["operation"] for endpoint in edge["endpoints"]] == ["publish", "consume"]
    evidence = assert_references(graph)
    assert {evidence[ref]["line"] for ref in edge["evidence_refs"]} == {4, 5}
    assert {evidence[ref]["source_analyzer"] for ref in edge["evidence_refs"]} == {"config"}
    assert {evidence[ref]["repo_id"] for ref in edge["evidence_refs"]} == {edge["source"], edge["target"]}
    assert all(endpoint["evidence_refs"] for endpoint in edge["endpoints"])
    result.results.reverse()
    assert build_fleet_architecture(result) == graph
    overview = aggregate_fleet_architecture(graph)
    aggregate, = [row for row in overview["edges"] if row["kind"] == "producer_consumer"]
    assert aggregate["underlying_edge_ids"] == [edge["id"]] and aggregate["directed"] is True
    assert aggregate["resolution"] == "declared"
    assert not result.links and not result.cross_boundary


@pytest.mark.parametrize("field,value", [
    ("scope", "staging"), ("protocol", "amqp"), ("transport", "plaintext"),
    ("host", "other.example.internal"), ("port", 9092), ("namespace", "other-cluster"),
    ("channel", "orders.updated"), ("channel", "Orders.created")])
def test_every_identity_dimension_prevents_false_join(field, value):
    left, right = declaration(), declaration("C:/consumer", "consume")
    right["identity"][field] = value
    if field == "protocol":
        with pytest.raises(ValueError):
            project_producer_consumer([left, right])
    else:
        graph = project_producer_consumer([left, right])
        assert graph["associations"] == [] and len(graph["unmatched"]) == 2


@pytest.mark.parametrize("operations,roots", [
    (("publish", "publish"), ("C:/a", "C:/b")),
    (("consume", "consume"), ("C:/a", "C:/b")),
    (("publish", "consume"), ("C:/a", "c:\\A")),
])
def test_complementary_operations_in_distinct_roots_are_required(operations, roots):
    graph = project_producer_consumer([declaration(root, op, observation=f"d-{i}")
                                     for i, (root, op) in enumerate(zip(roots, operations))])
    assert graph["associations"] == [] and len(graph["unmatched"]) == 2


def test_conflicting_source_identity_operation_or_location_is_quarantined():
    for mutation in ("identity", "operation", "source"):
        left = declaration()
        conflict = deepcopy(left)
        if mutation == "identity":
            conflict["identity"]["channel"] = "other"
        elif mutation == "operation":
            conflict["operation"] = "consume"
        else:
            conflict["source"]["line"] = 5
        peer = declaration("C:/consumer", "consume")
        graph = project_producer_consumer([left, conflict, peer])
        assert not graph["associations"] and len(graph["ambiguous"]) == 1
        assert graph["ambiguous"][0]["reason"] == "conflicting_declarations_for_source_observation"
        assert graph == project_producer_consumer([peer, conflict, left, peer])


def test_ids_are_stable_under_permutation_duplicates_and_dns_canonicalization():
    records = [declaration(), declaration("C:/consumer", "consume"),
               declaration("C:/other-consumer", "consume")]
    before = deepcopy(records)
    graph = project_producer_consumer(records)
    assert len(graph["associations"]) == 2
    assert graph == project_producer_consumer([*reversed(records), records[0]])
    canonical = deepcopy(records)
    canonical[1]["identity"]["host"] = "BROKER.EXAMPLE.INTERNAL."
    assert graph == project_producer_consumer(canonical)
    assert records == before
    assert not any("observed" in row["resolution"] or row["resolution"] == "inferred" for row in graph["associations"])


@pytest.mark.parametrize("field,value", [
    ("scope", "${ENV}"), ("scope", "unknown"), ("protocol", "amqp"), ("transport", "unknown"),
    ("host", "broker"), ("host", "localhost"), ("host", "127.0.0.1"), ("host", "::1"),
    ("host", "169.254.1.1"), ("host", "224.0.0.1"), ("host", "user:PrivateValue42@broker.example.internal"),
    ("host", "sk-proj-" + "a" * 30 + ".example.internal"),
    ("host", "SK-PROJ-" + "a" * 30 + ".example.internal"),
    ("port", "9093"), ("port", True), ("port", 0), ("channel", "${TOPIC}"),
    ("namespace", "unresolved")])
def test_nonliteral_incomplete_unsupported_and_secret_identity_are_opaque(field, value):
    scan = extract(document(**{field: value}))
    assert not scan.signals and len(scan.limitations) == 1
    encoded = scan.model_dump_json()
    assert "PrivateValue42" not in encoded and "sk-proj-" not in encoded.lower()
    record = declaration(**{field: value})
    with pytest.raises(ValueError) as error:
        project_producer_consumer([record])
    assert type(error.value) is ValueError
    assert error.value.__context__ is None and error.value.__cause__ is None


@pytest.mark.parametrize("mutation", ["missing", "extra", "credential", "operation", "version", "partial"])
def test_invalid_file_rejects_all_declarations_without_raw_values(mutation):
    data = document()
    envelope = data["attackmap_messaging"]
    record = envelope["declarations"][0]
    if mutation == "missing":
        del record["identity"]["namespace"]
    elif mutation == "extra":
        record["extra"] = "PrivateValue42"
    elif mutation == "credential":
        record["identity"]["password"] = "PrivateValue42"
    elif mutation == "operation":
        record["operation"] = "publish_consume"
    elif mutation == "version":
        envelope["schema_version"] = "2.0"
    else:
        envelope["declarations"].append({"identity": {}, "operation": "consume"})
    scan = extract(data)
    assert not scan.signals and scan.limitations
    assert "PrivateValue42" not in scan.model_dump_json()


@pytest.mark.parametrize("text,relative", [
    ('{"attackmap_messaging": {}, "attackmap_messaging": {}}', "config.json"),
    ('{"attackmap_messaging": {}, "unused": NaN}', "config.json"),
    ('attackmap_messaging: {}', "config.json"),
    ('attackmap_messaging: &a {schema_version: "1.0", declarations: [*a]}', "config.yml"),
    ('attackmap_messaging: !!python/object:os.system {}', "config.yml"),
    ('attackmap_messaging: {}\nattackmap_messaging: {}', "config.yml"),
    ('attackmap_messaging: {}\n---\n{}', "config.yml"),
    ('attackmap_messaging: [', "config.yml"),
    ('attackmap_messaging: {}\n#' + 'x' * 256000, "config.yml"),
    ('attackmap_messaging: ' + '[' * 40 + ']' * 40, "config.yml"),
], ids=["duplicate-json", "non-json-constant", "not-json", "alias", "custom-tag",
        "duplicate-yaml", "multi-document", "malformed", "byte-bound", "depth-bound"])
def test_unsafe_ambiguous_malformed_or_oversized_input_does_not_emit(text, relative):
    scan = extract(text=text, relative=relative)
    assert not scan.signals and scan.limitations


@pytest.mark.parametrize("path", ["tests", "__tests__", "fixtures", "mocks", "examples", "generated"])
def test_nonproduction_declarations_never_emit(path):
    assert not extract(relative=f"{path}/config.json").signals


def test_generic_queue_settings_and_nested_markers_never_establish_identity():
    for data in ({"kafka": {"bootstrap.servers": "broker.example.internal:9093", "topic": "orders.created"}},
                 {"messaging": IDENTITY}, {"unused": document()}):
        assert not extract(data).signals
    assert not extract(relative="config.toml").signals


@pytest.mark.parametrize("case", ["conflicts", "origin", "unknown_origin", "source_role", "kind", "line", "evidence_kind", "port"])
def test_normalized_signal_rejects_ambiguous_or_missing_provenance(case):
    scan = extract()
    signal = scan.signals[0]
    if case == "conflicts":
        signal.conflicts = [SignalConflict(field="operation", values=["publish", "consume"])]
    elif case == "origin":
        signal.origins.append(SignalOrigin(analyzer="other"))
    elif case == "unknown_origin":
        signal.origins.append(SignalOrigin())
    elif case == "port":
        signal.properties["port"] = "not-an-integer"
    elif case == "line":
        signal.line = None
    else:
        setattr(signal, case, {"source_role": "generated", "kind": "service", "evidence_kind": "unknown"}[case])
    assert extract_messaging_declarations(scan.signals, scan.root) == {"declarations": [], "rejected": 1}


def test_partial_and_failed_children_remain_explicit_and_do_not_supply_a_missing_peer():
    publisher = extract()
    publisher.limitations.append("Other unrelated analysis was partial.")
    result = fleet([publisher])
    result.failed = [{"root": "C:/consumer", "repo_id": "failed-consumer", "error": "child failed"}]
    graph = build_fleet_architecture(result, [{"root": "C:/publisher"}, {"root": "C:/consumer"}, {"root": "C:/missing"}])
    assert not [row for row in graph["edges"] if row["kind"] == "producer_consumer"]
    assert graph["coverage"]["repository_statuses"] == {"failed": 1, "partial": 1, "unavailable": 1}
    assert graph["coverage"]["protocols"]["producer_consumer"]["unmatched_count"] == 1
    assert graph["coverage"]["complete"] is False and graph["coverage"]["atomic_snapshot"] is False
    assert_references(graph)


def test_conflicting_normalized_observations_remain_ambiguous_with_source_evidence():
    publisher, consumer = extract(), extract(document("consume"), root="C:/consumer")
    conflicting = publisher.signals[0].model_copy(deep=True)
    conflicting.properties["channel"] = "other.topic"
    conflicting.line = 7
    publisher.signals.append(conflicting)
    graph = build_fleet_architecture(fleet([publisher, consumer]))
    assert not [row for row in graph["edges"] if row["kind"] == "producer_consumer"]
    assert graph["coverage"]["protocols"]["producer_consumer"]["ambiguous_count"] == 1
    ambiguity, = [row for row in graph["producer_consumer_unresolved"]
                  if row["reason"] == "conflicting_declarations_for_source_observation"]
    evidence = assert_references(graph)
    assert {evidence[ref]["line"] for ref in ambiguity["evidence_refs"]} == {1, 7}
    assert {evidence[ref]["source_analyzer"] for ref in ambiguity["evidence_refs"]} == {"config"}


def test_bounds_fail_closed_and_preserve_other_architecture():
    with pytest.raises(ValueError, match="declaration count"):
        project_producer_consumer([declaration()] * (MAX_MESSAGING_DECLARATIONS + 1))
    records = [declaration(f"C:/repo-{i}") for i in range(MAX_MESSAGING_REPOSITORIES + 1)]
    with pytest.raises(ValueError, match="repository count"):
        project_producer_consumer(records)
    scans = [extract(root=f"C:/repo-{i}") for i in range(MAX_MESSAGING_REPOSITORIES + 1)]
    graph = build_fleet_architecture(fleet(scans))
    assert len(graph["repositories"]) == MAX_MESSAGING_REPOSITORIES + 1
    assert graph["coverage"]["protocols"]["producer_consumer"]["projection_omitted"] is True
    assert graph["producer_consumer_unresolved"][0]["reason"] == "repository_count_exceeds_prepared_limit"
    assert not graph["edges"]


def test_identical_line_multiple_declarations_survive_normal_merge_distinctly():
    data = document()
    data["attackmap_messaging"]["declarations"].append({"identity": IDENTITY, "operation": "consume"})
    scan = extract(data)
    stamp_scan_provenance(scan, "config", "0.1.0")
    assert len(scan.signals) == 2 and len({signal.observation_id for signal in scan.signals}) == 2
    assert {signal.properties["operation"] for signal in scan.signals} == {"publish", "consume"}
    assert not any(signal.conflicts for signal in scan.signals)


def test_adding_and_removing_messaging_preserves_owner_and_framework_datastore_projection(tmp_path):
    owner_document = {"attackmap_datastores": {"schema_version": "1.0", "declarations": [{
        "identity": {"scope": "production", "protocol": "postgresql", "host": "db.example.internal",
                     "port": 5432, "namespace": "public", "resource": "orders"}, "operation": "read_write"}]}}
    rails = ("production:\n  adapter: postgresql\n  host: db.example.internal\n  port: 5432\n"
             "  database: orders\n  schema_search_path: public\n  replica: false\n")
    scans = []
    for name in ("publisher", "consumer"):
        root = tmp_path / name
        (root / "config").mkdir(parents=True)
        (root / "config" / "database.yml").write_text(rails, encoding="utf-8")
        scan = scan_config_repo(root)
        extract_config_datastores(json.dumps(owner_document), "config.json", scan)
        scans.append(scan)
    original = build_fleet_architecture(fleet(scans))
    assert {edge["resolution"] for edge in original["edges"] if edge["kind"] == "shared_datastore"} == {"declared", "candidate"}
    with_messages = deepcopy(scans)
    for scan, operation in zip(with_messages, ("publish", "consume")):
        extract_config_messaging(json.dumps(document(operation)), "config.json", scan)
    combined = build_fleet_architecture(fleet(with_messages))
    # Remove only the additive messaging projection and compare every remaining
    # field, including old resource/evidence IDs and both datastore ID domains.
    without_messaging = deepcopy(combined)
    without_messaging["nodes"] = [node for node in combined["nodes"] if node.get("component_role") != "messaging_topic"]
    without_messaging["edges"] = [edge for edge in combined["edges"] if edge["kind"] != "producer_consumer"]
    without_messaging["evidence"] = [row for row in combined["evidence"] if row["kind"] != "producer_consumer_declaration"]
    del without_messaging["producer_consumer_unresolved"]
    without_messaging["coverage"]["protocols"]["producer_consumer"] = original["coverage"]["protocols"]["producer_consumer"]
    changed_limitations = set(project_producer_consumer([])["limitations"])
    old_unanalysed = next(note for note in original["limitations"] if note.startswith("Cross-repository producer/consumer"))
    without_messaging["limitations"] = sorted((set(combined["limitations"]) - changed_limitations) | {old_unanalysed})
    assert without_messaging == original
    assert_references(combined)
