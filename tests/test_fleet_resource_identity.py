"""Fixture-only qualification of a prepared contract, without scanner claims."""
from copy import deepcopy
import json

import pytest
from pydantic import ValidationError

from attackmap.fleet_resource_identity import (MAX_DATASTORE_DECLARATIONS,
    MAX_DATASTORE_REPOSITORIES, DatastoreDeclaration, project_shared_datastores)


def declaration(root="C:/repos/reader", *, operation="read", observation="db-read"):
    return {"schema_version": "1.0",
            "identity": {"scope": "production.eu", "protocol": "postgresql",
                         "host": "db.example.internal", "port": 5432,
                         "namespace": "catalog", "resource": "items"},
            "operation": operation,
            "source": {"repository_root": root, "file": "src/store.py", "line": 17,
                       "observation_id": observation, "source_analyzer": "fixture-datastore"}}


def test_paired_declarations_preserve_both_sides_without_directed_or_observed_claim():
    left = declaration()
    right = declaration("C:/repos/writer", operation="write", observation="db-write")
    graph = project_shared_datastores([left, right])
    assert len(graph["resources"]) == len(graph["associations"]) == 1
    assert graph["unmatched"] == graph["ambiguous"] == []
    association = graph["associations"][0]
    assert association["resolution"] == "declared" and association["directed"] is False
    assert {endpoint["repository_root"] for endpoint in association["endpoints"]} == {
        "c:/repos/reader", "c:/repos/writer"}
    evidence = {record["id"]: record for record in graph["evidence"]}
    assert {evidence[ref]["observation_id"] for ref in association["evidence_refs"]} == {"db-read", "db-write"}
    assert all(endpoint["evidence_refs"] for endpoint in association["endpoints"])
    assert {evidence[ref]["source_analyzer"] for ref in association["evidence_refs"]} == {"fixture-datastore"}
    assert graph["production_extraction"] == "normalized_database_signals"
    assert "observed" not in json.dumps(graph)


@pytest.mark.parametrize(("field", "different"), [
    ("scope", "staging.eu"), ("protocol", "mysql"), ("host", "other.example.internal"),
    ("port", 6432), ("namespace", "other"), ("resource", "other"),
    ("namespace", "Catalog"), ("resource", "Items"),
])
def test_every_qualified_identity_dimension_prevents_false_join(field, different):
    left, right = declaration(), declaration("C:/repos/writer")
    right["identity"][field] = different
    graph = project_shared_datastores([left, right])
    assert graph["associations"] == []
    assert len(graph["unmatched"]) == 2
    assert {row["reason"] for row in graph["unmatched"]} == {"no_other_repository_declares_resource"}


def test_same_repository_and_repeated_observations_do_not_establish_a_fleet_link():
    original = declaration()
    alias = declaration("c:\\REPOS\\reader", operation="write", observation="db-write")
    graph = project_shared_datastores([original, alias, deepcopy(original)])
    assert graph["associations"] == [] and len(graph["unmatched"]) == 1
    assert len(graph["evidence"]) == 2
    assert graph["resources"][0]["repository_count"] == 1


def test_conflicting_source_observation_is_explicitly_ambiguous_and_cannot_join():
    original, conflicting, peer = declaration(), declaration(), declaration("C:/repos/writer")
    conflicting["identity"]["namespace"] = "ambiguous"
    graph = project_shared_datastores([original, conflicting, peer])
    assert graph["associations"] == []
    assert len(graph["ambiguous"]) == 1
    assert graph["ambiguous"][0]["reason"] == "conflicting_declarations_for_source_observation"
    assert graph["unmatched"][0]["reason"] == "no_other_repository_declares_resource"
    assert graph == project_shared_datastores([peer, conflicting, original, peer])


def test_conflicting_operation_or_source_location_cannot_be_silently_selected():
    original, conflicting = declaration(), declaration(operation="write")
    conflicting["source"]["line"] = 19
    graph = project_shared_datastores([original, conflicting, declaration("C:/repos/writer")])
    assert graph["associations"] == [] and len(graph["ambiguous"][0]["evidence_refs"]) == 2


def test_canonical_order_and_duplicate_invariance_without_input_mutation():
    declarations = [declaration(), declaration("C:/repos/writer", operation="write"),
                    declaration("C:/repos/third", operation="read_write")]
    before = deepcopy(declarations)
    graph = project_shared_datastores(declarations)
    assert graph == project_shared_datastores([*reversed(declarations), declarations[0]])
    assert len(graph["associations"]) == 3 and declarations == before
    json.dumps(graph, allow_nan=False)


def test_dns_case_and_final_dot_are_canonical_but_no_alias_or_default_port_is_inferred():
    left, right = declaration(), declaration("C:/repos/writer")
    right["identity"]["host"] = "DB.EXAMPLE.INTERNAL."
    assert len(project_shared_datastores([left, right])["associations"]) == 1
    del right["identity"]["port"]
    with pytest.raises(ValueError):
        project_shared_datastores([left, right])


@pytest.mark.parametrize("prefix", ["sk-proj-", "SK-PROJ-"])
def test_secret_shaped_dns_labels_are_rejected_before_and_after_canonicalization(prefix):
    from attackmap.fleet_resource_identity import QualifiedDatastoreIdentity
    from attackmap.redact import redact_text

    host = prefix + "a" * 30 + ".example.internal"
    assert redact_text(host.lower()) != host.lower()
    record = declaration()
    record["identity"]["host"] = host
    with pytest.raises(ValidationError):
        QualifiedDatastoreIdentity.model_validate(record["identity"])
    with pytest.raises(ValueError) as error:
        project_shared_datastores([record, declaration("C:/repos/writer")])
    assert type(error.value) is ValueError
    assert host not in str(error.value) and host.lower() not in str(error.value)
    assert error.value.__context__ is None and error.value.__cause__ is None


@pytest.mark.parametrize(("section", "field", "value"), [
    ("identity", "host", "postgresql://user:verysecret@db.example.internal:5432/catalog"),
    ("identity", "host", "db.example.internal?token=verysecret"),
    ("identity", "host", "user:verysecret@db.example.internal"),
    ("identity", "host", "db.example.internal/path"),
    ("identity", "host", "${DB_HOST}"), ("identity", "host", "db"),
    ("identity", "host", "localhost"), ("identity", "host", "one.localhost"),
    ("identity", "host", "127.0.0.1"), ("identity", "host", "::1"),
    ("identity", "host", "::ffff:127.0.0.1"), ("identity", "host", "2001:db8::1%verysecret"),
    ("identity", "host", "255.255.255.255"), ("identity", "host", "::ffff:255.255.255.255"),
    ("identity", "host", "127.000.000.001"),
    ("identity", "host", "0.0.0.0"), ("identity", "host", "fe80::1"),
    ("identity", "port", True), ("identity", "port", "5432"),
    ("identity", "port", 0), ("identity", "port", 65536),
    ("identity", "protocol", "postgres"), ("identity", "protocol", "sqlite"),
    ("identity", "namespace", "${DB_NAME}"), ("identity", "resource", "items?token=verysecret"),
    ("identity", "scope", "unknown"), ("identity", "scope", "production:password=verysecret"),
    ("source", "line", None), ("source", "line", True), ("source", "line", 0),
    ("source", "repository_root", "reader"), ("source", "repository_root", "\\\\host\\repo"),
    ("source", "file", "../store.py"), ("source", "file", "C:/src/store.py"),
    ("source", "observation_id", ""), ("source", "source_analyzer", "unknown"),
])
def test_incomplete_unqualified_and_secret_bearing_records_are_rejected(section, field, value):
    record = declaration()
    record[section][field] = value
    with pytest.raises(ValueError) as error:
        project_shared_datastores([record])
    assert "verysecret" not in str(error.value)
    assert "verysecret" not in repr(error.value)
    assert type(error.value) is ValueError
    assert error.value.__context__ is None and error.value.__cause__ is None


@pytest.mark.parametrize("section", [None, "identity", "source"])
def test_unknown_fields_and_raw_snippets_are_never_exported(section):
    record = declaration()
    target = record if section is None else record[section]
    target["evidence_text"] = "password=do-not-export"
    with pytest.raises(ValueError) as error:
        project_shared_datastores([record])
    assert "do-not-export" not in str(error.value)
    assert error.value.__context__ is None and error.value.__cause__ is None


@pytest.mark.parametrize("field", ["scope", "protocol", "host", "port", "namespace", "resource"])
def test_missing_identity_field_cannot_join(field):
    record = declaration()
    del record["identity"][field]
    with pytest.raises(ValidationError):
        DatastoreDeclaration.model_validate(record)


def test_empty_input_is_prepared_unknown_coverage_without_invented_resources():
    graph = project_shared_datastores([])
    assert not any(graph[key] for key in ("resources", "associations", "evidence", "ambiguous", "unmatched"))
    assert graph["production_extraction"] == "normalized_database_signals"


@pytest.mark.parametrize("address", ["192.0.2.20", "2001:db8::20"])
def test_explicit_nonlocal_ip_identity_is_supported(address):
    left, right = declaration(), declaration("C:/repos/writer")
    left["identity"]["host"] = right["identity"]["host"] = address
    assert len(project_shared_datastores([left, right])["associations"]) == 1


@pytest.mark.parametrize(("field", "value"), [("schema_version", "2.0"), ("operation", "connect"),
                                             ("operation", "produce"), ("operation", "unknown")])
def test_unsupported_versions_or_operations_are_not_reinterpreted(field, value):
    record = declaration()
    record[field] = value
    with pytest.raises(ValueError):
        project_shared_datastores([record])


def test_root_identity_is_independent_of_basename_and_accepts_absolute_posix_roots():
    left, right = declaration("/team-a/service"), declaration("/team-b/service")
    graph = project_shared_datastores([left, right])
    assert len(graph["associations"]) == 1
    assert {endpoint["repository_root"] for endpoint in graph["associations"][0]["endpoints"]} == {
        "/team-a/service", "/team-b/service"}


def test_prepared_contract_limits_declarations_before_validation_and_pairwise_output():
    with pytest.raises(ValueError, match="declaration count"):
        project_shared_datastores([{}] * (MAX_DATASTORE_DECLARATIONS + 1))
    records = [declaration(f"C:/repos/repo-{index}") for index in range(MAX_DATASTORE_REPOSITORIES + 1)]
    with pytest.raises(ValueError, match="repository count"):
        project_shared_datastores(records)
    graph = project_shared_datastores(records[:-1])
    assert len(graph["associations"]) == 120
    records = [declaration(observation=f"db-{index}") for index in range(MAX_DATASTORE_DECLARATIONS)]
    assert project_shared_datastores(records)["associations"] == []


@pytest.mark.parametrize("alias", ["C:/repos/reader.", "C:/repos/reader ", "C:/repos/reader. ",
                                  "C:/repos./reader", "C:/repos /reader", "C:\\repos\\reader.\\"])
def test_win32_trailing_dot_or_space_aliases_cannot_create_shared_repository_association(alias):
    with pytest.raises(ValueError):
        project_shared_datastores([declaration(), declaration(alias)])

