"""Focused static-fact tests; these do not establish live fleet or GUI acceptance."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from attackmap.contracts import ContractLink
from attackmap.fleet import FleetRepoResult, FleetScan
from attackmap.fleet_architecture import aggregate_fleet_architecture, build_fleet_architecture
from attackmap.fleet_resource_identity import MAX_DATASTORE_DECLARATIONS, MAX_DATASTORE_REPOSITORIES
from attackmap.models import (DatabaseHint, ExternalCall, Route, ScanResult,
                              SecretHint, ServiceHint, Signal, SignalOrigin)


def _result(slug: str, root: str, *, services=("api",)) -> FleetRepoResult:
    scan = ScanResult(root=root, service_hints=[ServiceHint(
        hint=f"service_name:{service}", file=f"services/{service}/main.ts", line=3,
        source_analyzer="fixture-service") for service in services])
    return FleetRepoResult(slug, root, f"C:/reports/{slug}", scan, [])


def _link(client: FleetRepoResult, server: FleetRepoResult, *, line=12,
          resolution="observed", target=None, proxy=None, service="api") -> ContractLink:
    target = target or f"https://{server.repo_id}/v1/items"
    call = ExternalCall(target=target, file=f"services/{service}/main.ts", line=line,
                        method="GET", source_analyzer="fixture-http")
    route = Route(path="/v1/items", method="GET", file="services/api/main.ts", line=41,
                  source_analyzer="fixture-http")
    client.scan.external_calls.append(call)
    if route not in server.scan.routes:
        server.scan.routes.append(route)
    return ContractLink(client.repo_id, server.repo_id, "GET", "v1/items", target,
                        call.file, line, route.path, route.file, 41,
                        client_method="GET", destination=proxy or server.repo_id,
                        resolution=resolution, resolution_reason="no_destination" if resolution == "candidate" else "",
                        scheme="https", alias_provenance=f"fleet.yml:proxies:{proxy}" if proxy else None,
                        proxy_host=proxy)


def fleet16_oracle(*, failed=False) -> tuple[FleetScan, list[dict]]:
    roots = ["C:/team-a/service", "C:/team-b/service"] + [f"C:/fleet/repo-{i:02}" for i in range(2, 16)]
    slugs = ["service", "service-2"] + [f"repo-{i:02}" for i in range(2, 16)]
    requested = [{"root": root, "requested_id": f"00000000-0000-0000-0000-{i:012}",
                  "repo_id": slugs[i], "generation": 7} for i, root in enumerate(roots)]
    results = [_result(slugs[i], roots[i], services=("api", "worker") if i == 0 else () if i == 3 else ("api",))
               for i in range(16)]
    links = [_link(results[0], results[1], line=12),
             _link(results[0], results[1], line=13),
             _link(results[1], results[0]),
             _link(results[0], results[5], line=14, target="/v1/items", resolution="candidate"),
             _link(results[5], results[6], proxy="edge.example.internal", resolution="observed_via_proxy")]
    # Short queue names and datastore dialects in separate repos never prove a
    # shared broker/database. They remain local static observations.
    for index in (6, 7):
        results[index].scan.external_calls.append(ExternalCall(
            target="queue://kafka/events", file="services/api/main.ts", line=22))
        results[index].scan.databases.append(DatabaseHint(
            kind="postgresql", file="services/api/main.ts", line=25))
    fleet = FleetScan(results=results, links=links)
    if failed:
        fleet.results = results[:-1]
        fleet.failed = [{"repo_id": slugs[-1], "root": roots[-1], "error": "fixture child failed"}]
    return fleet, requested


def _assert_references(graph: dict) -> None:
    node_ids = {node["id"] for node in graph["nodes"]}
    repository_ids = {repo["id"] for repo in graph["repositories"]}
    evidence_ids = {item["id"] for item in graph["evidence"]}
    assert len(node_ids) == len(graph["nodes"])
    assert len({edge["id"] for edge in graph["edges"]}) == len(graph["edges"])
    for node in graph["nodes"]:
        assert node["parent_id"] is None or node["parent_id"] in node_ids
        assert node["repo_id"] is None or node["repo_id"] in repository_ids
    for edge in graph["edges"]:
        assert edge["source"] in node_ids and edge["target"] in node_ids
        assert isinstance(edge["directed"], bool)
    for item in [*graph["nodes"], *graph["edges"]]:
        assert all(isinstance(ref, str) and ref in evidence_ids for ref in item["evidence_refs"])
    assert all(item["repo_id"] in repository_ids for item in graph["evidence"])


def test_sixteen_repo_oracle_and_full_serializable_contract():
    fleet, requested = fleet16_oracle()
    graph = build_fleet_architecture(fleet, requested)
    assert graph["schema_version"] == "1.0" and graph["kind"] == "fleet_architecture"
    assert len(graph["repositories"]) == 16
    assert graph["coverage"]["completed_repositories"] == 16
    assert graph["coverage"]["atomic_snapshot"] is False
    assert len({repo["requested_id"] for repo in graph["repositories"]}) == 16
    assert len([node for node in graph["nodes"] if node["kind"] == "repository"]) == 16
    library = next(repo for repo in graph["repositories"] if repo["repo_id"] == "repo-03")
    assert not any(node["parent_id"] == library["id"] for node in graph["nodes"])
    multi = next(repo for repo in graph["repositories"] if repo["repo_id"] == "service")
    assert {node["label"] for node in graph["nodes"] if node["parent_id"] == multi["id"]} >= {"api", "worker"}
    assert len([edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call"]) == 6
    assert json.loads(json.dumps(graph)) == graph
    _assert_references(graph)


@pytest.mark.parametrize("parallel_order", [1, 2, 4])
def test_normalized_serial_parallel_input_order_stability(parallel_order):
    fleet, requested = fleet16_oracle()
    expected = build_fleet_architecture(fleet, requested)
    fleet.results = list(reversed(fleet.results[::parallel_order])) + [
        result for i, result in reversed(list(enumerate(fleet.results))) if i % parallel_order]
    fleet.links.reverse()
    assert build_fleet_architecture(fleet, list(reversed(requested))) == expected


def test_same_basename_and_service_name_never_merge_repositories():
    fleet, requested = fleet16_oracle()
    graph = build_fleet_architecture(fleet, requested)
    repos = [repo for repo in graph["repositories"] if repo["repo_id"] in {"service", "service-2"}]
    assert len({repo["id"] for repo in repos}) == 2
    api_nodes = [node for node in graph["nodes"] if node["label"] == "api" and node["repo_id"] in {repo["id"] for repo in repos}]
    assert len(api_nodes) == 2 and len({node["id"] for node in api_nodes}) == 2


def test_failed_child_preserves_fifteen_siblings_and_sixteenth_group():
    fleet, requested = fleet16_oracle(failed=True)
    graph = build_fleet_architecture(fleet, requested)
    assert len(graph["repositories"]) == 16
    assert graph["coverage"]["completed_repositories"] == 15
    failed = next(repo for repo in graph["repositories"] if repo["status"] == "failed")
    assert failed["requested_id"] == requested[-1]["requested_id"]
    assert not failed["snapshot_available"]
    assert not any(edge["source"] == failed["id"] or edge["target"] == failed["id"] for edge in graph["edges"])
    _assert_references(graph)


def test_missing_or_skipped_requested_child_is_not_a_successful_empty_scan():
    graph = build_fleet_architecture(FleetScan(), [
        {"root": "C:/missing", "id": "transport-id", "status": "completed"},
        {"root": "C:/skipped", "requested_id": "skipped-id", "status": "skipped"}])
    assert {repo["status"] for repo in graph["repositories"]} == {"unavailable", "skipped"}
    assert all(repo["repo_id"] is None for repo in graph["repositories"])
    assert graph["edges"] == []
    assert graph["coverage"]["complete"] is False


def test_candidate_and_proxy_resolution_and_original_callsites_are_preserved():
    fleet, requested = fleet16_oracle()
    graph = build_fleet_architecture(fleet, requested)
    http = [edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call"]
    assert sum(edge["resolution"] == "candidate" for edge in http) == 1
    proxy_edges = [edge for edge in http if edge["resolution"] == "observed_via_proxy"]
    assert {edge["leg"] for edge in proxy_edges} == {"client_to_proxy", "proxy_to_server"}
    assert len({edge["relation_id"] for edge in proxy_edges}) == 1
    proxy = next(node for node in graph["nodes"] if node.get("component_role") == "proxy")
    assert all(proxy["id"] in (edge["source"], edge["target"]) for edge in proxy_edges)
    evidence = {item["id"]: item for item in graph["evidence"]}
    for edge in http:
        refs = [evidence[ref] for ref in edge["evidence_refs"]]
        assert {ref["kind"] for ref in refs} >= {"external_call", "route"}
        assert {ref["line"] for ref in refs} >= {41}
    repeated = [edge for edge in http if edge["resolution"] == "observed" and edge["client_target"] == "https://service-2/v1/items"]
    assert len(repeated) == 2 and len({edge["id"] for edge in repeated}) == 2


def test_collapsed_overview_preserves_underlying_ids_and_distinct_resolution():
    fleet, requested = fleet16_oracle()
    graph = build_fleet_architecture(fleet, requested)
    overview = aggregate_fleet_architecture(graph)
    canonical = {edge["id"] for edge in graph["edges"] if edge["kind"] != "containment"}
    assert {ref for edge in overview["edges"] for ref in edge["underlying_edge_ids"]} == canonical
    assert sum(edge["count"] for edge in overview["edges"]) == len(canonical)
    assert any(edge["count"] == 2 and edge["resolution"] == "observed" for edge in overview["edges"])
    assert overview["path_semantics"] == "presentation_only_not_detail_reachability"
    assert build_fleet_architecture(fleet, requested) == graph  # Projection does not mutate canonical data.


def test_ambiguous_file_ownership_uses_repository_endpoint():
    client = _result("client", "C:/client", services=())
    server = _result("server", "C:/server")
    client.scan.service_hints = [ServiceHint(hint="service_name:" + name, file="src/main.ts") for name in ("one", "two")]
    link = _link(client, server)
    link = ContractLink(**{**vars(link), "client_file": "src/main.ts"})
    graph = build_fleet_architecture(FleetScan(results=[client, server], links=[link]))
    edge = next(edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call")
    repo = next(repo for repo in graph["repositories"] if repo["repo_id"] == "client")
    assert edge["source"] == repo["id"]
    assert edge["endpoint_resolution"]["source"] == "repository_only"


def test_original_observation_and_origin_location_are_retained():
    client, server = _result("client", "C:/client"), _result("server", "C:/server")
    link = _link(client, server)
    client.scan.signals = [Signal(kind="external_call", label=link.client_target,
        file=link.client_file, line=link.client_line, observation_id="original-observation",
        properties={"method": "GET"}, origins=[SignalOrigin(analyzer="producer", file="src/config.ts", line=81)])]
    graph = build_fleet_architecture(FleetScan(results=[client, server], links=[link]))
    assert any(item["observation_id"] == "original-observation" and item["file"] == "src/config.ts" and item["line"] == 81
               and item["source_analyzer"] == "producer" for item in graph["evidence"])


def test_unknown_lines_remain_unknown_and_no_short_name_non_http_join():
    fleet, requested = fleet16_oracle()
    fleet.results[6].scan.databases[0].line = None
    graph = build_fleet_architecture(fleet, requested)
    datastores = [node for node in graph["nodes"] if node["kind"] == "datastore"]
    assert len(datastores) == 2 and len({node["id"] for node in datastores}) == 2
    assert all(node["qualified_identity"] is None for node in datastores)
    assert any(item["kind"] == "database" and item["line"] is None for item in graph["evidence"])
    assert not any(edge["scope"] == "cross_repository" for edge in graph["edges"]
                   if edge["kind"] != "cross_repo_http_call" and "scope" in edge)
    assert graph["coverage"]["protocols"]["producer_consumer"]["status"] == "unanalysed"
    assert graph["coverage"]["protocols"]["shared_datastore"]["status"] == "supported"


def test_no_secret_values_or_snippets_are_exported():
    client, server = _result("client", "C:/client"), _result("server", "C:/server")
    client.scan.secret_hints.append(SecretHint(name="do-not-export-this-secret", file=".env", evidence_text="TOKEN=do-not-export-this-secret"))
    link = _link(client, server, target="https://user:supersecretpassword@server/v1/items?api_key=secretvalue12345")
    serialized = json.dumps(build_fleet_architecture(FleetScan(results=[client, server], links=[link])))
    assert "supersecretpassword" not in serialized
    assert "secretvalue12345" not in serialized
    assert "do-not-export-this-secret" not in serialized
    assert "evidence_text" not in serialized


@pytest.mark.parametrize("requests", [
    [{"root": "C:/a", "requested_id": "same"}, {"root": "C:/b", "requested_id": "same"}],
    [{"root": "C:/a"}, {"root": "c:\\A"}],
    [{"requested_id": "no-root"}],
])
def test_ambiguous_requested_identity_is_rejected(requests):
    with pytest.raises(ValueError):
        build_fleet_architecture(FleetScan(), requests)


def test_duplicate_result_slug_does_not_guess_link_endpoints():
    client = _result("client", "C:/client")
    one, two = _result("same", "C:/one"), _result("same", "C:/two")
    link = _link(client, one)
    graph = build_fleet_architecture(FleetScan(results=[client, one, two], links=[link]))
    assert not any(edge["kind"] == "cross_repo_http_call" for edge in graph["edges"])
    assert any("ambiguous core repository" in limitation for limitation in graph["limitations"])


def test_repo_overview_chain_does_not_invent_a_service_path_through_middle_repo():
    a, b, c = _result("a", "C:/a"), _result("b", "C:/b", services=("api", "worker")), _result("c", "C:/c")
    links = [_link(a, b), _link(b, c, service="worker")]
    graph = build_fleet_architecture(FleetScan(results=[a, b, c], links=links))
    b_repo = next(repo["id"] for repo in graph["repositories"] if repo["repo_id"] == "b")
    b_nodes = {node["label"]: node["id"] for node in graph["nodes"] if node["parent_id"] == b_repo}
    assert not any(edge["source"] == b_nodes["api"] and edge["target"] == b_nodes["worker"] for edge in graph["edges"])
    http = [edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call"]
    assert any(edge["target"] == b_nodes["api"] for edge in http)
    assert any(edge["source"] == b_nodes["worker"] for edge in http)
    assert aggregate_fleet_architecture(graph)["path_semantics"] == "presentation_only_not_detail_reachability"


def test_conflicting_resolution_never_collapses_candidate_into_observed():
    client, server = _result("client", "C:/client"), _result("server", "C:/server")
    observed = _link(client, server)
    candidate = replace(observed, resolution="candidate", resolution_reason="ambiguous_identity")
    graph = build_fleet_architecture(FleetScan(results=[client, server], links=[candidate, observed]))
    http = [edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call"]
    assert len(http) == 2 and {edge["resolution"] for edge in http} == {"candidate", "observed"}
    overview = aggregate_fleet_architecture(graph)
    http = [edge for edge in overview["edges"] if edge["kind"] == "cross_repo_http_call"]
    assert len(http) == 2 and all(edge["count"] == 1 for edge in http)


def test_proxy_without_intermediary_is_omitted_with_notice_instead_of_shortcut():
    client, server = _result("client", "C:/client"), _result("server", "C:/server")
    link = _link(client, server, resolution="observed_via_proxy")
    graph = build_fleet_architecture(FleetScan(results=[client, server], links=[link]))
    assert not any(edge["kind"] == "cross_repo_http_call" for edge in graph["edges"])
    assert any("lacks its declared intermediary" in item for item in graph["limitations"])
    _assert_references(graph)


def test_build_does_not_mutate_supplied_child_facts():
    fleet, requested = fleet16_oracle()
    before = [result.scan.model_dump(mode="json") for result in fleet.results]
    build_fleet_architecture(fleet, requested)
    assert [result.scan.model_dump(mode="json") for result in fleet.results] == before


@pytest.mark.parametrize("line", [None, 0, -9])
def test_unknown_and_invalid_source_lines_never_become_known_locations(line):
    client, server = _result("client", "C:/client"), _result("server", "C:/server")
    link = replace(_link(client, server), client_line=line)
    client.scan.external_calls[0].line = line
    graph = build_fleet_architecture(FleetScan(results=[client, server], links=[link]))
    registry = {item["id"]: item for item in graph["evidence"]}
    edge = next(edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call")
    refs = [registry[ref] for ref in edge["evidence_refs"] if registry[ref]["kind"] == "external_call"]
    assert refs and all(ref["line"] is None and ref["location_status"] == "file_only" for ref in refs)
    assert all(item["line"] is None or item["line"] > 0 for item in graph["evidence"])
    assert all(ref["location_reason"] == ("line_not_supplied" if line is None else "invalid_source_line") for ref in refs)


def test_unknown_callsite_line_does_not_acquire_other_callsites_known_lines():
    client, server = _result("client", "C:/client"), _result("server", "C:/server")
    known = _link(client, server)
    _link(client, server, line=13)
    graph = build_fleet_architecture(FleetScan(results=[client, server], links=[replace(known, client_line=None)]))
    registry = {item["id"]: item for item in graph["evidence"]}
    edge = next(edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call")
    assert all(registry[ref]["line"] is None for ref in edge["evidence_refs"] if registry[ref]["kind"] == "external_call")


@pytest.mark.parametrize("failure", [False, True])
def test_explicit_requested_set_rejects_foreign_result_or_failure_roots(failure):
    fleet = FleetScan(failed=[{"repo_id": "foreign", "root": "C:/foreign", "error": "old generation"}]) if failure else FleetScan(results=[_result("foreign", "C:/foreign")])
    with pytest.raises(ValueError, match="root was not requested"):
        build_fleet_architecture(fleet, [{"root": "C:/requested", "requested_id": "current-child"}])
    with pytest.raises(ValueError, match="root was not requested"):
        build_fleet_architecture(fleet, [])


def test_heuristic_layout_ownership_is_labelled_separately_from_analyzer_file_hint():
    client, server = _result("client", "C:/client", services=()), _result("server", "C:/server")
    link = _link(client, server)
    graph = build_fleet_architecture(FleetScan(results=[client, server], links=[link]))
    edge = next(edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call")
    assert edge["endpoint_resolution"] == {"source": "layout_inferred_file_owner", "target": "analyzer_hint_file_owner"}
    assert "exact_file_owner" not in json.dumps(graph)


def test_snapshot_root_mismatch_is_rejected_before_identity_attachment():
    result = _result("client", "C:/current")
    result.scan.root = "C:/old"
    with pytest.raises(ValueError, match="snapshot roots disagree"):
        build_fleet_architecture(FleetScan(results=[result]))


def test_qualified_datastore_contract_does_not_upgrade_runtime_connectivity():
    fleet, requested = fleet16_oracle()
    graph = build_fleet_architecture(fleet, requested)
    coverage = graph["coverage"]["protocols"]
    assert coverage["shared_datastore"]["status"] == "supported"
    assert coverage["shared_datastore"]["declaration_count"] == 0
    assert coverage["shared_datastore"]["association_count"] == 0
    assert coverage["producer_consumer"]["status"] == "unanalysed"
    assert coverage["rpc_schema"]["status"] == "unanalysed"
    assert not any(edge["kind"] == "shared_datastore" for edge in graph["edges"])
    assert [edge["leg"] for edge in graph["edges"]
            if edge["kind"] == "cross_repo_http_call"].count("direct") == 4
    assert {edge["leg"] for edge in graph["edges"]
            if edge["resolution"] == "observed_via_proxy"} == {"client_to_proxy", "proxy_to_server"}


def _datastore_signal(*, operation="read", observation="db-read", file="src/store.py", line=17):
    return Signal(
        kind="database", label="shared_datastore", file=file, line=line,
        observation_id=observation, evidence_kind="static_extraction",
        properties={
            "shared_datastore_declaration": "1.0", "scope": "production.eu",
            "protocol": "postgresql", "host": "db.example.internal", "port": "5432",
            "namespace": "catalog", "resource": "items", "operation": operation,
        },
        origins=[SignalOrigin(analyzer="fixture-datastore", file=file, line=line)],
    )


def test_qualified_paired_datastore_signals_create_declared_two_sided_association():
    reader, writer = _result("reader", "C:/reader"), _result("writer", "C:/writer")
    reader.scan.signals = [_datastore_signal()]
    writer.scan.signals = [_datastore_signal(operation="write", observation="db-write", line=29)]
    graph = build_fleet_architecture(FleetScan(results=[reader, writer]))
    associations = [edge for edge in graph["edges"] if edge["kind"] == "shared_datastore"]
    assert len(associations) == 1
    association = associations[0]
    assert association["directed"] is False
    assert association["resolution"] == "declared"
    assert association["scope"] == "cross_repository"
    assert {association["source"], association["target"]} == {
        repo["id"] for repo in graph["repositories"]}
    evidence = {item["id"]: item for item in graph["evidence"]}
    refs = [evidence[ref] for ref in association["evidence_refs"]]
    assert {ref["observation_id"] for ref in refs} == {"db-read", "db-write"}
    assert {ref["repo_id"] for ref in refs} == {association["source"], association["target"]}
    assert all(ref["kind"] == "shared_datastore_declaration" for ref in refs)
    assert all(ref["source_analyzer"] == "fixture-datastore" for ref in refs)
    resource = next(node for node in graph["nodes"] if node["id"] == association["resource_id"])
    assert resource["qualified_identity"] == {
        "scope": "production.eu", "protocol": "postgresql", "host": "db.example.internal",
        "port": 5432, "namespace": "catalog", "resource": "items"}
    assert graph["coverage"]["protocols"]["shared_datastore"]["association_count"] == 1
    overview_edge = next(edge for edge in aggregate_fleet_architecture(graph)["edges"]
                         if edge["kind"] == "shared_datastore")
    assert overview_edge["directed"] is False
    assert overview_edge["underlying_edge_ids"] == [association["id"]]
    assert build_fleet_architecture(FleetScan(results=[writer, reader])) == graph
    _assert_references(graph)


@pytest.mark.parametrize(("field", "different"), [
    ("scope", "staging.eu"), ("protocol", "mysql"), ("host", "other.example.internal"),
    ("port", "6432"), ("namespace", "other"), ("resource", "other"),
])
def test_mismatched_qualified_datastore_identity_remains_explicitly_unmatched(field, different):
    reader, writer = _result("reader", "C:/reader"), _result("writer", "C:/writer")
    left, right = _datastore_signal(), _datastore_signal(observation="db-write")
    right.properties[field] = different
    reader.scan.signals, writer.scan.signals = [left], [right]
    graph = build_fleet_architecture(FleetScan(results=[reader, writer]))
    assert not any(edge["kind"] == "shared_datastore" for edge in graph["edges"])
    coverage = graph["coverage"]["protocols"]["shared_datastore"]
    assert coverage["status"] == "supported"
    assert coverage["declaration_count"] == 2
    assert coverage["association_count"] == 0
    assert coverage["unmatched_count"] == 2
    assert {item["reason"] for item in graph["shared_datastore_unresolved"]} == {
        "no_other_repository_declares_resource"}
    _assert_references(graph)


def test_conflicting_datastore_observation_is_quarantined_with_source_evidence():
    reader, writer = _result("reader", "C:/reader"), _result("writer", "C:/writer")
    conflicting = _datastore_signal(file="src/other.py", line=41)
    conflicting.properties["namespace"] = "ambiguous"
    reader.scan.signals = [_datastore_signal(), conflicting]
    writer.scan.signals = [_datastore_signal(observation="db-write")]
    graph = build_fleet_architecture(FleetScan(results=[reader, writer]))
    assert not any(edge["kind"] == "shared_datastore" for edge in graph["edges"])
    coverage = graph["coverage"]["protocols"]["shared_datastore"]
    assert coverage["ambiguous_count"] == 1
    assert coverage["unmatched_count"] == 1
    unresolved = {item["reason"]: item for item in graph["shared_datastore_unresolved"]}
    ambiguity = unresolved["conflicting_declarations_for_source_observation"]
    evidence = {item["id"]: item for item in graph["evidence"]}
    assert {evidence[ref]["file"] for ref in ambiguity["evidence_refs"]} == {
        "src/store.py", "src/other.py"}
    assert all(ref in evidence for item in graph["shared_datastore_unresolved"]
               for ref in item["evidence_refs"])
    _assert_references(graph)


def test_secret_bearing_datastore_declaration_is_rejected_without_raw_output():
    reader, writer = _result("reader", "C:/reader"), _result("writer", "C:/writer")
    invalid = _datastore_signal()
    invalid.properties["host"] = "user:wp044secret@db.example.internal"
    reader.scan.signals = [invalid]
    writer.scan.signals = [_datastore_signal(observation="db-write")]
    graph = build_fleet_architecture(FleetScan(results=[reader, writer]))
    coverage = graph["coverage"]["protocols"]["shared_datastore"]
    assert coverage["declaration_count"] == 1
    assert coverage["rejected_declaration_count"] == 1
    assert coverage["association_count"] == 0
    assert "wp044secret" not in json.dumps(graph)
    _assert_references(graph)


@pytest.mark.parametrize("source_role", ["test", "fixture", "mock", "example"])
def test_nonproduction_datastore_declarations_cannot_create_cross_repository_association(source_role):
    reader, writer = _result("reader", "C:/reader"), _result("writer", "C:/writer")
    left, right = _datastore_signal(), _datastore_signal(observation="db-write")
    left.source_role = right.source_role = source_role
    reader.scan.signals, writer.scan.signals = [left], [right]
    graph = build_fleet_architecture(FleetScan(results=[reader, writer]))
    coverage = graph["coverage"]["protocols"]["shared_datastore"]
    assert not any(edge["kind"] == "shared_datastore" for edge in graph["edges"])
    assert not any(node.get("qualified_identity") for node in graph["nodes"])
    assert coverage["declaration_count"] == 0
    assert coverage["rejected_declaration_count"] == 2
    assert coverage["resource_count"] == coverage["association_count"] == 0
    assert any("non-production" in item for item in graph["limitations"])


def _assert_limit_preserves_architecture(graph, baseline, reason, declaration_count):
    for key in ("repositories", "nodes", "edges", "evidence"):
        assert graph[key] == baseline[key]
    assert graph["coverage"]["protocols"]["shared_datastore"]["declaration_count"] == declaration_count
    assert graph["coverage"]["protocols"]["shared_datastore"]["association_count"] == 0
    assert graph["shared_datastore_unresolved"] == [{
        "id": graph["shared_datastore_unresolved"][0]["id"],
        "kind": "shared_datastore", "reason": reason, "resource_id": None,
        "evidence_refs": [],
    }]
    assert any("prepared contract limit" in item for item in graph["limitations"])


def test_declaration_limit_preserves_existing_repository_http_and_proxy_architecture():
    fleet, requested = fleet16_oracle()
    baseline = build_fleet_architecture(fleet, requested)
    fleet.results[0].scan.signals = [
        _datastore_signal(observation=f"db-{index}", line=index + 1)
        for index in range(MAX_DATASTORE_DECLARATIONS + 1)]
    graph = build_fleet_architecture(fleet, requested)
    _assert_limit_preserves_architecture(
        graph, baseline, "declaration_count_exceeds_prepared_limit", MAX_DATASTORE_DECLARATIONS + 1)


def test_repository_limit_preserves_existing_repository_http_and_proxy_architecture():
    fleet, requested = fleet16_oracle()
    root = "C:/fleet/repo-16"
    fleet.results.append(_result("repo-16", root))
    requested.append({"root": root, "requested_id": "00000000-0000-0000-0000-000000000016",
                      "repo_id": "repo-16", "generation": 7})
    baseline = build_fleet_architecture(fleet, requested)
    for index, result in enumerate(fleet.results):
        result.scan.signals = [_datastore_signal(observation=f"db-{index}")]
    graph = build_fleet_architecture(fleet, requested)
    assert len(graph["repositories"]) == MAX_DATASTORE_REPOSITORIES + 1
    _assert_limit_preserves_architecture(
        graph, baseline, "repository_count_exceeds_prepared_limit", MAX_DATASTORE_REPOSITORIES + 1)
