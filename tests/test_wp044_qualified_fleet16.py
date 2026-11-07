"""Physical 16-root source extraction; fault projection checks are explicitly synthetic.

No analyzer-emitted observations are injected. JSON declarations are operator
assertions, never evidence of live Kafka delivery or database connectivity.
"""
from collections import Counter
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import ntpath
import os
from pathlib import Path
import shutil

import pytest

from attackmap.fleet_architecture import aggregate_fleet_architecture, build_fleet_architecture
from attackmap.scan_service import ScanRequest, execute_scan_request

FIXTURE = Path(__file__).parent / "fixtures/wp044_qualified_fleet16"
ORACLE = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))


def hashes(root):
    return {str(p.relative_to(root)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


@pytest.fixture(scope="module")
def campaign(tmp_path_factory, request):
    environment = pytest.MonkeyPatch()
    request.addfinalizer(environment.undo)
    # Real subprocess workers must load this source checkout, as does pytest.
    environment.setenv("PYTHONPATH", str(FIXTURE.parents[2] / "src") + os.pathsep + os.environ.get("PYTHONPATH", ""))
    work = tmp_path_factory.mktemp("qualified-fleet16")
    source = work / "physical fleet"
    shutil.copytree(FIXTURE, source)
    before = hashes(source)
    save(work / "oracle-before-runtime.json", {"oracle": ORACLE, "physical_inputs_sha256": before})
    roots = [source / name for name in ORACLE["roots"]]
    runs = []
    for workers in (1, 2):
        captured = []
        result = execute_scan_request(ScanRequest(repo_paths=roots, output=work / f"workers-{workers}",
            output_format="json", modules=["config", "javascript-web", "python-web"], max_workers=workers,
            no_progress=True, echo=lambda *args, **kwargs: None,
            fleet_finished=lambda output, fleet: captured.append(fleet)))
        assert result.exit_code == 0, result.error
        assert len(captured) == 1
        summary = json.loads(result.fleet_summary_path.read_text(encoding="utf-8"))
        assert len(captured[0].results) == 16 and not captured[0].failed
        runs.append((captured[0], summary))
    assert hashes(source) == before
    save(work / "campaign.json", {"actual_source_runs": 2, "workers": [1, 2], "children_per_run": 16,
        "fixture_unchanged": True, "input_hashes": before, "whole_wp044_accepted": False,
        "limits": "Source only; no frozen/native/production-fleet qualification or runtime message delivery."})
    return work, roots, runs


def references(graph):
    nodes = {row["id"]: row for row in graph["nodes"]}
    evidence = {row["id"]: row for row in graph["evidence"]}
    assert len(nodes) == len(graph["nodes"]) and len(evidence) == len(graph["evidence"])
    assert len({row["id"] for row in graph["edges"]}) == len(graph["edges"])
    for node in nodes.values():
        assert node["parent_id"] is None or node["parent_id"] in nodes
        assert set(node["evidence_refs"]) <= evidence.keys()
    for edge in graph["edges"]:
        assert edge["source"] in nodes and edge["target"] in nodes
        assert set(edge["evidence_refs"]) <= evidence.keys()
    for collection in ("shared_datastore_unresolved", "producer_consumer_unresolved"):
        for item in graph.get(collection, []):
            assert set(item["evidence_refs"]) <= evidence.keys()
    return nodes, evidence


def test_physical_http_namespace_backend_and_declaration_oracle(campaign):
    _, roots, runs = campaign
    for fleet, summary in runs:
        assert [row.repo_id for row in fleet.results] == ORACLE["repository_ids"]
        links = summary["cross_repo_links"]
        assert len(links) == ORACLE["http_link_count"]
        actual = {}
        for link in links:
            call = next(row for row in ORACLE["http_calls"] if row["target"] == link["client_target"])
            key = (link["client_target"], link["server_repo"])
            assert key not in actual
            actual[key] = (link["resolution"], link["resolution_reason"])
            owning = call["owner"] == link["server_repo"]
            expected = (call["resolution"], call["reason"]) if owning or call["owner"] is None else ("candidate", "unresolved_host")
            assert actual[key] == expected
            assert link["client_location"] == f'client.js:{call["line"]}'
            assert link["server_location"] == "app.py:3"
            metadata = (link["server_namespace"], link["server_port"], link["server_protocol"])
            expected_metadata = tuple(ORACLE["backend"][link["server_repo"]]) if owning else (None, None, None)
            assert metadata == expected_metadata
            declarations = link["declaration_refs"]
            if owning:
                root = roots[1 if link["server_repo"] == "auth-api" else 2]
                assert {(Path(row["repository_root"]), row["file"], row["line"]) for row in declarations} == {
                    (root.resolve(), "service.yaml", None), (root.resolve(), "ingress.yaml", None)}
            else:
                assert declarations == []
            assert (link["proxy_host"] is not None) == (link["resolution"] == "observed_via_proxy")
        assert Counter(row["resolution"] for row in links) == {"candidate": 14, "observed_via_proxy": 2}
        assert {row["repo_id"] for row in summary["repos"]} == set(ORACLE["repository_ids"])
        repositories = summary["fleet_architecture"]["repositories"]
        by_root = {ntpath.normcase(ntpath.normpath(row["root"])): row for row in repositories}
        assert len(by_root) == 16
        for root, repo_id in zip(roots, ORACLE["repository_ids"]):
            key = ntpath.normcase(ntpath.normpath(str(root.resolve())))
            row = by_root[key]
            canonical = json.dumps([key.replace("\\", "/")], ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            assert row["id"] == "repository-" + hashlib.sha256(canonical.encode()).hexdigest()
            assert row["repo_id"] == repo_id and row["snapshot_available"] is True


def test_physical_declared_resource_direction_negative_identity_and_refs(campaign):
    for _, summary in campaign[2]:
        graph = summary["fleet_architecture"]
        nodes, evidence = references(graph)
        repositories = {row["id"]: row["repo_id"] for row in graph["repositories"]}
        for kind, expected, directed in [("producer_consumer", ORACLE["messaging_pairs"], True),
                                          ("shared_datastore", ORACLE["datastore_pairs"], False)]:
            edges = [row for row in graph["edges"] if row["kind"] == kind]
            assert [[repositories[row["source"]], repositories[row["target"]]] for row in edges] == expected
            edge, = edges
            assert edge["directed"] is directed and edge["resolution"] == "declared"
            assert {evidence[ref]["repo_id"] for ref in edge["evidence_refs"]} == {edge["source"], edge["target"]}
            assert all(evidence[ref]["file"] == "config.json" and evidence[ref]["observation_id"]
                       and evidence[ref]["source_analyzer"] == "config" for ref in edge["evidence_refs"])
        http = [row for row in graph["edges"] if row["kind"] == "cross_repo_http_call"]
        assert Counter(row["resolution"] for row in http) == {"candidate": 14, "observed_via_proxy": 4}
        assert Counter(row["leg"] for row in http if row["resolution"] == "observed_via_proxy") == {
            "client_to_proxy": 2, "proxy_to_server": 2}
        for edge in http:
            refs = [evidence[ref] for ref in edge["evidence_refs"]]
            assert {row["kind"] for row in refs} >= {"route", "external_call"}
            declarations = [row for row in refs if row["kind"] == "deployment_declaration"]
            assert all(row["snapshot_binding"] == "unverified" for row in declarations)
            assert bool(declarations) == (edge["server_namespace"] is not None)
        assert len(graph["repositories"]) == 16
        assert graph["coverage"]["atomic_snapshot"] is False
        assert graph["coverage"]["complete"] is False
        assert graph["coverage"]["protocols"]["rpc_schema"]["status"] == "unanalysed"
        assert sorted(row["label"] for row in nodes.values() if row["kind"] == "external") == sorted(ORACLE["external_nodes"])
        # Unmatched raw URLs must not invent a graph component without ownership.
        assert not any("telemetry.external.example" in row["label"] for row in nodes.values())
        multi_id, = [row["id"] for row in graph["repositories"] if row["repo_id"] == "multi-service"]
        assert sorted(row["label"] for row in nodes.values() if row["repo_id"] == multi_id and row["kind"] == "service") == ORACLE["multi_service_nodes"]


def test_serial_parallel_full_graph_and_reversible_overview(campaign):
    graphs = []
    for fleet, summary in campaign[2]:
        graph = deepcopy(summary["fleet_architecture"])
        assert graph == build_fleet_architecture(fleet)
        # Only independent output location is replaced after exact validation.
        for row in graph["repositories"]:
            child, = [child for child in fleet.results if child.repo_id == row["repo_id"]]
            assert row["report_dir"] == child.report_dir
            row["report_dir"] = row["repo_id"]
        graphs.append(graph)
        overview = aggregate_fleet_architecture(graph)
        source = {row["id"]: row for row in graph["edges"] if row["kind"] != "containment"}
        recovered = []
        for edge in overview["edges"]:
            ids = edge["underlying_edge_ids"]
            assert edge["count"] == len(ids) == len(set(ids))
            recovered.extend(ids)
            for underlying in ids:
                assert (source[underlying]["kind"], source[underlying]["directed"], source[underlying]["resolution"], source[underlying].get("leg")) == (
                    edge["kind"], edge["directed"], edge["resolution"], edge["leg"])
        assert set(recovered) == source.keys() and len(recovered) == len(source)
        assert overview["path_semantics"] == "presentation_only_not_detail_reachability"
    assert graphs[0] == graphs[1]  # No clock, evidence or provenance normalization.


def test_projection_only_partial_and_failed_child_preserve_all_identities(campaign):
    _, roots, runs = campaign
    original = runs[0][0]
    requests = [{"root": str(root.resolve()), "requested_id": f"transport-{i}"} for i, root in enumerate(roots)]
    children = []
    for child in original.results:
        if child.repo_id == "orphan":
            continue
        if child.repo_id == "partial-child":
            child = replace(child, scan=child.scan.model_copy(update={"limitations": [*child.scan.limitations,
                "Synthetic projection-only unavailable-analyzer fixture; not a runtime fault."]}))
        children.append(child)
    fleet = replace(original, results=children, failed=[{"root": str(roots[12].resolve()), "repo_id": "orphan",
        "error": "Synthetic projection-only failed-child fixture; not a runtime fault."}])
    graph = build_fleet_architecture(fleet, requests)
    references(graph)
    assert len(graph["repositories"]) == 16
    assert {row["requested_id"] for row in graph["repositories"]} == {f"transport-{i}" for i in range(16)}
    statuses = {row["repo_id"]: row["status"] for row in graph["repositories"]}
    assert statuses["orphan"] == "failed" and statuses["partial-child"] == "partial"
    assert graph["coverage"]["available_repositories"] == 15
    assert graph["coverage"]["repository_results_complete"] is False
    assert len(original.results) == 16 and not original.failed
    assert "Synthetic" not in str(original.results[-1].scan.limitations)
