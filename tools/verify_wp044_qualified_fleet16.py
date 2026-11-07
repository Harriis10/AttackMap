"""Real CLI qualification of the pre-pinned physical WP044 corpus; no GUI."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from verify_wp018_closeout import ROOT, launch, collect, production_inputs, read, require, save, sha

FIXTURE = ROOT / "tests/fixtures/wp044_qualified_fleet16"
MODULES = ["config", "javascript-web", "python-web"]


def fixture_hashes():
    return {p.relative_to(FIXTURE).as_posix(): sha(p) for p in sorted(FIXTURE.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts}


def verify(summary, oracle, roots):
    ids = oracle["repository_ids"]
    require(summary["repo_count"] == 16 and not summary["failed"], "Fleet incomplete")
    require([r["repo_id"] for r in summary["repos"]] == ids, "Ordered repository identities differ")
    for row, root in zip(summary["repos"], roots):
        require(Path(row["root"]).resolve() == root, "Wrong repository root")
    expected = {}
    for call in oracle["http_calls"]:
        for server in ("auth-api", "auth-api-2"):
            expected[call["target"], server] = ((call["resolution"], call["reason"])
                if call["owner"] in (None, server) else ("candidate", "unresolved_host"))
    actual = {}
    for link in summary["cross_repo_links"]:
        key = link["client_target"], link["server_repo"]
        require(key in expected and key not in actual, "Unexpected/duplicate HTTP seam")
        actual[key] = link["resolution"], link["resolution_reason"]
        call = next(c for c in oracle["http_calls"] if c["target"] == key[0])
        require(link["client_repo"] == "client" and link["client_location"] == f'{oracle["client_file"]}:{call["line"]}'
                and link["server_location"] == oracle["server_location"] and link["method"] == oracle["method"]
                and link["server_route_path"] == oracle["server_route_path"], "Wrong HTTP source/route provenance")
        url = urlsplit(call["target"])
        require(link["scheme"] == url.scheme and link["destination"] == url.netloc, "Authority changed")
        owning = call["owner"] == key[1]
        backend = (link["server_namespace"], link["server_port"], link["server_protocol"])
        require(backend == (tuple(oracle["backend"][key[1]]) if owning else (None, None, None)), "Wrong namespace/backend")
        require(link["server_service_name"] == ("auth-api" if owning else None), "Wrong scoped service")
        refs = link["declaration_refs"]
        supplied = {(Path(r["repository_root"]).resolve(), r["file"], r["line"]) for r in refs}
        wanted = {(roots[ids.index(key[1])], f, None) for f in oracle["backend_declarations"][key[1]]} if owning else set()
        require(supplied == wanted and len(refs) == len(wanted), "Wrong/missing deployment origin")
        require(link["proxy_host"] == (url.hostname if link["resolution"] == "observed_via_proxy" else None), "Phantom proxy")
    require(actual == expected, "Exact HTTP oracle differs")
    graph = summary["fleet_architecture"]
    nodes = {r["id"]: r for r in graph["nodes"]}
    evidence = {r["id"]: r for r in graph["evidence"]}
    repos = {r["id"]: r["repo_id"] for r in graph["repositories"]}
    require(len(repos) == 16 and set(repos.values()) == set(ids), "Graph lost repository identity")
    require(len(nodes) == len(graph["nodes"]) and len(evidence) == len(graph["evidence"])
            and len({e["id"] for e in graph["edges"]}) == len(graph["edges"]), "Duplicate graph ID")
    for node in nodes.values():
        require(node["parent_id"] is None or node["parent_id"] in nodes, "Dangling parent")
        require(set(node["evidence_refs"]) <= evidence.keys(), "Dangling node evidence")
    for edge in graph["edges"]:
        require(edge["source"] in nodes and edge["target"] in nodes and set(edge["evidence_refs"]) <= evidence.keys(), "Dangling graph reference")
    for collection in ("shared_datastore_unresolved", "producer_consumer_unresolved"):
        for row in graph.get(collection, []):
            require(set(row["evidence_refs"]) <= evidence.keys(), "Dangling unresolved evidence")
    for kind, pairs, directed in (("producer_consumer", oracle["messaging_pairs"], True),
                                  ("shared_datastore", oracle["datastore_pairs"], False)):
        edges = [e for e in graph["edges"] if e["kind"] == kind]
        require([[repos[e["source"]], repos[e["target"]]] for e in edges] == pairs, "Phantom/missing declared association")
        for edge in edges:
            require(edge["directed"] is directed and edge["resolution"] == "declared", "Wrong association direction/resolution")
            refs = [evidence[r] for r in edge["evidence_refs"]]
            require({r["repo_id"] for r in refs} == {edge["source"], edge["target"]}, "Association origin differs")
            require(all(r["file"] == "config.json" and r["observation_id"] and r["source_analyzer"] == "config" for r in refs), "Association lacks actual config evidence")
    http = [e for e in graph["edges"] if e["kind"] == "cross_repo_http_call"]
    require(Counter(e["kind"] for e in graph["edges"]) == {"containment": 2, "cross_repo_http_call": 18,
            "producer_consumer": 1, "shared_datastore": 1}, "Unexpected graph association kind/count")
    repository_nodes = {name: node for node, name in repos.items()}
    proxies = {n["label"]: n["id"] for n in nodes.values() if n["kind"] == "external"}
    expected_http = {}
    for link in summary["cross_repo_links"]:
        source, target = repository_nodes["client"], repository_nodes[link["server_repo"]]
        pairs = [(source, target, "direct")]
        if link["resolution"] == "observed_via_proxy":
            proxy = proxies[link["proxy_host"]]
            pairs = [(source, proxy, "client_to_proxy"), (proxy, target, "proxy_to_server")]
        for source, target, leg in pairs:
            key = source, target, leg, link["client_target"]
            require(key not in expected_http, "Duplicate expected graph endpoint")
            expected_http[key] = link
    actual_http = set()
    for edge in http:
        key = edge["source"], edge["target"], edge["leg"], edge["client_target"]
        require(key in expected_http and key not in actual_http, "Wrong/duplicate HTTP graph endpoint")
        actual_http.add(key)
        link = expected_http[key]
        require(all(edge[field] == link[field] for field in ("resolution", "resolution_reason", "server_namespace",
                    "server_service_name", "server_port", "server_protocol")), "Graph facts cross-bound to wrong link")
        refs = [evidence[ref] for ref in edge["evidence_refs"]]
        call = next(c for c in oracle["http_calls"] if c["target"] == edge["client_target"])
        locations = {(r["repo_id"], r["kind"], r["file"], r["line"]) for r in refs}
        require({row for row in locations if row[1] == "external_call"}
                    == {(repository_nodes["client"], "external_call", oracle["client_file"], call["line"])}
                and {row for row in locations if row[1] == "route"}
                    == {(repository_nodes[link["server_repo"]], "route", "app.py", 3)},
                "HTTP graph evidence wrong repository/file/line")
    require(actual_http == expected_http.keys(), "Missing HTTP graph endpoint")
    require(Counter(e["resolution"] for e in http) == {"candidate": oracle["http_link_count"] - oracle["proxy_observed_count"], "observed_via_proxy": 2 * oracle["proxy_observed_count"]}, "Wrong graph HTTP legs")
    require(Counter(e["leg"] for e in http if e["resolution"] == "observed_via_proxy") == {"client_to_proxy": 2, "proxy_to_server": 2}, "Wrong proxy direction")
    for edge in http:
        require(edge["directed"] is True, "HTTP direction lost")
        refs = [evidence[r] for r in edge["evidence_refs"]]
        require({r["kind"] for r in refs} >= {"route", "external_call"}, "HTTP source refs lost")
        declarations = [r for r in refs if r["kind"] == "deployment_declaration"]
        require(bool(declarations) == (edge["server_namespace"] is not None), "Graph phantom/missing declaration")
        require(all(r["snapshot_binding"] == "unverified" for r in declarations), "Declaration invented verified content")
        if declarations:
            owner, = [repo for repo, backend in oracle["backend"].items() if backend[0] == edge["server_namespace"]]
            require((edge["server_namespace"], edge["server_port"], edge["server_protocol"]) == tuple(oracle["backend"][owner])
                    and edge["server_service_name"] == "auth-api", "Graph backend facts differ")
            require({(r["core_repo_id"], r["file"], r["line"], r["location_status"], r["location_reason"]) for r in declarations}
                    == {(owner, f, None, "file_only", "line_not_supplied") for f in oracle["backend_declarations"][owner]}, "Graph config origin cross-bound")
            require(all(repos[r["repo_id"]] == owner and r["basis"] == "supplied_static_config_declaration"
                        for r in declarations), "Graph declaration ownership/basis invented")
    require(graph["coverage"]["atomic_snapshot"] is False and graph["coverage"]["complete"] is False, "Overstated coverage")
    require(graph["coverage"]["protocols"]["rpc_schema"]["status"] == "unanalysed", "Overstated RPC support")
    require({n["label"] for n in nodes.values() if n["kind"] == "external"} == set(oracle["external_nodes"]), "External nodes differ")
    multi_id, = [repo for repo, name in repos.items() if name == "multi-service"]
    require(sorted(n["label"] for n in nodes.values() if n["repo_id"] == multi_id and n["kind"] == "service")
            == oracle["multi_service_nodes"], "Supported multi-service component identities differ")
    return {"repository_count": 16, "http_links": len(actual), "graph_http_edges": len(http),
            "declared_messaging_pairs": oracle["messaging_pairs"], "declared_datastore_pairs": oracle["datastore_pairs"],
            "oracle_exact": True, "graph_references_valid": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    engine = parser.add_mutually_exclusive_group(required=True)
    engine.add_argument("--python", type=Path)
    engine.add_argument("--engine", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    oracle = read(FIXTURE / "expected.json")
    require(sha(FIXTURE / "expected.json") == "8b63fb1a97184459015969299330058565435177f6e611c7f28e1d4bd609a08b", "Final pre-runtime oracle pin differs")
    roots = [(FIXTURE / name).resolve(strict=True) for name in oracle["roots"]]
    require(len(roots) == len(set(roots)) == 16, "Require pinned sixteen roots")
    executable = (args.engine or args.python).resolve(strict=True)
    identity = {"path": str(executable), "sha256": sha(executable), "kind": "Frozen" if args.engine else "SourcePython"}
    before = {"fixture_sha256": fixture_hashes(), "production_inputs": production_inputs(),
              "engine": identity, "verifier_sha256": sha(Path(__file__)), "roots": list(map(str, roots)), "modules": MODULES,
              "oracle": oracle}
    save(output / "inputs-before.json", before)
    result = {"passed": False, "engine": identity, "whole_wp044_done": False, "gui": "UNKNOWN",
              "scope": "Actual CLI JSON workers2, physical sixteen roots; declared associations are not runtime delivery"}
    try:
        prefix = [str(executable)] if args.engine else [str(executable), "-m", "attackmap"]
        argv = [*prefix, "analyze", *map(str, roots), "--output", str(output / "reports"), "--format", "json", "--fleet-workers", "2"]
        for module in MODULES: argv += ["--module", module]
        save(output / "command.json", argv)
        launch(argv, output, args.timeout)
        generation, manifest, children = collect(output / "reports", roots)
        require([c["slug"] for c in children] == oracle["repository_ids"], "Wrong child generation identities")
        summary_path = generation / "fleet-summary.json"
        result.update(generation=str(generation), summary_path=str(summary_path), summary_sha256=sha(summary_path),
                      parent_manifest_sha256=sha(generation / "artifact-manifest.json"),
                      child_manifests=[{"path": c["manifest_path"], "sha256": c["manifest_sha256"]} for c in children])
        result.update(verify(read(summary_path), oracle, roots))
        require(fixture_hashes() == before["fixture_sha256"], "Physical corpus changed during runtime")
        require(production_inputs() == before["production_inputs"] and sha(executable) == identity["sha256"], "Source/engine changed")
        result.update(passed=True, inputs_unchanged=True)
    except Exception as error:
        result["error"] = str(error)
    save(output / "inputs-after.json", {"fixture_sha256": fixture_hashes(), "production_inputs": production_inputs(),
        "engine_sha256": sha(executable), "verifier_sha256": sha(Path(__file__))})
    save(output / "verification.json", result)
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
