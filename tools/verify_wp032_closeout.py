"""Scan the pinned physical C28 three-service oracle with a real CLI engine.

The expected edge classifications precede runtime qualification and tuning. No
normalized observations are injected, and no provider/network option is enabled.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from verify_wp018_closeout import ROOT, cli_matrix, collect, input_hashes, launch, read, require, save, sha
from attackmap.models import ScanResult

FIXTURE = ROOT / "tests/fixtures/wp032_namespace_reference"
MODULES = ("javascript-web", "python-web", "config")


def expected_edges(oracle, variant):
    result = {}
    for call in oracle["calls"]:
        if call.get("no_links"):
            continue
        for server in oracle["repository_ids"][1:]:
            resolution = call["resolved"].get(server, "candidate")
            reason = call.get("candidate_reasons", {}).get(server, "")
            if variant != "baseline" and server == "auth-api" and resolution != "candidate":
                resolution = "candidate"
                reason = "unresolved_host" if variant == "port-mismatch" else "unsupported_protocol"
            if variant == "port-mismatch" and server == "auth-api" and urlsplit(call["target"]).hostname == "prod-api.example":
                resolution, reason = "candidate", "unresolved_host"
            key = ("client", server, call["target"], f'{oracle["client_file"]}:{call["line"]}',
                   oracle["method"], oracle["server_route"], f'{oracle["server_file"]}:{oracle["server_line"]}')
            result[key] = (resolution, reason)
    return result


def verify_edges(summary, oracle, variant):
    expected = expected_edges(oracle, variant)
    links = summary["cross_repo_links"]
    actual = {}
    roots = {row["repo_id"]: os.path.normcase(os.path.normpath(row["root"])) for row in summary["repos"]}
    expected_declarations = {}
    for link in links:
        key = tuple(link[name] for name in ("client_repo", "server_repo", "client_target", "client_location",
                    "method", "server_route_path", "server_location"))
        require(key not in actual, "Duplicate reference edge")
        actual[key] = (link["resolution"], link["resolution_reason"])
        call = next((row for row in oracle["calls"] if row["target"] == link["client_target"]), None)
        require(call is not None, "Unsupported caller target")
        authority = urlsplit(call["target"])
        require(link["scheme"] == authority.scheme and link["destination"] == authority.hostname,
                "Contract authority/protocol differs from the exact source call")
        known_scope = link["server_repo"] in call["resolved"] or link["server_repo"] in call.get("known_scope", [])
        if variant == "port-mismatch" and authority.hostname == "prod-api.example" and link["server_repo"] == "auth-api":
            known_scope = False
        require({"server_namespace", "server_service_name", "server_port", "server_protocol"} <= link.keys(), "Backend identity fields disappeared")
        if known_scope:
            protocol = None if variant in {"grpc", "conflict"} and link["server_repo"] == "auth-api" else oracle["backend_protocol"]
            require(link.get("server_namespace") == call["namespace"]
                    and link.get("server_service_name") == "auth-api" and link["server_port"] == oracle["backend_port"]
                    and link["server_protocol"] == protocol, "Known scoped candidate/resolved seam lost namespace/service/backend identity")
        else:
            require(all(link[key] is None for key in ("server_namespace", "server_service_name", "server_port", "server_protocol")),
                    "Unrelated candidate acquired another namespace/service identity")
        files = {"service.yaml", "ingress.yaml"} if known_scope else set()
        if known_scope and variant == "conflict" and link["server_repo"] == "auth-api":
            files.add("conflict.yaml")
        wanted_declarations = {(roots[link["server_repo"]], file, None) for file in files}
        declarations = link.get("declaration_refs", [])
        supplied = {(os.path.normcase(os.path.normpath(row["repository_root"])), row["file"], row["line"]) for row in declarations}
        require(supplied == wanted_declarations and len(supplied) == len(declarations),
                "Missing/wrong/cross-namespace config declaration origin")
        expected_declarations[(link["client_target"], link["server_repo"])] = files
        if link["resolution"] == "candidate":
            require(bool(link["resolution_reason"]), "Candidate lacks its unresolved reason")
            require(link["proxy_host"] is None, "Candidate acquired a positive intermediary claim")
        else:
            require(link["resolution"] == "observed_via_proxy", "Reference unexpectedly creates a direct observed trust path")
            require(link["proxy_host"] == authority.hostname and
                    link["alias_provenance"] == f'scoped_proxies:{authority.hostname} (auth-api/ingress.yaml)',
                    "Resolved proxy lost its exact authority/declaration origin")
    require(actual == expected, "Exact three-service reference edges differ from the pinned oracle: "
            + repr({"missing": list(expected.keys() - actual.keys()), "extra": list(actual.keys() - expected.keys()),
                    "wrong": [(key, expected[key], actual[key]) for key in expected.keys() & actual.keys() if expected[key] != actual[key]]}))
    require(not summary["cross_boundary_flows"] and not summary["trust_gaps"], "Proxy/candidate links created direct observed trust paths")
    graph = summary["fleet_architecture"]
    repository_ids = {row["repo_id"]: row["id"] for row in graph["repositories"]}
    require(set(repository_ids) == set(roots), "Graph repository mapping differs from selected sources")
    nodes = {row["id"]: row for row in graph["nodes"]}
    evidence = {row["id"]: row for row in graph["evidence"]}
    require(len(nodes) == len(graph["nodes"]) and len(evidence) == len(graph["evidence"]), "Duplicate graph identity")
    for item in [*graph["nodes"], *graph["edges"]]:
        require(all(ref in evidence for ref in item["evidence_refs"]), "Dangling evidence reference")
    for edge in graph["edges"]:
        require(edge["source"] in nodes and edge["target"] in nodes, "Dangling graph endpoint")
    http = [edge for edge in graph["edges"] if edge["kind"] == "cross_repo_http_call"]
    expected_counts = Counter(value[0] for value in actual.values())
    expected_counts["observed_via_proxy"] *= 2  # the two explicit intermediary legs
    require(Counter(edge["resolution"] for edge in http) == +expected_counts, "Graph changed canonical link classifications/counts")
    edge_links = Counter()
    edge_legs = Counter()
    for edge in http:
        refs = [evidence[ref] for ref in edge["evidence_refs"]]
        require(any(ref["kind"] == "external_call" and ref["file"] == oracle["client_file"] for ref in refs)
                and any(ref["kind"] == "route" and ref["file"] == oracle["server_file"] for ref in refs),
                "Graph relationship lost source-backed caller or route evidence")
        candidates = [link for link in links if link["client_target"] == edge["client_target"]
            and link["server_route_path"] == edge["server_route_path"] and link["method"] == edge["method"]
            and any(ref["core_repo_id"] == link["server_repo"] and ref["kind"] == "route"
                    and f'{ref["file"]}:{ref["line"]}' == link["server_location"] for ref in refs)
            and any(ref["core_repo_id"] == link["client_repo"] and ref["kind"] == "external_call"
                    and f'{ref["file"]}:{ref["line"]}' == link["client_location"] for ref in refs)]
        require(len(candidates) == 1, "Graph edge not bound to one exact source-backed contract link")
        link = candidates[0]
        require(edge["resolution"] == link["resolution"] and edge["resolution_reason"] == link["resolution_reason"],
                "Graph changed a link resolution")
        require(edge.get("server_namespace") == link.get("server_namespace")
                and edge.get("server_service_name") == link.get("server_service_name")
                and edge.get("server_port") == link["server_port"] and edge.get("server_protocol") == link["server_protocol"],
                "Graph lost explicit namespace/service/backend facts")
        source, target = nodes[edge["source"]], nodes[edge["target"]]
        leg = edge["leg"]
        if link["resolution"] == "observed_via_proxy":
            require(leg in {"client_to_proxy", "proxy_to_server"}, "Proxy relationship lost its intermediary leg")
            proxy = target if leg == "client_to_proxy" else source
            endpoint = source if leg == "client_to_proxy" else target
            owner = link["client_repo"] if leg == "client_to_proxy" else link["server_repo"]
            require(endpoint["repo_id"] == repository_ids[owner] and proxy["repo_id"] is None
                    and proxy["component_role"] == "proxy" and proxy["authority"] == link["proxy_host"]
                    and proxy["scheme"] == link["scheme"], "Proxy leg changed selected endpoint/authority/protocol")
        else:
            require(leg == "direct" and source["repo_id"] == repository_ids[link["client_repo"]]
                    and target["repo_id"] == repository_ids[link["server_repo"]], "Candidate graph endpoint belongs to another repository")
        declarations = [ref for ref in refs if ref["kind"] == "deployment_declaration"]
        require({(ref["core_repo_id"], ref["file"], ref["line"]) for ref in declarations}
                == {(link["server_repo"], file, None) for file in expected_declarations[(link["client_target"], link["server_repo"])]},
                "Graph config origin is missing or belongs to another same-basename repository")
        require(all(ref["snapshot_binding"] == "unverified" and ref["location_status"] == "file_only"
                    and ref["location_reason"] == "line_not_supplied" for ref in declarations),
                "Config attribution invented snapshot/line verification")
        edge_links[(link["client_target"], link["server_repo"])] += 1
        edge_legs[(link["client_target"], link["server_repo"], leg)] += 1
    require(edge_links == Counter({(link["client_target"], link["server_repo"]):
             2 if link["resolution"] == "observed_via_proxy" else 1 for link in links}), "Graph lost or duplicated a modeled relationship")
    require(edge_legs == Counter({(link["client_target"], link["server_repo"], leg): 1 for link in links
                for leg in (["client_to_proxy", "proxy_to_server"] if link["resolution"] == "observed_via_proxy" else ["direct"])}),
            "Graph duplicated or lost a specific intermediary leg")
    return dict(links=len(links), resolutions=dict(Counter(value[0] for value in actual.values())), graph_http_edges=len(http),
                graph_evidence=len(evidence), no_unsupported_observed_edges=True)


def verify_child_reports(children, oracle):
    scored = 0
    signals = 0
    references = []
    for child in children:
        report = read(Path(child["manifest_path"]).parent / "attackmap-report.json")
        scan = report["scan"]
        require(not scan["analyzer_errors"], "A reference analyzer failed")
        if child["slug"] == "client":
            actual = {(row["target"], row["file"], row["line"]) for row in scan["external_calls"] if row["file"] == oracle["client_file"]}
            expected = {(row["target"], oracle["client_file"], row["line"]) for row in oracle["calls"]}
            require(actual == expected, "Actual JS extraction differs from source locations pinned in the oracle")
        else:
            require(any(row["path"] == oracle["server_route"] and row["file"] == oracle["server_file"]
                        and row["line"] == oracle["server_line"] for row in scan["routes"]), "Actual Flask route extraction missing")
        for signal in scan["signals"]:
            signals += 1
            require(bool(signal["observation_id"]) and signal["origins"], "Normalized observation lost ID/origins")
            require(signal["source_role"] and signal["evidence_kind"], "Missing explicit source/evidence classification")
            for origin in signal["origins"]:
                require(origin["metadata_status"] == "legacy_unknown" or (origin["analyzer"] and origin["analyzer_version"]),
                        "Known analyzer origin lacks identity/version")
                require((origin["file"] and origin["line"]) or origin["location_reason"], "Missing source location and unavailable reason")
        for finding in report["findings"]:
            if finding["exploitability"] is None:
                continue
            reference = finding["exploitability_reference"]
            require(reference and reference["scope"] == "repository_snapshot", "Scored finding lacks exact snapshot-qualified producer identity")
            require(reference["repository_root"] == scan["root"]
                    and reference["snapshot_id"] == scan["scan_snapshot"]["snapshot_id"], "Cross-repository/snapshot score association")
            matches = [row for row in report["exploitability"] if row["producer_reference"] == reference]
            require(len(matches) == 1 and matches[0]["score"] == finding["exploitability"]
                    and matches[0]["tier"] == finding["exploitability_tier"], "Finding score resolved by value instead of exact producer identity")
            require(finding["context"]["priority"]["score_reference"]["status"] == "resolved", "Read-only finding consumer lost exact score reference")
            references.append(reference)
            scored += 1
    require(scored >= 2 and signals > 0, "Vacuous source/reference qualification")
    return dict(actual_observations=signals, snapshot_bound_finding_scores=scored, score_references=references)


def verify_observation_references(graph, children):
    observations = {}
    for child in children:
        scan = read(Path(child["manifest_path"]).parent / "attackmap-report.json")["scan"]
        model = ScanResult.model_validate(scan)
        known = set()
        for signal in [*model.signals, *model.all_signals()]:
            known.add((signal.observation_id, signal.file, signal.line))
            known.update((signal.observation_id, origin.file, origin.line) for origin in signal.origins)
        observations[child["slug"]] = known
    checked = 0
    for reference in graph["evidence"]:
        require(reference["core_repo_id"] in observations, "Evidence belongs to an unselected repository")
        if reference.get("observation_id") is not None:
            require((reference["observation_id"], reference.get("file"), reference.get("line"))
                    in observations[reference["core_repo_id"]], "Evidence observation ID/source location is not owned by its selected child")
            checked += 1
    require(checked > 0, "Vacuous observation-reference qualification")
    return checked


def prepare_inputs(variant, path):
    if variant == "baseline":
        return FIXTURE
    require(path is not None, "Variant requires a task-owned --inputs directory shared by source/frozen runs")
    wanted = input_hashes([FIXTURE])
    # Construct expected bytes before touching a caller-selected output tree.
    files = {p.relative_to(FIXTURE): p.read_bytes() for p in FIXTURE.rglob("*") if p.is_file()}
    target = Path("prod/auth-api/service.yaml") if variant == "grpc" else Path("prod/auth-api/ingress.yaml") if variant == "port-mismatch" else Path("prod/auth-api/conflict.yaml")
    source = "prod-grpc-service.yaml" if variant == "grpc" else "prod-ingress-port-mismatch.yaml" if variant == "port-mismatch" else "prod-conflicting-service.yaml"
    files[target] = (FIXTURE / "variants" / source).read_bytes()
    if not path.exists():
        path.mkdir(parents=True)
        for name, data in files.items():
            destination = path / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    require({p.relative_to(path): p.read_bytes() for p in path.rglob("*") if p.is_file()} == files,
            "Variant input directory differs from the pinned source oracle")
    require(wanted == input_hashes([FIXTURE]), "Original fixture changed during preparation")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    engine = parser.add_mutually_exclusive_group(required=True)
    engine.add_argument("--python", type=Path)
    engine.add_argument("--engine", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variant", choices=("baseline", "grpc", "conflict", "port-mismatch"), default="baseline")
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--single", action="store_true", help="One JSON/parallel scan; does not claim the six-case format matrix")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    selected = (args.engine or args.python).resolve(strict=True)
    oracle = read(FIXTURE / "expected.json")
    fixture = prepare_inputs(args.variant, args.inputs.resolve() if args.inputs else None)
    roots = [fixture / path for path in oracle["roots"]]
    before = input_hashes(roots)
    save(output / "inputs.json", dict(engine=str(selected), engine_sha256=sha(selected), oracle_sha256=sha(FIXTURE / "expected.json"),
        verifier_sha256=sha(Path(__file__)), variant=args.variant, roots=list(map(str, roots)), fixture_hashes=before, modules=MODULES))
    prefix = [str(selected)] if args.engine else [str(selected), "-m", "attackmap"]
    results = []
    try:
        if args.single:
            folder = output / "cli-json-w2"
            folder.mkdir()
            argv = [*prefix, "analyze", *map(str, roots), "--output", str(folder / "reports"), "--format", "json", "--fleet-workers", "2"]
            for module in MODULES:
                argv.extend(["--module", module])
            launch(argv, folder, 240)
        else:
            cli_matrix(prefix, output, roots, 240, 60, MODULES)
        for folder in sorted(path for path in output.iterdir() if path.is_dir() and path.name.startswith("cli-")):
            generation, _, children = collect(folder / "reports", roots)
            summary = read(generation / "fleet-summary.json")
            result = dict(case=folder.name, generation=str(generation), **verify_edges(summary, oracle, args.variant),
                          **verify_child_reports(children, oracle),
                          bound_observation_references=verify_observation_references(summary["fleet_architecture"], children))
            save(folder / "reference-verification.json", result)
            results.append(result)
        require(before == input_hashes(roots), "Analyzed sources changed")
        save(output / "summary.json", dict(passed=True, cases=results, variant=args.variant,
             scope="WP032 static reference service resolution and exact score/evidence bindings; not runtime connectivity, GUI rendering or release"))
        print(json.dumps(dict(passed=True, cases=len(results), output=str(output))))
    except Exception as error:
        save(output / "failure.json", dict(passed=False, error=str(error), completed_cases=results))
        raise


if __name__ == "__main__":
    main()
