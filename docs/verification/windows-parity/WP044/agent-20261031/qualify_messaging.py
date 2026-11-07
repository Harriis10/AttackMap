"""Bounded physical source verification; no provider, native or release claim."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "src"))
from attackmap.scan_service import ScanRequest, execute_scan_request


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def declaration(operation="publish", **identity):
    return {"attackmap_messaging": {"schema_version": "1.0", "declarations": [{
        "identity": {"scope": "production-eu", "protocol": "kafka", "transport": "tls",
                     "host": "broker.example.internal", "port": 9093,
                     "namespace": "orders-cluster", "channel": "orders.created", **identity},
        "operation": operation}]}}


def run(paths, out, name, workers):
    errors = []
    def echo(message, **kwargs):
        if kwargs.get("err"):
            errors.append(str(message))
    started = time.monotonic()
    result = execute_scan_request(ScanRequest(repo_paths=paths, output=out / name,
        output_format="json", modules=["config"], max_workers=workers, no_progress=True,
        llm=False, cve=False, install_missing=False, run_id=name, echo=echo))
    assert result.exit_code == 0, {"name": name, "exit_code": result.exit_code, "errors": errors}
    summary = json.loads(result.fleet_summary_path.read_text(encoding="utf-8"))
    manifest = json.loads((result.fleet_summary_path.parent / "artifact-manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["children"]) == len(paths)
    child_manifests = []
    for child in manifest["children"]:
        path = result.fleet_summary_path.parent / child["path"] / "artifact-manifest.json"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == child["manifest_sha256"]
        content = json.loads(path.read_text(encoding="utf-8"))
        assert content["exit_state"]["status"] == "succeeded"
        for section in content["sections"]:
            assert hashlib.sha256((path.parent / section["path"]).read_bytes()).hexdigest() == section["checksum"]
        child_manifests.append({"path": str(path.relative_to(out)), "sha256": digest})
    info = {"exit_code": result.exit_code, "workers": workers,
            "seconds": round(time.monotonic() - started, 3),
            "summary": str(result.fleet_summary_path.relative_to(out)),
            "child_manifests": child_manifests, "provider_calls": 0}
    write(out / (name + "-info.json"), info)
    return summary["fleet_architecture"], info


def main(out):
    corpus = out / "physical-corpus"
    paths = [corpus / "team-a" / "service", corpus / "team-b" / "service"]
    paths += [corpus / f"repo-{i:02}" for i in range(2, 16)]
    for i, path in enumerate(paths):
        data = declaration()
        if i == 1:
            data = declaration("consume")
        elif 2 <= i <= 7:
            field, value = [("scope", "staging"), ("transport", "plaintext"),
                ("host", "other.example.internal"), ("port", 9092),
                ("namespace", "archive-cluster"), ("channel", "orders.updated")][i - 2]
            data = declaration("consume", **{field: value})
        elif i == 8:
            data = {"kafka": {"bootstrap.servers": "broker.example.internal:9093", "topic": "orders.created"}}
        elif i == 9:
            data = declaration("consume", host="broker")
        elif i >= 10:
            data = {"library": "no owner declarations"}
        write(path / "config.json", data)
        if i == 10:
            write(path / "tests" / "config.json", declaration("consume"))
        if i == 11:
            write(path / "examples" / "config.json", declaration("consume"))
        if i == 13:
            (path / "config.json").write_text('{"attackmap_messaging": [', encoding="utf-8")
        if i == 14:
            write(path / "config.json", declaration("consume", protocol="amqp"))
    serial, serial_info = run(paths, out, "serial", 1)
    parallel, parallel_info = run(paths, out, "parallel", 2)
    stable = ("nodes", "edges", "evidence", "shared_datastore_unresolved",
              "producer_consumer_unresolved", "coverage", "limitations")
    assert all(serial[key] == parallel[key] for key in stable)
    write(out / "serial-architecture.json", serial)
    write(out / "parallel-architecture.json", parallel)
    relationships = [row for row in serial["edges"] if row["kind"] == "producer_consumer"]
    edge, = relationships
    assert edge["directed"] is True and edge["resolution"] == "declared"
    assert len(edge["evidence_refs"]) == 2
    evidence = {item["id"]: item for item in serial["evidence"]}
    roots = {item["id"]: item["root"] for item in serial["repositories"]}
    assert roots[edge["source"]].endswith("/team-a/service")
    assert roots[edge["target"]].endswith("/team-b/service")
    assert {evidence[ref]["line"] for ref in edge["evidence_refs"]} == {4}
    assert {evidence[ref]["source_analyzer"] for ref in edge["evidence_refs"]} == {"config"}
    assert {evidence[ref]["repo_id"] for ref in edge["evidence_refs"]} == {edge["source"], edge["target"]}
    for endpoint in edge["endpoints"]:
        assert len(endpoint["evidence_refs"]) == 1
        assert set(endpoint["evidence_refs"]) <= set(edge["evidence_refs"])
        assert all(evidence[ref]["repo_id"] == endpoint["repository_id"] for ref in endpoint["evidence_refs"])
    assert len(serial["repositories"]) == 16
    coverage = serial["coverage"]["protocols"]["producer_consumer"]
    assert coverage["declaration_count"] == 8 and coverage["association_count"] == 1
    assert coverage["unmatched_count"] == 6 and coverage["ambiguous_count"] == 0
    juice, juice_info = run([Path("C:/tmp/juice-shop"), paths[-1]], out, "juice-shop-negative", 1)
    assert not [row for row in juice["edges"] if row["kind"] == "producer_consumer"]
    assert juice["coverage"]["protocols"]["producer_consumer"]["status"] == "unanalysed"
    result = {"result": "PASS", "corpus_kind": "synthetic physical 16-repository corpus",
        "serial_parallel_fact_parity": True, "provider_calls": 0, "network_install_enabled": False,
        "qualified_declarations": coverage["declaration_count"], "producer_consumer_edges": 1,
        "resolution": "declared", "directed": True, "both_endpoint_source_evidence": True,
        "nodes": len(serial["nodes"]), "edges": len(serial["edges"]), "evidence": len(serial["evidence"]),
        "edge_kinds": dict(Counter(item["kind"] for item in serial["edges"])),
        "resource_count": coverage["resource_count"], "unmatched_count": coverage["unmatched_count"],
        "repository_statuses": serial["coverage"]["repository_statuses"],
        "serial": serial_info, "parallel": parallel_info, "juice_shop_negative": juice_info,
        "native_frozen_release_acceptance": False, "representative_production_fleet_acceptance": False}
    write(out / "qualification.json", result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    main(args.output.resolve())
