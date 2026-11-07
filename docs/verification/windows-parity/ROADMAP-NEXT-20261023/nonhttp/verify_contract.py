"""Reproduce deterministic fixture checks; never invokes scanning or providers."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import xml.etree.ElementTree as ET

from attackmap.fleet_resource_identity import DatastoreDeclaration, project_shared_datastores


ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent


def save(name, value):
    (OUT / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main():
    architecture_tests = runpy.run_path(str(ROOT / "tests/test_fleet_architecture.py"))
    resource_tests = runpy.run_path(str(ROOT / "tests/test_fleet_resource_identity.py"))
    fleet, requested = architecture_tests["fleet16_oracle"]()
    after = architecture_tests["build_fleet_architecture"](fleet, requested)
    before = json.loads((OUT / "fleet16-before.json").read_text(encoding="utf-8"))
    normalized = deepcopy(after)
    added = normalized["coverage"]["protocols"]["shared_datastore"].pop("extraction_contract")
    assert normalized == before, "Existing fleet graph changed beyond additive coverage metadata"
    save("fleet16-after.json", after)

    declaration = resource_tests["declaration"]
    paired = [declaration(), declaration("C:/repos/writer", operation="write", observation="db-write")]
    separated = deepcopy(paired)
    separated[1]["identity"]["port"] = 6432
    conflict = deepcopy(paired[0])
    conflict["identity"]["namespace"] = "ambiguous"
    for name, records in (("paired", paired), ("different-port", separated),
                          ("ambiguous", [*paired, conflict])):
        save(f"fixture-{name}.json", {"declarations": records,
                                     "projection": project_shared_datastores(records),
                                     "scope": "synthetic explicit declarations; no scanner execution"})
    save("shared-datastore-declaration.schema.json", DatastoreDeclaration.model_json_schema())

    paths = ["src/attackmap/fleet_resource_identity.py", "src/attackmap/fleet_architecture.py",
             "tests/test_fleet_resource_identity.py", "tests/test_fleet_architecture.py"]
    rows = [{"path": path, "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}
            for path in paths]
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    save("source-after.json", {"paths": rows, "working_tree_content_sha256": digest})
    suite = ET.parse(OUT / "tests-03.xml").getroot().find("testsuite")
    save("verification.json", {
        "task_id": "WP044-shared-datastore-contract", "status": "prepared_contract_only",
        "focused_tests": {key: suite.attrib[key] for key in ("tests", "failures", "errors", "skipped")},
        "complete_fleet16_graph_equal_after_removing_only_added_coverage_metadata": True,
        "http_proxy_nodes_edges_evidence_unchanged": True, "added_metadata": added,
        "live_provider_calls": 0, "scanner_executions": 0, "native_builds": 0,
        "working_tree_content_sha256": digest,
        "capabilities": {"shared_datastore_production": "unanalysed",
                         "producer_consumer": "unanalysed", "rpc_schema": "unanalysed"},
        "remaining_gates": ["qualified extraction and snapshot binding", "runtime adapter integration",
                            "representative real production fleet", "native mapping and visual/manual checks",
                            "release and clean-host checks", "macOS acceptance"]})
    print(json.dumps({"passed": True, "focused_tests": suite.attrib["tests"],
                      "only_graph_change": "additive prepared extraction-contract metadata",
                      "working_tree_content_sha256": digest}))


if __name__ == "__main__":
    main()
