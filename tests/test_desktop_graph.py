"""Selected-report replay, evidence preservation and stale-file rejection."""
import hashlib
import json
from pathlib import Path

import pytest

from attackmap.desktop_actions import ActionRequest, execute_action, run_action_file
from attackmap.desktop_graph import project_report_graph


def _report(tmp_path, scan=None):
    scan = scan or {"root": str(tmp_path / "source"), "service_hints": [
        {"hint": "service_name:api", "file": "services/api/main.ts", "line": 3},
        {"hint": "service_name:worker", "file": "services/worker/main.ts", "line": 4}],
        "edge_hints": [{"hint": "edge:api->worker", "file": "services/api/main.ts", "line": 9}]}
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"scan": scan, "findings": [], "legacy_additive_field": True}), encoding="utf-8")
    return path, {"report_path": str(path), "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "run_id": "selected-run", "repository_root": scan["root"]}


def test_action_preserves_local_topology_and_closed_evidence_without_mutation(tmp_path):
    path, payload = _report(tmp_path)
    before = path.read_bytes()
    result = execute_action(ActionRequest(request_id="graph-1", operation="report_graph",
                            output_path=str(tmp_path / "results"), payload=payload))
    graph = result["graph"]
    assert graph["schema_version"] == "1.0" and graph["kind"] == "fleet_architecture"
    assert len(graph["repositories"]) == 1
    assert {node["label"] for node in graph["nodes"] if node["kind"] == "service"} == {"api", "worker"}
    relations = [edge for edge in graph["edges"] if edge["kind"] == "analyzer-declared"]
    assert len(relations) == 1 and relations[0]["scope"] == "repository"
    evidence = {item["id"]: item for item in graph["evidence"]}
    assert all(ref in evidence for item in graph["nodes"] + graph["edges"] for ref in item["evidence_refs"])
    assert any(item["file"] == "services/api/main.ts" for item in evidence.values())
    assert result["report_sha256"] == payload["report_sha256"] and result["run_id"] == "selected-run"
    assert result["snapshot_id"] is None  # legacy report, no fabricated snapshot
    assert path.read_bytes() == before
    assert not (tmp_path / "source").exists()  # no source discovery or scan


def test_minimal_legacy_report_does_not_invent_relationships(tmp_path):
    _, payload = _report(tmp_path, {"root": str(tmp_path / "source")})
    graph = project_report_graph(payload)["graph"]
    assert len(graph["nodes"]) == 1 and graph["edges"] == [] and graph["evidence"] == []
    coverage = graph["coverage"]["protocols"]["shared_datastore"]
    assert coverage["status"] == "supported"
    assert coverage["declaration_count"] == coverage["association_count"] == 0


@pytest.mark.parametrize("change", ["hash", "root", "extra", "relative", "unc", "ads"])
def test_rejects_unbound_or_nonlocal_requests(tmp_path, change):
    _, payload = _report(tmp_path)
    if change == "hash": payload["report_sha256"] = "0" * 64
    if change == "root": payload["repository_root"] = str(tmp_path / "other")
    if change == "extra": payload["unknown"] = True
    if change == "relative": payload["report_path"] = "report.json"
    if change == "unc": payload["report_path"] = "//server/share/report.json"
    if change == "ads": payload["report_path"] += ":alternate"
    with pytest.raises((ValueError, OSError)):
        project_report_graph(payload)


def test_bounded_read_and_nonregular_rejected(tmp_path, monkeypatch):
    path, payload = _report(tmp_path)
    monkeypatch.setattr("attackmap.desktop_graph.MAX_REPORT_BYTES", 5)
    with pytest.raises(ValueError): project_report_graph(payload)
    payload["report_path"] = str(tmp_path)
    with pytest.raises(ValueError): project_report_graph(payload)


def test_redirection_is_rejected_even_when_hash_matches(tmp_path):
    path, payload = _report(tmp_path)
    linked = tmp_path / "link.json"
    try:
        linked.symlink_to(path)
    except OSError:
        pytest.skip("Host does not allow test symlinks")
    payload["report_path"] = str(linked)
    with pytest.raises(OSError): project_report_graph(payload)


def test_mutation_during_projection_cannot_publish(tmp_path, monkeypatch):
    import attackmap.desktop_graph as adapter
    path, payload = _report(tmp_path)
    original = adapter.build_fleet_architecture
    def change(*args, **kwargs):
        graph = original(*args, **kwargs)
        path.write_text("{}", encoding="utf-8")
        return graph
    monkeypatch.setattr(adapter, "build_fleet_architecture", change)
    with pytest.raises(ValueError): project_report_graph(payload)


@pytest.mark.parametrize("raw", [b'[]', b'{"scan":{}}', b'{"scan":{"root":null}}',
                                 b'{"scan":{},"scan":{}}', b'{"scan":{"root":NaN}}'])
def test_malformed_scan_json_fails_sanitized_transport(tmp_path, capsys, raw):
    path, payload = _report(tmp_path)
    path.write_bytes(raw)
    payload["report_sha256"] = hashlib.sha256(raw).hexdigest()
    request = ActionRequest(request_id="bad-graph", operation="report_graph",
                            output_path=str(tmp_path / "results"), payload=payload)
    request_path = tmp_path / "request.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    assert run_action_file(request_path, engine=True) == 1
    output = capsys.readouterr()
    assert str(path) not in output.out + output.err
    assert not (tmp_path / "results/bad-graph.result.json").exists()
