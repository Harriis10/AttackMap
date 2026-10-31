"""Finite fleet input quotas; these are not working-set memory qualification."""
import json
import os
from dataclasses import fields
from pathlib import Path
import subprocess
import sys

import pytest

from attackmap import scan_service as service
from attackmap.analyzers import BuiltinPythonWebAnalyzer
from attackmap.contracts import DeploymentAliases
from attackmap.fleet import FleetRepoResult, FleetScan
from attackmap.fleet_admission import FleetMemoryEstimate, FleetMemoryPolicy
from attackmap.models import ScanResult


def request(tmp_path, budget, count=2, **kwargs):
    return service.ScanRequest(
        [tmp_path / chr(ord("a") + i) for i in range(count)], tmp_path / "out",
        fleet_input_byte_budget=budget, echo=lambda *a, **k: None, **kwargs)


def captured_result(repo_id, repo, budget):
    return {"scan": {"root": str(repo), "files_scanned": 1, "scan_snapshot": {
        "snapshot_id": "synthetic", "files": {"a.py": "synthetic"},
        "total_size": min(4, budget), "index_config": {"index_byte_budget": budget}}}}


def fake_child(calls):
    def run(argv, **kwargs):
        calls.append(kwargs)
        budget = int(kwargs["env"]["ATTACKMAP_INDEX_BYTE_BUDGET"])
        repo = argv[argv.index("analyze") + 1]
        Path(argv[argv.index("--fleet-result") + 1]).write_text(
            json.dumps(captured_result(Path(repo).name, repo, budget)))
        result = subprocess.CompletedProcess(argv, 0, "", "")
        result.cleanup_verified = True
        return result
    return run


def test_fixed_quotas_and_child_environment_do_not_mutate_parent(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKMAP_INDEX_BYTE_BUDGET", "777")
    monkeypatch.setenv("ATTACKMAP_INPUT_SENTINEL", "preserved")
    calls = []
    monkeypatch.setattr(service, "_run_supervised_worker", fake_child(calls))
    req = request(tmp_path, 11, max_workers=2)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(req, [], fleet, req.output)
    assert [row.repo_id for row in fleet.results] == ["a", "b"]
    inputs = admission["input_bytes"]
    assert inputs["repository_quotas"] == {"a": 6, "b": 5}
    assert inputs["allocated_bytes"] == 11 == inputs["total_bytes"]
    assert inputs["verified_captured_bytes"] == 8
    assert inputs["capture_status"] == "within_quotas"
    assert sorted(int(call["env"]["ATTACKMAP_INDEX_BYTE_BUDGET"]) for call in calls) == [5, 6]
    assert all(call["env"]["ATTACKMAP_INPUT_SENTINEL"] == "preserved" for call in calls)
    assert os.environ["ATTACKMAP_INDEX_BYTE_BUDGET"] == "777"


def test_zero_quota_is_typed_failure_and_successful_sibling_survives(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(service, "_run_supervised_worker", fake_child(calls))
    req = request(tmp_path, 1, max_workers=2)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(req, [], fleet, req.output)
    assert [row.repo_id for row in fleet.results] == ["a"]
    assert [(row["repo_id"], row["error_type"]) for row in fleet.failed] == [("b", "fleet_input_capacity")]
    assert len(calls) == 1
    assert admission["input_bytes"]["repository_quotas"] == {"a": 1, "b": 0}
    assert admission["input_bytes"]["capture_status"] == "partial"


def test_aggregate_policy_never_relaxes_stricter_inherited_file_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKMAP_INDEX_BYTE_BUDGET", "3")
    calls = []
    monkeypatch.setattr(service, "_run_supervised_worker", fake_child(calls))
    req = request(tmp_path, 11, max_workers=2)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(req, [], fleet, req.output)
    assert not fleet.failed
    assert admission["input_bytes"]["repository_quotas"] == {"a": 6, "b": 5}
    assert [row.scan.scan_snapshot.index_config["index_byte_budget"] for row in fleet.results] == [3, 3]
    assert admission["input_bytes"]["verified_captured_bytes"] == 6
    assert os.environ["ATTACKMAP_INDEX_BYTE_BUDGET"] == "3"


def test_single_repo_public_request_cannot_silently_ignore_fleet_budget(tmp_path, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("single-repo scan silently ignored fleet policy")
    monkeypatch.setattr(service, "_run_single_repo", unexpected)
    with pytest.raises(service.ScanRequestError, match="at least two"):
        service.execute_scan_request(request(tmp_path, 10, count=1))


def test_input_quotas_compose_with_retained_memory_admission(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(service, "_run_supervised_worker", fake_child(calls))
    memory = FleetMemoryPolicy(100, 10, 10, 10, {
        key: FleetMemoryEstimate(40, 20, 10000, "synthetic-policy-not-a-product-default")
        for key in ("a", "b")})
    req = request(tmp_path, 11, max_workers=2, fleet_memory_policy=memory)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(req, [], fleet, req.output)
    assert [row.repo_id for row in fleet.results] == ["a"]
    assert fleet.failed[0]["error_type"] == "fleet_memory_capacity"
    assert len(calls) == 1
    assert admission["reserved_bytes"] == 50
    assert admission["retained_result_bytes"] == 20
    assert admission["input_bytes"]["repository_quotas"] == {"a": 6, "b": 5}
    assert admission["input_bytes"]["allocated_bytes"] == 11
    assert admission["input_bytes"]["verified_captured_bytes"] == 4


def test_pre_cancel_never_dispatches_or_redistributes_input_quotas(tmp_path, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("cancelled quota dispatched")
    monkeypatch.setattr(service, "_run_fleet_repo_worker", unexpected)
    req = request(tmp_path, 11, max_workers=2, cancel_check=lambda: True)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(req, [], fleet, req.output)
    assert [row["error_type"] for row in fleet.failed] == ["fleet_admission_cancelled"] * 2
    assert admission["input_bytes"]["repository_quotas"] == {"a": 6, "b": 5}
    assert admission["input_bytes"]["verified_captured_bytes"] == 0
    assert admission["input_bytes"]["capture_status"] == "partial"


@pytest.mark.parametrize("total,count", [(1, 3), (10, 3), (100, 7), (2**64, 5)])
def test_quota_accounting_is_exact_for_remainders_and_small_budgets(total, count):
    names = [f"repo-{i}" for i in range(count)]
    quotas = service._fleet_input_quotas(total, names)
    assert list(quotas) == names
    assert sum(quotas.values()) == total
    assert min(quotas.values()) >= 0
    assert max(quotas.values()) - min(quotas.values()) <= 1
    assert quotas == service._fleet_input_quotas(total, names)


@pytest.mark.parametrize("budget", [0, -1, True, 1.5, "10"])
def test_invalid_opt_in_budget_fails_before_dispatch(tmp_path, monkeypatch, budget):
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid quota dispatched")
    monkeypatch.setattr(service, "_run_fleet_repo_worker", unexpected)
    req = request(tmp_path, budget, max_workers=2)
    with pytest.raises(service.ScanRequestError, match="positive integer"):
        service._run_fleet_parallel(req, [], FleetScan(), req.output)


def test_no_opt_in_preserves_existing_worker_signature_and_manifest(tmp_path, monkeypatch):
    def worker(req, repo_id, repo, output, names):
        return FleetRepoResult(repo_id=repo_id, root=str(repo), report_dir=str(output),
                               scan=ScanResult(root=str(repo)), findings=[])
    monkeypatch.setattr(service, "_run_fleet_repo_worker", worker)
    req = service.ScanRequest([tmp_path / "a", tmp_path / "b"], tmp_path / "out",
                              max_workers=2, echo=lambda *a, **k: None)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(req, [], fleet, req.output)
    assert [row.repo_id for row in fleet.results] == ["a", "b"]
    assert "input_bytes" not in admission


def test_legacy_positional_request_keeps_final_deployment_aliases(tmp_path, monkeypatch):
    aliases = DeploymentAliases(hosts={"api.example.test": "b"})
    original = service.ScanRequest(
        [tmp_path / "a", tmp_path / "b"], tmp_path / "out",
        deployment_aliases=aliases, atomic_output=False, echo=lambda *a, **k: None)
    # Before the input-budget option, deployment_aliases was the final argument.
    legacy_values = [getattr(original, item.name) for item in fields(original)
                     if item.name != "fleet_input_byte_budget"]
    assert legacy_values[-1] is aliases
    legacy_request = service.ScanRequest(*legacy_values)
    dispatched = []

    def fleet(req, analyzers):
        dispatched.append(req)
        return service.RunSummary(exit_code=0)

    monkeypatch.setattr(service, "_run_fleet", fleet)
    assert service.execute_scan_request(legacy_request).exit_code == 0
    assert dispatched == [legacy_request]
    assert legacy_request.deployment_aliases is aliases
    assert legacy_request.fleet_input_byte_budget is None


@pytest.mark.parametrize("mode", ["missing", "missing_size", "coerced_size", "over_budget", "wrong_budget"])
def test_unbound_or_excess_worker_capture_is_typed_failure(tmp_path, monkeypatch, mode):
    def child(argv, **kwargs):
        budget = int(kwargs["env"]["ATTACKMAP_INDEX_BYTE_BUDGET"])
        data = captured_result("a", tmp_path / "a", budget)
        if mode == "missing":
            data["scan"].pop("scan_snapshot")
        elif mode == "missing_size":
            data["scan"]["scan_snapshot"].pop("total_size")
        elif mode == "coerced_size":
            data["scan"]["scan_snapshot"]["total_size"] = "4"
        elif mode == "over_budget":
            data["scan"]["scan_snapshot"]["total_size"] = budget + 1
        else:
            data["scan"]["scan_snapshot"]["index_config"]["index_byte_budget"] = budget + 1
        Path(argv[argv.index("--fleet-result") + 1]).write_text(json.dumps(data))
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(service, "_run_supervised_worker", child)
    req = request(tmp_path, 10, count=1)
    fleet = FleetScan()
    service._run_fleet_parallel(req, [], fleet, req.output)
    assert not fleet.results
    assert fleet.failed[0]["error_type"] == "fleet_input_budget_unverified"


def test_actual_subprocess_capture_preserves_skip_events_and_partial_scope(tmp_path, monkeypatch):
    # Real child processes run the production capture gates and JSON interchange.
    # No providers, scanner scale benchmark, native packaging or OS memory claim.
    script = (
        "import json,pathlib,sys; from attackmap.index import RepoIndex; "
        "index=RepoIndex.build(sys.argv[1]); "
        "data={'scan':{'root':sys.argv[1],'files_scanned':len(index.files),"
        "'limitations':list(index.limitations),'resource_limit_scopes':list(index.resource_limit_scopes),"
        "'resource_limit_reporting':index.resource_limit_reporting,"
        "'resource_limit_events':[x.model_dump(mode='json') for x in index.resource_limit_events],"
        "'scan_snapshot':index.snapshot.identity().model_dump(mode='json')}}; "
        "pathlib.Path(sys.argv[-1]).write_text(json.dumps(data))")
    monkeypatch.setattr(service, "_run_fleet_repo_argv", lambda req, repo, *args:
                        [sys.executable, "-c", script, str(repo)])
    req = request(tmp_path, 11, max_workers=2)
    for repo in req.repo_paths:
        repo.mkdir()
        (repo / "a.py").write_bytes(b"x=1\n")
        (repo / "b.py").write_bytes(b"y=2\n")
    fleet = FleetScan()
    admission = service._run_fleet_parallel(req, [], fleet, req.output)
    assert not fleet.failed
    assert [row.scan.files_scanned for row in fleet.results] == [1, 1]
    assert sum(row.scan.scan_snapshot.total_size for row in fleet.results) == 8 <= 11
    for result, quota in zip(fleet.results, (6, 5)):
        assert result.scan.scan_snapshot.index_config["index_byte_budget"] == quota
        events = [event for event in result.scan.resource_limit_events if event.category == "index_bytes"]
        assert len(events) == 1 and events[0].limit == quota
        assert events[0].action == "skipped_file"
        assert events[0].observed_bytes > quota
        assert result.scan.limitations
    assert admission["input_bytes"]["verified_captured_bytes"] == 8
    assert admission["input_bytes"]["capture_status"] == "partial"


@pytest.mark.parametrize("total", [32, 1])
def test_actual_scanner_serial_opt_in_publishes_partial_diagnostics(tmp_path, monkeypatch, total):
    monkeypatch.delenv("ATTACKMAP_INDEX_BYTE_BUDGET", raising=False)
    completed = []
    req = request(tmp_path, total, max_workers=1, no_progress=True, no_suppress=True,
                  analyzers=[BuiltinPythonWebAnalyzer()],
                  fleet_finished=lambda output, fleet: completed.append(fleet), atomic_output=False)
    for repo in req.repo_paths:
        repo.mkdir()
        (repo / "a.py").write_bytes(b"print('one')\n")
        (repo / "b.py").write_bytes(b"print('two')\n")
    summary = service.execute_scan_request(req)
    manifest = json.loads((req.output / "run-manifest.json").read_text(encoding="utf-8"))
    inputs = manifest["fleet_resource_admission"]["input_bytes"]
    assert sum(inputs["repository_quotas"].values()) == total
    assert inputs["verified_captured_bytes"] <= total
    assert inputs["capture_status"] == "partial"
    assert manifest["diagnostic_context"]["fleet"]["children"][0]["coverage"]["limitation_count"] > 0
    assert any(event["category"] == "index_bytes" for event in
               manifest["diagnostic_context"]["fleet"]["children"][0]["resource_events"]["items"])
    fleet_summary = json.loads((req.output / "fleet-summary.json").read_text(encoding="utf-8"))
    assert fleet_summary["fleet_architecture"]["coverage"]["complete"] is False
    if total == 32:
        assert summary.exit_code == 0
        assert [row.scan.files_scanned for row in completed[0].results] == [1, 1]
        assert inputs["verified_captured_bytes"] == 26
        assert not completed[0].failed
    else:
        assert summary.exit_code != 0
        assert [row.repo_id for row in completed[0].results] == ["a"]
        assert completed[0].failed[0]["error_type"] == "fleet_input_capacity"
