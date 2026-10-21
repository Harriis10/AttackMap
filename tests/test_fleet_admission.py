"""Logical reservation contracts plus actual small supervised child processes."""
import json
from pathlib import Path
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from attackmap import scan_service as service
from attackmap.fleet import FleetScan
from attackmap.fleet_admission import (FleetAdmissionError, FleetMemoryEstimate, FleetMemoryPolicy,
    FleetMemoryLedger, current_reservation, unverified_fleet_cleanup)


def estimate(live=40, retained=20):
    return FleetMemoryEstimate(live, retained, 10000, "synthetic-unit-policy-not-a-measured-product-default")


def policy(names=("a", "b"), total=150, live=40, retained=20):
    return FleetMemoryPolicy(total, 10, 10, 10, {name: estimate(live, retained) for name in names})


def test_concurrent_reservations_never_exceed_budget():
    ledger = FleetMemoryLedger(policy(total=100))
    barrier = Barrier(2)
    def reserve(name):
        barrier.wait()
        return ledger.reserve(name)
    with ThreadPoolExecutor(2) as pool:
        reservations = list(pool.map(reserve, ("a", "b")))
    assert sum(row is not None for row in reservations) == 1
    assert ledger.snapshot()["reserved_bytes"] == 90
    for row in reservations:
        if row:
            ledger.settle(row, cleanup_verified=True, keep_result=False)


def test_success_transfers_retention_atomically_and_cannot_double_refund():
    ledger = FleetMemoryLedger(policy(total=100))
    first = ledger.reserve("a")
    ledger.settle(first, cleanup_verified=True, keep_result=True)
    ledger.settle(first, cleanup_verified=True, keep_result=False)
    assert ledger.snapshot()["reserved_bytes"] == 50
    assert ledger.snapshot()["retained_result_bytes"] == 20
    with pytest.raises(FleetAdmissionError, match="retained") as error:
        ledger.reserve("b")
    assert error.value.kind == "fleet_memory_capacity"


def test_unknown_memory_is_failure_without_charge_or_dispatch():
    ledger = FleetMemoryLedger(policy(names=("a",)))
    with pytest.raises(FleetAdmissionError) as error:
        ledger.reserve("unknown")
    assert error.value.kind == "fleet_memory_unknown"
    assert ledger.snapshot()["reserved_bytes"] == 30


def test_unknown_cleanup_retains_charge_and_quarantines_until_verified():
    ledger = FleetMemoryLedger(policy())
    reservation = ledger.reserve("a")
    reservation.process_cleanup_verified = False
    try:
        ledger.settle(reservation, cleanup_verified=False, keep_result=False)
        assert ledger.snapshot()["reserved_bytes"] == 90
        assert unverified_fleet_cleanup()
        with pytest.raises(FleetAdmissionError) as error:
            ledger.reserve("b")
        assert error.value.kind == "fleet_cleanup_unknown"
        with pytest.raises(service.ScanRequestError, match="cleanup remains unverified"):
            service._run_fleet_generation(service.ScanRequest([], Path("unused")), [])
    finally:
        ledger.verified_cleanup(reservation)
    assert ledger.snapshot()["reserved_bytes"] == 30
    assert not unverified_fleet_cleanup()


def test_verified_cleanup_wins_race_with_stale_unknown_notice():
    ledger = FleetMemoryLedger(policy())
    reservation = ledger.reserve("a")
    reservation.process_cleanup_verified = False
    ledger.verified_cleanup(reservation)
    ledger.settle(reservation, cleanup_verified=False, keep_result=False)
    assert not unverified_fleet_cleanup()
    assert ledger.snapshot()["reserved_bytes"] == 30


def test_cancel_does_not_refund_running_child():
    ledger = FleetMemoryLedger(policy())
    reservation = ledger.reserve("a")
    reservation.process_cleanup_verified = False
    ledger.cancel()
    with pytest.raises(FleetAdmissionError) as error:
        ledger.reserve("b")
    assert error.value.kind == "fleet_admission_cancelled"
    assert ledger.snapshot()["reserved_bytes"] == 90
    ledger.verified_cleanup(reservation)
    ledger.settle(reservation, cleanup_verified=True, keep_result=False)
    assert ledger.snapshot()["reserved_bytes"] == 30


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_policy_is_not_silently_unlimited(value):
    with pytest.raises(ValueError):
        FleetMemoryEstimate(value, 20, 100, "fixture")


@pytest.mark.parametrize("with_progress", [False, True])
def test_timeout_forwarding_does_not_depend_on_progress_callback(tmp_path, monkeypatch, with_progress):
    calls = []
    def child(argv, **kwargs):
        calls.append(kwargs)
        Path(argv[argv.index("--fleet-result") + 1]).write_text(json.dumps({"root": str(tmp_path)}))
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(service, "_run_supervised_worker", child)
    request = service.ScanRequest([tmp_path], tmp_path / "out", fleet_timeout_seconds=17,
                                 fleet_event=(lambda event: None) if with_progress else None)
    service._run_fleet_repo_worker(request, "a", tmp_path, request.output, [])
    assert calls[0]["timeout"] == 17


def test_payload_limit_rejects_before_model_parse(tmp_path):
    path = tmp_path / "result.json"
    path.write_bytes(b"x" * 33)
    with pytest.raises(FleetAdmissionError) as error:
        service._load_repo_scan(path, max_bytes=32)
    assert error.value.kind == "fleet_result_bytes"


def test_actual_small_supervised_children_keep_results_and_reservations(tmp_path, monkeypatch):
    # Actual OS process/job cleanup, JSON interchange and Pydantic admission.
    # This is not a scanner memory benchmark or an OS memory-cap test.
    script = "import json,pathlib,sys; pathlib.Path(sys.argv[-1]).write_text(json.dumps({'root':sys.argv[1], 'files_scanned':1}))"
    monkeypatch.setattr(service, "_run_fleet_repo_argv", lambda request, repo, *args:
                        [sys.executable, "-c", script, str(repo)])
    repos = [tmp_path / "a", tmp_path / "b"]
    request = service.ScanRequest(repos, tmp_path / "out", max_workers=2, fleet_timeout_seconds=10,
                                 fleet_memory_policy=policy(), echo=lambda *a, **k: None)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(request, [], fleet, request.output)
    assert [row.repo_id for row in fleet.results] == ["a", "b"]
    assert not fleet.failed
    assert admission["retained_result_bytes"] == 40
    assert admission["active_children"] == []
    assert admission["reserved_bytes"] == 70
    assert admission["peak_reserved_bytes"] <= 150
    assert not admission["os_enforced"]


def test_unknown_estimate_preserves_actual_sibling_and_typed_failure(tmp_path, monkeypatch):
    script = "import json,pathlib,sys; pathlib.Path(sys.argv[-1]).write_text(json.dumps({'root':sys.argv[1]}))"
    monkeypatch.setattr(service, "_run_fleet_repo_argv", lambda request, repo, *args:
                        [sys.executable, "-c", script, str(repo)])
    request = service.ScanRequest([tmp_path / "a", tmp_path / "b"], tmp_path / "out", max_workers=2,
                                 fleet_memory_policy=policy(names=("a",)), echo=lambda *a, **k: None)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(request, [], fleet, request.output)
    assert [row.repo_id for row in fleet.results] == ["a"]
    assert fleet.failed[0]["repo_id"] == "b"
    assert fleet.failed[0]["error_type"] == "fleet_memory_unknown"
    assert admission["retained_result_bytes"] == 20


def test_pre_cancel_with_policy_admits_no_worker(tmp_path, monkeypatch):
    def unexpected(*args):
        raise AssertionError("cancelled child dispatched")
    monkeypatch.setattr(service, "_run_fleet_repo_worker", unexpected)
    request = service.ScanRequest([tmp_path / "a", tmp_path / "b"], tmp_path / "out", max_workers=2,
        fleet_memory_policy=policy(), cancel_check=lambda: True, echo=lambda *a, **k: None)
    fleet = FleetScan()
    admission = service._run_fleet_parallel(request, [], fleet, request.output)
    assert not fleet.results
    assert [row["error_type"] for row in fleet.failed] == ["fleet_admission_cancelled"] * 2
    assert admission["reserved_bytes"] == 30


def test_actual_cancelled_child_keeps_reservation_until_verified_exit(tmp_path):
    from attackmap.fleet_admission import reservation_scope
    ledger = FleetMemoryLedger(policy())
    reservation = ledger.reserve("a")
    reservation.process_cleanup_verified = False
    marker = tmp_path / "started"
    command = [sys.executable, "-c", "import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text('started');time.sleep(5)", str(marker)]
    with reservation_scope(reservation):
        result = service._run_supervised_worker(command, cancel_check=marker.exists, timeout=10)
    assert marker.exists()
    assert result.returncode == 130 and result.cleanup_verified
    # Callback proves cleanup; reservation remains owned until explicit settlement.
    assert ledger.snapshot()["reserved_bytes"] == 90
    ledger.settle(reservation, cleanup_verified=result.cleanup_verified, keep_result=False)
    assert ledger.snapshot()["reserved_bytes"] == 30


def test_actual_hard_timeout_is_not_a_stage_budget():
    result = service._run_supervised_worker([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert result.returncode != 0
    assert result.cleanup_verified


def test_unknown_supervisor_cleanup_blocks_then_late_verified_callback_releases(monkeypatch):
    import attackmap.execution as execution
    from attackmap.fleet_admission import reservation_scope
    callbacks = []
    class UnknownSupervisor:
        running = True
        cancelled = False
        stderr_tail = "Worker exited but process-tree termination could not be verified."
        def start(self, argv, *, on_done, timeout):
            callbacks.append(on_done)
            return True
        def wait(self, timeout):
            return False
    monkeypatch.setattr(execution, "ProcessSupervisor", UnknownSupervisor)
    ledger = FleetMemoryLedger(policy())
    reservation = ledger.reserve("a")
    reservation.process_cleanup_verified = False
    try:
        with reservation_scope(reservation):
            result = service._run_supervised_worker(["synthetic-uncertain-worker"])
        assert not result.cleanup_verified and unverified_fleet_cleanup()
        assert ledger.snapshot()["reserved_bytes"] == 90
    finally:
        callbacks[0](1, "later verified cleanup")
    assert not unverified_fleet_cleanup()
    assert ledger.snapshot()["reserved_bytes"] == 30


def test_submit_failure_refunds_only_never_launched_reservation(tmp_path, monkeypatch):
    observed = []
    original = service.FleetMemoryLedger
    def ledger_factory(policy):
        ledger = original(policy)
        observed.append(ledger)
        return ledger
    class RejectedExecutor:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def submit(self, *args): raise RuntimeError("executor rejected")
    monkeypatch.setattr(service, "FleetMemoryLedger", ledger_factory)
    monkeypatch.setattr(service, "ThreadPoolExecutor", RejectedExecutor)
    request = service.ScanRequest([tmp_path / "a"], tmp_path / "out", max_workers=2,
                                 fleet_memory_policy=policy(), echo=lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="executor rejected"):
        service._run_fleet_parallel(request, [], FleetScan(), request.output)
    assert observed[0].snapshot()["reserved_bytes"] == 30
