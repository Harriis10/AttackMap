"""Pre-resume Windows policy ordering and controlled actual OS allocation tests."""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock
from concurrent.futures import ThreadPoolExecutor

import pytest
import attackmap.execution as execution
from attackmap.execution import ProcessSupervisor
from attackmap.execution import windows
from attackmap import analyzer_host as host


def no_threads(monkeypatch):
    original = execution.threading
    monkeypatch.setattr(execution, "threading", SimpleNamespace(
        Lock=original.Lock, Event=original.Event,
        Thread=lambda **kwargs: SimpleNamespace(start=lambda: None)))


def test_configure_before_popen_assign_and_resume(monkeypatch):
    calls = []
    monkeypatch.setattr(execution, "os", SimpleNamespace(name="nt"))
    no_threads(monkeypatch)
    class Job:
        def __init__(self, memory_bytes):
            assert memory_bytes == 123456
            calls.append("configure")
        def attach_and_resume(self, proc):
            calls.extend(("assign", "resume"))
    def popen(**kwargs):
        assert calls == ["configure"]
        assert kwargs["creationflags"] & 4  # CREATE_SUSPENDED
        calls.append("popen_suspended")
        return object()
    monkeypatch.setattr(execution, "WindowsProcessJob", Job)
    monkeypatch.setattr(execution.subprocess, "Popen", popen)
    supervisor = ProcessSupervisor()
    assert supervisor.start(["fixture"], job_memory_bytes=123456)
    assert calls == ["configure", "popen_suspended", "assign", "resume"]
    assert supervisor.memory_policy == {"requested_bytes": 123456, "enforced_bytes": 123456, "status": "enforced"}


def test_cap_setup_failure_never_creates_or_resumes_child(monkeypatch):
    monkeypatch.setattr(execution, "os", SimpleNamespace(name="nt"))
    def denied(**kwargs): raise OSError("injected cap denial")
    def forbidden(**kwargs): raise AssertionError("uncapped process created")
    monkeypatch.setattr(execution, "WindowsProcessJob", denied)
    monkeypatch.setattr(execution.subprocess, "Popen", forbidden)
    supervisor = ProcessSupervisor()
    done = []
    assert not supervisor.start(["fixture"], job_memory_bytes=1024, on_done=lambda *args: done.append(args))
    assert not supervisor.running and supervisor.wait(0)
    assert len(done) == 1 and "cap denial" in done[0][1]
    assert supervisor.memory_policy["status"] == "setup_failed"
    assert supervisor.memory_policy["enforced_bytes"] == 0


def test_nonwindows_explicit_request_stays_functional_but_unenforced(monkeypatch):
    monkeypatch.setattr(execution, "os", SimpleNamespace(name="posix"))
    no_threads(monkeypatch)
    def popen(**kwargs):
        assert kwargs["start_new_session"]
        return object()
    monkeypatch.setattr(execution.subprocess, "Popen", popen)
    supervisor = ProcessSupervisor()
    assert supervisor.start(["fixture"], job_memory_bytes=1024)
    assert supervisor.memory_policy == {"requested_bytes": 1024, "enforced_bytes": 0, "status": "unsupported_on_platform"}


@pytest.mark.skipif(os.name != "nt", reason="Windows ctypes job API structure")
def test_job_struct_contains_both_flags_before_create_child_and_closes_on_denial(monkeypatch):
    kernel = SimpleNamespace(**{name: Mock(return_value=1) for name in (
        "CreateJobObjectW", "AssignProcessToJobObject", "SetInformationJobObject", "QueryInformationJobObject",
        "TerminateJobObject", "CloseHandle")})
    kernel.CreateJobObjectW.return_value = 123
    seen = []
    def configure(handle, kind, pointer, size):
        seen.append((pointer._obj.basic.flags, pointer._obj.job_memory))
        return 1
    kernel.SetInformationJobObject.side_effect = configure
    monkeypatch.setattr(windows.ctypes, "WinDLL", lambda *a, **k: kernel)
    job = windows.WindowsProcessJob(memory_bytes=4096)
    assert seen == [(0x2000 | 0x200, 4096)]
    job.close()
    kernel.SetInformationJobObject.side_effect = lambda *args: 0
    monkeypatch.setattr(windows.ctypes, "get_last_error", lambda: 5)
    with pytest.raises(OSError):
        windows.WindowsProcessJob(memory_bytes=4096)
    assert kernel.CloseHandle.call_count == 2


@pytest.mark.parametrize("value", [-1, True, 1.5, 1 << 128])
def test_invalid_memory_policy_cannot_silently_disable_cap(value):
    with pytest.raises(ValueError): host.HostLimits(memory_bytes=value)


def test_near_cap_success_is_not_misclassified_as_memory_failure(tmp_path):
    (tmp_path / "result.json").write_text(json.dumps({"root": "fixture"}))
    outcome = host._classify("fixture", tmp_path, {"code": 0, "peak_memory": 999}, 1000, 10000)
    assert outcome.ok


def test_memoryerror_report_does_not_claim_proven_cap_causality(tmp_path):
    (tmp_path / "status.json").write_text(json.dumps({"status": "error", "error_type": "MemoryError"}))
    outcome = host._classify("fixture", tmp_path, {"code": 1}, 1000, 10000)
    assert outcome.error_type == host.HOST_MEMORY_LIMIT
    assert "worker reported MemoryError" in outcome.message
    assert "causality is unverified" in outcome.message and "unknown" in outcome.message


def test_retry_only_releases_after_proof_and_old_run_cannot_complete_reused_pid(monkeypatch):
    supervisor = ProcessSupervisor()
    old = SimpleNamespace(pid=123, poll=lambda: 1)
    old_job = SimpleNamespace(close=Mock())
    supervisor._proc, supervisor._job, supervisor.running = old, old_job, True
    supervisor._completed.clear()
    done = []
    supervisor._pending_completion = (old, old_job, 1, "uncertain", lambda *args: done.append(args))
    monkeypatch.setattr(supervisor, "_finish_tree", lambda *args, **kwargs: False)
    assert not supervisor.retry_cleanup() and supervisor.running and not done
    monkeypatch.setattr(supervisor, "_finish_tree", lambda *args, **kwargs: True)
    with ThreadPoolExecutor(2) as pool:
        list(pool.map(lambda _: supervisor.retry_cleanup(), range(2)))
    assert len(done) == 1 and old_job.close.call_count == 1
    # A new owned object can have the same numerical PID; stale completion must
    # never release that run or close its job. No process is looked up by PID.
    new_job = SimpleNamespace(close=Mock())
    supervisor._proc = SimpleNamespace(pid=123)
    supervisor._job, supervisor.running = new_job, True
    supervisor._completed.clear()
    supervisor._publish_done(old, 1, "stale", lambda *args: done.append(args))
    assert supervisor.running and not supervisor.wait(0)
    assert new_job.close.call_count == 0 and len(done) == 1


def test_host_quarantine_keeps_workdir_until_owned_cleanup_verified(tmp_path):
    workdir = tmp_path / "quarantine"
    workdir.mkdir()
    verified = [False]
    supervisor = Mock()
    supervisor.wait.side_effect = lambda timeout: verified[0]
    supervisor.retry_cleanup.side_effect = lambda: verified[0]
    host._QUARANTINED_HOSTS[supervisor] = workdir
    try:
        assert not host._recover_quarantined_hosts() and workdir.exists()
        outcome = host.run_isolated_analyzer(SimpleNamespace(name="sibling"), tmp_path)
        assert outcome.error_type == host.HOST_STUCK
        verified[0] = True
        assert host._recover_quarantined_hosts() and not workdir.exists()
    finally:
        host._QUARANTINED_HOSTS.pop(supervisor, None)


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows pre-resume Job Object memory enforcement")
@pytest.mark.parametrize("allocation,expected", [(8 * 1024**2, 0), (96 * 1024**2, 7)])
def test_actual_immediate_allocation_is_inside_preconfigured_cap(allocation, expected):
    script = "import sys\ntry:\n b=bytearray(int(sys.argv[1])); print('allocated')\nexcept MemoryError:\n print('MemoryError'); sys.exit(7)"
    supervisor = ProcessSupervisor()
    done = []
    assert supervisor.start([sys.executable, "-c", script, str(allocation)], job_memory_bytes=64 * 1024**2,
                            timeout=10, on_done=lambda code, tail: done.append((code, tail)))
    assert supervisor.wait(15) and not supervisor.running
    assert done[0][0] == expected, done
    assert ("MemoryError" if expected else "allocated") in done[0][1]
    assert supervisor.memory_policy["enforced_bytes"] == 64 * 1024**2


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows descendant cleanup after allocation failure")
def test_actual_capped_child_failure_reaps_descendant_then_good_sibling_runs():
    from test_ui_supervision import is_alive
    supervisor = ProcessSupervisor()
    done = []
    script = "import subprocess,sys\np=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\nprint('child='+str(p.pid),flush=True)\nb=bytearray(256*1024**2)"
    assert supervisor.start([sys.executable, "-c", script], job_memory_bytes=128 * 1024**2,
                            timeout=10, on_done=lambda code, tail: done.append((code, tail)))
    assert supervisor.wait(15) and not supervisor.running
    assert done[0][0] != 0 and "MemoryError" in done[0][1]
    child = int(next(line.split("=", 1)[1] for line in done[0][1].splitlines() if line.startswith("child=")))
    assert not is_alive(child)
    assert supervisor.start([sys.executable, "-c", "print('sibling intact')"], job_memory_bytes=128 * 1024**2,
                            timeout=10, on_done=lambda code, tail: done.append((code, tail)))
    assert supervisor.wait(15) and done[-1] == (0, "sibling intact")
