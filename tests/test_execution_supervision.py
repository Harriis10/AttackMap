"""Shared supervisor regression checks and controlled Windows lifecycle evidence."""
import os
import subprocess
import sys
import threading
import time

import pytest

from attackmap.execution import ProcessSupervisor


def test_worker_stdin_is_closed_instead_of_inheriting_control_channel():
    broker = '''import sys
from attackmap.execution import ProcessSupervisor
supervisor = ProcessSupervisor()
result = []
assert supervisor.start(
    [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"],
    on_done=lambda code, tail: result.append((code, tail)),
)
assert supervisor.wait(5)
assert result == [(0, "''")]
print(sys.stdin.readline().strip())
'''
    result = subprocess.run([sys.executable, "-c", broker], input="cancel-sentinel\n",
                            text=True, capture_output=True, timeout=8)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "cancel-sentinel"


def test_timeout_uses_verified_cleanup():
    supervisor = ProcessSupervisor()
    done = []
    assert supervisor.start([sys.executable, "-c", "import time; time.sleep(30)"],
                            timeout=0.1, on_done=lambda code, tail: done.append(code))
    assert supervisor.wait(7)
    assert supervisor.timed_out and supervisor.cancelled
    assert not supervisor.running
    assert len(done) == 1 and done[0] != 0


def test_failed_cleanup_retains_admission(monkeypatch):
    supervisor = ProcessSupervisor()
    original_cleanup = supervisor._finish_tree
    finished = threading.Event()
    monkeypatch.setattr(supervisor, "_finish_tree", lambda *args, **kwargs: False)
    assert supervisor.start([sys.executable, "-c", "pass"],
                            on_done=lambda *args: finished.set())
    deadline = time.monotonic() + 5
    while supervisor._proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not supervisor.wait(0.1)
    assert supervisor.running and not finished.is_set()
    assert not supervisor.start([sys.executable, "-c", "pass"])
    # Recovery must prove the same owned tree empty before publishing completion.
    monkeypatch.setattr(supervisor, "_finish_tree", original_cleanup)
    assert supervisor.retry_cleanup()
    assert supervisor.wait(0) and not supervisor.running and finished.is_set()
    assert supervisor.retry_cleanup()  # repeated recovery cannot republish callbacks


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object lifecycle proof")
def test_fifty_cancel_cycles(tmp_path):
    from test_ui_supervision import is_alive, wait_for

    worker = tmp_path / "controlled.py"
    worker.write_text("""import os, signal, subprocess, sys, time
from pathlib import Path
signal.signal(signal.SIGBREAK, signal.SIG_IGN)
if len(sys.argv) > 2:
    ready = Path(sys.argv[1])
    pending = ready.with_suffix(".tmp")
    pending.write_text(str(os.getpid()))
    os.replace(pending, ready)
else:
    subprocess.Popen([sys.executable, __file__, sys.argv[1], "child"])
while True:
    time.sleep(0.01)
""", encoding="utf-8")
    supervisor = ProcessSupervisor()
    acknowledgements, exits = [], []
    for cycle in range(50):
        ready = tmp_path / f"child-{cycle}.pid"
        assert supervisor.start([sys.executable, str(worker), str(ready)])
        try:
            wait_for(ready.exists)
            child = int(ready.read_text())
            parent = supervisor._proc.pid
            started = time.monotonic()
            assert supervisor.request_cancel()
            acknowledgements.append(time.monotonic() - started)
            assert supervisor.wait(5)
            exits.append(time.monotonic() - started)
            assert not supervisor.running
            assert not is_alive(parent) and not is_alive(child)
        finally:
            if supervisor.running:
                supervisor.request_cancel()
                assert supervisor.wait(7), "Test-owned worker cleanup was not verified"
    ack_p95 = sorted(acknowledgements)[47]
    exit_p95 = sorted(exits)[47]
    print(f"Windows 50 cycles: acknowledgement p95={ack_p95:.6f}s; "
          f"tree exit p95={exit_p95:.6f}s; max exit={max(exits):.6f}s")
    assert ack_p95 <= 0.25
    assert max(exits) <= 5
