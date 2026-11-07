"""Controlled workers exercise Windows admission and process-tree cancellation."""

import ctypes
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from attackmap.ui.runner import ScanRunner


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("Controlled worker did not reach expected state")


def is_alive(pid):
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
    finally:
        kernel.CloseHandle(handle)


@pytest.mark.skipif(os.name != "nt", reason="Windows job containment")
def test_twenty_starts_admit_one_and_cancel_reaps_ignoring_descendant(tmp_path, monkeypatch):
    child_ready = tmp_path / "child.pid"
    worker = tmp_path / "worker.py"
    worker.write_text('''import os, signal, subprocess, sys, time
from pathlib import Path
signal.signal(signal.SIGBREAK, signal.SIG_IGN)
if len(sys.argv) > 2:
    Path(sys.argv[1]).write_text(str(os.getpid()))
else:
    subprocess.Popen([sys.executable, __file__, sys.argv[1], "child"])
while True:
    time.sleep(0.05)
''', encoding="utf-8")
    runner = ScanRunner()
    real_popen = subprocess.Popen
    calls = []

    def popen(**kwargs):
        calls.append(kwargs["args"])
        return real_popen(**kwargs)

    monkeypatch.setattr("attackmap.ui.runner.subprocess.Popen", popen)
    gate = threading.Barrier(20)
    done = threading.Event()

    def start(_):
        gate.wait(timeout=5)
        return runner.start(tmp_path, tmp_path / "out", argv=[sys.executable, str(worker), str(child_ready)], on_done=lambda *args: done.set())

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(start, range(20)))
    assert results.count(True) == 1
    assert len(calls) == 1
    wait_for(child_ready.exists)
    child_pid = int(child_ready.read_text())
    parent_pid = runner._proc.pid
    assert is_alive(parent_pid) and is_alive(child_pid)
    started = time.monotonic()
    assert runner.request_cancel()
    assert time.monotonic() - started < 0.25
    assert runner.running
    assert not runner.start(tmp_path, tmp_path / "another")
    assert done.wait(6.5)
    elapsed = time.monotonic() - started
    assert elapsed < 6.5  # One fixture measurement; not a p95 assertion.
    wait_for(lambda: not runner.running)
    assert not is_alive(parent_pid)
    assert not is_alive(child_pid)


def test_unverified_exit_keeps_admission_slot(tmp_path, monkeypatch):
    runner = ScanRunner()
    runner.running = True
    runner._proc = type("P", (), {"pid": 43211, "poll": lambda self: None, "send_signal": lambda *args: None, "terminate": lambda *args: None})()
    signals = []
    if os.name != "nt":
        def killpg(pid, value):
            assert pid == runner._proc.pid
            signals.append(value)
        monkeypatch.setattr("attackmap.execution.os.killpg", killpg)
    monkeypatch.setattr(runner, "_finish_tree", lambda *args, **kwargs: False)
    assert not runner.cancel()
    if os.name != "nt":
        import signal
        assert signals == [signal.SIGTERM]
    assert runner.running
    assert not runner.start(tmp_path, tmp_path / "out")


def test_tree_query_failure_cannot_acknowledge_verified_exit(tmp_path):
    runner = ScanRunner()
    proc = type("P", (), {"poll": lambda self: 0})()

    class BrokenJob:
        def active(self):
            raise OSError("fixture query failure")

    assert not runner._finish_tree(proc, BrokenJob())


def test_output_is_bounded_and_callback_failure_does_not_abandon_worker(tmp_path):
    runner = ScanRunner()
    done = threading.Event()
    result = {}

    def progress(event):
        raise RuntimeError("fixture callback failed")

    def finish(code, report, tail):
        result.update(code=code, tail=tail)
        done.set()

    code = 'import sys; sys.stderr.write(\'{"event":"tick"}\\n\'); sys.stdout.write("x" * 500000); sys.stderr.write("y" * 500000)'
    assert runner.start(tmp_path, tmp_path / "out", argv=[sys.executable, "-c", code], on_progress=progress, on_done=finish)
    assert done.wait(10)
    wait_for(lambda: not runner.running)
    assert result["code"] == 0
    assert len(result["tail"]) <= 50 * 4097


def test_invalid_argv_releases_admission(tmp_path):
    runner = ScanRunner()
    assert not runner.start(tmp_path, tmp_path / "out", argv=["invalid\x00executable"])
    assert not runner.running


@pytest.mark.parametrize("failure", [False, "exception"])
def test_cancel_http_ack_is_prompt_and_cleanup_failure_blocks_restart(monkeypatch, failure):
    import json
    from http.server import ThreadingHTTPServer
    from urllib.request import Request, urlopen
    from attackmap.ui.server import LoopbackApp, _handler, _start_scan
    from attackmap.ui.run_state import GuiRunState

    app = LoopbackApp()
    app._run_state = GuiRunState.RUNNING
    app.run_id = "controlled-run"
    entered, release = threading.Event(), threading.Event()
    calls = []

    class SlowRunner:
        running = True

        def cancel(self):
            calls.append("cancel")
            entered.set()
            release.wait(3)
            if failure == "exception":
                raise OSError("private-sentinel-must-not-appear")
            return False

    app.runner = SlowRunner()
    monkeypatch.setattr("attackmap.ui.server.has_llm_key", lambda provider: False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(app))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/cancel"
        request = Request(url, data=b"{}", headers={"X-AttackMap-Token": app.token})
        started = time.monotonic()
        with urlopen(request, timeout=2) as response:
            snapshot = json.load(response)
        assert time.monotonic() - started < 0.25
        assert entered.wait(1)
        assert snapshot["runContract"]["message"]["state"] == "cancelling"
        assert app.runner.running
        _start_scan(app, {})
        assert app.run_id == "controlled-run"
        with urlopen(request, timeout=2) as response:
            response.read()
        assert calls == ["cancel"]
        release.set()
        wait_for(lambda: app.error is not None)
        assert "restart remains blocked" in app.error
        assert "private-sentinel" not in app.error
        assert app._run_state == GuiRunState.CANCELLING
    finally:
        release.set()
        server.shutdown()
        server.server_close()


def test_old_cancel_failure_cannot_mutate_new_run():
    from attackmap.ui.server import LoopbackApp, _request_scan_cancel
    from attackmap.ui.run_state import GuiRunState

    app = LoopbackApp()
    app._run_state = GuiRunState.RUNNING
    app.run_id = "old"
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()

    class SlowRunner:
        def cancel(self):
            entered.set()
            release.wait(3)
            returned.set()
            return False

    app.runner = SlowRunner()
    _request_scan_cancel(app)
    assert entered.wait(1)
    with app._lock:
        app.run_id = "new"
        app._run_state = GuiRunState.RUNNING
    release.set()
    assert returned.wait(1)
    time.sleep(0.05)
    assert app.error is None
    assert app._run_state == GuiRunState.RUNNING
