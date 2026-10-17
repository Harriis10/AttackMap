"""Presentation-neutral worker admission, timeout, streams and tree cleanup."""
from __future__ import annotations
import json
import os
import signal
import subprocess
import threading
import time
from collections import deque
from typing import Any, Callable
from .windows import WindowsProcessJob

ProgressHook = Callable[[dict[str, Any]], None]
DoneHook = Callable[[int, str], None]

class ProcessSupervisor:
    """One exclusive worker slot; release requires verified containment cleanup."""

    def __init__(self) -> None:
        self.running = False
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self.stderr_tail = ""
        self._job = None
        self._stop_lock = threading.Lock()
        self._cancelled = False
        self.timed_out = False
        self._completed = threading.Event()
        self._completed.set()

    def start(
        self,
        argv: list[str],
        *,
        on_progress: ProgressHook | None = None,
        on_done: DoneHook | None = None,
        env: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> bool:
        with self._lock:
            if self.running:
                return False
            if timeout is not None and timeout <= 0:
                raise ValueError("timeout must be positive")
            self._completed.clear()
            self.timed_out = False
            self.running = True
            self.stderr_tail = ""
            self._cancelled = False
            try:
                command = argv
                popen_kwargs = dict(
                    args=command, stdin=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                    text=True, encoding="utf-8", errors="replace", env=env,
                )
                if os.name == "nt":
                    self._job = WindowsProcessJob()
                    popen_kwargs["creationflags"] = (
                        subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW | 4
                    )  # CREATE_SUSPENDED: contain the process before it can spawn children.
                else:
                    popen_kwargs["start_new_session"] = True
                self._proc = subprocess.Popen(**popen_kwargs)
                if self._job is not None:
                    self._job.attach_and_resume(self._proc)
            except (OSError, ValueError) as exc:
                if self._proc is not None:
                    try:
                        self._proc.kill()
                        self._proc.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired):
                        self.stderr_tail = "Launch failed and worker termination could not be verified."
                        return False
                if self._job is not None:
                    self._job.close()
                    self._job = None
                self._proc = None
                self.running = False
                self.stderr_tail = str(exc)
                self._completed.set()
                if on_done is not None:
                    on_done(1, self.stderr_tail)
                return False
            proc = self._proc
            job = self._job
        threading.Thread(
            target=self._pump, args=(proc, job, on_progress, on_done), daemon=True,
        ).start()
        if timeout is not None:
            threading.Thread(target=self._timeout, args=(proc, timeout), daemon=True).start()
        return True

    def wait(self, timeout: float | None = None) -> bool:
        return self._completed.wait(timeout)

    def _timeout(self, proc, timeout: float) -> None:
        if self._completed.wait(timeout):
            return
        with self._lock:
            if self._proc is not proc:
                return
            self.timed_out = True
            self._cancelled = True
            job = self._job
        self._cancel_process(proc, job)

    def _pump(self, proc, job, on_progress, on_done) -> None:
        tail: deque[str] = deque(maxlen=50)
        tail_lock = threading.Lock()

        def drain(stream, progress=False):
            if stream is None:
                return
            try:
                while True:
                    # Bound both unterminated lines and retained diagnostics.
                    chunk = stream.readline(4096)
                    if not chunk:
                        break
                    stripped = chunk.strip()
                    if not stripped:
                        continue
                    event = _progress_event(stripped) if progress else None
                    if event is not None:
                        try:
                            if on_progress is not None:
                                on_progress(event)
                        except Exception:
                            with tail_lock:
                                tail.append("Progress callback failed.")
                    else:
                        with tail_lock:
                            tail.append(stripped)
            except (OSError, ValueError):
                pass
            finally:
                stream.close()

        readers = [threading.Thread(target=drain, args=(proc.stderr, True), daemon=True),
                   threading.Thread(target=drain, args=(proc.stdout,), daemon=True)]
        for reader in readers:
            reader.start()
        code = proc.wait()
        # A worker may exit while descendants still hold its pipes. Reap its job
        # before releasing admission or publishing completion.
        with self._stop_lock:
            exited = self._finish_tree(proc, job, force=True)
        if not exited:
            self.stderr_tail = "Worker exited but process-tree termination could not be verified."
            return  # Keep admission occupied: starting another scan is unsafe.
        for reader in readers:
            reader.join(timeout=0.25)
        with tail_lock:
            self.stderr_tail = "\n".join(tail)
        try:
            if on_done is not None:
                on_done(code, self.stderr_tail)
        finally:
            with self._lock:
                if self._proc is proc:
                    self.running = False
                    self._proc = None
                    if self._job is not None:
                        self._job.close()
                        self._job = None
                    self._completed.set()

    def _finish_tree(self, proc, job, *, force=False) -> bool:
        deadline = time.monotonic() + (2 if force else 3)
        try:
            if force:
                if job is not None:
                    job.terminate()
                elif os.name != "nt":
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif proc.poll() is None:
                    proc.kill()
            while time.monotonic() < deadline:
                if proc.poll() is not None and self._tree_empty(proc, job):
                    return True
                time.sleep(0.02)
        except OSError:
            return False
        return False

    @staticmethod
    def _tree_empty(proc, job) -> bool:
        if job is not None:
            return job.active() == 0
        if os.name == "nt":
            return True
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            return True
        return False

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> bool:
        """Request cancellation; retain admission until the entire job exits."""
        with self._lock:
            proc = self._proc
            if proc is None:
                return not self.running
            self._cancelled = True
            job = self._job
        return self._cancel_process(proc, job)

    def request_cancel(self) -> bool:
        """Acknowledge promptly; on_done remains the verified exit notification."""
        with self._lock:
            if self._proc is None:
                return False
            if self._cancelled:
                return True
            self._cancelled = True
            proc, job = self._proc, self._job
        threading.Thread(target=self._cancel_process, args=(proc, job), daemon=True).start()
        return True

    def _cancel_process(self, proc, job) -> bool:
        with self._stop_lock:
            try:
                if proc.poll() is None:
                    if os.name == "nt":
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                pass
            if self._finish_tree(proc, job):
                return True
            return self._finish_tree(proc, job, force=True)


def _progress_event(line: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict) and ("event" in payload or "v" in payload):
        return payload
    return None

