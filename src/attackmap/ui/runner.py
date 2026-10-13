"""Spawn ``sys.executable -m attackmap`` and stream NDJSON progress plus stderr tails."""

from __future__ import annotations

import json
import os
import subprocess
import threading
from collections import deque
from pathlib import Path
from typing import Any, Callable

from .config import analyze_argv

__all__ = ["ScanRunner", "analyze_argv", "child_python_env"]


def child_python_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for GUI-spawned ``python -m attackmap`` children."""
    env = os.environ.copy()
    src_root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = src_root + os.pathsep + env.get("PYTHONPATH", "")
    if extra:
        overlay = dict(extra)
        extra_path = overlay.pop("PYTHONPATH", None)
        env.update(overlay)
        if extra_path:
            env["PYTHONPATH"] = extra_path + os.pathsep + env["PYTHONPATH"]
    return env

ProgressHook = Callable[[dict[str, Any]], None]
DoneHook = Callable[..., None]


class ScanRunner:
    def __init__(self) -> None:
        self.running = False
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self.stderr_tail = ""

    def start(
        self,
        repo: Path,
        output: Path,
        *,
        on_progress: ProgressHook | None = None,
        on_done: DoneHook | None = None,
        env: dict[str, str] | None = None,
        cve: bool = False,
        llm: str = "none",
        modules: str = "auto",
        baseline: Path | None = None,
        argv: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        with self._lock:
            if self.running:
                return
            self.running = True
            self.stderr_tail = ""
        command = argv or analyze_argv(
            repo, output, cve=cve, llm=llm, modules=modules, baseline=baseline, **kwargs
        )
        child_env = child_python_env(env)
        popen_kwargs: dict[str, Any] = {
            "args": command,
            "stderr": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "env": child_env,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
                subprocess, "CREATE_NO_WINDOW", 0
            )
        try:
            self._proc = subprocess.Popen(**popen_kwargs)
        except OSError as exc:
            with self._lock:
                self.running = False
                self.stderr_tail = str(exc)
            _invoke_done(on_done, 1, None, str(exc))
            return
        threading.Thread(target=self._pump, args=(output, on_progress, on_done), daemon=True).start()

    def _pump(self, output: Path, on_progress: ProgressHook | None, on_done: DoneHook | None) -> None:
        proc = self._proc
        assert proc is not None and proc.stderr is not None
        tail: deque[str] = deque(maxlen=50)
        stdout_box: list[str] = []

        def _drain_stdout() -> None:
            if proc.stdout is None:
                return
            stdout_box.append(proc.stdout.read() or "")

        reader = threading.Thread(target=_drain_stdout, daemon=True)
        reader.start()
        try:
            for line in proc.stderr:
                stripped = line.strip()
                if not stripped:
                    continue
                event = _progress_event(stripped)
                if event is not None:
                    if on_progress is not None:
                        on_progress(event)
                    continue
                tail.append(stripped)
            reader.join(timeout=30)
            for extra in "".join(stdout_box).splitlines():
                if extra.strip():
                    tail.append(extra.strip())
            code = proc.wait()
        except Exception as exc:  # noqa: BLE001 — always surface a terminal status
            code = getattr(proc, "returncode", None) or 1
            tail.append(f"{type(exc).__name__}: {exc}")
        report = output / "attackmap-report.json"
        report_path = report if report.is_file() else None
        self.stderr_tail = "\n".join(tail)
        try:
            _invoke_done(on_done, code, report_path, self.stderr_tail)
        finally:
            with self._lock:
                self.running = False
                self._proc = None

    def cancel(self) -> None:
        with self._lock:
            proc = self._proc
            self.running = False
            self._proc = None
        if proc is None:
            return
        pid = getattr(proc, "pid", None)
        terminate = getattr(proc, "terminate", None)
        if terminate is not None:
            try:
                terminate()
            except OSError:
                pass
        if os.name == "nt" and isinstance(pid, int) and pid > 1 and getattr(proc, "poll", lambda: None)() is None:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                check=False,
                creationflags=flags,
            )


def _progress_event(line: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict) and ("event" in payload or "v" in payload):
        return payload
    return None


def _invoke_done(on_done: DoneHook | None, code: int, report: Path | None, tail: str) -> None:
    if on_done is None:
        return
    try:
        on_done(code, report, tail)
    except TypeError:
        on_done(code, report)
