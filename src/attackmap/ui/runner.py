"""Spawn ``sys.executable -m attackmap`` and stream NDJSON progress."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable

ProgressHook = Callable[[dict[str, Any]], None]
DoneHook = Callable[[int, Path | None], None]


def analyze_argv(
    repo: Path,
    output: Path,
    *,
    cve: bool = False,
    llm: str = "none",
    modules: str = "auto",
    baseline: Path | None = None,
) -> list[str]:
    argv = [
        sys.executable,
        "-m",
        "attackmap",
        "analyze",
        str(repo),
        "--output",
        str(output),
        "--progress-format",
        "json",
        "--format",
        "json",
    ]
    if cve:
        argv.append("--cve")
    if llm and llm not in {"none", "None (heuristic only)"}:
        provider = "openai" if str(llm).lower().startswith("openai") else "claude"
        argv.extend(["--llm", "--llm-provider", provider])
    if modules and modules not in {"auto", "Auto"}:
        argv.extend(["-m", modules])
    if baseline is not None and baseline.is_file():
        argv.extend(["--baseline", str(baseline)])
    return argv


class ScanRunner:
    def __init__(self) -> None:
        self.running = False
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

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
    ) -> None:
        with self._lock:
            if self.running:
                return
            self.running = True
        argv = analyze_argv(repo, output, cve=cve, llm=llm, modules=modules, baseline=baseline)
        child_env = os.environ.copy()
        if env:
            child_env.update(env)
        kwargs: dict[str, Any] = {
            "args": argv,
            "stderr": subprocess.PIPE,
            "stdout": subprocess.DEVNULL,
            "text": True,
            "env": child_env,
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        self._proc = subprocess.Popen(**kwargs)
        threading.Thread(target=self._pump, args=(output, on_progress, on_done), daemon=True).start()

    def _pump(self, output: Path, on_progress: ProgressHook | None, on_done: DoneHook | None) -> None:
        proc = self._proc
        assert proc is not None and proc.stderr is not None
        try:
            for line in proc.stderr:
                line = line.strip()
                if not line or on_progress is None:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                on_progress(event)
            code = proc.wait()
        finally:
            with self._lock:
                self.running = False
                self._proc = None
        report = output / "attackmap-report.json"
        if on_done:
            on_done(code, report if report.is_file() else None)

    def cancel(self) -> None:
        with self._lock:
            proc = self._proc
            self.running = False
            self._proc = None
        if proc is None:
            return
        terminate = getattr(proc, "terminate", None)
        if terminate is not None:
            terminate()
