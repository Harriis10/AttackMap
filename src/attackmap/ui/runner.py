"""Spawn ``sys.executable -m attackmap`` and stream NDJSON progress plus stderr tails."""

from __future__ import annotations

import os
import subprocess  # Retained public patch seam for callers replacing Popen.
from pathlib import Path
from typing import Any, Callable

from .config import analyze_argv
from ..execution import ProcessSupervisor

__all__ = ["ScanRunner", "analyze_argv", "child_python_env"]


def child_python_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for GUI-spawned ``python -m attackmap`` children."""
    env = os.environ.copy()
    # Desktop provider selection is explicit; inherited shell configuration
    # must not silently change its destination or authorize another provider.
    for name in (
        "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID",
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    ):
        env.pop(name, None)
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


class ScanRunner(ProcessSupervisor):
    """Desktop command and artifact adapter over the shared worker supervisor."""

    def start(self, repo: Path, output: Path, *, on_progress=None, on_done=None,
              env=None, cve=False, llm="none", modules="auto", baseline=None,
              argv=None, report_path=None, timeout=None, **kwargs: Any) -> bool:
        command = argv or analyze_argv(
            repo, output, cve=cve, llm=llm, modules=modules, baseline=baseline, **kwargs
        )

        def finish(code, tail):
            report = report_path or output / "attackmap-report.json"
            _invoke_done(on_done, code, report if report.is_file() else None, tail)

        return super().start(command, env=child_python_env(env), on_progress=on_progress,
                             on_done=finish, timeout=timeout)


def _invoke_done(on_done: DoneHook | None, code: int, report: Path | None, tail: str) -> None:
    if on_done is None:
        return
    try:
        on_done(code, report, tail)
    except TypeError:
        on_done(code, report)
