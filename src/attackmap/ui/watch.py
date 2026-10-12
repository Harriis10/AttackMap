"""Debounced repo watch; never overlaps a running scan."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable

_SKIP_DIR_NAMES = {".git", "reports", "__pycache__", "node_modules", ".venv"}


class Watcher:
    def __init__(
        self,
        repo: Path,
        report_dir: Path,
        on_quiet: Callable[[], None],
        debounce_s: float = 1.5,
    ) -> None:
        self.repo = repo
        self.report_dir = report_dir
        self.on_quiet = on_quiet
        self.debounce_s = debounce_s
        self.enabled = False
        self._busy = False
        self._timer: threading.Timer | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._mtimes: dict[str, float] = {}

    def notify(self) -> None:
        """Synchronous debounce gate used by tests and the poll loop."""
        if self._busy:
            return
        self._busy = True
        try:
            self.on_quiet()
        finally:
            self._busy = False

    def start(self) -> None:
        self.enabled = True
        self._stop.clear()
        self._mtimes = self._snapshot()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.enabled = False
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(0.4):
            if self._changed():
                if self._timer is not None:
                    self._timer.cancel()
                self._timer = threading.Timer(self.debounce_s, self.notify)
                self._timer.daemon = True
                self._timer.start()

    def _snapshot(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for path in self.repo.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            try:
                if path.resolve().is_relative_to(self.report_dir.resolve()):
                    continue
            except (OSError, ValueError):
                continue
            try:
                out[str(path)] = path.stat().st_mtime
            except OSError:
                continue
        return out

    def _changed(self) -> bool:
        now = self._snapshot()
        changed = now != self._mtimes
        self._mtimes = now
        return changed
