"""Debounced repo watch; never overlaps a running scan; ignores report output."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Callable

_SKIP_DIR_NAMES = {".git", "reports", "__pycache__", "node_modules", ".venv", ".attackmap"}

FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
WAIT_OBJECT_0 = 0


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

    def should_ignore(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return True
        if any(part in _SKIP_DIR_NAMES for part in resolved.parts):
            return True
        try:
            if resolved.is_relative_to(self.report_dir.resolve()):
                return True
        except (OSError, ValueError):
            return True
        return False

    def notify(self) -> None:
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
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.enabled = False
        self._stop.set()
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _schedule(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
        self._timer = threading.Timer(self.debounce_s, lambda: self.enabled and self.notify())
        self._timer.daemon = True
        self._timer.start()

    def _loop(self) -> None:
        if os.name == "nt":
            self._loop_win32()
            return
        while not self._stop.wait(0.4):
            pass

    def _loop_win32(self) -> None:
        import ctypes

        kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel.FindFirstChangeNotificationW.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel.FindNextChangeNotification.argtypes = [ctypes.c_void_p]
        kernel.FindCloseChangeNotification.argtypes = [ctypes.c_void_p]
        mask = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE
        handle = kernel.FindFirstChangeNotificationW(str(self.repo), True, mask)
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, 0, invalid}:
            while not self._stop.wait(0.4):
                pass
            return
        try:
            while not self._stop.is_set():
                wait = kernel.WaitForSingleObject(handle, 400)
                if wait == WAIT_OBJECT_0:
                    self._schedule()
                    kernel.FindNextChangeNotification(handle)
        finally:
            kernel.FindCloseChangeNotification(handle)
