"""Debounced repo watch; never overlaps a running scan; ignores report output.

Windows event source is ``ReadDirectoryChangesW`` so changed paths are known
and generated AttackMap output is excluded via the engine's own output marker
and artifact-manifest helpers instead of a second artifact list (C31).
Changes arriving while a scan runs set a pending-dirty flag that the owner
drains after the run completes (exactly one follow-up scan per burst).
"""

from __future__ import annotations

import os
import struct
import threading
from pathlib import Path
from typing import Callable

from ..artifact_manifest import generated_artifact_names
from ..safe_fs import OUTPUT_MARKER

_PLATFORM = os.name

_PLATFORM_NOTICE = (
    "Live watching is only implemented on Windows; changes are not detected automatically."
)

_SKIP_DIR_NAMES = {".git", "reports", "__pycache__", "node_modules", ".venv", ".attackmap"}

FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
WAIT_OBJECT_0 = 0
_CHANGE_MASK = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE


class Watcher:
    """Watch one repository root, debouncing change bursts into single scans.

    ``is_running`` tells the watcher whether an analysis is active; changes
    observed then are recorded via :meth:`mark_pending` instead of dropped.
    The owner drains the flag with :meth:`take_pending` after the run
    completes, so each accumulated burst triggers exactly one follow-up.
    """

    def __init__(
        self,
        repo: Path,
        report_dir: Path,
        on_quiet: Callable[[], None],
        debounce_s: float = 1.5,
        is_running: Callable[[], bool] | None = None,
    ) -> None:
        self.repo = repo
        self.report_dir = report_dir
        self.on_quiet = on_quiet
        self.debounce_s = debounce_s
        self.is_running = is_running
        self.enabled = False
        # Honest limitation surfaced to the UI when the platform or the
        # filesystem cannot deliver change events.
        self.limitation: str | None = None
        self._busy = False
        self._pending = False
        self._pending_lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def supported(self) -> bool:
        return _PLATFORM == "nt"

    def should_ignore(self, path: Path, generated: set[str] | None = None) -> bool:
        """True when *path* cannot be a real source change.

        Own generated output is detected with the engine's existing helpers:
        directories marked with ``.attackmap-output`` and files claimed by a
        valid ``artifact-manifest.json`` (see :func:`generated_artifact_names`).
        ``generated`` may pass a precomputed set for the path's directory.
        """
        try:
            resolved = path.resolve()
            repo = self.repo.resolve()
            report = self.report_dir.resolve()
        except OSError:
            return True
        if not resolved.is_relative_to(repo):
            return True
        if any(part in _SKIP_DIR_NAMES for part in resolved.parts):
            return True
        try:
            if resolved.is_relative_to(report):
                return True
        except (OSError, ValueError):
            return True
        for parent in (resolved, *resolved.parents):
            if not parent.is_relative_to(repo):
                break
            if (parent / OUTPUT_MARKER).is_file():
                return True
        if generated is None:
            # The manifest helper needs the directory listing (it only
            # considers a manifest when artifact-manifest.json is present
            # among the candidate names).
            try:
                candidates = os.listdir(resolved.parent)
            except OSError:
                candidates = [resolved.name]
            try:
                generated = generated_artifact_names(resolved.parent, candidates)
            except OSError:
                generated = set()
        return resolved.name in generated

    def mark_pending(self) -> None:
        with self._pending_lock:
            self._pending = True

    def take_pending(self) -> bool:
        with self._pending_lock:
            pending = self._pending
            self._pending = False
            return pending

    @property
    def pending(self) -> bool:
        with self._pending_lock:
            return self._pending

    def notify(self) -> None:
        if self._busy or (self.is_running is not None and self.is_running()):
            # A scan is active or this callback is re-entered: remember the
            # burst for exactly one follow-up instead of dropping it.
            self.mark_pending()
            return
        self._busy = True
        try:
            self.on_quiet()
        finally:
            self._busy = False

    def start(self) -> None:
        self.enabled = True
        self._stop.clear()
        if not self.supported:
            self.limitation = _PLATFORM_NOTICE
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.enabled = False
        self._stop.set()
        timer = self._timer
        if timer is not None:
            timer.cancel()
        self._timer = None

    def _schedule(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
        self._timer = threading.Timer(self.debounce_s, lambda: self.enabled and self.notify())
        self._timer.daemon = True
        self._timer.start()

    def _loop(self) -> None:
        if self.supported:
            self._loop_win32()
            return
        while not self._stop.wait(0.4):
            pass

    def _handle_records(self, raw: bytes) -> None:
        """Filter one FILE_NOTIFY_INFORMATION buffer and debounce once."""
        paths: list[Path] = []
        offset = 0
        while offset + 12 <= len(raw):
            next_offset, _action, length = struct.unpack_from("<III", raw, offset)
            if length and offset + 12 + length <= len(raw):
                name = raw[offset + 12 : offset + 12 + length].decode("utf-16-le", "replace")
                name = name.replace("\\", "/")
                if name:
                    paths.append(self.repo / name)
            if next_offset == 0 or offset + next_offset > len(raw):
                break
            offset += next_offset
        if not paths:
            return
        by_dir: dict[Path, set[str]] = {}
        for path in paths:
            by_dir.setdefault(path.parent, set()).add(path.name)
        generated_by_dir: dict[Path, set[str]] = {}
        for path in paths:
            parent = path.parent
            if parent not in generated_by_dir:
                try:
                    candidates = os.listdir(parent)
                except OSError:
                    candidates = sorted(by_dir[parent])
                try:
                    generated_by_dir[parent] = generated_artifact_names(parent, candidates)
                except OSError:
                    generated_by_dir[parent] = set()
            if not self.should_ignore(path, generated=generated_by_dir[parent]):
                self._schedule()
                return

    def _loop_win32(self) -> None:
        import ctypes

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            ulong_ptr: type = ctypes.c_ulonglong
        else:
            ulong_ptr = ctypes.c_ulong

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", ulong_ptr),
                ("InternalHigh", ulong_ptr),
                ("Offset", ctypes.c_uint),
                ("OffsetHigh", ctypes.c_uint),
                ("hEvent", ctypes.c_void_p),
            ]

        kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
        kernel.CreateEventW.restype = ctypes.c_void_p
        kernel.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
        kernel.ReadDirectoryChangesW.restype = ctypes.c_int
        kernel.ReadDirectoryChangesW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        kernel.WaitForSingleObject.restype = ctypes.c_uint
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel.GetOverlappedResult.restype = ctypes.c_int
        kernel.GetOverlappedResult.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]

        invalid = ctypes.c_void_p(-1).value
        directory = kernel.CreateFileW(
            str(self.repo),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            None,
        )
        if directory in {None, 0, invalid}:
            self.limitation = "Repository cannot be watched on this filesystem; changes are not detected automatically."
            while not self._stop.wait(0.4):
                pass
            return
        changed = kernel.CreateEventW(None, 0, 0, None)
        if changed in {None, 0, invalid}:
            kernel.CloseHandle(directory)
            self.limitation = "Repository cannot be watched on this filesystem; changes are not detected automatically."
            while not self._stop.wait(0.4):
                pass
            return

        overlapped = OVERLAPPED()
        overlapped.hEvent = changed
        buffer = ctypes.create_string_buffer(65536)
        nbytes = ctypes.c_uint(0)
        pending_read = False
        try:
            while not self._stop.is_set():
                if not pending_read:
                    ok = kernel.ReadDirectoryChangesW(
                        directory, buffer, ctypes.sizeof(buffer), True, _CHANGE_MASK,
                        None, ctypes.byref(overlapped), None,
                    )
                    if not ok:
                        self.limitation = "Repository watch failed; changes are not detected automatically."
                        break
                    pending_read = True
                if kernel.WaitForSingleObject(changed, 400) != WAIT_OBJECT_0:
                    continue
                pending_read = False
                if not kernel.GetOverlappedResult(directory, ctypes.byref(overlapped), ctypes.byref(nbytes), False):
                    continue
                self._handle_records(buffer.raw[: nbytes.value])
        finally:
            kernel.CloseHandle(directory)
            kernel.CloseHandle(changed)
