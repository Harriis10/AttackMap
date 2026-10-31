"""Independent WP043 native-window capture runner.

The pure protocol helpers are importable on every platform. Windows UI Automation,
ctypes, and Pillow are loaded only by WindowsLiveBackend during a live run.
"""

from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import time
from typing import Callable, Iterable, TypeVar


SCHEMA_VERSION = "wp043-live-evidence-v1"
DESTINATIONS = (
    "Overview",
    "Findings",
    "Architecture",
    "Inventory",
    "Reports",
    "History",
    "Scan options",
    "Risk and paths",
    "Evidence inventory",
    "Diagrams",
    "Fleet",
    "Suppressions",
    "Settings",
)
INTERVENTION_EVENTS = {
    "F9": ("f9-before-local-brush", "f9-after-local-brush"),
    "F10": ("f10-before-local-spacing", "f10-after-local-spacing"),
    "F11": ("f11-before-detail-spacing", "f11-detail-spacing-changed", "f11-after-detail-spacing"),
    "F12": ("f12-before-detail-brush", "f12-detail-brush-replaced", "f12-after-detail-brush"),
}
T = TypeVar("T")


@dataclass
class WindowInfo:
    hwnd: int
    pid: int
    title: str
    visible: bool
    minimized: bool
    cloaked: bool
    rect: tuple[int, int, int, int]
    # EnumWindows order: zero is the highest Z-order window.
    z_order: int = 0
    class_name: str | None = None


class MissingLiveDependency(RuntimeError):
    pass


class FrameSafetyError(RuntimeError):
    pass


class NativeWindowSafetyError(FrameSafetyError):
    def __init__(self, message, diagnostics):
        self.diagnostics = diagnostics
        super().__init__(message)


class NavigationFocusError(FrameSafetyError):
    def __init__(self, diagnostics):
        self.diagnostics = diagnostics
        super().__init__(f"Navigation focus failed at {diagnostics['failureStage']}")


class WindowEnumerationError(FrameSafetyError):
    def __init__(self, stage, winerror, *, hwnd=None, cause=None):
        self.stage = stage
        self.winerror = winerror
        self.hwnd = hwnd
        detail = f"GetLastError={winerror}"
        if cause is not None:
            detail += f"; HWND={hwnd}; {type(cause).__name__}: {cause}"
        super().__init__(f"EnumWindows {stage} failed ({detail})")


class ClientModalError(FrameSafetyError):
    def __init__(self, details, diagnostics=None):
        self.details = details
        self.diagnostics = diagnostics or {}
        super().__init__(f"Visible in-client modal: {details!r}")


class ClientModalInspectionError(FrameSafetyError):
    def __init__(self, diagnostics):
        self.diagnostics = diagnostics
        super().__init__(f"Client modal inspection failed at {diagnostics['failureStage']}")


class LiveBackend(ABC):
    @abstractmethod
    def launch(self, command, environment, cwd, stdout_path, stderr_path, diagnostics_dir):
        raise NotImplementedError

    @abstractmethod
    def read_events(self) -> list[dict]:
        raise NotImplementedError

    @abstractmethod
    def wait_for_window(self, pid: int, timeout: float) -> WindowInfo:
        raise NotImplementedError

    @abstractmethod
    def list_windows(self) -> list[WindowInfo]:
        raise NotImplementedError

    @abstractmethod
    def process_alive(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def foreground_hwnd(self) -> int:
        raise NotImplementedError

    def window_process_id(self, hwnd: int) -> int | None:
        return next((window.pid for window in self.list_windows() if window.hwnd == hwnd), None)

    @abstractmethod
    def restore(self, window: WindowInfo) -> None:
        raise NotImplementedError

    @abstractmethod
    def activate(self, window: WindowInfo) -> None:
        raise NotImplementedError

    @abstractmethod
    def move_resize(self, window: WindowInfo, width: int, height: int) -> None:
        raise NotImplementedError

    @abstractmethod
    def focus_navigation(self, window: WindowInfo, label: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def require_navigation_focus(self, window: WindowInfo, label: str) -> None:
        """Verify the intended item's keyboard focus immediately before Enter."""
        raise NotImplementedError

    @abstractmethod
    def select_first_finding(self, window: WindowInfo) -> None:
        raise NotImplementedError

    @abstractmethod
    def read_finding_detail(self, window: WindowInfo) -> dict:
        raise NotImplementedError

    @abstractmethod
    def select_diagram_view(self, window: WindowInfo, label: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def read_diagram_content(self, window: WindowInfo) -> dict:
        raise NotImplementedError

    @abstractmethod
    def send_key(self, key: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def grab(self, window: WindowInfo):
        raise NotImplementedError

    @abstractmethod
    def grab_print_window(self, window: WindowInfo):
        raise NotImplementedError

    @abstractmethod
    def client_modal_details(self, window: WindowInfo) -> list[dict]:
        """Read visible client dialogs; inspection failures must raise."""
        raise NotImplementedError

    @abstractmethod
    def save_image(self, image, path: Path) -> None:
        raise NotImplementedError

    @abstractmethod
    def close(self, window: WindowInfo) -> None:
        raise NotImplementedError

    @abstractmethod
    def wait_exit(self, timeout: float) -> bool:
        raise NotImplementedError

    @abstractmethod
    def kill_owned_tree(self) -> None:
        raise NotImplementedError


def _is_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def validate_new_output(path: Path) -> Path:
    raw = os.fspath(path)
    if raw.startswith(("\\\\", "//")):
        raise ValueError("UNC output paths are rejected")
    output = Path(os.path.abspath(raw))
    if str(output).startswith(("\\\\", "//")) or (os.name == "nt" and not output.drive):
        raise ValueError("output must be a local absolute path, not UNC")
    if os.path.lexists(output):
        raise ValueError("existing output paths are rejected; choose a new empty path")
    for current in (output, *output.parents):
        if _is_reparse(current):
            raise ValueError(f"reparse-point output path component is rejected: {current}")
    return output


def validate_capture_name(name: str, seen: set[str] | None = None) -> str:
    invalid = (
        not name
        or name in {".", ".."}
        or any(separator in name for separator in ("/", "\\", "\x00"))
        or Path(name).name != name
    )
    if invalid:
        raise ValueError(f"invalid capture name: {name!r}")
    if seen is not None:
        if name in seen:
            raise ValueError(f"duplicate capture name: {name}")
        seen.add(name)
    return name


def choose_owned_window(windows: list[WindowInfo], pid: int) -> WindowInfo:
    matches = [
        window
        for window in windows
        if window.pid == pid and window.title == "AttackMap" and window.visible
    ]
    if len(matches) != 1:
        raise RuntimeError(f"Require exactly one owned visible AttackMap window; found {len(matches)}")
    return matches[0]


def _intersects(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    return max(left[0], right[0]) < min(left[2], right[2]) and max(left[1], right[1]) < min(
        left[3], right[3]
    )


def intersecting_occluders(windows: list[WindowInfo], target: WindowInfo) -> list[WindowInfo]:
    return [
        window
        for window in windows
        if window.hwnd != target.hwnd
        and window.visible
        and not window.minimized
        and not window.cloaked
        and window.z_order < target.z_order
        and _intersects(window.rect, target.rect)
    ]


def _window_details(window: WindowInfo | None) -> dict | None:
    if window is None:
        return None
    return {
        "hwnd": window.hwnd, "pid": window.pid, "title": window.title,
        "className": window.class_name, "rect": list(window.rect), "zOrder": window.z_order,
        "visible": window.visible, "minimized": window.minimized, "cloaked": window.cloaked,
    }


def _native_window_snapshot(backend: LiveBackend, target: WindowInfo, phase: str, *,
                            require_same_rect: bool = False, require_native_handle: bool = False):
    """Assess identity and Z ordering only within one EnumWindows result."""
    alive = backend.process_alive()
    foreground_before = backend.foreground_hwnd()
    windows = backend.list_windows()
    foreground_after = backend.foreground_hwnd()
    snapshot_id = getattr(backend, "_native_snapshot_sequence", 0) + 1
    backend._native_snapshot_sequence = snapshot_id
    matches = [item for item in windows if item.pid == target.pid
               and item.title == "AttackMap" and item.visible]
    current = matches[0] if len(matches) == 1 else None
    valid_handle = direct_pid = None
    if require_native_handle:
        valid_handle = bool(backend._user32().IsWindow(target.hwnd))
        direct_pid = backend.window_process_id(target.hwnd)
    identity_ok = (alive and current is not None and current.hwnd == target.hwnd
                   and not current.minimized and not current.cloaked
                   and (not require_native_handle or (valid_handle and direct_pid == target.pid)))
    foreground_ok = foreground_before == target.hwnd == foreground_after
    geometry_ok = current is not None and (
        current.rect[2] - current.rect[0], current.rect[3] - current.rect[1]
    ) == (1600, 1000) and (not require_same_rect or current.rect == target.rect)
    blockers = intersecting_occluders(windows, current) if current is not None else []
    details = {
        "api": "Win32", "snapshotId": snapshot_id, "phase": phase,
        "targetBefore": _window_details(target), "targetAfter": _window_details(current),
        "observedTargetHwnd": _window_details(next((item for item in windows if item.hwnd == target.hwnd), None)),
        "identity": {"status": "safe" if identity_ok else "failed", "processAlive": alive,
                     "ownedVisibleCount": len(matches), "nativeHandleValid": valid_handle,
                     "directPid": direct_pid, "candidates": [_window_details(item) for item in matches]},
        "foreground": {"status": "safe" if foreground_ok else "failed",
                       "beforeHwnd": foreground_before, "afterHwnd": foreground_after,
                       "before": _window_details(next((item for item in windows if item.hwnd == foreground_before), None)),
                       "after": _window_details(next((item for item in windows if item.hwnd == foreground_after), None))},
        "geometry": {"status": "safe" if geometry_ok else "failed", "expectedSize": [1600, 1000],
                     "requireUnchanged": require_same_rect, "beforeRect": list(target.rect),
                     "afterRect": list(current.rect) if current is not None else None},
        "occlusion": {"status": "blocked" if blockers else "clear" if current is not None else "unknown",
                      "blockers": [_window_details(item) for item in blockers]},
    }
    if not identity_ok:
        failure, message = "identity", "Owned live visible non-minimized HWND identity changed"
    elif not foreground_ok:
        failure, message = "foreground", "Owned foreground HWND is required"
    elif not geometry_ok:
        failure, message = "geometry", "Environment outer-window geometry mismatch: expected unchanged 1600x1000"
    elif blockers:
        failure = "occlusion"
        message = f"Visible higher-Z-order occluder intersects target: {_window_details(blockers[0])!r}"
    else:
        return current, details
    details["failureStage"] = failure
    raise NativeWindowSafetyError(message, details)


def _owned_transient_only(error: Exception, target: WindowInfo) -> bool:
    """Qualify recovery from the originating native snapshot, never a later close."""
    if isinstance(error, ClientModalInspectionError):
        # The raw UIA retry performs a native target recheck after its fresh
        # descendants scan. Preserve that exact native provenance when it is
        # wrapped for the UIA diagnostic; do not treat generic UIA failures as
        # recoverable or walk an arbitrary exception chain.
        details = error.diagnostics
        cause = error.__cause__
        if not (
            details.get("api") == "UIAutomation"
            and details.get("failureStage") == "owned-target-recheck"
            and details.get("attempt") == 2
            and not details.get("modalConfirmed")
            and isinstance(cause, NativeWindowSafetyError)
            and cause.diagnostics.get("phase") in {
                "uia-retry-before-descendants",
                "uia-retry-after-descendants",
            }
        ):
            return False
        return _owned_transient_only(cause, target)
    if not isinstance(error, NativeWindowSafetyError):
        return False
    try:
        details = error.diagnostics
        identity, foreground, geometry = (details[key] for key in ("identity", "foreground", "geometry"))
        before, after = details["targetBefore"], details["targetAfter"]
        blockers = details["occlusion"]["blockers"]
        stable_target = all(
            item["hwnd"] == target.hwnd and item["pid"] == target.pid and item["title"] == "AttackMap"
            and item["visible"] is True and item["minimized"] is False and item["cloaked"] is False
            and item["rect"] == list(target.rect)
            for item in (before, after)
        )
        return (
            details["api"] == "Win32" and type(details["snapshotId"]) is int and details["snapshotId"] > 0
            and details["failureStage"] == "occlusion" and stable_target
            and identity["status"] == "safe" and identity["processAlive"] is True
            and identity["ownedVisibleCount"] == 1
            and foreground["status"] == "safe" and foreground["beforeHwnd"] == target.hwnd == foreground["afterHwnd"]
            and geometry["status"] == "safe" and geometry["expectedSize"] == [1600, 1000]
            and geometry["beforeRect"] == geometry["afterRect"] == list(target.rect)
            and details["occlusion"]["status"] == "blocked" and isinstance(blockers, list) and bool(blockers)
            and all(item["pid"] == target.pid and item["title"] == "Hostitel místní nabídky" for item in blockers)
        )
    except (KeyError, TypeError, AttributeError):
        return False


def _sequence(event: dict) -> int:
    sequence = event.get("sequence", 0)
    return sequence if isinstance(sequence, int) else 0


def _navigation_ack(
    events: list[dict],
    after_sequence: int,
    label: str,
    expected_run_id: str | None,
    expected_report_hash: str | None,
    minimum_navigation_revision: int,
) -> dict | None:
    for event in events:
        if _sequence(event) <= after_sequence or event.get("kind") != "navigation-after-turn":
            continue
        run_id = event.get("runId")
        if not run_id or (expected_run_id is not None and run_id != expected_run_id):
            continue
        detail = event.get("detail")
        if not isinstance(detail, dict):
            continue
        required = {
            "rootTheme",
            "selectedDestination",
            "headingText",
            "generation",
            "displayedRun",
            "displayedReadHash",
            "navigationRevision",
            "navigation",
            "heading",
        }
        if not required.issubset(detail):
            continue
        report_hash = detail.get("displayedReadHash")
        revision = detail.get("navigationRevision")
        selected_destination = detail.get("selectedDestination")
        destination_matches = (
            isinstance(selected_destination, str)
            and bool(selected_destination)
            and (selected_destination == label or label == "Settings")
        )
        if (
            detail.get("rootTheme") == "Dark"
            and destination_matches
            and detail.get("headingText") == label
            and isinstance(report_hash, str)
            and bool(report_hash)
            and (expected_report_hash is None or report_hash == expected_report_hash)
            and isinstance(revision, int)
            and revision >= minimum_navigation_revision
        ):
            return event
    return None


def navigation_acknowledged(
    events: list[dict],
    after_sequence: int,
    label: str,
    *,
    expected_run_id: str | None = None,
    expected_report_hash: str | None = None,
    minimum_navigation_revision: int = 1,
) -> bool:
    return (
        _navigation_ack(
            events,
            after_sequence,
            label,
            expected_run_id,
            expected_report_hash,
            minimum_navigation_revision,
        )
        is not None
    )


def diagram_activation_acknowledged(
    events: list[dict],
    after_sequence: int,
    expected_run_id: str,
    expected_report_hash: str,
    navigation_revision: int,
) -> bool:
    for event in events:
        if (
            _sequence(event) <= after_sequence
            or event.get("kind") not in {"activation-completed", "activation-failed"}
            or event.get("runId") != expected_run_id
        ):
            continue
        detail = event.get("detail")
        if (
            isinstance(detail, dict)
            and detail.get("displayedReadHash") == expected_report_hash
            and detail.get("navigationRevision") == navigation_revision
            and detail.get("viewKind") == "interactive"
        ):
            if event.get("kind") == "activation-failed":
                raise RuntimeError(
                    "Bound interactive diagram activation failed: "
                    f"{detail.get('errorType')}: {detail.get('errorMessage')}"
                )
            return True
    return False


def diagram_content_ready(content: dict, expected_view: str) -> bool:
    if content.get("selectedView") != expected_view:
        return False
    if expected_view == "Report diagrams and summary":
        text = content.get("legacyText")
        marker = "Complete supplied source:"
        return isinstance(text, str) and marker in text and bool(text.split(marker, 1)[1].strip())
    if expected_view == "Interactive architecture":
        notice = content.get("notice")
        if not isinstance(notice, str) or not notice.startswith("Captured run "):
            return False
        prefix, separator, _ = notice.partition(" nodes; ")
        nodes = prefix.split()[-1] if separator else ""
        return (
            content.get("reportArchitectureVisible") is True
            and nodes.isdigit()
            and int(nodes) > 0
        )
    raise ValueError(f"Unsupported diagram view: {expected_view}")


def finding_detail_ready(content: dict, expected_finding_id: str) -> bool:
    text = content.get("text")
    return (
        content.get("visible") is True
        and isinstance(text, str)
        and text.startswith(expected_finding_id + "\n")
        and "Evidence (engine supplied; classification shown above)" in text
    )


def _finding_selection_ack(
    events: list[dict], after_sequence: int, expected_run_id: str,
    expected_report_hash: str, navigation_revision: int,
) -> dict | None:
    acknowledgment = None
    for event in events:
        if (
            _sequence(event) <= after_sequence
            or event.get("kind") != "finding-selection"
            or event.get("runId") != expected_run_id
        ):
            continue
        detail = event.get("detail")
        if not isinstance(detail, dict):
            continue
        required = {
            "generation", "displayedRun", "displayedReadHash",
            "navigationRevision", "findingRevision", "hasFinding",
        }
        if (
            required.issubset(detail)
            and detail.get("displayedReadHash") == expected_report_hash
            and detail.get("navigationRevision") == navigation_revision
            and detail.get("hasFinding") is True
            and isinstance(detail.get("findingRevision"), int)
        ):
            acknowledgment = event
    return acknowledgment


def finding_selection_acknowledged(
    events: list[dict], after_sequence: int, expected_run_id: str,
    expected_report_hash: str, navigation_revision: int,
) -> bool:
    return _finding_selection_ack(
        events, after_sequence, expected_run_id, expected_report_hash, navigation_revision
    ) is not None


def _detail_render_terminal(
    events: list[dict],
    after_sequence: int,
    expected_run_id: str,
    expected_report_hash: str,
    navigation_revision: int,
    finding_revision: int,
) -> dict | None:
    started = {
        event["detail"].get("probeId")
        for event in events
        if _sequence(event) > after_sequence
        and event.get("kind") == "detail-render-capture-started"
        and event.get("runId") == expected_run_id
        and isinstance(event.get("detail"), dict)
        and event["detail"].get("displayedReadHash") == expected_report_hash
        and event["detail"].get("navigationRevision") == navigation_revision
        and event["detail"].get("findingRevision") == finding_revision
        and isinstance(event["detail"].get("probeId"), str)
        and bool(event["detail"]["probeId"])
    }
    for event in events:
        if (
            _sequence(event) <= after_sequence
            or event.get("kind") not in {"detail-render-capture-completed", "detail-render-capture-failed"}
            or event.get("runId") != expected_run_id
            or not isinstance(event.get("detail"), dict)
        ):
            continue
        detail = event["detail"]
        if (
            detail.get("probeId") in started
            and detail.get("displayedReadHash") == expected_report_hash
            and detail.get("navigationRevision") == navigation_revision
            and detail.get("findingRevision") == finding_revision
        ):
            return event
    return None


def _detail_root_render_terminal(
    events: list[dict], after_sequence: int, expected_run_id: str,
    expected_report_hash: str, navigation_revision: int, finding_revision: int,
) -> dict | None:
    started = {
        event["detail"].get("probeId"): _sequence(event)
        for event in events
        if _sequence(event) > after_sequence
        and event.get("kind") == "detail-root-render-capture-started"
        and event.get("runId") == expected_run_id
        and isinstance(event.get("detail"), dict)
        and event["detail"].get("displayedReadHash") == expected_report_hash
        and event["detail"].get("navigationRevision") == navigation_revision
        and event["detail"].get("findingRevision") == finding_revision
        and isinstance(event["detail"].get("probeId"), str)
        and bool(event["detail"]["probeId"])
    }
    for event in events:
        if (
            _sequence(event) <= after_sequence
            or event.get("kind") not in {"detail-root-render-capture-completed", "detail-root-render-capture-failed"}
            or event.get("runId") != expected_run_id or not isinstance(event.get("detail"), dict)
        ):
            continue
        detail = event["detail"]
        if (
            detail.get("probeId") in started
            and _sequence(event) > started[detail.get("probeId")]
            and detail.get("displayedReadHash") == expected_report_hash
            and detail.get("navigationRevision") == navigation_revision
            and detail.get("findingRevision") == finding_revision
        ):
            return event
    return None


def _detail_root_png(diagnostics_dir: Path, event: dict, prefix: str) -> tuple[Path, int, int, float]:
    file_name = event.get(prefix + "FileName")
    width = event.get(prefix + "Width")
    height = event.get(prefix + "Height")
    scale = event.get("scale")
    if (
        not isinstance(file_name, str) or Path(file_name).name != file_name
        or Path(file_name).suffix.lower() != ".png"
        or not isinstance(width, int) or isinstance(width, bool)
        or not isinstance(height, int) or isinstance(height, bool)
        or not 0 < width <= 16384 or not 0 < height <= 16384
        or width * height * 4 > 128 * 1024 * 1024
        or not isinstance(scale, (int, float)) or isinstance(scale, bool)
        or not 0 < scale < float("inf")
    ):
        raise ValueError("Detail/root render metadata exceeds capture bounds")
    path = _strict_file(diagnostics_dir / file_name, "Detail/root render PNG")
    if path.parent != diagnostics_dir.resolve() or not 24 <= path.stat().st_size <= 128 * 1024 * 1024:
        raise ValueError("Detail/root render PNG escaped its directory or exceeds capture bounds")
    with path.open("rb") as stream:
        header = stream.read(24)
        stream.seek(-12, os.SEEK_END)
        iend = stream.read(12)
    if (
        header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR"
        or struct.unpack(">II", header[16:24]) != (width, height)
        or iend != b"\x00\x00\x00\x00IEND\xaeB\x60\x82"
    ):
        raise ValueError("Detail/root render PNG header, dimensions, or IEND are invalid")
    return path, width, height, float(scale)


def _png_quality(path: Path) -> dict:
    # Decode independently of native metadata. Hidden RGB is not visible evidence.
    from PIL import Image
    with Image.open(path) as source:
        if source.format != "PNG" or source.width * source.height * 4 > 128 * 1024 * 1024:
            raise ValueError("Diagnostic PNG decode exceeds capture bounds")
        source.verify()  # PNG chunk CRCs, including IDAT, must be valid.
    with Image.open(path) as source:
        source.load()
        rgba = source.convert("RGBA")
        first = None
        visible = 0
        variation = False
        transparent = False
        for red, green, blue, alpha in (rgba.get_flattened_data() if hasattr(rgba, "get_flattened_data") else rgba.getdata()):
            if not alpha:
                transparent = True
                continue
            visible += 1
            value = (red * alpha, green * alpha, blue * alpha, alpha)
            if first is None:
                first = value
            elif value != first:
                variation = True
        variation = variation or (visible > 0 and transparent)
        return {"visiblePixels": visible, "hasVisibleVariation": variation,
                "classification": "empty" if not visible else "nonuniform" if variation else "uniform"}


def intervention_acknowledged(
    events: list[dict],
    after_sequence: int,
    key: str,
    *,
    expected_run_id: str | None = None,
) -> bool:
    normalized = key.upper()
    if normalized not in INTERVENTION_EVENTS:
        raise ValueError(f"unsupported diagnostic intervention: {key}")
    observed = {
        event.get("kind")
        for event in events
        if _sequence(event) > after_sequence
        and event.get("runId")
        and (expected_run_id is None or event.get("runId") == expected_run_id)
    }
    return all(kind in observed for kind in INTERVENTION_EVENTS[normalized])


def diagnostics_snapshot_ready(
    events: list[dict],
    expected_run_id: str,
    expected_report_hash: str,
    selected_label: str | None = None,
) -> bool:
    if not expected_report_hash or not any(
        event.get("kind") == "enabled" and event.get("runId") == expected_run_id for event in events
    ):
        return False
    snapshots = [
        event
        for event in events
        if event.get("runId") == expected_run_id
        and isinstance(event.get("detail"), dict)
        and "rootTheme" in event["detail"]
    ]
    if not snapshots:
        return False
    detail = snapshots[-1]["detail"]
    required = {
        "rootTheme",
        "selectedDestination",
        "headingText",
        "generation",
        "displayedRun",
        "displayedReadHash",
        "navigationRevision",
    }
    return (
        required.issubset(detail)
        and detail.get("rootTheme") == "Dark"
        and detail.get("displayedReadHash") == expected_report_hash
        and (selected_label is None or detail.get("selectedDestination") == selected_label)
    )


def read_diagnostics_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as source:
        lines = source.readlines()
    events = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if index == len(lines) - 1 and not line.endswith("\n"):
                break
            raise RuntimeError("Diagnostics JSONL contains an invalid complete event")
        if (
            not isinstance(event, dict)
            or not isinstance(event.get("runId"), str)
            or not event["runId"]
            or not isinstance(event.get("kind"), str)
            or not event["kind"]
            or not isinstance(event.get("detail"), dict)
        ):
            raise RuntimeError("Every diagnostics event requires runId, kind, and object detail")
        event["sequence"] = index + 1
        events.append(event)
    return events


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _strict_file(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label} must resolve to a file")
    return resolved


def _wait_for(
    callback: Callable[[], T | None],
    timeout: float,
    poll_interval: float,
    description: str,
) -> T:
    deadline = time.monotonic() + timeout
    while True:
        result = callback()
        if result is not None and result is not False:
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Timed out waiting for {description}")
        time.sleep(poll_interval)


def _events_and_run_id(backend: LiveBackend, expected_run_id: str | None = None) -> tuple[list[dict], str]:
    events = backend.read_events()
    enabled = [event for event in events if event.get("kind") == "enabled"]
    if not enabled or not enabled[0].get("runId"):
        raise RuntimeError("Diagnostics enabled event has not established a run ID")
    run_id = enabled[0]["runId"]
    if expected_run_id is not None and run_id != expected_run_id:
        raise RuntimeError("Diagnostics run ID changed during capture")
    if any(event.get("runId") != run_id for event in events):
        raise RuntimeError("Diagnostics contain multiple run IDs")
    return events, run_id


def _latest_sequence(events: Iterable[dict]) -> int:
    return max((_sequence(event) for event in events), default=0)


def _latest_navigation_revision(events: Iterable[dict]) -> int:
    revisions = [
        event["detail"].get("navigationRevision", 0)
        for event in events
        if isinstance(event.get("detail"), dict)
    ]
    return max((revision for revision in revisions if isinstance(revision, int)), default=0)


def _require_finding_revision(events: list[dict], expected_revision: int) -> None:
    revisions = [
        event["detail"].get("findingRevision")
        for event in events
        if event.get("kind") == "finding-selection" and isinstance(event.get("detail"), dict)
    ]
    if not revisions or revisions[-1] != expected_revision:
        raise FrameSafetyError("Finding detail finding revision changed during the capture triplet")


def _require_safe(
    backend: LiveBackend,
    target: WindowInfo,
    run_id: str,
    report_hash: str,
    *, inspection_context: dict | None = None,
) -> tuple[WindowInfo, list[dict]]:
    context = {"actionPhase": None, "destination": None, "diagnosticsSequence": None,
               **(inspection_context or {})}
    backend.modal_inspection_context = context
    try:
        current, before = _native_window_snapshot(backend, target, "before-client-inspection")
    except NativeWindowSafetyError as error:
        error.diagnostics.update(context)
        raise
    try:
        modals = backend.client_modal_details(current)
    except ClientModalInspectionError as error:
        error.diagnostics.update({key: error.diagnostics.get(key) or value for key, value in context.items()})
        error.diagnostics["nativeBeforeInspection"] = before
        raise
    except Exception as error:
        raise ClientModalInspectionError({
            "api": "UIAutomation", "failureStage": "backend", "hwnd": current.hwnd,
            "pid": current.pid, **context, "classification": "inspection-failure", "cause": _inspection_cause(error),
            "nativeBeforeInspection": before,
        }) from error
    if modals:
        inspections = getattr(backend, "modal_inspection_diagnostics", [])
        modal_diagnostic = inspections[-1] if inspections and inspections[-1].get("status") == "modal-present" else {}
        raise ClientModalError(modals, {**context, "inspectionInvocationId":
                              getattr(backend, "_modal_inspection_sequence", None), **modal_diagnostic})
    events, _ = _events_and_run_id(backend, run_id)
    if not diagnostics_snapshot_ready(events, run_id, report_hash):
        raise FrameSafetyError("Expected report hash and Dark diagnostics snapshot are required")
    try:
        current, _ = _native_window_snapshot(backend, current, "after-client-inspection", require_same_rect=True)
    except NativeWindowSafetyError as error:
        error.diagnostics["beforeInspection"] = before
        error.diagnostics.update(context)
        raise
    return current, events


def _write_evidence(output: Path, evidence: dict) -> None:
    (output / "evidence.json").write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _error_details(error: Exception) -> dict:
    details = {"type": type(error).__name__, "message": str(error)}
    enumeration_error = error
    seen = set()
    while enumeration_error is not None and id(enumeration_error) not in seen:
        seen.add(id(enumeration_error))
        if isinstance(enumeration_error, ClientModalInspectionError):
            details.update(enumeration_error.diagnostics)
            break
        if isinstance(enumeration_error, (NativeWindowSafetyError, NavigationFocusError)):
            details.update(enumeration_error.diagnostics)
            break
        if isinstance(enumeration_error, ClientModalError):
            details.update(enumeration_error.diagnostics)
            details["clientModals"] = enumeration_error.details
            break
        if isinstance(enumeration_error, WindowEnumerationError):
            details.update(
                api="EnumWindows", failureStage=enumeration_error.stage,
                winerror=enumeration_error.winerror, hwnd=enumeration_error.hwnd,
            )
            if enumeration_error.__cause__ is not None:
                details["cause"] = {
                    "type": type(enumeration_error.__cause__).__name__, "message": str(enumeration_error.__cause__),
                }
            break
        enumeration_error = enumeration_error.__cause__
    return details


def _inspection_cause(error: Exception) -> dict:
    details = {"type": type(error).__name__, "message": str(error)[:1024]}
    hresult = getattr(error, "hresult", None)
    if isinstance(hresult, int):
        details.update(hresult=hresult, hresultHex=f"0x{hresult & 0xffffffff:08X}")
    winerror = getattr(error, "winerror", None)
    if isinstance(winerror, int):
        details["winerror"] = winerror
    if isinstance(error, NativeWindowSafetyError):
        details["nativeWindowSafety"] = error.diagnostics
    return details


def run(args: argparse.Namespace, backend: LiveBackend) -> dict:
    executable = _strict_file(args.executable, "executable")
    report = _strict_file(args.report, "report")
    engine_argument = getattr(args, "engine", None)
    if engine_argument is not None and not engine_argument.is_absolute():
        raise ValueError("engine must be an absolute executable path")
    engine = _strict_file(engine_argument, "engine") if engine_argument is not None else None
    output = validate_new_output(args.output)
    if not args.native_only or args.theme != "dark":
        raise ValueError("WP043 live capture requires --native-only --theme dark")
    if (args.width, args.height, args.rounds) != (1600, 1000, 5):
        raise ValueError("WP043 live capture requires 1600x1000 and exactly five rounds")
    if args.detail_spacing_probe_round and args.detail_brush_probe_round:
        raise ValueError("Detail spacing and brush probes cannot be combined in one run")
    if (args.detail_render_probe or args.detail_root_render_probe) and (
        args.diagnostic_interventions or args.detail_spacing_probe_round
        or args.detail_brush_probe_round or args.print_window_detail_capture
        or (args.detail_render_probe and args.detail_root_render_probe)
    ):
        raise ValueError("Detail render probes cannot be combined with other capture or intervention modes")

    output.mkdir(parents=True, exist_ok=False)
    diagnostics_dir = output / "diagnostics"
    diagnostics_dir.mkdir()
    captures_dir = output / "captures"
    captures_dir.mkdir()
    discarded_dir = output / "discarded"
    discarded_dir.mkdir()
    profile = output / "profile"
    local_app_data = profile / "AppData" / "Local"
    roaming_app_data = profile / "AppData" / "Roaming"
    local_app_data.mkdir(parents=True)
    roaming_app_data.mkdir(parents=True)
    theme_path = local_app_data / "AttackMap" / "NativePreview" / "theme.json"
    theme_path.parent.mkdir(parents=True)
    theme_path.write_text('{"theme":"dark"}', encoding="utf-8")
    if engine is not None:
        (theme_path.parent / "settings.json").write_text(
            json.dumps({"SchemaVersion": 1, "PythonPath": str(engine)}), encoding="utf-8",
        )
    webview_profile = output / "webview-profile"
    webview_profile.mkdir()
    stdout_path = output / "stdout.log"
    stderr_path = output / "stderr.log"
    stdout_path.touch()
    stderr_path.touch()

    report_hash = _sha256(report)
    report_data = json.loads(report.read_text(encoding="utf-8-sig"))
    supplied_findings = report_data.get("findings")
    if not isinstance(supplied_findings, list) or not supplied_findings:
        raise ValueError("WP043 live capture requires at least one supplied finding")
    expected_finding_id = supplied_findings[0].get("id")
    if not isinstance(expected_finding_id, str) or not expected_finding_id:
        raise ValueError("The first supplied finding requires a non-empty id")
    command = [
        str(executable),
        "--show-report",
        str(report),
        "--render-native-only",
        "--render-diagnostics",
        str(diagnostics_dir),
    ]
    evidence = {
        "schemaVersion": SCHEMA_VERSION,
        "status": "running",
        "manual_review": "not-run",
        "rendering_acceptance": "not-established",
        "diagnosticInterventions": bool(args.diagnostic_interventions or args.detail_spacing_probe_round or args.detail_brush_probe_round),
        "command": command,
        "pid": None,
        "runId": None,
        "inputs": {
            "executable": {"path": str(executable), "sha256": _sha256(executable)},
            "report": {"path": str(report), "sha256": report_hash},
            **({"engine": {"path": str(engine), "sha256": _sha256(engine)}} if engine is not None else {}),
        },
        "isolation": {
            "USERPROFILE": str(profile),
            "LOCALAPPDATA": str(local_app_data),
            "APPDATA": str(roaming_app_data),
            "WEBVIEW2_USER_DATA_FOLDER": str(webview_profile),
            "themeFile": str(theme_path),
        },
        "diagnostics": str(diagnostics_dir / "render-diagnostics.jsonl"),
        "captures": [],
        "discardedCaptures": [],
        "actions": [],
        "shortcuts": {},
        "interventions": {},
        "detailSpacingProbe": None,
        "detailBrushProbe": None,
        "detailRenderProbe": None if not args.detail_render_probe else [],
        "detailRootRenderProbe": None if not args.detail_root_render_probe else [],
        "diagramContent": [],
        "completedRounds": 0,
        "closedCleanly": False,
    }
    environment = os.environ.copy()
    environment["USERPROFILE"] = str(profile)
    environment["LOCALAPPDATA"] = str(local_app_data)
    environment["APPDATA"] = str(roaming_app_data)
    environment["WEBVIEW2_USER_DATA_FOLDER"] = str(webview_profile)
    capture_names: set[str] = set()
    window = None
    launched = False
    close_attempted = False
    poll_interval = getattr(args, "poll_interval", 0.1)
    layout_delay = getattr(args, "layout_delay", 0.5)
    placement_delay = getattr(args, "placement_delay", 1.0)
    action_context = {"actionPhase": "startup-safety", "destination": "Findings"}

    def fresh_events(run_id: str) -> list[dict]:
        return _events_and_run_id(backend, run_id)[0]

    def inspect_safe(current, run_id, *, phase=None, attempt=0):
        if phase is not None:
            action_context["actionPhase"] = phase
        context = {**action_context, "diagnosticsSequence": _latest_sequence(fresh_events(run_id)),
                   "safetyAttempt": attempt + 1}
        return _require_safe(backend, current, run_id, report_hash, inspection_context=context)

    def dispatch_navigation(current: WindowInfo, label: str, run_id: str) -> tuple[WindowInfo, dict, int]:
        action_context.update(actionPhase="navigation-before-focus", destination=label)
        current, events = require_safe_after_transient(current, run_id)
        backend.focus_navigation(current, label)
        action_context["actionPhase"] = "navigation-before-enter"
        current, events = require_safe_after_transient(current, run_id)
        after = _latest_sequence(events)
        previous_revision = _latest_navigation_revision(events)
        action = {"type": "navigation", "label": label, "afterSequence": after, "status": "dispatched"}
        evidence["actions"].append(action)
        try:
            backend.require_navigation_focus(current, label)
            backend.send_key("ENTER")

            def acknowledged():
                latest = fresh_events(run_id)
                return _navigation_ack(
                    latest,
                    after,
                    label,
                    run_id,
                    report_hash,
                    previous_revision + 1,
                )

            acknowledgment = _wait_for(
                acknowledged, args.action_timeout, poll_interval, f"navigation acknowledgment for {label}"
            )
        except Exception:
            action["status"] = "failed"
            raise
        action["status"] = "acknowledged"
        action["acknowledgmentSequence"] = _sequence(acknowledgment)
        return current, acknowledgment, after

    def dismiss_owned_transient(current: WindowInfo, *, recovering: bool = False) -> WindowInfo:
        expected_pid, expected_hwnd, expected_rect = current.pid, current.hwnd, current.rect

        def unchanged_target(windows):
            latest = choose_owned_window(windows, expected_pid)
            if (latest.hwnd != expected_hwnd or latest.rect != expected_rect
                    or latest.minimized or latest.cloaked):
                raise FrameSafetyError("Owned target identity or geometry changed during transient dismissal")
            return latest

        if not backend.process_alive():
            raise FrameSafetyError("Owned process is not live before transient dismissal")
        foreground = backend.foreground_hwnd()
        if foreground != current.hwnd:
            actual = next((item for item in backend.list_windows() if item.hwnd == foreground), None)
            if actual is None:
                pid = backend.window_process_id(foreground)
                identity = f"hwnd={foreground}, pid={pid} (not enumerated)"
            else:
                identity = f"hwnd={actual.hwnd}, pid={actual.pid}, title={actual.title!r}"
            raise FrameSafetyError(f"Owned foreground process is required before transient dismissal; actual {identity}")
        windows = backend.list_windows()
        current = unchanged_target(windows)
        if backend.foreground_hwnd() != expected_hwnd:
            raise FrameSafetyError("Owned foreground HWND changed during transient dismissal")
        blockers = intersecting_occluders(windows, current)
        if not blockers:
            return current
        if any(blocker.pid != current.pid or blocker.title != "Hostitel místní nabídky" for blocker in blockers):
            if recovering:
                raise FrameSafetyError("Unexpected external or mixed occlusion during owned transient recovery")
            return current
        action = {"type": "dismiss-owned-transient", "title": blockers[0].title, "method": "wm-close", "status": "dispatched"}
        evidence["actions"].append(action)
        try:
            backend.close(blockers[0])

            def cleared():
                if not backend.process_alive() or backend.foreground_hwnd() != expected_hwnd:
                    raise FrameSafetyError("Owned process or foreground changed during transient dismissal")
                windows = backend.list_windows()
                latest = unchanged_target(windows)
                remaining = intersecting_occluders(windows, latest)
                if recovering and any(item.pid != latest.pid or item.title != "Hostitel místní nabídky" for item in remaining):
                    raise FrameSafetyError("Unexpected external or mixed occlusion during owned transient recovery")
                return latest if not remaining else None

            current = _wait_for(cleared, args.action_timeout, poll_interval, "owned transient dismissal")
        except Exception:
            action["status"] = "failed"
            raise
        action["status"] = "dismissed"
        return current

    def require_safe_after_transient(current: WindowInfo, run_id: str, attempt: int = 0) -> tuple[WindowInfo, list[dict]]:
        current = dismiss_owned_transient(current, recovering=attempt > 0)
        try:
            return inspect_safe(current, run_id, attempt=attempt)
        except FrameSafetyError as error:
            if attempt >= 2 or not _owned_transient_only(error, current):
                raise
            current = dismiss_owned_transient(current, recovering=True)
            return require_safe_after_transient(current, run_id, attempt + 1)

    def capture(current: WindowInfo, name: str, round_number: int, destination: str, run_id: str, attempt: int = 0, capture_method: str = "ImageGrab", expected_finding_revision: int | None = None) -> WindowInfo:
        action_context.update(actionPhase="capture-before-grab", destination=destination)
        validate_capture_name(name, capture_names)
        time.sleep(layout_delay)
        current = dismiss_owned_transient(current, recovering=attempt > 0)
        try:
            current, events = inspect_safe(current, run_id, attempt=attempt)
            if expected_finding_revision is not None:
                _require_finding_revision(events, expected_finding_revision)
        except FrameSafetyError as error:
            if attempt >= 2 or not _owned_transient_only(error, current):
                raise
            current = dismiss_owned_transient(current, recovering=True)
            return capture(current, name + "-after-transient", round_number, destination, run_id, attempt + 1, capture_method, expected_finding_revision)
        diagnostics_before = _latest_sequence(events)
        image = backend.grab_print_window(current) if capture_method == "PrintWindow" else backend.grab(current)
        try:
            current, events = inspect_safe(current, run_id, phase="capture-after-grab", attempt=attempt)
            if expected_finding_revision is not None:
                _require_finding_revision(events, expected_finding_revision)
            if backend.foreground_hwnd() != current.hwnd:
                raise FrameSafetyError("Owned foreground HWND changed immediately before save")
        except Exception as error:
            path = discarded_dir / f"{name}.png"
            backend.save_image(image, path)
            evidence["discardedCaptures"].append(
                {
                    "name": name,
                    "round": round_number,
                    "destination": destination,
                    "status": "discarded-invalid",
                    "reason": str(error),
                    "error": _error_details(error),
                    "path": path.relative_to(output).as_posix(),
                    "rect": list(current.rect),
                    "bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                    "runId": run_id,
                    "reportHash": report_hash,
                    "diagnosticsBeforeSequence": diagnostics_before,
                    "diagnosticsSequence": _latest_sequence(events),
                }
            )
            if attempt < 2 and _owned_transient_only(error, current):
                current = dismiss_owned_transient(current, recovering=True)
                return capture(current, name + "-after-transient", round_number, destination, run_id, attempt + 1, capture_method, expected_finding_revision)
            raise FrameSafetyError(f"Discarded invalid capture {name}: {error}") from error
        path = captures_dir / f"{name}.png"
        backend.save_image(image, path)
        evidence["captures"].append(
            {
                "name": name,
                "round": round_number,
                "destination": destination,
                "status": "valid",
                "captureMethod": capture_method,
                "path": path.relative_to(output).as_posix(),
                "rect": list(current.rect),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
                "runId": run_id,
                "reportHash": report_hash,
                "diagnosticsBeforeSequence": diagnostics_before,
                "diagnosticsSequence": _latest_sequence(events),
            }
        )
        return current

    try:
        pid = backend.launch(
            command,
            environment,
            executable.parent,
            stdout_path,
            stderr_path,
            diagnostics_dir,
        )
        launched = True
        evidence["pid"] = pid
        window = backend.wait_for_window(pid, args.window_timeout)
        evidence["hwnd"] = window.hwnd
        if window.minimized:
            backend.restore(window)
            window = choose_owned_window(backend.list_windows(), pid)
        backend.activate(window)

        def initial_run_id():
            try:
                return _events_and_run_id(backend)[1]
            except RuntimeError:
                return None

        run_id = _wait_for(initial_run_id, args.window_timeout, poll_interval, "diagnostics enabled event")
        evidence["runId"] = run_id
        window = _wait_for(
            lambda: (
                choose_owned_window(backend.list_windows(), pid)
                if diagnostics_snapshot_ready(fresh_events(run_id), run_id, report_hash, "Findings")
                else None
            ),
            args.window_timeout,
            poll_interval,
            "Dark Findings snapshot with expected report hash",
        )
        # HWND creation precedes the application's Loaded placement restore.
        # Size only after the report is ready so startup cannot overwrite it.
        placement = {"type": "window-placement", "status": "dispatched", "beforeRect": list(window.rect)}
        evidence["actions"].append(placement)
        backend.move_resize(window, args.width, args.height)

        def placement_acknowledged():
            if not backend.process_alive():
                raise FrameSafetyError("Owned process exited during window placement")
            current = choose_owned_window(backend.list_windows(), pid)
            if current.hwnd != window.hwnd or current.minimized:
                raise FrameSafetyError("Owned visible non-minimized HWND changed during window placement")
            placement["observedRect"] = list(current.rect)
            return current if (current.rect[2] - current.rect[0], current.rect[3] - current.rect[1]) == (args.width, args.height) else None

        window = _wait_for(
            placement_acknowledged, args.window_timeout, poll_interval,
            "environment outer-window geometry acknowledgment: expected 1600x1000",
        )
        placement["status"] = "acknowledged"
        time.sleep(placement_delay)
        window, _ = require_safe_after_transient(window, run_id)

        for round_number in range(1, 6):
            for position, label in enumerate(DESTINATIONS, start=1):
                window, acknowledgment, navigation_after = dispatch_navigation(window, label, run_id)
                slug = label.replace(" ", "-")
                if label == "Diagrams":
                    navigation_revision = acknowledgment["detail"]["navigationRevision"]
                    if round_number == 1:
                        _wait_for(
                            lambda: diagram_activation_acknowledged(
                                fresh_events(run_id), navigation_after, run_id,
                                report_hash, navigation_revision,
                            ) or None,
                            args.action_timeout,
                            poll_interval,
                            "bound interactive diagram activation",
                        )

                    def ready_diagram(view):
                        content = backend.read_diagram_content(window)
                        return content if diagram_content_ready(content, view) else None

                    interactive = _wait_for(
                        lambda: ready_diagram("Interactive architecture"),
                        args.action_timeout, poll_interval, "loaded Interactive architecture content",
                    )
                    window = capture(window, f"r{round_number:02d}-{position:02d}-{slug}", round_number, label, run_id)
                    backend.select_diagram_view(window, "Report diagrams and summary")
                    legacy = _wait_for(
                        lambda: ready_diagram("Report diagrams and summary"),
                        args.action_timeout, poll_interval, "loaded Report diagrams and summary content",
                    )
                    window = capture(
                        window, f"r{round_number:02d}-{position:02d}-DiagramsSummary",
                        round_number, "DiagramsSummary", run_id,
                    )
                    backend.select_diagram_view(window, "Interactive architecture")
                    _wait_for(
                        lambda: ready_diagram("Interactive architecture"),
                        args.action_timeout, poll_interval, "restored Interactive architecture content",
                    )
                    evidence["diagramContent"].append({
                        "round": round_number,
                        "interactiveNotice": interactive["notice"],
                        "legacyCharacters": len(legacy["legacyText"]),
                        "interactiveRestored": True,
                    })
                else:
                    window = capture(window, f"r{round_number:02d}-{position:02d}-{slug}", round_number, label, run_id)
                if label == "Findings":
                    action_context.update(actionPhase="finding-selection-before-input", destination="Findings")
                    window, events = require_safe_after_transient(window, run_id)
                    after = _latest_sequence(events)
                    navigation_revision = acknowledgment["detail"]["navigationRevision"]
                    action = {
                        "type": "finding-selection",
                        "round": round_number,
                        "afterSequence": after,
                        "status": "dispatched",
                    }
                    evidence["actions"].append(action)
                    try:
                        backend.select_first_finding(window)
                        selection_ack = _wait_for(
                            lambda: _finding_selection_ack(
                                fresh_events(run_id), after, run_id, report_hash, navigation_revision
                            ),
                            args.action_timeout,
                            poll_interval,
                            "bound first-finding selection acknowledgment",
                        )
                        finding_revision = selection_ack["detail"]["findingRevision"]

                        def ready_finding_detail():
                            content = backend.read_finding_detail(window)
                            return content if finding_detail_ready(content, expected_finding_id) else None

                        detail = _wait_for(
                            ready_finding_detail,
                            args.action_timeout,
                            poll_interval,
                            "Finding detail UIA content for the first supplied finding",
                        )
                        action["detailCharacters"] = len(detail["text"])
                        action["detailSha256"] = hashlib.sha256(detail["text"].encode("utf-8")).hexdigest()
                        action["uiaVisible"] = detail["visible"]
                    except Exception:
                        action["status"] = "failed"
                        window = capture(
                            window,
                            f"r{round_number:02d}-{position:02d}-FindingDetail-content-rejected",
                            round_number,
                            "FindingDetailContentRejected",
                            run_id,
                        )
                        raise
                    action["status"] = "acknowledged"
                    window = capture(
                        window,
                        f"r{round_number:02d}-{position:02d}-FindingDetail",
                        round_number,
                        "FindingDetail",
                        run_id,
                        expected_finding_revision=finding_revision,
                    )
                    detail_capture = evidence["captures"][-1]["name"]
                    if args.detail_render_probe:
                        action_context.update(actionPhase="detail-render-before-input", destination="FindingDetail")
                        window, events = require_safe_after_transient(window, run_id)
                        _require_finding_revision(events, finding_revision)
                        after = _latest_sequence(events)
                        try:
                            backend.send_key("F8")
                            terminal = _wait_for(
                                lambda: _detail_render_terminal(
                                    fresh_events(run_id), after, run_id, report_hash,
                                    navigation_revision, finding_revision,
                                ),
                                args.action_timeout, poll_interval, "F8 Detail render terminal acknowledgment",
                            )
                            if terminal.get("kind") != "detail-render-capture-completed":
                                raise RuntimeError("F8 Detail render failed before after-capture")
                            detail_event = terminal["detail"]
                            file_name = detail_event.get("fileName")
                            if (
                                not isinstance(file_name, str) or Path(file_name).name != file_name
                                or Path(file_name).suffix.lower() != ".png"
                            ):
                                raise ValueError("F8 Detail render requires a simple PNG file name")
                            render_path = _strict_file(diagnostics_dir / file_name, "F8 Detail render PNG")
                            if render_path.parent != diagnostics_dir.resolve():
                                raise ValueError("F8 Detail render PNG escaped diagnostics directory")
                            width, height, scale = (detail_event.get(key) for key in ("width", "height", "scale"))
                            if (
                                not isinstance(width, int) or isinstance(width, bool)
                                or not isinstance(height, int) or isinstance(height, bool)
                                or not 0 < width <= 16384 or not 0 < height <= 16384
                                or width * height * 4 > 128 * 1024 * 1024
                                or not isinstance(scale, (int, float)) or isinstance(scale, bool)
                                or not 0 < scale < float("inf")
                                or render_path.stat().st_size > 128 * 1024 * 1024
                            ):
                                raise ValueError("F8 Detail render metadata or PNG exceeds capture bounds")
                        except Exception:
                            raise RuntimeError("F8 Detail render did not produce a valid bound PNG") from None
                        after_capture = detail_capture + "-render-after"
                        window = capture(
                            window, after_capture, round_number, "FindingDetailRenderAfter", run_id,
                            expected_finding_revision=finding_revision,
                        )
                        evidence["detailRenderProbe"].append({
                            "round": round_number,
                            "findingRevision": finding_revision,
                            "beforeCapture": detail_capture,
                            "renderCapture": {
                                "name": render_path.stem,
                                "path": (Path("diagnostics") / file_name).as_posix(),
                                "bytes": render_path.stat().st_size,
                                "sha256": _sha256(render_path),
                                "width": width, "height": height, "scale": scale,
                            },
                            "afterCapture": evidence["captures"][-1]["name"],
                            "afterSequence": after,
                            "terminalSequence": _sequence(terminal),
                            "status": "captured-awaiting-visual-review",
                        })
                    if args.detail_root_render_probe:
                        action_context.update(actionPhase="detail-root-render-before-input", destination="FindingDetail")
                        window, events = require_safe_after_transient(window, run_id)
                        _require_finding_revision(events, finding_revision)
                        after = _latest_sequence(events)
                        probe_record = {"round": round_number, "status": "rejected"}
                        try:
                            backend.send_key("CTRL+ALT+SHIFT+R")
                            terminal = _wait_for(
                                lambda: _detail_root_render_terminal(
                                    fresh_events(run_id), after, run_id, report_hash,
                                    navigation_revision, finding_revision,
                                ),
                                args.action_timeout, poll_interval, "Detail/root render terminal acknowledgment",
                            )
                            probe_record = {"round": round_number, "status": "rejected", "terminal": terminal}
                            if terminal.get("kind") != "detail-root-render-capture-completed":
                                # Native quality rejection preserves files. Decode those too,
                                # independently, without allowing this failed ACK to release B.
                                for prefix in ("detail", "root"):
                                    if terminal["detail"].get(prefix + "FileName"):
                                        rejected_path, _, _, _ = _detail_root_png(diagnostics_dir, terminal["detail"], prefix)
                                        probe_record[prefix + "Quality"] = _png_quality(rejected_path)
                                raise RuntimeError(terminal["detail"].get("failureReason") or "Detail/root render failed before after-capture")
                            detail_path, detail_width, detail_height, scale = _detail_root_png(
                                diagnostics_dir, terminal["detail"], "detail")
                            root_path, root_width, root_height, root_scale = _detail_root_png(
                                diagnostics_dir, terminal["detail"], "root")
                            detail_quality = _png_quality(detail_path)
                            root_quality = _png_quality(root_path)
                            probe_record.update(detailQuality=detail_quality, rootQuality=root_quality)
                            if root_quality["classification"] != "nonuniform":
                                raise ValueError("root-raster-" + root_quality["classification"])
                            if root_scale != scale:
                                raise ValueError("Detail/root render scales differ")
                        except Exception as error:
                            probe_record["failureReason"] = str(error)
                            evidence.setdefault("rejectedDetailRootRenderProbes", []).append(probe_record)
                            raise RuntimeError(f"Detail/root render rejected: {error}") from error
                        window = capture(
                            window, detail_capture + "-root-render-after", round_number,
                            "FindingDetailRootRenderAfter", run_id,
                            expected_finding_revision=finding_revision,
                        )
                        evidence["detailRootRenderProbe"].append({
                            "round": round_number,
                            "findingRevision": finding_revision,
                            "beforeCapture": detail_capture,
                            "detailQuality": detail_quality, "rootQuality": root_quality,
                            "detailRenderCapture": {
                                "name": detail_path.stem, "path": (Path("diagnostics") / detail_path.name).as_posix(),
                                "bytes": detail_path.stat().st_size, "sha256": _sha256(detail_path),
                                "width": detail_width, "height": detail_height, "scale": scale,
                            },
                            "rootRenderCapture": {
                                "name": root_path.stem, "path": (Path("diagnostics") / root_path.name).as_posix(),
                                "bytes": root_path.stat().st_size, "sha256": _sha256(root_path),
                                "width": root_width, "height": root_height, "scale": root_scale,
                            },
                            "afterCapture": evidence["captures"][-1]["name"],
                            "afterSequence": after,
                            "terminalSequence": _sequence(terminal),
                            "status": "captured-awaiting-visual-review",
                        })
                    if args.print_window_detail_capture:
                        window = capture(
                            window,
                            detail_capture + "-printwindow",
                            round_number,
                            "FindingDetailPrintWindow",
                            run_id,
                            capture_method="PrintWindow",
                        )
                    if args.detail_spacing_probe_round == round_number:
                        before_capture = detail_capture
                        after = _latest_sequence(fresh_events(run_id))
                        try:
                            backend.send_key("F11")
                            _wait_for(
                                lambda: intervention_acknowledged(
                                    fresh_events(run_id), after, "F11", expected_run_id=run_id
                                ) or None,
                                args.action_timeout,
                                poll_interval,
                                "F11 Detail spacing invocation and application events",
                            )
                        except Exception:
                            evidence["interventions"]["F11"] = "failed"
                            raise
                        evidence["interventions"]["F11"] = "acknowledged"
                        after_capture = before_capture + "-spacing-after"
                        window = capture(
                            window, after_capture, round_number, "FindingDetailSpacingAfter", run_id
                        )
                        evidence["detailSpacingProbe"] = {
                            "round": round_number,
                            "beforeCapture": before_capture,
                            "afterCapture": after_capture,
                            "status": "captured-awaiting-visual-review",
                        }
                    if args.detail_brush_probe_round == round_number:
                        before_capture = detail_capture
                        after = _latest_sequence(fresh_events(run_id))
                        try:
                            backend.send_key("F12")
                            _wait_for(
                                lambda: intervention_acknowledged(
                                    fresh_events(run_id), after, "F12", expected_run_id=run_id
                                ) or None,
                                args.action_timeout,
                                poll_interval,
                                "F12 Detail brush invocation and application events",
                            )
                        except Exception:
                            evidence["interventions"]["F12"] = "failed"
                            raise
                        evidence["interventions"]["F12"] = "acknowledged"
                        after_capture = before_capture + "-brush-after"
                        window = capture(
                            window, after_capture, round_number, "FindingDetailBrushAfter", run_id
                        )
                        evidence["detailBrushProbe"] = {
                            "round": round_number,
                            "beforeCapture": before_capture,
                            "afterCapture": after_capture,
                            "status": "captured-awaiting-visual-review",
                        }
            evidence["completedRounds"] = round_number

        for key, label in (("CTRL+H", "History"), ("CTRL+COMMA", "Settings")):
            action_context.update(actionPhase="shortcut-before-input", destination=label)
            window, events = require_safe_after_transient(window, run_id)
            after = _latest_sequence(events)
            previous_revision = _latest_navigation_revision(events)
            try:
                backend.send_key(key)
                _wait_for(
                    lambda: navigation_acknowledged(
                        fresh_events(run_id),
                        after,
                        label,
                        expected_run_id=run_id,
                        expected_report_hash=report_hash,
                        minimum_navigation_revision=previous_revision + 1,
                    )
                    or None,
                    args.action_timeout,
                    poll_interval,
                    f"{key} navigation acknowledgment",
                )
            except Exception:
                evidence["shortcuts"][key] = "failed"
                raise
            evidence["shortcuts"][key] = "acknowledged"

        if args.diagnostic_interventions:
            for key in ("F9", "F10"):
                action_context.update(actionPhase="diagnostic-intervention-before-input", destination="Settings")
                window, events = require_safe_after_transient(window, run_id)
                after = _latest_sequence(events)
                try:
                    backend.send_key(key)
                    _wait_for(
                        lambda: intervention_acknowledged(
                            fresh_events(run_id), after, key, expected_run_id=run_id
                        )
                        or None,
                        args.action_timeout,
                        poll_interval,
                        f"{key} invocation and application events",
                    )
                except Exception:
                    evidence["interventions"][key] = "failed"
                    raise
                evidence["interventions"][key] = "acknowledged"

        close_attempted = True
        backend.close(window)
        if not backend.wait_exit(args.exit_timeout):
            raise TimeoutError("Owned process did not exit after window close")
        evidence["closedCleanly"] = True
        evidence["status"] = "independent-live-window-captured"
    except MissingLiveDependency as error:
        evidence["status"] = "not-run"
        evidence["error"] = {"type": type(error).__name__, "message": str(error)}
    except Exception as error:
        evidence["status"] = "failed"
        evidence["error"] = _error_details(error)
        if "clientModals" in evidence["error"] or evidence["error"].get("api") == "UIAutomation":
            snapshot = {"status": "not-captured", "error": evidence["error"]}
            if "clientModals" in evidence["error"]:
                snapshot["modalDetails"] = evidence["error"]["clientModals"]
            evidence["failureSnapshot"] = snapshot
            try:
                def diagnostic_window():
                    if window is None:
                        raise FrameSafetyError("Owned process is not live for failure review")
                    phase = "failure-review-after-grab" if snapshot.get("nativeChecks") else "failure-review-before-grab"
                    current, check = _native_window_snapshot(backend, window, phase, require_same_rect=True)
                    snapshot.setdefault("nativeChecks", []).append(check)
                    return current

                current = diagnostic_window()
                image = backend.grab(current)
                after = diagnostic_window()
                if after.rect != current.rect:
                    raise FrameSafetyError("Window moved during failure review")
                filename = "client-modal-inspection.png" if evidence["error"].get("api") == "UIAutomation" else "client-modal.png"
                path = output / "failure-review" / filename
                path.parent.mkdir()
                backend.save_image(image, path)
                snapshot.update(status="rejected-diagnostic-only", path=path.relative_to(output).as_posix(),
                                rect=list(current.rect), width=1600, height=1000,
                                bytes=path.stat().st_size, sha256=_sha256(path), captureMethod="ImageGrab")
            except Exception as snapshot_error:
                snapshot["reason"] = str(snapshot_error)
                snapshot["safetyError"] = _error_details(snapshot_error)
    finally:
        modal_inspections = getattr(backend, "modal_inspection_diagnostics", None)
        if modal_inspections:
            evidence["clientModalInspections"] = modal_inspections
        if launched and backend.process_alive():
            try:
                if window is not None and not close_attempted:
                    backend.close(window)
                if not backend.wait_exit(args.exit_timeout):
                    backend.kill_owned_tree()
                    backend.wait_exit(args.exit_timeout)
            except Exception as cleanup_error:
                evidence["cleanupError"] = {
                    "type": type(cleanup_error).__name__,
                    "message": str(cleanup_error),
                }
        finish = getattr(backend, "finish", None)
        if callable(finish):
            finish()
        _write_evidence(output, evidence)
    return evidence


class WindowsLiveBackend(LiveBackend):
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("WindowsLiveBackend requires Windows")
        self.process = None
        self.pid = None
        self.diagnostics_path = None
        self.stdout = None
        self.stderr = None
        self._pywinauto = None
        self.modal_inspection_diagnostics = []

    @staticmethod
    def _require_live_dependencies():
        if importlib.util.find_spec("pywinauto") is None:
            raise MissingLiveDependency("Install pywinauto into the project .venv for live UI Automation")
        if importlib.util.find_spec("PIL") is None:
            raise MissingLiveDependency("Install Pillow into the project .venv for live screen capture")

    def launch(self, command, environment, cwd, stdout_path, stderr_path, diagnostics_dir):
        self._require_live_dependencies()
        import pywinauto

        self._pywinauto = pywinauto
        self.diagnostics_path = Path(diagnostics_dir) / "render-diagnostics.jsonl"
        self.stdout = Path(stdout_path).open("wb")
        self.stderr = Path(stderr_path).open("wb")
        try:
            self.process = subprocess.Popen(
                command,
                cwd=cwd,
                env=environment,
                stdout=self.stdout,
                stderr=self.stderr,
            )
        except Exception:
            self.finish()
            raise
        self.pid = self.process.pid
        return self.pid

    def finish(self):
        for stream in (self.stdout, self.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    def read_events(self):
        return read_diagnostics_jsonl(self.diagnostics_path)

    @staticmethod
    def _user32():
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        user32.SetProcessDPIAware()
        if not getattr(user32, "_wp043_configured", False):
            user32.GetForegroundWindow.argtypes = []
            user32.GetForegroundWindow.restype = wintypes.HWND
            user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
            user32.GetWindowThreadProcessId.restype = wintypes.DWORD
            user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
            user32.GetWindowRect.restype = wintypes.BOOL
            user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
            user32.GetWindowTextLengthW.restype = ctypes.c_int
            user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
            user32.GetWindowTextW.restype = ctypes.c_int
            user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
            user32.GetClassNameW.restype = ctypes.c_int
            user32.IsWindowVisible.argtypes = [wintypes.HWND]
            user32.IsWindowVisible.restype = wintypes.BOOL
            user32.IsWindow.argtypes = [wintypes.HWND]
            user32.IsWindow.restype = wintypes.BOOL
            user32.IsIconic.argtypes = [wintypes.HWND]
            user32.IsIconic.restype = wintypes.BOOL
            user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
            user32.PrintWindow.restype = wintypes.BOOL
            user32.MoveWindow.argtypes = [
                wintypes.HWND,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                wintypes.BOOL,
            ]
            user32.MoveWindow.restype = wintypes.BOOL
            user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
            user32.SetCursorPos.restype = wintypes.BOOL
            user32.SetWindowPos.argtypes = [
                wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                ctypes.c_int, ctypes.c_int, wintypes.UINT,
            ]
            user32.SetWindowPos.restype = wintypes.BOOL
            user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.PostMessageW.restype = wintypes.BOOL
            user32._wp043_configured = True
        return user32

    def list_windows(self):
        import ctypes
        from ctypes import wintypes

        user32 = self._user32()
        windows = []
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        callback_error = None

        def inspect_window(hwnd):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            length = user32.GetWindowTextLengthW(hwnd)
            title_buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, title_buffer, length + 1)
            class_buffer = ctypes.create_unicode_buffer(256)
            class_name = class_buffer.value if user32.GetClassNameW(hwnd, class_buffer, len(class_buffer)) else None
            rect = wintypes.RECT()
            if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                return True
            cloaked = wintypes.DWORD()
            try:
                ctypes.windll.dwmapi.DwmGetWindowAttribute(
                    hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)
                )
            except Exception:
                cloaked.value = 0
            windows.append(
                WindowInfo(
                    hwnd=int(hwnd),
                    pid=pid.value,
                    title=title_buffer.value,
                    visible=bool(user32.IsWindowVisible(hwnd)),
                    minimized=bool(user32.IsIconic(hwnd)),
                    cloaked=bool(cloaked.value),
                    rect=(rect.left, rect.top, rect.right, rect.bottom),
                    z_order=len(windows),
                    class_name=class_name,
                )
            )
            return True

        def visit(hwnd, _):
            nonlocal callback_error
            try:
                return inspect_window(hwnd)
            except BaseException as error:
                # ctypes cannot propagate Python exceptions across a native callback.
                # Stop enumeration and re-raise outside the callback, never return a partial list.
                callback_error = (hwnd, error)
                return False

        callback = callback_type(visit)
        # Keep a private, explicitly typed binding: shared windll functions do not
        # preserve GetLastError and may have been configured by another UI library.
        enum_windows = ctypes.WinDLL("user32", use_last_error=True).EnumWindows
        enum_windows.argtypes = [callback_type, wintypes.LPARAM]
        enum_windows.restype = wintypes.BOOL
        ctypes.set_last_error(0)
        completed = enum_windows(callback, 0)
        winerror = ctypes.get_last_error()
        if callback_error is not None:
            hwnd, error = callback_error
            raise WindowEnumerationError("callback", winerror, hwnd=hwnd, cause=error) from error
        if not completed:
            raise WindowEnumerationError("OS call", winerror)
        return windows

    def wait_for_window(self, pid, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if not self.process_alive():
                raise RuntimeError("Owned native process exited before its window appeared")
            matches = [
                window
                for window in self.list_windows()
                if window.pid == pid and window.title == "AttackMap" and window.visible
            ]
            if matches:
                return choose_owned_window(matches, pid)
            if time.monotonic() >= deadline:
                raise TimeoutError("Timed out waiting for exactly one owned AttackMap window")
            time.sleep(0.2)

    def process_alive(self):
        return self.process is not None and self.process.poll() is None

    def foreground_hwnd(self):
        return int(self._user32().GetForegroundWindow())

    def window_process_id(self, hwnd):
        import ctypes
        from ctypes import wintypes

        pid = wintypes.DWORD()
        if not self._user32().GetWindowThreadProcessId(hwnd, ctypes.byref(pid)):
            return None
        return pid.value

    def restore(self, window):
        if not self._user32().ShowWindow(window.hwnd, 9):
            # ShowWindow returns previous visibility, not a success flag; state is verified later.
            pass

    def activate(self, window):
        self._uia_window(window).set_focus()
        # Keep only the owned QA window above unrelated topmost overlays; occlusion checks remain enforced.
        if not self._user32().SetWindowPos(window.hwnd, -1, 0, 0, 0, 0, 0x0003):
            raise RuntimeError("Could not place the owned QA window above unrelated overlays")
        if not self._user32().SetCursorPos(0, 0):
            raise RuntimeError("Could not move the cursor outside the owned QA window")

    def move_resize(self, window, width, height):
        if window.minimized:
            raise RuntimeError("Do not resize a minimized window")
        if not self._user32().MoveWindow(window.hwnd, 40, 40, width, height, True):
            raise RuntimeError("MoveWindow failed")

    def _uia_window(self, window):
        desktop = self._pywinauto.Desktop(backend="uia")
        return desktop.window(handle=window.hwnd)

    @staticmethod
    def _uia_automation():
        from pywinauto.uia_defines import IUIA

        return IUIA()

    def focus_navigation(self, window, label):
        self._navigation_focus = None
        stage = "navigation-descendants"
        count = None
        try:
            uia = self._uia_automation()
            root = uia.iuia.ElementFromHandle(window.hwnd)
            descendants = root.FindAll(uia.tree_scope["descendants"], uia.true_condition)
            count = descendants.Length
            candidates = []
            for index in range(count):
                stage = "navigation-element-info"
                item = descendants.GetElement(index)
                name, automation_id = item.CurrentName, item.CurrentAutomationId
                if name != label and not (label == "Settings" and automation_id == "SettingsItem"):
                    continue
                if "NavigationViewItem" in (item.CurrentClassName or "") or item.CurrentControlType in {
                    50007, 50024, 50019,  # ListItem, TreeItem, TabItem
                }:
                    candidates.append(item)
            stage = "navigation-unique-item"
            if len(candidates) != 1:
                raise ValueError(f"Expected one UIA navigation item for {label!r}; found {len(candidates)}")
            stage = "navigation-set-focus"
            candidates[0].SetFocus()
            self._navigation_focus = (window.hwnd, label, candidates[0])
            self.require_navigation_focus(window, label)
        except NavigationFocusError:
            raise
        except Exception as error:
            raise NavigationFocusError({
                **getattr(self, "modal_inspection_context", {}),
                "api": "UIAutomation", "failureStage": stage, "hwnd": window.hwnd,
                "pid": window.pid, "destination": label, "descendantCount": count,
                "cause": _inspection_cause(error),
            }) from error

    def require_navigation_focus(self, window, label):
        try:
            focused = getattr(self, "_navigation_focus", None)
            if focused is None or focused[:2] != (window.hwnd, label):
                raise ValueError("No matching directly focused navigation element")
            value = focused[2].GetCurrentPropertyValue(30008)  # UIA_HasKeyboardFocusPropertyId
            if not isinstance(value, (bool, int)) or value not in (False, True):
                raise ValueError("UIA keyboard-focus property did not return a Boolean")
            if not value:
                raise ValueError("Intended navigation item does not have keyboard focus")
        except Exception as error:
            raise NavigationFocusError({
                **getattr(self, "modal_inspection_context", {}),
                "api": "UIAutomation", "failureStage": "navigation-keyboard-focus", "hwnd": window.hwnd,
                "pid": window.pid, "destination": label, "propertyId": 30008,
                "cause": _inspection_cause(error),
            }) from error

    def select_first_finding(self, window):
        native_window = self._uia_window(window)
        lists = [
            item
            for item in native_window.descendants(control_type="List")
            if item.element_info.automation_id == "Findings" or item.element_info.name == "Findings"
        ]
        if len(lists) != 1:
            raise RuntimeError(f"Expected one UIA Findings list; found {len(lists)}")
        items = lists[0].children(control_type="ListItem")
        if len(items) < 2:
            raise RuntimeError("Findings list needs two UIA items for an acknowledged round-trip selection")
        # Select another row, then the first: SelectionChanged is acknowledged even
        # when the baseline has no ItemClick handler for an already-selected row.
        items[1].select()
        items[0].select()

    def read_finding_detail(self, window):
        details = [
            item for item in self._uia_window(window).descendants(control_type="Text")
            if item.element_info.automation_id == "Detail"
        ]
        if len(details) != 1:
            raise RuntimeError(f"Expected one UIA Finding detail text; found {len(details)}")
        detail = details[0]
        return {"text": detail.element_info.name or "", "visible": detail.is_visible()}

    def _diagram_view_selector(self, window):
        selectors = [
            item for item in self._uia_window(window).descendants(control_type="ComboBox")
            if item.element_info.name == "Choose interactive architecture or original report diagrams and summary"
        ]
        if len(selectors) != 1:
            raise RuntimeError(f"Expected one UIA diagram view selector; found {len(selectors)}")
        return selectors[0]

    def select_diagram_view(self, window, label):
        if label not in {"Interactive architecture", "Report diagrams and summary"}:
            raise ValueError(f"Unsupported diagram view: {label}")
        self._diagram_view_selector(window).select(label)

    def read_diagram_content(self, window):
        native_window = self._uia_window(window)
        descendants = native_window.descendants()
        editors = [
            item for item in descendants if item.element_info.control_type == "Edit"
            and item.element_info.name == "Complete diagram nodes, edges and original source; selectable read-only text"
        ]
        legacy_text = ""
        if editors:
            values = [item.get_value() or "" for item in editors]
            if len(set(values)) != 1:
                metadata = [
                    {
                        "automationId": item.element_info.automation_id,
                        "className": item.element_info.class_name,
                        "handle": item.element_info.handle,
                        "rectangle": str(item.element_info.rectangle),
                        "visible": item.is_visible(),
                    }
                    for item in editors
                ]
                raise RuntimeError(f"Conflicting diagram source editors; found {len(editors)}: {metadata}")
            legacy_text = values[0]
        text = [item for item in descendants if item.element_info.control_type == "Text"]
        notices = [item.element_info.name for item in text if item.element_info.name.startswith("Captured run ")]
        return {
            "selectedView": self._diagram_view_selector(window).selected_text(),
            "notice": notices[0] if notices else "",
            "reportArchitectureVisible": any(
                item.element_info.name == "Report architecture" and item.is_visible() for item in text
            ),
            "legacyText": legacy_text,
        }

    def send_key(self, key):
        from pywinauto.keyboard import send_keys

        keys = {
            "ENTER": "{ENTER}",
            "ESC": "{ESC}",
            "CTRL+H": "^h",
            "CTRL+COMMA": "^,",
            "CTRL+ALT+SHIFT+R": "^%+r",
            "F8": "{F8}",
            "F9": "{F9}",
            "F10": "{F10}",
            "F11": "{F11}",
            "F12": "{F12}",
        }
        if key not in keys:
            raise ValueError(f"Unsupported live key: {key}")
        send_keys(keys[key], pause=0.05)

    def grab(self, window):
        try:
            from PIL import ImageGrab
        except ImportError as error:
            raise MissingLiveDependency("Install Pillow into the project .venv for live screen capture") from error
        return ImageGrab.grab(bbox=window.rect, all_screens=True)

    def grab_print_window(self, window):
        # pywinauto.capture_as_image() is only another screen grab. Use the
        # independent window-rendering API explicitly for capture divergence evidence.
        import win32gui
        import win32ui
        from PIL import Image

        left, top, right, bottom = window.rect
        width, height = right - left, bottom - top
        if width <= 0 or height <= 0:
            raise RuntimeError(f"PrintWindow requires positive bounds; got {window.rect}")
        window_dc = source_dc = memory_dc = bitmap = previous = None
        try:
            window_dc = win32gui.GetWindowDC(window.hwnd)
            source_dc = win32ui.CreateDCFromHandle(window_dc)
            memory_dc = source_dc.CreateCompatibleDC()
            bitmap = win32ui.CreateBitmap()
            bitmap.CreateCompatibleBitmap(source_dc, width, height)
            previous = memory_dc.SelectObject(bitmap)
            if not self._user32().PrintWindow(window.hwnd, memory_dc.GetSafeHdc(), 2):
                raise RuntimeError("PrintWindow(PW_RENDERFULLCONTENT) failed")
            info = bitmap.GetInfo()
            return Image.frombuffer(
                "RGB", (info["bmWidth"], info["bmHeight"]), bitmap.GetBitmapBits(True),
                "raw", "BGRX", 0, 1,
            )
        finally:
            if memory_dc is not None and previous is not None:
                memory_dc.SelectObject(previous)
            if bitmap is not None:
                win32gui.DeleteObject(bitmap.GetHandle())
            if memory_dc is not None:
                memory_dc.DeleteDC()
            if source_dc is not None:
                source_dc.DeleteDC()
            if window_dc is not None:
                win32gui.ReleaseDC(window.hwnd, window_dc)

    def client_modal_details(self, window):
        invocation_id = getattr(self, "_modal_inspection_sequence", 0) + 1
        self._modal_inspection_sequence = invocation_id
        context = {"inspectionInvocationId": invocation_id, "actionPhase": None,
                   "destination": None, "diagnosticsSequence": None,
                   **getattr(self, "modal_inspection_context", {})}
        native_rechecks = []

        def require_current_target(phase):
            _, details = _native_window_snapshot(self, window, phase, require_same_rect=True,
                                                  require_native_handle=True)
            native_rechecks.append(details)

        def boolean_property(element, property_id):
            value = element.GetCurrentPropertyValue(property_id)
            if not isinstance(value, (bool, int)) or value not in (False, True):
                raise ValueError(f"UIA property {property_id} did not return a Boolean")
            return bool(value)

        # pywinauto masks provider errors in descendants, visibility and metadata
        # readers. Use raw UIA calls: only a complete readable scan establishes safety.
        failures = []
        for attempt in (1, 2):
            stage = "owned-target-recheck" if attempt > 1 else "descendants"
            metadata = {}
            modal_confirmed = False
            descendant_count = None
            try:
                if attempt > 1:
                    require_current_target("uia-retry-before-descendants")
                stage = "descendants"
                uia = self._uia_automation()
                root = uia.iuia.ElementFromHandle(window.hwnd)
                descendants = root.FindAll(uia.tree_scope["descendants"], uia.true_condition)
                descendant_count = descendants.Length
                for index in range(descendant_count):
                    metadata = {"elementIndex": index}
                    stage = "element-info"
                    element = descendants.GetElement(index)
                    stage = "visibility"
                    if boolean_property(element, 30022):  # UIA_IsOffscreenPropertyId
                        continue
                    stage = "class-name"
                    metadata["className"] = element.CurrentClassName or ""
                    modal = "ContentDialog" in metadata["className"]
                    is_dialog = window_pattern_is_modal = None
                    if not modal:
                        stage = "is-dialog"
                        is_dialog = boolean_property(element, 30174)  # UIA_IsDialogPropertyId
                        modal = is_dialog
                        if not modal:
                            # iface_window masks *all* COMError as unsupported in
                            # pywinauto. Query availability and the modal property
                            # directly so access/provider failures retain their HRESULT.
                            stage = "window-pattern-available"
                            available = boolean_property(element, 30044)
                            if available:
                                stage = "window-is-modal"
                                window_pattern_is_modal = boolean_property(element, 30077)
                                modal = window_pattern_is_modal
                    if modal:
                        modal_confirmed = True
                        stage = "modal-metadata"
                        result = [{**metadata, "automationId": element.CurrentAutomationId,
                                   "name": (element.CurrentName or "")[:256],
                                   "controlType": uia.known_control_type_ids[element.CurrentControlType],
                                   "isDialog": is_dialog, "windowPatternIsModal": window_pattern_is_modal}]
                        self.modal_inspection_diagnostics.append({
                            **context,
                            "status": "modal-present", "hwnd": window.hwnd, "attempt": attempt,
                            "descendantCount": descendant_count, "nativeRechecks": list(native_rechecks),
                            "clientModals": result,
                        })
                        return result
                if attempt > 1:
                    stage = "owned-target-recheck"
                    require_current_target("uia-retry-after-descendants")
            except Exception as error:
                cause = _inspection_cause(error)
                # UIA_E_ELEMENTNOTAVAILABLE and an invalid HWND are the only
                # recognized disappearance races. Access denied, RPC failure,
                # unsupported/invalid properties and unknown failures stay fatal.
                stale = (cause.get("hresultHex") in {"0x80040201", "0x80070578"}
                         or cause.get("winerror") == 1400)
                retry = stale and attempt == 1 and not modal_confirmed
                diagnostic = {
                    **context,
                    "api": "UIAutomation", "failureStage": stage, "hwnd": window.hwnd,
                    "pid": window.pid, "attempt": attempt, **metadata, "cause": cause,
                    "descendantCount": descendant_count, "nativeRechecks": list(native_rechecks),
                    "classification": "stale-element-race" if stale else "inspection-failure",
                    "status": "retry-fresh-scan" if retry else "failed",
                }
                property_id = {"visibility": 30022, "is-dialog": 30174,
                               "window-pattern-available": 30044, "window-is-modal": 30077}.get(stage)
                if property_id is not None:
                    diagnostic["propertyId"] = property_id
                if modal_confirmed:
                    diagnostic["modalConfirmed"] = True
                failures.append(diagnostic)
                self.modal_inspection_diagnostics.append(diagnostic)
                if retry:
                    continue
                raise ClientModalInspectionError({**diagnostic, "attempts": failures}) from error
            if failures:
                self.modal_inspection_diagnostics.append({
                    **context,
                    "status": "recovered-fresh-scan", "hwnd": window.hwnd, "attempt": attempt,
                    "inspectedDescendants": descendant_count, "descendantCount": descendant_count,
                    "nativeRechecks": list(native_rechecks),
                })
            return []

    def save_image(self, image, path):
        image.save(path)

    def close(self, window):
        if not self._user32().PostMessageW(window.hwnd, 0x0010, 0, 0):
            raise RuntimeError("Posting WM_CLOSE to the owned window failed")

    def wait_exit(self, timeout):
        if self.process is None:
            return True
        try:
            self.process.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def kill_owned_tree(self):
        if self.process is None or self.process.poll() is not None:
            return
        subprocess.run(
            ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
        self.process.wait(timeout=5)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--engine", type=Path,
        help="Explicit engine executable seeded only into the new isolated profile")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-only", action="store_true", required=True)
    parser.add_argument("--theme", choices=["dark"], required=True)
    parser.add_argument("--width", type=int, default=1600)
    parser.add_argument("--height", type=int, default=1000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--diagnostic-interventions", action="store_true")
    parser.add_argument("--detail-render-probe", action="store_true",
        help="Add non-mutating ImageGrab/RenderTargetBitmap/ImageGrab comparisons for each FindingDetail")
    parser.add_argument("--detail-root-render-probe", action="store_true",
        help="Add non-mutating ImageGrab/Detail-RTB/root-RTB/ImageGrab comparisons for each FindingDetail")
    parser.add_argument("--detail-spacing-probe-round", type=int, choices=range(0, 6), default=0,
        help="QA-only one-shot F11 Detail CharacterSpacing probe in the selected round; 0 disables it")
    parser.add_argument("--detail-brush-probe-round", type=int, choices=range(0, 6), default=0,
        help="QA-only one-shot F12 Detail fresh-brush probe in the selected round; 0 disables it")
    parser.add_argument("--print-window-detail-capture", action="store_true",
        help="Add a non-mutating PrintWindow comparison after each FindingDetail screen capture")
    parser.add_argument("--window-timeout", type=float, default=30.0)
    parser.add_argument("--action-timeout", type=float, default=10.0)
    parser.add_argument("--exit-timeout", type=float, default=15.0)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    evidence = run(args, WindowsLiveBackend())
    print(json.dumps(evidence, indent=2, ensure_ascii=False))
    return 0 if evidence["status"] == "independent-live-window-captured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
