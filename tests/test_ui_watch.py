"""C31 watch correctness: debounce, pending-dirty follow-up, output exclusion.

These tests are deterministic: fake scan callbacks, monkeypatched scan starts,
and explicit record buffers. No real repositories, subprocesses, or AI calls.
"""

from __future__ import annotations

import os
import struct
import threading
import time
from pathlib import Path

import pytest

from attackmap.artifact_manifest import write_artifact_manifest
from attackmap.safe_fs import OUTPUT_MARKER
from attackmap.ui import server as ui_server
from attackmap.ui import watch as ui_watch
from attackmap.ui.run_state import GuiRunState
from attackmap.ui.server import LoopbackApp, _drain_watch_pending, _sync_watch
from attackmap.ui.watch import Watcher


def _records(*names: str) -> bytes:
    """Build one FILE_NOTIFY_INFORMATION buffer with *names* (win32 style)."""
    raw = b""
    for index, name in enumerate(names):
        encoded = name.encode("utf-16-le")
        last = index == len(names) - 1
        header = struct.pack("<III", 0 if last else 12 + len(encoded), 0x3, len(encoded))
        raw += header + encoded
    return raw


def _stop_and_join(watcher: Watcher) -> None:
    watcher.stop()
    if watcher._thread is not None:
        watcher._thread.join(timeout=2.0)


@pytest.fixture()
def gui_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> LoopbackApp:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    app = LoopbackApp()
    yield app
    if app.watcher is not None:
        _stop_and_join(app.watcher)


@pytest.fixture()
def started_scans(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    def fake_start(app: LoopbackApp, body: dict) -> None:
        calls.append(app.repository_key)
    monkeypatch.setattr(ui_server, "_start_scan_locked", fake_start)
    return calls


def test_burst_collapses_into_one_scan(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    calls: list[int] = []
    fired = threading.Event()

    def on_quiet() -> None:
        calls.append(1)
        fired.set()

    watcher = Watcher(repo, tmp_path / "out", on_quiet, debounce_s=0.05)
    watcher.enabled = True  # armed without the platform event thread
    try:
        for _ in range(6):
            watcher._schedule()
            time.sleep(0.005)
        assert fired.wait(3.0)
        time.sleep(0.3)  # a second firing must not appear after the burst
        assert calls == [1]
    finally:
        _stop_and_join(watcher)


def test_change_during_analysis_is_pending_not_lost(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    scans: list[str] = []
    running = threading.Event()

    watcher = Watcher(
        repo, tmp_path / "out", lambda: scans.append("scan"),
        debounce_s=0.01, is_running=running.is_set,
    )
    watcher.notify()
    assert scans == ["scan"]
    running.set()
    watcher.notify()
    watcher.notify()  # whole burst during analysis
    assert scans == ["scan"]  # no scan overlaps the active run
    assert watcher.pending
    running.clear()
    assert watcher.take_pending() is True  # exactly one follow-up claim
    assert watcher.take_pending() is False


def test_follow_up_after_run_completes_exactly_once(
    gui_app: LoopbackApp, started_scans: list[str], tmp_path: Path,
) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    gui_app.watch = True
    gui_app.repos = [repo]  # setter syncs the watcher
    watcher = gui_app.watcher
    assert watcher is not None

    watcher.notify()  # idle: the change starts a scan
    assert len(started_scans) == 1

    gui_app.runner.running = True
    watcher.notify()  # burst during analysis
    watcher.notify()
    assert len(started_scans) == 1
    assert watcher.pending

    # Drain while a run is still active keeps the burst pending.
    gui_app._run_state = GuiRunState.RUNNING
    _drain_watch_pending(gui_app)
    assert watcher.pending

    gui_app._run_state = GuiRunState.SUCCEEDED
    gui_app.runner.running = False
    _drain_watch_pending(gui_app)  # run completed: exactly one follow-up
    assert len(started_scans) == 2
    assert not watcher.pending
    _drain_watch_pending(gui_app)  # nothing accumulated: no further scans
    assert len(started_scans) == 2


def test_no_follow_up_without_accumulated_changes(
    gui_app: LoopbackApp, started_scans: list[str], tmp_path: Path,
) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    gui_app.watch = True
    gui_app.repos = [repo]
    assert gui_app.watcher is not None

    gui_app.watcher.notify()  # normal scan; no changes during the run
    _drain_watch_pending(gui_app)
    assert len(started_scans) == 1


def test_cancelled_run_drops_pending_without_rescan(
    gui_app: LoopbackApp, started_scans: list[str], tmp_path: Path,
) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    gui_app.watch = True
    gui_app.repos = [repo]
    watcher = gui_app.watcher
    assert watcher is not None
    watcher.mark_pending()
    gui_app._run_state = GuiRunState.CANCELLED
    _drain_watch_pending(gui_app)
    assert started_scans == []
    assert not watcher.pending  # user stopped on purpose; nothing lingers


def test_own_output_publication_under_repo_root_is_ignored(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    src = repo / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    watcher = Watcher(repo, tmp_path / "reports", lambda: None)

    # Marker directory: the engine's own OUTPUT_MARKER excludes everything.
    out = repo / "out"
    out.mkdir()
    (out / OUTPUT_MARKER).write_text("AttackMap report directory\n", encoding="utf-8")
    assert watcher.should_ignore(out / "attackmap-report.json")
    assert watcher.should_ignore(out / "nested" / "findings.json")
    assert watcher.should_ignore(out / OUTPUT_MARKER)

    # Manifest-claimed output without a marker (real helper, not a copy).
    pub = repo / "pub"
    write_artifact_manifest(
        pub, "run-1", "9.9.9", str(repo), "r", [], 0, "ok",
        {"scan": {}, "findings": []},
    )
    pub.joinpath(OUTPUT_MARKER).unlink()  # force manifest-based detection
    assert watcher.should_ignore(pub / "findings.json")
    assert watcher.should_ignore(pub / "artifact-manifest.json")
    assert not watcher.should_ignore(pub / "README.md")

    # A user file with a reserved-looking name stays an input.
    plain = repo / "plain"
    plain.mkdir()
    (plain / "attackmap-report.json").write_text('{"not": "a report"}\n', encoding="utf-8")
    assert not watcher.should_ignore(plain / "attackmap-report.json")
    assert not watcher.should_ignore(src / "a.py")

    # The win32 event path filters through the same helpers.
    scheduled: list[int] = []
    watcher._schedule = lambda: scheduled.append(1)  # type: ignore[method-assign]
    watcher._handle_records(_records("out\\attackmap-report.json", "pub\\findings.json"))
    assert scheduled == []
    watcher._handle_records(_records("out\\x.json", "src\\a.py"))
    assert scheduled == [1]


def test_switching_repos_stops_previous_watcher(
    gui_app: LoopbackApp, tmp_path: Path,
) -> None:
    first_repo = tmp_path / "a"
    second_repo = tmp_path / "b"
    first_repo.mkdir()
    second_repo.mkdir()

    gui_app.watch = True
    gui_app.repos = [first_repo]
    first_watcher = gui_app.watcher
    assert first_watcher is not None
    assert first_watcher.repo == first_repo

    gui_app.repos = [second_repo]
    assert first_watcher.enabled is False  # previous watcher stopped
    assert gui_app.watcher is not None
    assert gui_app.watcher is not first_watcher
    assert gui_app.watcher.repo == second_repo

    same = gui_app.watcher
    gui_app.repos = [second_repo]  # unchanged selection: no restart churn
    assert gui_app.watcher is same

    gui_app.repos = []
    assert gui_app.watcher is None


def test_watcher_not_created_when_watch_disabled(gui_app: LoopbackApp, tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    gui_app.watch = False
    gui_app.repos = [repo]
    assert gui_app.watcher is None


def test_watch_notice_is_honest_about_coverage(
    gui_app: LoopbackApp, tmp_path: Path,
) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()

    assert gui_app.state()["watchNotice"] is None  # watch off: nothing claimed
    gui_app.watch = True
    gui_app.repos = [one]
    if os.name == "nt":
        assert gui_app.state()["watchNotice"] is None  # single repo, covered
    gui_app.repos = [one, two]  # fleet: explicit single-repo restriction
    notice = gui_app.state()["watchNotice"]
    assert notice is not None and "1 of 2" in notice


def test_watch_notice_names_unsupported_platform(
    gui_app: LoopbackApp, monkeypatch: pytest.MonkeyPatch,
) -> None:
    gui_app.watch = True
    notice = ui_server._watch_notice(gui_app, platform="posix")
    assert notice is not None and "Windows" in notice


def test_watcher_reports_platform_limitation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    monkeypatch.setattr(ui_watch, "_PLATFORM", "posix")
    watcher = Watcher(repo, tmp_path / "out", lambda: None)
    assert not watcher.supported
    watcher.start()
    try:
        assert watcher.limitation is not None and "Windows" in watcher.limitation
    finally:
        _stop_and_join(watcher)


def test_sync_watch_wires_is_running_and_pending(
    gui_app: LoopbackApp, started_scans: list[str], tmp_path: Path,
) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    gui_app.watch = True
    gui_app.repos = [repo]
    watcher = gui_app.watcher
    assert watcher is not None
    assert watcher.is_running is not None
    gui_app.runner.running = True
    assert watcher.is_running() is True
    watcher.on_quiet()  # on_quiet marks pending instead of dropping
    assert watcher.pending
    assert started_scans == []
    gui_app.runner.running = False
    assert watcher.is_running() is False


def test_enabling_and_disabling_watch_manages_the_watcher(
    gui_app: LoopbackApp, tmp_path: Path,
) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    gui_app.repos = [repo]
    assert gui_app.watcher is None  # watch off at first
    _sync_watch(gui_app)
    assert gui_app.watcher is None
    gui_app.watch = True
    _sync_watch(gui_app)
    assert gui_app.watcher is not None and gui_app.watcher.enabled
    gui_app.watch = False
    _sync_watch(gui_app)
    assert gui_app.watcher is None
