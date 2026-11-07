"""Ordered capture preserves admission, raw bytes and diagnostics under overlap."""
import threading
import time
from pathlib import Path

import pytest

from attackmap import index as module


def capture(root, monkeypatch, workers, **kwargs):
    monkeypatch.setenv("ATTACKMAP_INDEX_READ_WORKERS", str(workers))
    result = module.RepoIndex.build(root, **kwargs)
    return (result.files, result.sources, result.limitations,
            result.resource_limit_events, result.resource_limit_scopes, result.snapshot)


@pytest.mark.parametrize("limits", [{}, {"max_files": 3}, {"max_bytes": 17},
                                  {"max_bytes": 300, "max_files": 4}])
def test_prefetch_preserves_exact_capture_and_admission(tmp_path, monkeypatch, limits):
    monkeypatch.setattr(module, "max_file_bytes", lambda: 24)
    for name, raw in [("a.py", b"a\r\nb\r\n"), ("b.py", b"\xef\xbb\xbfprint(1)"),
                      ("c.bin", b"\xff\xfe\x00"), ("d.py", b"d" * 25),
                      ("e.py", b"e" * 15), ("f.py", b"f")]:
        (tmp_path / name).write_bytes(raw)
    expected = capture(tmp_path, monkeypatch, 1, **limits)
    assert capture(tmp_path, monkeypatch, 4, **limits) == expected


@pytest.mark.parametrize("budget", [0, 300, 20])
def test_growing_and_failed_reads_keep_original_event_order(tmp_path, monkeypatch, budget):
    monkeypatch.setattr(module, "max_file_bytes", lambda: 12)
    for name in ("a.py", "b.py", "c.py", "d.py", "e.py"):
        (tmp_path / name).write_bytes(b"x")
    original = module._read_capture_bytes

    def read(path, limit):
        if path.name == "a.py":
            time.sleep(.01)  # Later completions cannot reorder diagnostics.
            raise PermissionError("fixture")
        if path.name == "b.py":
            return b"grown" * 3  # Growth beyond the per-file bound.
        if path.name == "c.py":
            return b"c" * 10  # Accepted growth or aggregate-budget rejection.
        return original(path, limit)

    monkeypatch.setattr(module, "_read_capture_bytes", read)
    kwargs = {"max_bytes": budget} if budget else {}
    expected = capture(tmp_path, monkeypatch, 1, **kwargs)
    assert capture(tmp_path, monkeypatch, 4, **kwargs) == expected
    assert "PermissionError" in expected[2][0]
    assert "grew beyond capture" in expected[2][1]


def test_pending_reads_are_bounded_and_threads_are_joined(tmp_path, monkeypatch):
    for number in range(30):
        (tmp_path / f"{number:02}.py").write_bytes(b"x")
    monkeypatch.setenv("ATTACKMAP_INDEX_READ_WORKERS", "999")
    lock = threading.Lock()
    calls = 0
    ready = threading.Event()

    def read(path, limit):
        nonlocal calls
        with lock:
            calls += 1
            if calls >= 4:
                ready.set()
        assert ready.wait(2)
        return b"x"

    monkeypatch.setattr(module, "_read_capture_bytes", read)
    iterator = module._ordered_capture_inputs(tmp_path, 12, lambda n: True)
    first = next(iterator)
    assert first[3].result() == b"x"
    # Eight submitted slots, four executing threads; no refill without consumption.
    time.sleep(.01)
    assert 4 <= calls <= 8
    iterator.close()
    assert not any(t.name.startswith("attackmap-capture") for t in threading.enumerate())


def test_tight_admission_never_reads_rejected_files(tmp_path, monkeypatch):
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_bytes(b"x")
    original = module._read_capture_bytes
    read = []

    def track(path, limit):
        read.append(path.name)
        return original(path, limit)

    monkeypatch.setattr(module, "_read_capture_bytes", track)
    monkeypatch.setenv("ATTACKMAP_INDEX_READ_WORKERS", "4")
    module.RepoIndex.build(tmp_path, max_files=1, max_bytes=1)
    assert read == ["a.py"]


def test_stat_failures_and_walk_notes_keep_source_order(tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ("a.py", "b.py", "c.py")]
    for path in paths:
        path.write_bytes(b"x")

    def walk(root, *, prune, on_symlink):
        yield paths[0]
        on_symlink(root / "middle-link")
        yield paths[1]
        yield paths[2]
        on_symlink(root / "last-link")

    original_stat = Path.stat

    def stat(path, *args, **kwargs):
        if path == paths[1]:
            raise FileNotFoundError("fixture")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(module, "walk_repo", walk)
    monkeypatch.setattr(Path, "stat", stat)
    expected = capture(tmp_path, monkeypatch, 1)
    assert capture(tmp_path, monkeypatch, 4) == expected
    assert expected[2] == ("symlink not followed: middle-link",
                           "unreadable file skipped (FileNotFoundError): b.py",
                           "symlink not followed: last-link")
