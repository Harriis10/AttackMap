"""Byte fidelity and publication boundaries of the new-report-only writer."""
import ctypes
import json
import os
from pathlib import Path
import tempfile

import pytest

from artifact_fixture import write_generation
from attackmap import safe_fs
from attackmap.artifact_publisher import CURRENT_POINTER, current_generation, publish_generation, validate_generation
from attackmap.models import ScanResult
from attackmap.report import write_reports


@pytest.fixture
def previous_generation(tmp_path):
    base = tmp_path / "published"
    old = base / "prior"
    write_generation(old)
    publish_generation(base, "prior")
    pointer = (base / CURRENT_POINTER).read_bytes()
    def unchanged():
        assert (base / CURRENT_POINTER).read_bytes() == pointer
        assert current_generation(base) == old
        validate_generation(old)
    return unchanged


def _security(path):
    if os.name != "nt":
        return path.stat().st_mode, path.stat().st_uid, path.stat().st_gid
    from ctypes import wintypes
    api = ctypes.WinDLL("advapi32", use_last_error=True).GetFileSecurityW
    api.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    api.restype = wintypes.BOOL
    size = wintypes.DWORD()
    api(str(path), 7, None, 0, ctypes.byref(size))
    buffer = ctypes.create_string_buffer(size.value)
    if not api(str(path), 7, buffer, len(buffer), ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw[:size.value]


@pytest.mark.parametrize("value", [None, {}, [], {"z": 1, "a": 2},
    {"nested": [True, False, None, {}, [], {"text": 'line\n\t"\\é😀'}]},
    {1: "integer", None: "null", False: "boolean"},
    {"floats": [-0.0, 1e-30, float("nan"), float("inf"), float("-inf")]},
    {"long": "x" * 70000, "nested_keys": {1: ["a"], None: {"b": "c"}}}])
def test_exact_legacy_json_bytes_new_and_existing(tmp_path, monkeypatch, value):
    target = tmp_path / "report.json"
    expected = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    safe_fs.safe_write_json_report(tmp_path, target, value)
    assert target.read_bytes() == expected
    inode, security = target.stat().st_ino, _security(target)
    monkeypatch.setattr(tempfile, "TemporaryFile", lambda **kwargs: pytest.fail("existing destination staged"))
    safe_fs.safe_write_json_report(tmp_path, target, value)
    assert target.read_bytes() == expected
    assert target.stat().st_ino == inode and _security(target) == security


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("kind", ["dict", "list"])
def test_cycles_fail_before_destination_open(tmp_path, existing, kind):
    value = {} if kind == "dict" else []
    if kind == "dict":
        value["self"] = value
    else:
        value.append(value)
    target = tmp_path / "report.json"
    if existing:
        target.write_bytes(b"prior")
    with pytest.raises(ValueError, match="Circular"):
        safe_fs.safe_write_json_report(tmp_path, target, value)
    assert target.read_bytes() == b"prior" if existing else not target.exists()
    assert not list(tmp_path.glob(".report-stage-*"))


def test_existing_branch_preserves_encoding_before_path_error(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    target = tmp_path / "outside.json"
    target.write_bytes(b"prior")
    monkeypatch.setattr(tempfile, "TemporaryFile", lambda **kwargs: pytest.fail("existing destination staged"))
    with pytest.raises(TypeError):
        safe_fs.safe_write_json_report(out, target, {"bad": object()})
    with pytest.raises(safe_fs.UnsafePathError):
        safe_fs.safe_write_json_report(out, target, {})
    assert target.read_bytes() == b"prior"


class _TempProxy:
    def __init__(self, handle, phase="none"):
        self.handle, self.phase = handle, phase
    @property
    def name(self):
        raise AssertionError("application accessed temporary pathname")
    def __enter__(self):
        self.handle.__enter__()
        return self
    def __exit__(self, *args):
        result = self.handle.__exit__(*args)
        if self.phase == "temp_close":
            raise OSError("temporary close fault")
        return result
    def write(self, value):
        if self.phase == "stage_write":
            raise OSError("stage write fault")
        return self.handle.write(value)
    def flush(self):
        if self.phase == "stage_flush":
            raise OSError("stage flush fault")
        return self.handle.flush()
    def seek(self, where):
        if self.phase == "stage_seek":
            raise OSError("stage seek fault")
        return self.handle.seek(where)
    def read(self, size):
        assert size == 65536
        if self.phase == "copy_read":
            raise OSError("copy read fault")
        return self.handle.read(size)


@pytest.mark.parametrize("phase", ["encoder", "stage_write", "stage_flush", "stage_seek",
                                   "copy_read", "copy_write", "target_fdopen", "temp_close"])
def test_failure_phase_and_prior_generation(tmp_path, monkeypatch, previous_generation, phase):
    target = tmp_path / "report.json"
    original_temp, fdopen = tempfile.TemporaryFile, os.fdopen
    monkeypatch.setattr(tempfile, "TemporaryFile", lambda **kw: _TempProxy(original_temp(**kw), phase))
    class CopyFault:
        def __init__(self, handle):
            self.handle = handle
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.handle.close()
        def write(self, chunk):
            self.handle.write(chunk[:5])
            self.handle.flush()
            raise OSError("final copy write fault")
    def wrapped(fd, mode, *args, **kwargs):
        if phase == "target_fdopen" and mode == "wb":
            raise OSError("target wrapping fault")
        handle = fdopen(fd, mode, *args, **kwargs)
        return CopyFault(handle) if phase == "copy_write" and mode == "wb" else handle
    monkeypatch.setattr(os, "fdopen", wrapped)
    value = {"bad": object()} if phase == "encoder" else {"new": "complete stage"}
    with pytest.raises((TypeError, OSError)):
        safe_fs.safe_write_json_report(tmp_path, target, value)
    if phase in ("encoder", "stage_write", "stage_flush", "stage_seek"):
        assert not target.exists()
    else:
        assert target.exists()
        expected_size = {"copy_read": 0, "copy_write": 5, "target_fdopen": 0, "temp_close": 30}[phase]
        assert target.stat().st_size == expected_size
    assert not list(tmp_path.glob(".report-stage-*"))
    previous_generation()


@pytest.mark.parametrize("when", ["before_final_recheck", "after_final_recheck"])
@pytest.mark.parametrize("kind", ["regular", "symlink", "hardlink"])
def test_concurrent_destination_is_refused(tmp_path, monkeypatch, previous_generation, when, kind):
    target, actor = tmp_path / "report.json", tmp_path / "actor.json"
    actor.write_bytes(b"actor-owned")
    checked, opened = safe_fs._check_output_target, safe_fs._open_output_fd
    count, created = 0, []
    def appear():
        try:
            if kind == "regular":
                target.write_bytes(b"actor-owned")
            elif kind == "symlink":
                target.symlink_to(actor)
            else:
                os.link(actor, target)
        except OSError as error:
            pytest.skip(f"Owned {kind} fixture unavailable: {error}")
        created.append((target.stat().st_ino, _security(target)))
    def check(out, path):
        nonlocal count
        if path == target:
            count += 1
            if when == "before_final_recheck" and count == 2:
                appear()
        return checked(out, path)
    def open_fd(out, path, flags):
        if path == target and when == "after_final_recheck":
            appear()
        return opened(out, path, flags)
    monkeypatch.setattr(safe_fs, "_check_output_target", check)
    monkeypatch.setattr(safe_fs, "_open_output_fd", open_fd)
    with pytest.raises((FileExistsError, safe_fs.UnsafePathError)):
        safe_fs.safe_write_json_report(tmp_path, target, {"new": "must not overwrite"})
    assert target.read_bytes() == actor.read_bytes() == b"actor-owned"
    assert (target.stat().st_ino, _security(target)) == created[0]
    assert not list(tmp_path.glob(".report-stage-*"))
    previous_generation()


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows delete-on-close substitution")
@pytest.mark.parametrize("kind", ["regular", "hardlink"])
def test_temp_name_substitution_preserves_held_bytes_and_actor(tmp_path, monkeypatch, kind):
    target, moved, actor = tmp_path / "report.json", tmp_path / "moved.tmp", tmp_path / "actor.json"
    actor.write_bytes(b"foreign must survive")
    factory, observations = tempfile.TemporaryFile, {}
    class Swap(_TempProxy):
        def seek(self, where):
            result = self.handle.seek(where)
            name = Path(self.handle.name)  # Test actor only; writer must not access it.
            try:
                name.rename(moved)
            except OSError as error:
                pytest.skip(f"Windows denied actual temporary rename: {error}")
            if kind == "regular":
                name.write_bytes(b"foreign must survive")
            else:
                os.link(actor, name)
            observations["foreign"] = name
            return result
    monkeypatch.setattr(tempfile, "TemporaryFile", lambda **kw: Swap(factory(**kw)))
    value = {"held": "original bytes"}
    safe_fs.safe_write_json_report(tmp_path, target, value)
    assert target.read_bytes() == (json.dumps(value, indent=2) + "\n").encode()
    assert observations["foreign"].read_bytes() == actor.read_bytes() == b"foreign must survive"
    assert not moved.exists()


def test_report_return_and_existing_overwrite_bytes_are_unchanged(tmp_path, monkeypatch):
    scan = ScanResult(root="fixture", languages=["python"])
    before = scan.model_dump_json()
    for existing in (False, True):
        if existing:
            monkeypatch.setattr(tempfile, "TemporaryFile", lambda **kw: pytest.fail("overwrite staged"))
        result = write_reports(tmp_path, scan, "architecture", "surface", "review", [], [], [])
        assert (tmp_path / "attackmap-report.json").read_bytes() == (json.dumps(result, indent=2) + "\n").encode()
        assert scan.model_dump_json() == before
