"""Sealed snapshot protocol, actual child SDK pinning and lease ownership."""
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import zipfile

import pytest

from attackmap import analyzer_host as host
from attackmap.index import RepoIndex, active_index_for, pinned_index_scope
from attackmap.snapshot_transport import (SnapshotBundle, SnapshotInputError, read_snapshot,
                                         SealedSnapshot)


def capture(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_bytes(b"/captured\r\n")
    (root / "legacy.txt").write_bytes(b"/caf\xe9\r\n")
    (root / "bom.txt").write_bytes(b"\xef\xbb\xbf/captured-bom\r\n")
    (root / "binary.dat").write_bytes(b"\0\xff")
    (root / "latin.txt").write_bytes(b"/latin\x81\r\n")
    return root, RepoIndex.build(root)


def plugin(tmp_path, monkeypatch):
    file = tmp_path / "sdk_plugin.py"
    file.write_text('''import os
from pathlib import Path
from attackmap.sdk.fs import read_source, iter_repo_files
from attackmap.models import ScanResult, Route
root_at_import = os.environ.get('WP035_CAPTURE_ROOT')
if root_at_import:
    marker = os.environ.get('WP035_IMPORT_MARKER')
    if marker: Path(marker).write_text('imported')
    imported = read_source(Path(root_at_import) / 'legacy.txt', root=root_at_import)
else:
    imported = None
class SnapshotAnalyzer:
    name = 'snapshot-sdk'
    def detect(self, root): return True
    def analyze(self, root):
        if os.environ.get('WP035_THREAD_READ'):
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(1) as pool:
                app = pool.submit(read_source, Path(root) / 'app.py', root=root).result()
        else:
            app = read_source(Path(root) / 'app.py', root=root)
        if os.environ.get('WP035_SHUTDOWN_READ'):
            import sys, threading, time
            def late_read():
                result_file = Path(sys.argv[sys.argv.index('--workdir') + 1]) / 'result.json'
                deadline = time.monotonic() + 5
                while not result_file.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                value = read_source(Path(root) / 'app.py', root=root)
                Path(os.environ['WP035_SHUTDOWN_READ']).write_bytes((value or 'MISSING').encode('utf-8'))
            threading.Thread(target=late_read).start()
        files = [p.relative_to(root).as_posix() for p in iter_repo_files(root)]
        return ScanResult(root=str(root), scanned_files=files, files_scanned=len(files), routes=[
            Route(path=imported.strip(), method='GET', file='legacy.txt', line=1),
            Route(path=app.strip(), method='GET', file='app.py', line=1)])
''', encoding="utf-8")
    module_name = "wp035_snapshot_plugin"
    spec = importlib.util.spec_from_file_location(module_name, file)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module.SnapshotAnalyzer()


def limits():
    return host.HostLimits(timeout_seconds=20, memory_bytes=0)


def rewrite(bundle, change):
    path = Path(bundle.descriptor.path)
    with zipfile.ZipFile(path) as archive:
        payloads = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(payloads["manifest.json"])
    compression = zipfile.ZIP_STORED
    duplicate = False
    if change == "version": manifest["protocol"] = "attackmap-host-input/2.0"
    elif change == "path": manifest["records"][0][0] = "../outside"
    elif change == "rawhash": manifest["records"][0][3] = "0" * 64
    elif change == "snapshot": manifest["snapshot"]["snapshot_id"] = "0" * 64
    elif change == "config": manifest["snapshot"]["config_identity"] = "0" * 64
    elif change == "compressed": compression = zipfile.ZIP_DEFLATED
    elif change == "extra": payloads["extra"] = b"unexpected"
    elif change == "duplicate": duplicate = True
    elif change == "missing": payloads.pop("payloads/00000000.bin")
    payloads["manifest.json"] = json.dumps(manifest).encode()
    if change == "duplicate_json":
        payloads["manifest.json"] = b'{"protocol":"duplicate",' + payloads["manifest.json"][1:]
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, raw in payloads.items(): archive.writestr(name, raw)
        if duplicate: archive.writestr("payloads/00000000.bin", b"duplicate")
    descriptor = replace(bundle.descriptor, archive_bytes=path.stat().st_size,
                         manifest_bytes=len(payloads["manifest.json"]),
                         archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    bundle.descriptor = descriptor


def test_roundtrip_preserves_raw_core_orders_identity_and_resource_metadata(tmp_path):
    root, index = capture(tmp_path)
    with SnapshotBundle(index) as bundle:
        restored = read_snapshot(SealedSnapshot.loads(bundle.descriptor.dumps()))
    assert restored.snapshot == index.snapshot
    assert restored.files == index.files
    assert restored.sources == index.sources
    assert restored.resource_limit_events == index.resource_limit_events
    assert restored.resource_limit_scopes == index.resource_limit_scopes
    assert restored.resource_limit_reporting == index.resource_limit_reporting


def test_scoped_pin_restores_previous_capture(tmp_path):
    root, index = capture(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    previous = RepoIndex.build(other)
    with pinned_index_scope(index):
        assert active_index_for(root) is index
    assert active_index_for(other) is previous


def test_bundle_close_waits_for_all_verified_reader_leases(tmp_path):
    _root, index = capture(tmp_path)
    bundle = SnapshotBundle(index)
    path = Path(bundle.descriptor.path)
    first, second = bundle.acquire(), bundle.acquire()
    bundle.close()
    assert path.exists()
    first.release(); first.release()
    assert path.exists()
    second.release()
    assert not path.exists()


@pytest.mark.parametrize("change", ["version", "path", "rawhash", "snapshot", "config", "compressed", "extra", "duplicate", "missing", "duplicate_json"])
def test_sealed_malformed_input_is_rejected(tmp_path, change):
    _root, index = capture(tmp_path)
    with SnapshotBundle(index) as bundle:
        rewrite(bundle, change)
        with pytest.raises(SnapshotInputError):
            read_snapshot(bundle.descriptor)


@pytest.mark.parametrize("field", ["archive_bytes", "manifest_bytes", "file_count", "total_bytes", "file_bytes", "path_chars"])
def test_parent_declared_budget_cannot_be_expanded(tmp_path, field):
    _root, index = capture(tmp_path)
    with SnapshotBundle(index) as bundle:
        descriptor = replace(bundle.descriptor, **{field: max(0, getattr(bundle.descriptor, field) - 1)})
        with pytest.raises(SnapshotInputError):
            read_snapshot(descriptor)


@pytest.mark.parametrize("threaded", [False, True])
def test_actual_child_uses_captured_bytes_and_enumeration_even_after_repo_deleted(tmp_path, monkeypatch, threaded):
    root, index = capture(tmp_path)
    analyzer = plugin(tmp_path, monkeypatch)
    monkeypatch.setenv("WP035_CAPTURE_ROOT", str(root))
    if threaded:
        monkeypatch.setenv("WP035_THREAD_READ", "1")
    with SnapshotBundle(index) as bundle:
        shutil.rmtree(root)
        outcome = host.run_isolated_analyzer(analyzer, root, limits(), index=index, bundle=bundle)
        assert outcome.ok, (outcome.error_type, outcome.message)
        assert {row.path for row in outcome.result.routes} == {"/captured", "/café"}
        assert outcome.result.scanned_files == [source.rel for source in index.sources]
        assert outcome.result.scan_snapshot == index.snapshot.identity()


def test_actual_background_sdk_read_after_analyze_scope_and_during_shutdown(tmp_path, monkeypatch):
    root, index = capture(tmp_path)
    analyzer = plugin(tmp_path, monkeypatch)
    marker = tmp_path / "shutdown-read"
    monkeypatch.setenv("WP035_CAPTURE_ROOT", str(root))
    monkeypatch.setenv("WP035_SHUTDOWN_READ", str(marker))
    with SnapshotBundle(index) as bundle:
        shutil.rmtree(root)
        outcome = host.run_isolated_analyzer(analyzer, root, limits(), index=index, bundle=bundle)
    assert outcome.ok, (outcome.error_type, outcome.message)
    assert marker.read_bytes() == b"/captured\r\n"


def test_process_pin_is_immutable_without_installing_into_parent(tmp_path, monkeypatch):
    import attackmap.index as module
    root, index = capture(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    conflicting = RepoIndex.build(other)
    # Inject the child-only starting state; restoration prevents parent/default
    # SDK behavior from changing in this test process.
    monkeypatch.setattr(module, "_PROCESS_SNAPSHOT", None)
    module.install_process_snapshot(index)
    module.install_process_snapshot(index)
    with pytest.raises(ValueError, match="cannot replace"):
        module.install_process_snapshot(conflicting)
    module.clear_pinned_index()
    assert module.active_index_for(root) is index


@pytest.mark.parametrize("change", ["rawhash", "config", "version"])
def test_actual_invalid_child_input_never_imports_plugin(tmp_path, monkeypatch, change):
    root, index = capture(tmp_path)
    analyzer = plugin(tmp_path, monkeypatch)
    marker = tmp_path / "import-marker"
    monkeypatch.setenv("WP035_CAPTURE_ROOT", str(root))
    monkeypatch.setenv("WP035_IMPORT_MARKER", str(marker))
    with SnapshotBundle(index) as bundle:
        rewrite(bundle, change)
        outcome = host.run_isolated_analyzer(analyzer, root, limits(), index=index, bundle=bundle)
    assert outcome.error_type == host.HOST_INPUT_INVALID, (outcome.error_type, outcome.message)
    assert not marker.exists()


@pytest.mark.parametrize("conflict", ["root", "snapshot"])
def test_actual_siblings_share_one_bundle_and_bad_result_does_not_invalidate_it(tmp_path, monkeypatch, conflict):
    root, index = capture(tmp_path)
    analyzer = plugin(tmp_path, monkeypatch)
    monkeypatch.setenv("WP035_CAPTURE_ROOT", str(root))
    with SnapshotBundle(index) as bundle:
        path = Path(bundle.descriptor.path)
        source = tmp_path / "sdk_plugin.py"
        original = source.read_text(encoding="utf-8")
        # Change length as well as bytes: timestamp/size pyc validation must not
        # reuse the original module during this deliberately rewritten fixture.
        replacement = "root='foreign-outside-selected-capture'," if conflict == "root" else "root=str(root), scan_snapshot={'snapshot_id':'foreign','files':{},'index_config':{},'config_identity':'foreign'},"
        source.write_text(original.replace("root=str(root),", replacement), encoding="utf-8")
        bad = host.run_isolated_analyzer(analyzer, root, limits(), index=index, bundle=bundle)
        assert bad.error_type == host.HOST_INVALID_OUTPUT, (bad.error_type, bad.message)
        source.write_text(original, encoding="utf-8")
        first = host.run_isolated_analyzer(analyzer, root, limits(), index=index, bundle=bundle)
        assert path.exists()
        second = host.run_isolated_analyzer(analyzer, root, limits(), index=index, bundle=bundle)
        assert first.ok and second.ok
        assert first.result.model_dump() == second.result.model_dump()
    assert not path.exists()


def test_core_only_utf8_preserves_partial_sdk_acceptance_and_original_size(tmp_path):
    from attackmap.sdk.fs import iter_repo_files, read_source
    root = tmp_path / "core-only"
    root.mkdir()
    (root / "a_legacy.txt").write_bytes(b"\xe9")
    (root / "z_app.py").write_bytes(b"x\r\n")
    index = RepoIndex.build(root, max_files=1)
    assert [s.rel for s in index.sources] == ["a_legacy.txt"]
    assert [f.rel for f in index.files] == ["z_app.py"]
    with SnapshotBundle(index) as bundle:
        restored = read_snapshot(bundle.descriptor)
    assert restored.snapshot == index.snapshot
    assert restored.files == index.files and restored.sources == index.sources
    assert restored.resource_limit_events == index.resource_limit_events
    with pinned_index_scope(restored):
        assert [p.name for p in iter_repo_files(root)] == ["a_legacy.txt"]
        assert read_source(root / "z_app.py", root=root) is None


def test_empty_snapshot_has_finite_zero_payload_budget(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    index = RepoIndex.build(root)
    with SnapshotBundle(index) as bundle:
        assert bundle.descriptor.total_bytes == 0
        restored = read_snapshot(bundle.descriptor)
    assert restored.snapshot == index.snapshot and not restored.files and not restored.sources


def test_stale_bundle_cannot_borrow_new_capture_identity_or_import_plugin(tmp_path, monkeypatch):
    root, original = capture(tmp_path)
    analyzer = plugin(tmp_path, monkeypatch)
    marker = tmp_path / "import-marker"
    monkeypatch.setenv("WP035_CAPTURE_ROOT", str(root))
    monkeypatch.setenv("WP035_IMPORT_MARKER", str(marker))
    with SnapshotBundle(original) as bundle:
        (root / "app.py").write_text("/new")
        current = RepoIndex.build(root)
        outcome = host.run_isolated_analyzer(analyzer, root, limits(), index=current, bundle=bundle)
    assert outcome.error_type == host.HOST_INPUT_INVALID
    assert not marker.exists()


def test_quarantined_host_retains_shared_bundle_until_verified_reader_exit(tmp_path, monkeypatch):
    import attackmap.execution as execution
    root, index = capture(tmp_path)
    analyzer = plugin(tmp_path, monkeypatch)
    state = {"verified": False}
    class Supervisor:
        timed_out = False
        running = True
        _job = None
        memory_policy = {"requested_bytes": 0, "enforced_bytes": 0, "status": "disabled"}
        def start(self, argv, *, on_done, **kwargs):
            self.done = on_done
            return True
        def wait(self, timeout): return state["verified"]
        def request_cancel(self): pass
        def retry_cleanup(self):
            if state["verified"]:
                self.done(1, "later verified cleanup")
                return True
            return False
    monkeypatch.setattr(execution, "ProcessSupervisor", Supervisor)
    bundle = SnapshotBundle(index)
    path = Path(bundle.descriptor.path)
    try:
        outcome = host.run_isolated_analyzer(analyzer, root, limits(), index=index, bundle=bundle)
        assert outcome.error_type == host.HOST_STUCK
        bundle.close()
        assert path.exists()
        # wait remains false until retry publishes the verified callback.
        supervisor = next(iter(host._QUARANTINED_HOSTS))
        monkeypatch.setattr(supervisor, "wait", lambda timeout: False)
        state["verified"] = True
        assert host._recover_quarantined_hosts()
        assert not path.exists()
    finally:
        for supervisor in list(host._QUARANTINED_HOSTS):
            state["verified"] = True
            supervisor.retry_cleanup()
        host._recover_quarantined_hosts()
        bundle.close()
