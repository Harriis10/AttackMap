"""WP033 captured enumeration/bytes and cache identity regressions."""
from pathlib import Path
import json
import shutil

import pytest

from attackmap.index import RepoIndex, PassSources, clear_pinned_index
from attackmap.sbom import analyze_sbom
from attackmap.workflow_scanner import scan_workflows
from attackmap.supply_chain import scan_supply_chain
from attackmap.sdk.fs import iter_repo_files, read_source


@pytest.fixture(autouse=True)
def unpin():
    clear_pinned_index()
    yield
    clear_pinned_index()


def test_deleted_manifest_and_workflow_enumeration_stays_captured(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    (repo / "package.json").write_text(json.dumps({"dependencies": {"express": "*"}}), encoding="utf-8")
    workflow.write_text("on: pull_request\njobs:\n  test:\n    runs-on: self-hosted\n    steps:\n      - uses: actions/checkout@main\n", encoding="utf-8")
    index = RepoIndex.build(repo)
    expected = ([x.model_dump() for x in analyze_sbom(repo, index=index)],
                [x.model_dump() for x in scan_workflows(repo, index=index)],
                [x.model_dump() for x in scan_supply_chain(repo, index=index)])
    assert expected[0] and expected[1] and expected[2]
    (repo / "package.json").unlink()
    workflow.unlink()
    workflow.parent.rmdir()
    (repo / "package-lock.json").write_text("{}", encoding="utf-8")
    def forbidden(*args, **kwargs):
        raise AssertionError("Analyzer re-read or enumerated the live source tree")
    with monkeypatch.context() as guard:
        guard.setattr(Path, "iterdir", forbidden)
        guard.setattr(Path, "read_text", forbidden)
        guard.setattr(Path, "read_bytes", forbidden)
        actual = ([x.model_dump() for x in analyze_sbom(repo, index=index)],
                  [x.model_dump() for x in scan_workflows(repo, index=index)],
                  [x.model_dump() for x in scan_supply_chain(repo, index=index)])
    assert actual == expected
    assert not PassSources.for_root(repo).exists("package-lock.json")
    assert index.snapshot.verify(repo).state == "drifted"


@pytest.mark.parametrize("raw", [b"plain\r\nsecond\rthird\n", b"\xef\xbb\xbfBOM\r\n", b"price \x80 caf\xe9\r\n", b"legacy\x81\r\n"])
def test_sdk_capture_preserves_original_decoding_and_newlines(tmp_path, raw, monkeypatch):
    source = tmp_path / "legacy.py"
    source.write_bytes(raw)
    expected = read_source(source, root=tmp_path)
    index = RepoIndex.build(tmp_path)
    source.unlink()
    (tmp_path / "added.py").write_text("not captured", encoding="utf-8")
    with monkeypatch.context() as guard:
        guard.setattr(Path, "read_bytes", lambda *a, **k: (_ for _ in ()).throw(AssertionError("live SDK read")))
        guard.setattr(Path, "stat", lambda *a, **k: (_ for _ in ()).throw(AssertionError("live SDK stat")))
        assert [p.name for p in iter_repo_files(tmp_path)] == ["legacy.py"]
        assert read_source(source, root=tmp_path) == expected
        assert read_source(tmp_path / "added.py", root=tmp_path) is None
    assert index.captured_source_bytes == len(raw)
    assert index.snapshot.verify(tmp_path).deleted == ("legacy.py",)


def test_sdk_binary_enumeration_and_source_filters_remain_explicit(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "binary.py").write_bytes(b"\0\xff\x01")
    (tmp_path / "src" / "app.py").write_bytes(b"print('ok')\r\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "bundled.py").write_text("vendor", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    assert sorted(p.name for p in iter_repo_files(tmp_path)) == ["app.py", "binary.py"]
    assert read_source(tmp_path / "src" / "binary.py", root=tmp_path) is None
    assert [p.name for p in iter_repo_files(tmp_path, names={"app.py"})] == ["app.py"]
    assert index.snapshot.verify(tmp_path).state == "verified"


def test_raw_snapshot_identity_distinguishes_line_endings_and_preserves_legacy(tmp_path):
    from attackmap.index import ScanSnapshot
    source = tmp_path / "source.py"
    source.write_bytes(b"print('ok')\n")
    first = RepoIndex.build(tmp_path).snapshot
    source.write_bytes(b"print('ok')\r\n")
    second = RepoIndex.build(tmp_path).snapshot
    assert first.files == second.files  # established core text basis remains normalized
    assert first.raw_files != second.raw_files and first.snapshot_id != second.snapshot_id
    assert first.verify(tmp_path).changed == ("source.py",)
    source.write_bytes(b"\xef\xbb\xbfprint('ok')\n")
    third = RepoIndex.build(tmp_path).snapshot
    assert third.raw_files != first.raw_files and third.snapshot_id != first.snapshot_id
    encoded = third.identity().model_dump()
    assert ScanSnapshot.from_identity(encoded).snapshot_id == third.snapshot_id
    legacy = dict(encoded)
    legacy.pop("raw_files")
    restored = ScanSnapshot.from_identity(legacy)
    assert restored.raw_files == ()
    assert restored.snapshot_id == ScanSnapshot._id_for(restored.files)


def test_changed_exclusion_marker_marks_snapshot_incomplete(tmp_path):
    directory = tmp_path / "source"
    directory.mkdir()
    (directory / "app.py").write_text("print('captured')", encoding="utf-8")
    index = RepoIndex.build(tmp_path)
    (directory / ".attackmap-output").write_text("new exclusion", encoding="utf-8")
    verification = index.snapshot.verify(tmp_path)
    assert verification.state == "drifted" and verification.changed == ("source/app.py",)


def test_sdk_sidecar_count_limit_is_visible_without_tightening_core_count(tmp_path):
    (tmp_path / "a-legacy.py").write_bytes(b"caf\xe9")
    (tmp_path / "b-legacy.py").write_bytes(b"caf\xe9")
    (tmp_path / "c-core.py").write_text("core = True", encoding="utf-8")
    index = RepoIndex.build(tmp_path, max_files=1)
    assert index.get("c-core.py") is not None
    assert len(index.sources) == 1
    assert any("SDK coverage is partial" in line for line in index.limitations)
    assert "repo_index.index_files" in index.resource_limit_scopes
    assert any(event.producer == "repo_index" and event.category == "index_files" for event in index.resource_limit_events)


def test_growth_between_stat_and_capture_cannot_exceed_aggregate_budget(tmp_path, monkeypatch):
    source = tmp_path / "growing.py"
    source.write_bytes(b"x")
    original_open = Path.open
    def grow_before_open(path, mode="r", *args, **kwargs):
        if path == source and mode == "rb":
            with original_open(path, "wb") as writer:
                writer.write(b"ten-bytes!")
        return original_open(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, "open", grow_before_open)
    index = RepoIndex.build(tmp_path, max_bytes=5)
    assert not index.files and not index.sources
    assert any(event.category == "index_bytes" for event in index.resource_limit_events)


def test_unreadable_extractor_identity_is_uncacheable(monkeypatch):
    from attackmap.incremental import engine_identity
    original = Path.read_bytes
    def unreadable(path):
        if path.name == "scanner.py":
            raise OSError("source identity unavailable")
        return original(path)
    monkeypatch.setattr(Path, "read_bytes", unreadable)
    with pytest.raises(OSError, match="Cannot prove"):
        engine_identity()


def test_model_schema_change_invalidates_extractor_identity(monkeypatch):
    from attackmap.incremental import engine_identity
    previous = engine_identity()
    original = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: original(path) + (b"\n# changed schema" if path.name == "models.py" else b""))
    assert engine_identity() != previous


def test_explicit_incremental_false_overrides_inherited_cli_environment(tmp_path, monkeypatch):
    import attackmap.scanner as scanner
    from attackmap.analyzers import analyze_repository, BuiltinPythonWebAnalyzer
    from attackmap.scan_service import ScanRequest, _analyze_options
    (tmp_path / "app.py").write_text("from flask import Flask\napp=Flask(__name__)\n@app.route('/items')\ndef items(): return []\n", encoding="utf-8")
    monkeypatch.setenv("ATTACKMAP_INCREMENTAL", "1")
    monkeypatch.setattr(scanner, "_open_incremental_cache", lambda *a, **k: (_ for _ in ()).throw(AssertionError("explicit disabled request opened cache")))
    options = _analyze_options(ScanRequest(repo_paths=[tmp_path], output=tmp_path.parent / "reports", incremental=False), tmp_path, tmp_path.parent / "reports", None)
    assert options.incremental is False
    result = analyze_repository(tmp_path, analyzers=[BuiltinPythonWebAnalyzer()], incremental=options.incremental)
    assert result.routes


def test_full_incremental_findings_provenance_and_coverage_across_100_edits(tmp_path, monkeypatch):
    from attackmap.index import active_index_for
    from attackmap.scanner import scan_files, run_repo_passes
    from attackmap.recon_to_analysis import translate_recon
    from attackmap.signal_provenance import merge_normalized_signals
    import attackmap.incremental as cache_module
    repo = tmp_path / "repo"
    shutil.copytree(Path(__file__).parent / "fixtures" / "snapshot-shop", repo)
    cache = tmp_path / "cache"
    cache_file = cache / "per-file-cache.json"
    source = (repo / "app.py").read_text(encoding="utf-8")
    (repo / "package.json").write_text('{"dependencies":{"express":"*"}}', encoding="utf-8")
    (repo / "tests").mkdir(exist_ok=True)
    (repo / "tests" / "test_route.py").write_text("from flask import Flask\napp=Flask(__name__)\n@app.route('/test')\ndef test(): return []\n", encoding="utf-8")
    (repo / "generated").mkdir()
    (repo / "generated" / "source.py").write_text("from flask import Flask\napp=Flask(__name__)\n@app.route('/generated')\ndef generated(): return []\n", encoding="utf-8")
    exact_engine_identity = cache_module.engine_identity()
    schema_epoch = 0

    def canonical(incremental):
        scan = scan_files(repo, incremental=incremental, cache_dir=cache)
        index = active_index_for(repo)
        run_repo_passes(scan, repo, index=index)
        analysis = translate_recon(scan, index=index)
        observations = [(s.observation_id, s.kind, s.file) for s in merge_normalized_signals(scan.all_signals())]
        return json.dumps([scan.model_dump(mode="json"), [f.model_dump(mode="json") for f in analysis.findings], observations], sort_keys=True), scan, analysis

    _, initial, initial_analysis = canonical(False)
    assert initial.routes and initial.dependencies and initial_analysis.findings
    for sequence in range(100):
        operation = sequence % 10
        if operation == 0:
            current = repo / ("app.py" if (repo / "app.py").exists() else "renamed.py")
            current.write_text(source.replace("/api/orders", f"/api/orders-{sequence}"), encoding="utf-8")
        elif operation == 1:
            (repo / "package.json").write_text(json.dumps({"dependencies": {"express": f"{sequence}.0.0"}}), encoding="utf-8")
        elif operation == 2:
            (repo / ".attackmap.yaml").write_text(f"internal_prefixes: ['private-{sequence}']\n", encoding="utf-8")
        elif operation == 3:
            old = repo / "app.py"
            new = repo / "renamed.py"
            if old.exists():
                old.rename(new)
            else:
                new.rename(old)
        elif operation == 4:
            (repo / "extra.py").write_text(source, encoding="utf-8")
        elif operation == 5:
            (repo / "extra.py").unlink()
        elif operation == 6:
            if sequence % 20 == 6:
                monkeypatch.setenv("ATTACKMAP_INCLUDE_TESTS", "1")
            else:
                monkeypatch.delenv("ATTACKMAP_INCLUDE_TESTS", raising=False)
        elif operation == 7:
            marker = repo / "generated" / ".attackmap-output"
            if marker.exists():
                marker.unlink()
            else:
                marker.write_text("generated output", encoding="utf-8")
        elif operation == 8:
            schema_epoch += 1
            monkeypatch.setattr(cache_module, "engine_identity", lambda: exact_engine_identity + f":upgrade-{schema_epoch}")
        else:
            cache_file.write_text('{"truncated":', encoding="utf-8")
        full, full_scan, _ = canonical(False)
        if operation == 6:
            assert any(route.path == "/test" for route in full_scan.routes) == (sequence % 20 == 6)
        incremental, _, _ = canonical(True)
        assert full == incremental, f"full/incremental divergence at edit {sequence} operation {operation}"
