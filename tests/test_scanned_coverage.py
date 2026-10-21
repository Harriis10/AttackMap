"""Actual scanner acceptance, unique coverage and declared producer versions."""
from pathlib import Path

import pytest

from attackmap.analyzers import analyze_repository, merge_analyzer_results
from attackmap.analyzer_contracts import AnalyzerMetadata
from attackmap.config_scanner import scan_config_repo
from attackmap.index import RepoIndex
from attackmap.models import Route, ScanResult, Signal, SignalOrigin
from attackmap.scanner import scan_files
from attackmap.signal_provenance import stamp_scan_provenance


def test_source_enumerates_accepted_files_without_requiring_a_signal(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "32")
    for name, content in (("silent.py", b"x = 1\n"), ("other.js", b"let x = 1;\n"),
                          ("unsupported.txt", b"nothing"), ("oversized.py", b"x" * 33),
                          ("undecodable.py", b"\xff")):
        (tmp_path / name).write_bytes(content)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "skip.py").write_text("x=1")
    result = scan_files(tmp_path, suffixes={".py"})
    assert result.scanned_files == ["silent.py"] and result.files_scanned == 1
    assert result.routes == []


@pytest.mark.parametrize("indexed", [False, True])
def test_config_enumerates_only_successfully_read_accepted_files(tmp_path, monkeypatch, indexed):
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "32")
    for name, content in (("silent.yaml", b"setting: true\n"), ("package.json", b"{}"),
                          ("oversized.yaml", b"x" * 33), ("invalid.yaml", b"\xff"),
                          ("ignored.txt", b"text")):
        (tmp_path / name).write_bytes(content)
    result = scan_config_repo(tmp_path, index=RepoIndex.build(tmp_path) if indexed else None)
    assert result.scanned_files == ["silent.yaml"] and result.files_scanned == 1


@pytest.mark.parametrize("scanner,name", [(scan_files, "locked.py"), (scan_config_repo, "locked.yaml")])
def test_unreadable_file_is_not_enumerated(tmp_path, monkeypatch, scanner, name):
    path = tmp_path / name
    path.write_text("value = 1")
    real_open = Path.open
    denied = []

    def open_file(self, *args, **kwargs):
        if self == path:
            denied.append(self)
            raise PermissionError("fixture access denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_file)
    result = scanner(tmp_path)
    assert denied, "the scanner must reach the denied descriptor seam"
    assert result.scanned_files == [] and result.files_scanned == 0


def test_index_budget_exclusions_are_not_enumerated(tmp_path):
    (tmp_path / "a.py").write_bytes(b"x=1\n")
    (tmp_path / "b.py").write_bytes(b"x=2\n")
    index = RepoIndex.build(tmp_path, max_bytes=4)
    result = scan_files(tmp_path, index=index)
    assert set(result.scanned_files) == {item.rel for item in index.files}
    assert result.files_scanned == 1


def test_config_shared_index_preserves_skipped_directory_policy(tmp_path):
    from types import SimpleNamespace
    index = SimpleNamespace(files=[
        SimpleNamespace(rel="node_modules/ignored.yaml", text="value: true"),
        SimpleNamespace(rel="accepted.yaml", text="value: true"),
    ])
    result = scan_config_repo(tmp_path, index=index)
    assert result.scanned_files == ["accepted.yaml"] and result.files_scanned == 1


def test_overlap_counts_unique_files_and_legacy_plugin_remains_unknown():
    first = ScanResult(root=".", scanned_files=["app.py", "settings.yaml"], files_scanned=2)
    second = ScanResult(root=".", scanned_files=["app.py", "sub\\other.py"], files_scanned=2)
    merged = merge_analyzer_results([first, second])
    assert merged.scanned_files == ["app.py", "settings.yaml", "sub/other.py"]
    assert merged.files_scanned == 3
    unknown = merge_analyzer_results([first, ScanResult(root=".", files_scanned=2)])
    assert unknown.scanned_files is None and unknown.files_scanned == 4
    assert any("Unique-file coverage unavailable" in note for note in unknown.limitations)
    assert first.scanned_files == ["app.py", "settings.yaml"]


@pytest.mark.parametrize("declared", [False, True])
def test_only_declared_metadata_versions_are_propagated_and_original_result_is_owned(tmp_path, monkeypatch, declared):
    import attackmap.analyzers as analyzers

    source = ScanResult(root=str(tmp_path), scanned_files=["app.py"], files_scanned=1,
                        routes=[Route(path="/fixture", file="app.py", line=1)])

    class Analyzer:
        name = "fixture-producer"
        metadata = AnalyzerMetadata(name=name, **({"version": "7.8.9"} if declared else {}))

        def analyze(self, root):
            return source

    monkeypatch.setattr(analyzers, "run_repo_passes", lambda *args, **kwargs: None)
    result = analyze_repository(tmp_path, analyzers=[Analyzer()])
    origin = result.all_signals()[0].origins[0]
    assert origin.analyzer == "fixture-producer"
    assert origin.analyzer_version == ("7.8.9" if declared else None)
    assert origin.metadata_status == ("known" if declared else "legacy_unknown")
    assert source.routes[0].source_analyzer is None and source.signals == []
    assert ScanResult.model_validate_json(result.model_dump_json()).all_signals() == result.all_signals()


def test_specific_producer_version_is_not_fabricated_from_outer_analyzer():
    scan = ScanResult(root=".", routes=[Route(path="/nested", file="app.py", source_analyzer="nested")],
                      signals=[Signal(kind="service", label="explicit", file="service.py",
                                      origins=[SignalOrigin(analyzer="specific", analyzer_version="1.2.3", metadata_status="known")])])
    stamp_scan_provenance(scan, "outer", "9.9.9")
    by_kind = {signal.kind: signal for signal in scan.signals}
    nested = by_kind["route"].origins[0]
    assert nested.analyzer == "nested" and nested.analyzer_version is None
    assert nested.metadata_status == "legacy_unknown"
    explicit = by_kind["service"].origins[0]
    assert explicit.analyzer == "specific" and explicit.analyzer_version == "1.2.3"
