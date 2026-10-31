"""Deterministic mutation scheduling at WP033's four source-run boundaries.

Hooks mutate at actual capture/analyzer/publication boundaries. Excerpts use
the pinned raw snapshot when present. Transient changes followed by restoration
must either retain the analyzed bytes or publish an explicit unverified source
binding; a clean current tree alone cannot validate different excerpt bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import attackmap.artifact_manifest as manifest_mod
import attackmap.index as index_mod
from attackmap.analyzers import (
    BuiltinConfigAnalyzer,
    BuiltinJavaScriptWebAnalyzer,
    BuiltinPythonWebAnalyzer,
    analyze_repository,
)
from attackmap.citations import capture_source_spans, context_from_payload, validate_references
from attackmap.index import RepoIndex, clear_pinned_index
from attackmap.recon_to_analysis import translate_recon
from attackmap.safe_fs import ensure_output_dir, safe_write_text
from test_wp033_mutation_campaign import _app, _canonical, _record, _seed, _sha


@pytest.fixture
def phase_repo(tmp_path: Path, monkeypatch):
    for name in ("ATTACKMAP_INCLUDE_TESTS", "ATTACKMAP_INCLUDE_VENDORED",
                 "ATTACKMAP_INCREMENTAL", "ATTACKMAP_INDEX_BYTE_BUDGET",
                 "ATTACKMAP_INDEX_FILE_LIMIT", "ATTACKMAP_MAX_FILE_BYTES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ATTACKMAP_INDEX_READ_WORKERS", "1")
    repo = tmp_path / "repo"
    _seed(repo, 404)
    try:
        yield repo
    finally:
        clear_pinned_index()


def _analyze(repo: Path, index: RepoIndex):
    scan = analyze_repository(repo, analyzers=[BuiltinPythonWebAnalyzer(),
        BuiltinJavaScriptWebAnalyzer(), BuiltinConfigAnalyzer()],
        index=index, incremental=False, strict=True)
    analysis = translate_recon(scan, index=index)
    data = {"scan": scan.model_dump(mode="json"),
        "findings": [item.model_dump(mode="json") for item in analysis.findings],
        "attack_surfaces": [item.model_dump(mode="json") for item in analysis.attack_surfaces],
        "attack_paths": [item.model_dump(mode="json") for item in analysis.attack_paths],
        "suppressed_findings": [], "exploitability": []}
    comparable = {"findings": data["findings"],
        "provenance": [item.model_dump(mode="json") for item in scan.all_signals()],
        "scanned_files": scan.scanned_files,
        "snapshot": scan.scan_snapshot.model_dump(mode="json")}
    assert comparable["findings"] and comparable["provenance"] and comparable["scanned_files"]
    assert not scan.analyzer_errors
    return comparable, data


def _publish(repo: Path, out: Path, data: dict, spans=()):
    ensure_output_dir(out)
    safe_write_text(out, out / "attackmap-report.json", json.dumps(data))
    if spans:
        safe_write_text(out, out / "vulnerability-hypotheses.meta.json", json.dumps({
            "citation_context": {"sources": [span.metadata() for span in spans]}}))
    manifest_mod.write_artifact_manifest(output_dir=out, run_id="wp033-phase",
        engine_version="source-test", repo_root=str(repo), repo_name=repo.name,
        analyzer_metadata=[], exit_code=0, status="succeeded", report_data=data)
    return json.loads((out / "artifact-manifest.json").read_text(encoding="utf-8"))


def _captured_raw_sha(index: RepoIndex, rel: str) -> str:
    # Snapshot identities normalize CRLF; citation hashes intentionally cover
    # raw bytes. Compare the corresponding captured raw source on Windows.
    source = next(source for source in index.sources if source.rel == rel)
    return hashlib.sha256(source.raw).hexdigest()


def _incomplete(manifest: dict, phase: str, details: dict) -> None:
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["verification"]["state"] == "drifted"
    assert snapshot["verification"]["changed"] == ["src/app.py"]
    assert snapshot["incomplete"] is True
    assert manifest["exit_state"]["snapshot_state"] == "incomplete"
    assert "src/app.py" in snapshot["limitation"]
    _record(f"phase-{phase}", {"status": "PASS_WITH_DECLARED_BOUNDARY", "phase": phase,
        "published_snapshot": snapshot, **details})


def test_mutation_during_capture_pins_read_bytes_and_publishes_incomplete(phase_repo, tmp_path, monkeypatch):
    repo = phase_repo
    reference, _ = _analyze(repo, RepoIndex.build(repo))
    original = index_mod._read_capture_bytes
    events = []

    def mutate_after_read(path, limit):
        raw = original(path, limit)
        if path == repo / "src/app.py":
            path.write_text(_app("/capture-mutated/<item_id>"), encoding="utf-8")
            events.append(path.relative_to(repo).as_posix())
        return raw

    monkeypatch.setattr(index_mod, "_read_capture_bytes", mutate_after_read)
    index = RepoIndex.build(repo)
    assert events == ["src/app.py"]
    comparable, data = _analyze(repo, index)
    assert _canonical(comparable) == _canonical(reference)
    assert "/capture-mutated" not in index.get("src/app.py").text
    manifest = _publish(repo, tmp_path / "reports", data)
    _incomplete(manifest, "capture", {"result": "pinned captured bytes; live drift incomplete",
        "reference_sha256": _sha(reference), "pinned_sha256": _sha(comparable), "hook_events": events})


def test_mutation_between_analyzers_keeps_all_passes_on_one_snapshot(phase_repo, tmp_path, monkeypatch):
    repo = phase_repo
    index = RepoIndex.build(repo)
    reference, _ = _analyze(repo, index)
    original = BuiltinPythonWebAnalyzer.analyze
    events = []

    def mutate_after_python(self, root, progress=None, recall=False, index=None, incremental=None):
        result = original(self, root, progress=progress, recall=recall, index=index, incremental=incremental)
        (repo / "src/app.py").write_text(_app("/between-analyzers/<item_id>"), encoding="utf-8")
        events.append(self.name)
        return result

    monkeypatch.setattr(BuiltinPythonWebAnalyzer, "analyze", mutate_after_python)
    comparable, data = _analyze(repo, index)
    assert events == ["python-web"]
    assert _canonical(comparable) == _canonical(reference)
    manifest = _publish(repo, tmp_path / "reports", data)
    _incomplete(manifest, "detection", {"result": "pinned per-file plus whole-repository passes",
        "reference_sha256": _sha(reference), "pinned_sha256": _sha(comparable), "hook_events": events})


def test_mutation_during_section_publication_is_explicitly_incomplete(phase_repo, tmp_path, monkeypatch):
    repo = phase_repo
    comparable, data = _analyze(repo, RepoIndex.build(repo))
    original = manifest_mod.safe_write_text
    events = []

    def mutate_after_section(root, target, text):
        result = original(root, target, text)
        if target.name == "scan.json":
            (repo / "src/app.py").write_text(_app("/during-publication/<item_id>"), encoding="utf-8")
            events.append(target.name)
        return result

    monkeypatch.setattr(manifest_mod, "safe_write_text", mutate_after_section)
    manifest = _publish(repo, tmp_path / "reports", data)
    assert events == ["scan.json"]
    _incomplete(manifest, "publication", {"result": "captured analysis published with incomplete marker",
        "analysis_sha256": _sha(comparable), "hook_events": events})


def test_excerpt_after_capture_is_immutable_and_live_drift_is_incomplete(phase_repo, tmp_path):
    repo = phase_repo
    index = RepoIndex.build(repo)
    _, data = _analyze(repo, index)
    spans = capture_source_spans(repo, [("src/app.py", 5)], redact_line=lambda line: line)
    assert spans and spans[0].source_sha256 == _captured_raw_sha(index, "src/app.py")
    (repo / "src/app.py").write_text(_app("/after-excerpt/<item_id>"), encoding="utf-8")
    context = context_from_payload({}, spans, repository_root=str(repo))
    validation = validate_references("src/app.py:5", context)
    assert validation.source_reference_valid
    assert "/items/404" in validation.source_spans[0].excerpt
    assert "/after-excerpt" not in validation.source_spans[0].excerpt
    manifest = _publish(repo, tmp_path / "reports", data, spans)
    _incomplete(manifest, "excerpt-after-capture", {"result": "immutable captured span; live drift incomplete",
        "source_sha256": spans[0].source_sha256, "excerpt_sha256": spans[0].excerpt_sha256})


def test_excerpt_captured_after_index_drift_pins_raw_snapshot_and_run_is_incomplete(phase_repo, tmp_path):
    repo = phase_repo
    index = RepoIndex.build(repo)
    _, data = _analyze(repo, index)
    (repo / "src/app.py").write_text(_app("/before-excerpt/<item_id>"), encoding="utf-8")
    live_sha = hashlib.sha256((repo / "src/app.py").read_bytes()).hexdigest()
    assert live_sha != _captured_raw_sha(index, "src/app.py")
    spans = capture_source_spans(repo, [("src/app.py", 5)], redact_line=lambda line: line)
    assert spans and spans[0].source_sha256 == _captured_raw_sha(index, "src/app.py")
    assert "/items/404" in spans[0].excerpt and "/before-excerpt" not in spans[0].excerpt
    manifest = _publish(repo, tmp_path / "reports", data, spans)
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["source_capture_verification"]["state"] == "verified"
    assert snapshot["sources_captured"] == [{"path": "src/app.py",
        "source_sha256": _captured_raw_sha(index, "src/app.py"),
        "captured_under_snapshot_id": index.snapshot.snapshot_id}]
    _incomplete(manifest, "excerpt-before-capture", {
        "result": "RAW_SNAPSHOT_PINNED; persistent live drift still marks publication incomplete",
        "snapshot_raw_source_sha256": _captured_raw_sha(index, "src/app.py"),
        "live_mutated_source_sha256": live_sha, "captured_source_sha256": spans[0].source_sha256})


@pytest.mark.parametrize("pinned", [True, False], ids=["pinned-raw-A", "unpinned-raw-B-unverified"])
def test_excerpt_transient_drift_requires_matching_raw_snapshot_binding(phase_repo, tmp_path, pinned):
    repo = phase_repo
    index = RepoIndex.build(repo)
    _, data = _analyze(repo, index)
    path = repo / "src/app.py"
    original = path.read_bytes()
    path.write_text(_app("/transient-excerpt/<item_id>"), encoding="utf-8")
    transient_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert transient_sha != _captured_raw_sha(index, "src/app.py")
    if not pinned:
        clear_pinned_index()
    spans = capture_source_spans(repo, [("src/app.py", 5)], redact_line=lambda line: line)
    path.write_bytes(original)
    assert hashlib.sha256(original).hexdigest() == _captured_raw_sha(index, "src/app.py")
    assert spans
    expected_sha = _captured_raw_sha(index, "src/app.py") if pinned else transient_sha
    assert spans[0].source_sha256 == expected_sha
    manifest = _publish(repo, tmp_path / "reports", data, spans)
    snapshot = manifest["run_identity"]["snapshot"]
    source = snapshot["sources_captured"][0]
    assert source["source_sha256"] == expected_sha
    assert snapshot["verification"]["changed"] == []
    if pinned:
        assert "/items/404" in spans[0].excerpt and "/transient-excerpt" not in spans[0].excerpt
        assert snapshot["verification"]["state"] == "verified"
        assert snapshot["source_capture_verification"]["state"] == "verified"
        assert source["captured_under_snapshot_id"] == index.snapshot.snapshot_id
        assert "incomplete" not in snapshot
        assert "snapshot_state" not in manifest["exit_state"]
    else:
        assert "/transient-excerpt" in spans[0].excerpt
        assert snapshot["verification"]["state"] == "unverified"
        assert snapshot["source_capture_verification"]["state"] == "unverified"
        assert snapshot["source_capture_verification"]["unbound_paths"] == ["src/app.py"]
        assert "captured_under_snapshot_id" not in source
        assert snapshot["incomplete"] is True
        assert manifest["exit_state"]["snapshot_state"] == "incomplete"
        assert "src/app.py" in snapshot["limitation"]
    _record(f"phase-excerpt-transient-{'pinned' if pinned else 'unpinned'}", {"status": "FIX_REGRESSION_PASS",
        "capture_mode": "pinned raw A" if pinned else "unpinned raw B rejected as unverified",
        "snapshot_raw_source_sha256": _captured_raw_sha(index, "src/app.py"),
        "live_transient_source_sha256": transient_sha, "captured_source_sha256": spans[0].source_sha256,
        "published_snapshot": snapshot, "exit_state": manifest["exit_state"]})
