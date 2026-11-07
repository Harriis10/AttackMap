"""WP033 regressions: source excerpts must match the analyzed raw snapshot."""

import hashlib
import json
from pathlib import Path

import pytest

from attackmap.artifact_manifest import write_artifact_manifest
from attackmap.citations import capture_source_spans
from attackmap.index import RepoIndex, clear_pinned_index


@pytest.fixture(autouse=True)
def isolated_snapshot_pin():
    clear_pinned_index()
    yield
    clear_pinned_index()


def _source(tmp_path, raw=b"def original():\r\n    return 'captured'\r\n"):
    repo = tmp_path / "repo"
    path = repo / "src" / "app.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    return repo, path, raw


def _capture(repo, **kwargs):
    return capture_source_spans(repo, [("src/app.py", 1)], redact_line=lambda line: line,
                                **kwargs)


def _publish(tmp_path, repo, snapshot, spans):
    out = tmp_path / "reports"
    out.mkdir(exist_ok=True)
    (out / "defensive-review-llm.meta.json").write_text(json.dumps({
        "citation_context": {"sources": [span.metadata() for span in spans]},
    }), encoding="utf-8")
    manifest = write_artifact_manifest(
        out, "excerpt-regression", "test", str(repo), repo.name, [], 0, "succeeded",
        {"scan": {"root": str(repo), "scan_snapshot": snapshot}},
    )
    return json.loads(manifest.read_text(encoding="utf-8"))


def test_transient_live_mutation_cannot_enter_verified_snapshot_excerpt(tmp_path):
    repo, path, original = _source(tmp_path)
    index = RepoIndex.build(repo)
    path.write_bytes(b"def transient():\n    return 'other revision'\n")
    spans = _capture(repo)
    path.write_bytes(original)

    assert len(spans) == 1
    assert spans[0].source_sha256 == dict(index.snapshot.raw_files)["src/app.py"]
    assert spans[0].excerpt == "1: def original():\n2:     return 'captured'"
    manifest = _publish(tmp_path, repo, index.snapshot.identity().model_dump(), spans)
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["verification"]["state"] == "verified"
    assert snapshot["sources_captured"] == [{
        "path": "src/app.py", "source_sha256": hashlib.sha256(original).hexdigest(),
        "captured_under_snapshot_id": index.snapshot.snapshot_id,
    }]
    assert "snapshot_state" not in manifest["exit_state"]


def test_publication_rejects_unpinned_transient_excerpt_after_tree_is_restored(tmp_path):
    repo, path, original = _source(tmp_path)
    index = RepoIndex.build(repo)
    clear_pinned_index()
    path.write_bytes(b"def transient():\n    return 'other revision'\n")
    spans = _capture(repo)
    path.write_bytes(original)

    manifest = _publish(tmp_path, repo, index.snapshot.identity().model_dump(), spans)
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["verification"]["state"] == "unverified"
    assert snapshot["incomplete"] is True
    assert snapshot["sources_captured"] == [{
        "path": "src/app.py", "source_sha256": spans[0].source_sha256,
    }]
    assert snapshot["source_capture_verification"] == {
        "state": "unverified", "unbound_paths": ["src/app.py"],
        "basis": "sha256 of original captured bytes",
    }
    assert "src/app.py" in snapshot["limitation"]
    assert manifest["exit_state"]["snapshot_state"] == "incomplete"


def test_normalized_hash_cannot_substitute_for_absent_raw_snapshot_hash(tmp_path):
    repo, _, _ = _source(tmp_path)
    index = RepoIndex.build(repo)
    spans = _capture(repo)
    legacy = index.snapshot.identity().model_dump()
    legacy.pop("raw_files")

    manifest = _publish(tmp_path, repo, legacy, spans)
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["verification"]["state"] == "unverified"
    assert "captured_under_snapshot_id" not in snapshot["sources_captured"][0]
    assert manifest["exit_state"]["snapshot_state"] == "incomplete"


def test_pinned_capture_survives_deletion_and_does_not_discover_added_file(tmp_path):
    repo, path, raw = _source(tmp_path)
    RepoIndex.build(repo)
    path.unlink()
    (repo / "added.py").write_text("not in snapshot\n", encoding="utf-8")

    spans = capture_source_spans(repo, [("src/app.py", 1), ("added.py", 1)],
                                 redact_line=lambda line: line)
    assert len(spans) == 1
    assert spans[0].path == "src/app.py"
    assert spans[0].source_sha256 == hashlib.sha256(raw).hexdigest()


def test_pinned_capture_size_gate_uses_captured_bytes(tmp_path):
    repo, path, _ = _source(tmp_path)
    RepoIndex.build(repo)
    path.write_bytes(b"tiny\n")
    assert _capture(repo, max_file_bytes=10) == ()


def test_pinned_capture_preserves_raw_hash_and_existing_replacement_decoding(tmp_path):
    repo, path, raw = _source(tmp_path, b"# caf\xe9\r\noriginal = True\r\n")
    index = RepoIndex.build(repo)
    path.write_bytes(b"changed = True\n")
    spans = _capture(repo)
    assert spans[0].source_sha256 == hashlib.sha256(raw).hexdigest()
    assert spans[0].source_sha256 == dict(index.snapshot.raw_files)["src/app.py"]
    assert spans[0].excerpt == "1: # caf\ufffd\n2: original = True"


def test_another_repository_pin_does_not_change_direct_capture(tmp_path):
    repo, _, _ = _source(tmp_path)
    RepoIndex.build(repo)
    other = tmp_path / "other"
    path = other / "src" / "app.py"
    path.parent.mkdir(parents=True)
    raw = b"other = True\n"
    path.write_bytes(raw)
    spans = _capture(other)
    assert spans[0].source_sha256 == hashlib.sha256(raw).hexdigest()
    assert spans[0].excerpt == "1: other = True"


def test_unbound_excerpt_keeps_live_tree_drift_and_marks_run_incomplete(tmp_path):
    repo, path, _ = _source(tmp_path)
    index = RepoIndex.build(repo)
    clear_pinned_index()
    path.write_bytes(b"changed = True\n")
    spans = _capture(repo)
    manifest = _publish(tmp_path, repo, index.snapshot.identity().model_dump(), spans)
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["verification"]["state"] == "drifted"
    assert snapshot["verification"]["changed"] == ["src/app.py"]
    assert "captured_under_snapshot_id" not in snapshot["sources_captured"][0]
    assert manifest["exit_state"]["snapshot_state"] == "incomplete"
