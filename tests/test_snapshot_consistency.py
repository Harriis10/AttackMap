"""C33 / AM047: every pass, fingerprint and AI excerpt references ONE snapshot.

Mutation tests at the four roadmap phases — indexing, detection, report
writing, excerpt extraction. Each simulates a mid-scan file change by direct
two-phase invocation (build index, mutate, continue) so the tests stay
deterministic and fast. Policy under drift: the run is marked incomplete with
an explicit limitation; nothing retries in a loop.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from attackmap.analyzers import BuiltinPythonWebAnalyzer, analyze_repository
from attackmap.artifact_manifest import write_artifact_manifest
from attackmap.citations import capture_source_spans, context_from_payload, validate_references
from attackmap.fingerprint import assign_fingerprints
from attackmap.index import RepoIndex, content_sha256
from attackmap.models import Finding, FindingLocation, ScanResult
from attackmap.scanner import scan_files

FIXTURE = Path(__file__).parent / "fixtures" / "snapshot-shop"
_ORIGINAL_APP = (FIXTURE / "app.py").read_text(encoding="utf-8")
_MUTATED_APP = _ORIGINAL_APP.replace("list_orders", "list_admin_orders")


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "shop"
    shutil.copytree(FIXTURE, repo)
    return repo


def _report_data(scan: ScanResult) -> dict:
    return {
        "scan": scan.model_dump(),
        "findings": [], "attack_paths": [], "attack_surfaces": [],
        "exploitability": [], "suppressed_findings": [],
    }


# --- Phase 1: indexing — file changed after index build, before passes ------


def test_indexing_passes_read_snapshot_text_after_mutation(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    index = RepoIndex.build(repo)
    (repo / "app.py").write_text(_MUTATED_APP, encoding="utf-8")

    # The per-file pass streams index-time text: still the captured revision.
    result = scan_files(repo, index=index)
    assert any(r.path == "/api/orders" for r in result.routes)
    assert not any(r.path == "/api/admin" for r in result.routes)

    verification = index.snapshot.verify(repo)
    assert verification.state == "drifted"
    assert verification.changed == ("app.py",)
    assert "app.py" in index.mutation_warnings()[0]


def test_indexing_mutation_policy_never_retries_silently(tmp_path: Path) -> None:
    """Drift is reported, not retried: a rebuild simply gets a new identity."""
    repo = _repo(tmp_path)
    before = RepoIndex.build(repo).snapshot
    (repo / "app.py").write_text(_MUTATED_APP, encoding="utf-8")
    after = RepoIndex.build(repo).snapshot
    assert before.snapshot_id != after.snapshot_id
    assert dict(after.files)["config.yaml"] == dict(before.files)["config.yaml"]
    assert dict(after.files)["app.py"] != dict(before.files)["app.py"]


# --- Phase 2: detection — file changed between analyzers --------------------


def test_detection_between_analyzers_shares_one_snapshot(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    analyzer = BuiltinPythonWebAnalyzer()
    index = RepoIndex.build(repo)
    first = analyzer.analyze(repo, index=index)
    (repo / "app.py").write_text(_MUTATED_APP, encoding="utf-8")
    second = analyzer.analyze(repo, index=index)

    # Both analyzer invocations read the same captured revision.
    assert [r.path for r in first.routes] == [r.path for r in second.routes]
    assert "/api/orders" in [r.path for r in second.routes]
    assert any("new file" not in w and "app.py" in w for w in index.mutation_warnings())


def test_detection_new_and_deleted_files_are_detected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    index = RepoIndex.build(repo)
    (repo / "extra.py").write_text("y = 2\n", encoding="utf-8")
    (repo / "config.yaml").unlink()
    warnings = index.mutation_warnings()
    assert any("new file: extra.py" in w for w in warnings)
    assert any("config.yaml" in w for w in warnings)

    verification = index.snapshot.verify(repo)
    assert verification.state == "drifted"
    assert verification.added == ("extra.py",)
    assert verification.deleted == ("config.yaml",)


# --- Phase 3: report writing — file changed during publication --------------


def test_publication_marks_drifted_run_incomplete(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    out = tmp_path / "reports"
    scan = scan_files(repo)  # builds the index and stamps scan_snapshot
    assert scan.scan_snapshot is not None

    (repo / "app.py").write_text(_MUTATED_APP, encoding="utf-8")  # mid-publication
    write_artifact_manifest(
        output_dir=out, run_id="r", engine_version="test", repo_root=str(repo),
        repo_name=repo.name, analyzer_metadata=[{"name": "default", "version": "1"}],
        exit_code=0, status="succeeded", report_data=_report_data(scan),
    )
    manifest = json.loads((out / "artifact-manifest.json").read_text(encoding="utf-8"))
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["snapshot_id"] == scan.scan_snapshot.snapshot_id
    assert snapshot["verification"]["state"] == "drifted"
    assert snapshot["verification"]["changed"] == ["app.py"]
    assert snapshot["incomplete"] is True
    assert "app.py" in snapshot["limitation"]
    assert manifest["exit_state"]["snapshot_state"] == "incomplete"
    # The engine-owned status string is preserved, not rewritten here.
    assert manifest["exit_state"]["status"] == "succeeded"


def test_publication_clean_run_verifies_and_output_files_are_not_drift(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    out = repo / "reports"  # output inside the repo: run-written files excluded
    out.mkdir()
    (out / "user-note.md").write_text("not engine drift\n", encoding="utf-8")
    scan = scan_files(repo)

    write_artifact_manifest(
        output_dir=out, run_id="r", engine_version="test", repo_root=str(repo),
        repo_name=repo.name, analyzer_metadata=[], exit_code=0, status="succeeded",
        report_data=_report_data(scan),
    )
    manifest = json.loads((out / "artifact-manifest.json").read_text(encoding="utf-8"))
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["verification"]["state"] == "verified"
    assert snapshot["verification"]["added"] == []
    assert "incomplete" not in snapshot
    assert "snapshot_state" not in manifest["exit_state"]
    assert manifest["run_identity"]["analyzer_identity"]


# --- Phase 4: excerpt extraction — file changed after capture ---------------


def test_excerpts_keep_captured_span_and_record_snapshot_id(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    index = RepoIndex.build(repo)
    anchor = 9  # `def list_orders():` — the line the mutation rewrites
    spans = capture_source_spans(
        repo, [("app.py", anchor)], redact_line=lambda line: line
    )
    assert spans and spans[0].source_sha256 == hashlib.sha256(
        (repo / "app.py").read_bytes()
    ).hexdigest()

    (repo / "app.py").write_text(_MUTATED_APP, encoding="utf-8")  # after capture

    # The captured span is immutable: validation never re-reads the live file.
    context = context_from_payload({}, spans, repository_root=str(repo))
    validation = validate_references(f"app.py:{anchor}", context)
    assert validation.source_reference_valid
    assert "list_orders" in validation.source_spans[0].excerpt
    assert "list_admin_orders" not in validation.source_spans[0].excerpt

    # The manifest ties the captured span to the snapshot id it was taken
    # under, and the run is honestly marked incomplete for the live drift.
    out = tmp_path / "reports"
    scan = ScanResult(root=str(repo), scan_snapshot=index.snapshot.identity())
    meta = {"citation_context": {"sources": [spans[0].metadata()]}}
    from attackmap.safe_fs import safe_write_text, ensure_output_dir
    safe_write_text(ensure_output_dir(out), out / "vulnerability-hypotheses.meta.json",
                    json.dumps(meta))
    write_artifact_manifest(
        output_dir=out, run_id="r", engine_version="test", repo_root=str(repo),
        repo_name=repo.name, analyzer_metadata=[], exit_code=0, status="succeeded",
        report_data=_report_data(scan),
    )
    manifest = json.loads((out / "artifact-manifest.json").read_text(encoding="utf-8"))
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["sources_captured"] == [{
        "path": "app.py",
        "source_sha256": spans[0].source_sha256,
        "captured_under_snapshot_id": index.snapshot.snapshot_id,
    }]
    assert snapshot["verification"]["state"] == "drifted"
    assert manifest["exit_state"]["snapshot_state"] == "incomplete"


# --- End-to-end: the merged run carries the snapshot identity ----------------


def test_analyze_repository_result_carries_snapshot_identity(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    merged = analyze_repository(repo)
    expected = RepoIndex.build(repo).snapshot
    assert merged.scan_snapshot is not None
    assert merged.scan_snapshot.snapshot_id == expected.snapshot_id
    assert merged.scan_snapshot.files == dict(expected.files)
    assert merged.scan_snapshot.config_identity == expected.config_identity


# --- Fingerprints reference the snapshot when the index is supplied ----------


def test_fingerprints_pin_to_snapshot_lines_when_index_supplied(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    index = RepoIndex.build(repo)
    mutated_line = 9  # `def list_orders():` — rewritten by the mutation

    (repo / "app.py").write_text(_MUTATED_APP, encoding="utf-8")

    pinned = Finding(title="t", rule_id="rule-x", severity="medium",
                     evidence=[], mitigation="",
                     locations=[FindingLocation(file="app.py", line=mutated_line)])
    assign_fingerprints([pinned], repo, index=index)
    assert pinned.locations[0].fingerprint

    # Same content on a pristine copy yields the same fingerprint: the value
    # came from the snapshot, not the mutated live file.
    pristine = tmp_path / "pristine"
    shutil.copytree(FIXTURE, pristine)
    reference = Finding(title="t", rule_id="rule-x", severity="medium",
                        evidence=[], mitigation="",
                        locations=[FindingLocation(file="app.py", line=mutated_line)])
    assign_fingerprints([reference], pristine)
    assert pinned.locations[0].fingerprint == reference.locations[0].fingerprint

    # Without an index the live file is read (current caller behavior): a
    # changed line yields a different fingerprint, and only publication
    # verification flags the drift.
    live = Finding(title="t", rule_id="rule-x", severity="medium",
                   evidence=[], mitigation="",
                   locations=[FindingLocation(file="app.py", line=mutated_line)])
    assign_fingerprints([live], repo)
    assert live.locations[0].fingerprint != reference.locations[0].fingerprint
    assert index.snapshot.verify(repo).changed == ("app.py",)


def test_content_sha256_is_the_index_basis(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    index = RepoIndex.build(repo)
    item = index.get("app.py")
    assert item is not None
    assert item.sha256 == content_sha256(item.text)
    assert dict(index.snapshot.files) == {"app.py": item.sha256,
                                          "config.yaml": index.get("config.yaml").sha256}  # type: ignore[union-attr]
