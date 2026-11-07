"""C33 / AM047: every pass, fingerprint and AI excerpt references ONE snapshot.

Mutation tests at the roadmap phases — indexing, detection, whole-repo
passes, report writing, excerpt extraction, budget-faithful drift detection.
Each simulates a mid-scan file change by direct two-phase invocation (build
index, mutate, continue) so the tests stay deterministic and fast. Policy
under drift: the run is marked incomplete with an explicit limitation;
nothing retries in a loop.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from attackmap.analyzers import BuiltinPythonWebAnalyzer, analyze_repository
from attackmap.anomalies import find_anomalies
from attackmap.artifact_manifest import write_artifact_manifest
from attackmap.authz import analyze_authz
from attackmap.citations import capture_source_spans, context_from_payload, validate_references
from attackmap.fingerprint import assign_fingerprints
from attackmap.index import RepoIndex, clear_pinned_index, content_sha256
from attackmap.models import Finding, FindingLocation, ScanResult
from attackmap.recon_to_analysis import translate_recon
from attackmap.sbom import analyze_sbom
from attackmap.scanner import scan_files
from attackmap.supply_chain import scan_supply_chain
from attackmap.workflow_scanner import scan_workflows

FIXTURE = Path(__file__).parent / "fixtures" / "snapshot-shop"
_ORIGINAL_APP = (FIXTURE / "app.py").read_text(encoding="utf-8")
_MUTATED_APP = _ORIGINAL_APP.replace("list_orders", "list_admin_orders")

DEPS_FIXTURE = Path(__file__).parent / "fixtures" / "snapshot-deps"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "shop"
    shutil.copytree(FIXTURE, repo)
    return repo


def _deps_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "deps"
    shutil.copytree(DEPS_FIXTURE, repo)
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


# --- Phase 5: whole-repo passes read the snapshot, not the live tree --------
#
# SBOM (+ go.mod), supply-chain, CI workflows, authz and anomalies each
# re-read files from the repo tree. They now resolve content through the
# captured index: mutate a file after the build and the pass still analyzes
# the captured revision; a file added after the build is outside the snapshot
# entirely. Without a pin (direct calls, no ambient index) every pass reads
# the live tree exactly as before.


def test_whole_repo_sbom_reads_captured_manifests_after_mutation(tmp_path: Path) -> None:
    repo = _deps_repo(tmp_path)
    index = RepoIndex.build(repo)

    (repo / "go.mod").write_text(
        (DEPS_FIXTURE / "go.mod").read_text(encoding="utf-8")
        + "require github.com/evil/fork v0.0.1\n",
        encoding="utf-8",
    )
    package = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    package["dependencies"]["lodash"] = "^4.17.21"
    (repo / "package.json").write_text(json.dumps(package), encoding="utf-8")

    pinned = analyze_sbom(repo, index=index)
    pinned_names = {h.name for h in pinned}
    assert "github.com/gorilla/mux" in pinned_names
    assert "github.com/evil/fork" not in pinned_names
    assert "lodash" not in pinned_names

    clear_pinned_index()
    live = {h.name for h in analyze_sbom(repo)}
    assert "github.com/evil/fork" in live and "lodash" in live

    verification = index.snapshot.verify(repo)
    assert verification.state == "drifted"
    assert verification.changed == ("go.mod", "package.json")


def test_whole_repo_sbom_skips_manifest_added_after_index(tmp_path: Path) -> None:
    repo = _deps_repo(tmp_path)
    index = RepoIndex.build(repo)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "shop"\ndependencies = ["left-pad==1.3.0"]\n', encoding="utf-8"
    )

    pinned_names = {h.name for h in analyze_sbom(repo, index=index)}
    assert "left-pad" not in pinned_names  # outside the captured snapshot

    clear_pinned_index()
    assert "left-pad" in {h.name for h in analyze_sbom(repo)}

    assert any("new file: pyproject.toml" in w for w in index.mutation_warnings())
    assert index.snapshot.verify(repo).added == ("pyproject.toml",)


def test_whole_repo_supply_chain_reads_captured_configs_after_mutation(tmp_path: Path) -> None:
    repo = _deps_repo(tmp_path)
    index = RepoIndex.build(repo)

    # Strip the risky bits: the pip extra index and the go.mod replace fork.
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (repo / "go.mod").write_text(
        (DEPS_FIXTURE / "go.mod").read_text(encoding="utf-8").split("replace", 1)[0],
        encoding="utf-8",
    )

    pinned_kinds = {i.kind for i in scan_supply_chain(repo, index=index)}
    assert "dependency_confusion" in pinned_kinds  # from the captured --extra-index-url
    assert "mutable_vcs_dependency" in pinned_kinds  # from the captured replace

    clear_pinned_index()
    live_kinds = {i.kind for i in scan_supply_chain(repo)}
    assert "dependency_confusion" not in live_kinds
    assert "mutable_vcs_dependency" not in live_kinds


def test_whole_repo_workflow_scan_reads_captured_workflows_after_mutation(tmp_path: Path) -> None:
    repo = _deps_repo(tmp_path)
    index = RepoIndex.build(repo)

    mutated = (DEPS_FIXTURE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    mutated = mutated.replace(
        "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3", "actions/checkout@v4"
    )
    (repo / ".github" / "workflows" / "ci.yml").write_text(mutated, encoding="utf-8")
    (repo / ".github" / "workflows" / "nightly.yml").write_text(
        "on: [schedule]\njobs:\n  n:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@main\n",
        encoding="utf-8",
    )

    assert scan_workflows(repo, index=index) == []  # captured revision is clean

    clear_pinned_index()
    live = scan_workflows(repo)
    # nightly.yml has no permissions block, so it also draws the low-severity
    # default-token note; ci.yml only swaps the pinned SHA for a tag.
    assert {i.kind for i in live} == {"unpinned_action", "default_token_permissions"}
    assert {i.file for i in live} == {".github/workflows/ci.yml", ".github/workflows/nightly.yml"}

    assert index.snapshot.verify(repo).state == "drifted"


def test_whole_repo_authz_reads_captured_handlers_after_mutation(tmp_path: Path) -> None:
    repo = _deps_repo(tmp_path)
    index = RepoIndex.build(repo)
    scan = scan_files(repo, index=index)

    before = analyze_authz(scan, repo, index=index)
    assert [(c.route_path, c.route_method) for c in before] == [
        ("/api/orders/<int:order_id>", "GET")
    ]

    # A mid-run ownership check appears in the odd handler: the live tree is
    # now clean, the captured snapshot still has the BOLA candidate.
    guarded = (repo / "handlers.py").read_text(encoding="utf-8").replace(
        "def get_order(order_id):\n",
        "def get_order(order_id):\n"
        "    current_user = request.headers.get('authorization')\n",
    )
    (repo / "handlers.py").write_text(guarded, encoding="utf-8")

    pinned = analyze_authz(scan, repo, index=index)
    assert [(c.route_path, c.route_method) for c in pinned] == [
        ("/api/orders/<int:order_id>", "GET")
    ]

    clear_pinned_index()
    assert analyze_authz(scan, repo) == []
    assert index.snapshot.verify(repo).changed == ("handlers.py",)


def test_whole_repo_anomaly_pass_reads_captured_handlers_after_mutation(tmp_path: Path) -> None:
    repo = _deps_repo(tmp_path)
    index = RepoIndex.build(repo)
    scan = scan_files(repo, index=index)
    flagged = "/api/orders/<int:order_id>"

    def outliers(result_scan) -> list[str]:
        return [
            a.route_path
            for a in find_anomalies(result_scan, repo, index=index)
            if a.kind == "auth_outlier"
        ]

    assert outliers(scan) == [flagged]

    guarded = (repo / "handlers.py").read_text(encoding="utf-8").replace(
        "def get_order(order_id):\n",
        "def get_order(order_id):\n"
        "    current_user = request.headers.get('authorization')\n",
    )
    (repo / "handlers.py").write_text(guarded, encoding="utf-8")

    assert outliers(scan) == [flagged]  # peer comparison still uses captured lines

    clear_pinned_index()
    assert [
        a.route_path for a in find_anomalies(scan, repo) if a.kind == "auth_outlier"
    ] == []


def test_ambient_pin_covers_passes_called_without_index(tmp_path: Path) -> None:
    """run_repo_passes calls the passes with the repo root only; the pin that
    ``RepoIndex.build`` leaves for this thread must reach them there too."""
    repo = _deps_repo(tmp_path)
    RepoIndex.build(repo)  # pins the ambient index, as analyze_repository does

    (repo / "go.mod").write_text(
        (DEPS_FIXTURE / "go.mod").read_text(encoding="utf-8")
        + "require github.com/evil/fork v0.0.1\n",
        encoding="utf-8",
    )
    mutated = (DEPS_FIXTURE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        mutated.replace(
            "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3", "actions/checkout@v4"
        ),
        encoding="utf-8",
    )

    # No explicit index anywhere — exactly how scanner.run_repo_passes calls.
    assert "github.com/evil/fork" not in {h.name for h in analyze_sbom(repo)}
    assert scan_workflows(repo) == []

    clear_pinned_index()
    assert "github.com/evil/fork" in {h.name for h in analyze_sbom(repo)}
    assert [i.kind for i in scan_workflows(repo)] == ["unpinned_action"]


# --- Phase 6: translation fingerprints reference the analyzed revision ------


def test_translate_recon_threads_index_into_fingerprints(tmp_path: Path, monkeypatch) -> None:
    repo = _repo(tmp_path)
    index = RepoIndex.build(repo)
    scan = scan_files(repo, index=index)

    seen: list[object] = []

    def fake_assign(findings, root, index=None):  # noqa: ANN001
        seen.append(index)

    monkeypatch.setattr("attackmap.recon_to_analysis.assign_fingerprints", fake_assign)
    translate_recon(scan, index=index)
    assert seen[-1] is index
    translate_recon(scan)
    assert seen[-1] is None


def test_pipeline_passes_captured_index_to_fingerprints(tmp_path: Path, monkeypatch) -> None:
    from attackmap.pipeline import AnalyzeOptions, run_scan
    from attackmap.index import pinned_repo_index

    repo = _deps_repo(tmp_path)
    out = tmp_path / "reports"
    seen: list[object] = []

    def fake_assign(findings, root, index=None):  # noqa: ANN001
        seen.append(index)

    monkeypatch.setattr("attackmap.recon_to_analysis.assign_fingerprints", fake_assign)
    run_scan(AnalyzeOptions(repo_path=repo, output=out, atomic_output=False,
                            output_format="all", no_progress=True,
                            echo=lambda *a, **k: None))
    assert seen and seen[0] is not None
    assert Path(seen[0].root).resolve() == repo.resolve()  # type: ignore[attr-defined]
    # The run is over: the thread's pin is released, not left stale.
    assert pinned_repo_index() is None


# --- Phase 7: budget-faithful new-file detection -----------------------------
#
# When the index accepted files under a byte budget or count cap, a file that
# appears later is only drift if the recorded acceptance limits would have
# captured it. The replay walks in the build's order and charges the known
# files first.


def test_new_file_detection_replays_byte_budget(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    total = RepoIndex.build(repo).total_bytes
    index = RepoIndex.build(repo, max_bytes=total + 16)  # 16 bytes of headroom

    # The candidates live in zz/ so the walk charges every known file first —
    # under the real acceptance order the budget question is unambiguous.
    (repo / "zz").mkdir()
    (repo / "zz" / "big.py").write_text("#" * 64 + "\n", encoding="utf-8")  # would not fit
    (repo / "zz" / "tiny.py").write_text("y = 2\n", encoding="utf-8")  # fits the headroom

    verification = index.snapshot.verify(repo)
    assert verification.added == ("zz/tiny.py",)
    assert verification.state == "drifted"

    warnings = index.mutation_warnings()
    assert any("new file: zz/tiny.py" in w for w in warnings)
    assert not any("big.py" in w for w in warnings)


def test_new_file_detection_replays_file_count_cap(tmp_path: Path) -> None:
    repo = tmp_path / "cap"
    repo.mkdir()
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    (repo / "b.py").write_text("b = 2\n", encoding="utf-8")

    capped = RepoIndex.build(repo, max_files=2)
    (repo / "c.py").write_text("c = 3\n", encoding="utf-8")
    assert capped.snapshot.verify(repo).state == "verified"  # cap would skip c.py
    assert not any("c.py" in w for w in capped.mutation_warnings())

    with_headroom = RepoIndex.build(repo, max_files=4)  # c.py is now captured
    (repo / "d.py").write_text("d = 4\n", encoding="utf-8")
    verification = with_headroom.snapshot.verify(repo)
    assert verification.added == ("d.py",)  # d.py would have been accepted
    assert verification.state == "drifted"
