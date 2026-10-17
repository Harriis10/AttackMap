"""AttackMap never scans its own report output (#216)."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.artifact_manifest import generated_artifact_names, write_artifact_manifest
from attackmap.config_scanner import scan_config_repo
from attackmap.index import RepoIndex
from attackmap.safe_fs import OUTPUT_MARKER

runner = CliRunner()
SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
APP = (
    "import requests\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
    '@app.route("/p", methods=["POST"])\ndef p():\n'
    '    return requests.get(request.args["u"]).text\n'
    f'TOKEN = "{SECRET}"\nDB = "postgresql://u:pw123456@db/x"\n'
)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP, encoding="utf-8")
    return repo


def _summary(report: dict) -> list[tuple]:
    return sorted((f["rule_id"], len(f.get("locations", []))) for f in report["findings"]) + [
        ("files", report["scan"]["files_scanned"]),
        ("secrets", len(report["scan"]["secret_hints"])),
        ("databases", len(report["scan"]["databases"])),
    ]


@pytest.mark.parametrize("out_name", [None, "attackmap-reports", "custom/out"])
def test_second_run_is_identical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, out_name: str | None) -> None:
    repo = _repo(tmp_path)
    monkeypatch.chdir(repo)
    args = ["analyze", "."] + (["-o", out_name] if out_name else [])
    out = repo / (out_name or "reports")
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    report1 = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert (out / OUTPUT_MARKER).is_file()
    second = runner.invoke(app, args)
    assert second.exit_code == 0, second.output
    report2 = json.loads((out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert _summary(report1) == _summary(report2)


def test_fleet_output_is_excluded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    a, b = tmp_path / "svcA", tmp_path / "svcB"
    for d in (a, b):
        d.mkdir()
        (d / "app.py").write_text(APP, encoding="utf-8")
    monkeypatch.chdir(a)  # fleet output lands inside the first repo
    args = ["analyze", str(a), str(b), "-o", "fleet-out", "--format", "json"]
    assert runner.invoke(app, args).exit_code == 0
    first = json.loads((a / "fleet-out" / "fleet-summary.json").read_text(encoding="utf-8"))
    assert runner.invoke(app, args).exit_code == 0
    second = json.loads((a / "fleet-out" / "fleet-summary.json").read_text(encoding="utf-8"))
    # Report storage identifies the new generation; normalized analysis stays identical.
    assert first["repos"][0]["report_dir"] != second["repos"][0]["report_dir"]
    for summary in (first, second):
        for repo in summary["repos"]:
            repo.pop("report_dir")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_reports_from_older_versions_are_not_reingested(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    old = repo / "old-reports"  # written before the marker existed
    old.mkdir()
    (old / "attackmap-report.json").write_text(json.dumps({
        "scan": {"root": str(repo), "databases": [{"evidence_text": f"postgresql://a:b@{SECRET}"}]},
        "findings": [], "attack_paths": [], "attack_surfaces": [],
    }), encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(tmp_path / "o"), "--format", "json"])
    report = json.loads((tmp_path / "o" / "attackmap-report.json").read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert all(not d["file"].startswith("old-reports") for d in report["scan"]["databases"])


def test_dot_output_does_not_hide_the_repo(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    for _ in range(2):
        # Exercise source coverage with a known enumerating analyzer, independent
        # of installed plugins whose legacy aggregate counts can overlap.
        result = runner.invoke(app, ["analyze", str(repo), "-m", "python-web", "-o", str(repo), "--format", "json"])
        assert result.exit_code == 0
    report = json.loads((repo / "attackmap-report.json").read_text(encoding="utf-8"))
    assert report["scan"]["files_scanned"] == 1
    assert report["scan"]["scanned_files"] == ["app.py"]
    assert {item.rel for item in RepoIndex.build(repo).files} == {"app.py"}


@pytest.mark.parametrize("location", ["root", "nested", "outside"])
@pytest.mark.parametrize("output_format", ["json", "all"])
def test_three_runs_preserve_findings_and_source_coverage(tmp_path, location, output_format):
    repo = _repo(tmp_path)
    sources = repo / "sources"
    sources.mkdir()
    (sources / "scan.json").write_text('{"url": "https://api.user-owned.example/path"}', encoding="utf-8")
    output = {"root": repo, "nested": repo / "custom-results", "outside": tmp_path / "out"}[location]
    expected_files = {item.rel for item in RepoIndex.build(repo).files}
    findings = []
    summaries = []
    for _ in range(3):
        result = runner.invoke(app, ["analyze", str(repo), "-o", str(output), "--format", output_format])
        assert result.exit_code == 0, result.output
        report = json.loads((output / "attackmap-report.json").read_text(encoding="utf-8"))
        findings.append(report["findings"])
        summaries.append(_summary(report))
        assert {item.rel for item in RepoIndex.build(repo).files} == expected_files
        assert any(call["file"] == "sources/scan.json" for call in report["scan"]["external_calls"])
    assert findings[0] == findings[1] == findings[2]
    assert summaries[0] == summaries[1] == summaries[2]


@pytest.mark.parametrize("filename", [
    "scan.json", "findings.json", "attack_paths.json", "attack_surfaces.json",
    "exploitability.json", "suppressed_findings.json", "artifact-manifest.json",
    "attackmap-report.json", "run-manifest.json", "defensive-review.json",
    "review-context-pack.json", "fleet-summary.json", "defensive-review-llm.meta.json",
    "benchmark-results.json",
])
def test_artifact_basename_does_not_hide_user_config(tmp_path, filename):
    (tmp_path / filename).write_text('{"url": "https://api.user-owned.example/path"}', encoding="utf-8")
    result = scan_config_repo(tmp_path)
    assert result.files_scanned == 1
    assert result.external_calls[0].file == filename


def _manifest(directory):
    return write_artifact_manifest(
        directory, run_id="g1", engine_version="1.5.1", repo_root=str(directory),
        repo_name="repo", analyzer_metadata=[], exit_code=0, status="succeeded",
        report_data={"scan": {"root": str(directory)}, "findings": []},
    )


def test_manifest_identifies_generated_sections_without_directory_marker(tmp_path):
    _manifest(tmp_path)
    (tmp_path / OUTPUT_MARKER).unlink()
    assert not RepoIndex.build(tmp_path).files


@pytest.mark.parametrize("filename", ["scan.json", "attackmap-report.json"])
def test_checksum_mismatch_keeps_replaced_artifact_as_input(tmp_path, filename):
    legacy = {"scan": {}, "findings": [], "attack_paths": [], "attack_surfaces": []}
    (tmp_path / "attackmap-report.json").write_text(json.dumps(legacy), encoding="utf-8")
    _manifest(tmp_path)
    changed = {**legacy, "url": "https://api.user-owned.example/path"}
    (tmp_path / filename).write_text(json.dumps(changed), encoding="utf-8")
    result = scan_config_repo(tmp_path)
    assert result.files_scanned == 1
    assert result.external_calls[0].file == filename


@pytest.mark.parametrize("path", ["../source.json", "/source.json", "sub/source.json", "C:\\source.json"])
def test_manifest_paths_cannot_exclude_other_directories(tmp_path, path):
    manifest_path = _manifest(tmp_path)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["sections"].append({"path": path, "checksum": "irrelevant"})
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    generated = generated_artifact_names(tmp_path, [p.name for p in tmp_path.iterdir()])
    assert path not in generated


@pytest.mark.parametrize("content", ["{broken", "[]", '{"artifact_type": "something_else"}'])
def test_invalid_manifest_does_not_hide_source(tmp_path, content):
    (tmp_path / "artifact-manifest.json").write_text(content, encoding="utf-8")
    (tmp_path / "scan.json").write_text('{"url": "https://api.user-owned.example/path"}', encoding="utf-8")
    assert "scan.json" in {item.rel for item in RepoIndex.build(tmp_path).files}


def test_manifest_cannot_claim_arbitrary_source_file(tmp_path):
    source = "print('application source')\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    manifest_path = _manifest(tmp_path)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["sections"].append({"path": "app.py", "checksum": hashlib.sha256(source.encode()).hexdigest()})
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    assert {item.rel for item in RepoIndex.build(tmp_path).files} == {"app.py"}


def test_replaced_artifact_in_nested_marked_output_remains_visible(tmp_path):
    output = tmp_path / "custom-results"
    _manifest(output)
    assert not RepoIndex.build(tmp_path).files
    (output / "scan.json").write_text('{"url": "https://api.user-owned.example/path"}', encoding="utf-8")
    assert {item.rel for item in RepoIndex.build(tmp_path).files} == {"custom-results/scan.json"}


@pytest.mark.parametrize(("filename", "payload"), [
    ("run-manifest.json", {"engine_version": "1.0", "analyzers": [], "stages": [], "files_scanned": 1, "findings_by_severity": {}}),
    ("defensive-review.json", {"schema_version": "1.0", "target_metadata": {}, "raw_structured_signals": {}, "limitations_meta": {}}),
    ("review-context-pack.json", {"artifact_type": "attackmap_review_context_pack"}),
    ("fleet-summary.json", {"repo_count": 1, "repos": [], "cross_repo_links": [], "total_findings": 0}),
    ("defensive-review-llm.meta.json", {"backend": "api", "model": "local-model", "usage": {}}),
    ("benchmark-results.json", {"cases": [], "overall": {"injection": {"tp": 1, "fp": 0, "precision": 1, "recall": 1, "missed_expected": []}}}),
])
def test_legacy_artifact_structures_are_excluded(tmp_path, filename, payload):
    (tmp_path / filename).write_text(json.dumps(payload), encoding="utf-8")
    if filename.endswith(".meta.json"):
        # Common provider metadata keys alone do not establish generated output.
        assert filename in {item.rel for item in RepoIndex.build(tmp_path).files}
        companion = {"scan": {}, "findings": [], "attack_paths": [], "attack_surfaces": []}
        (tmp_path / "attackmap-report.json").write_text(json.dumps(companion), encoding="utf-8")
    assert not RepoIndex.build(tmp_path).files
