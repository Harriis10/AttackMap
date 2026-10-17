"""AM043/C30 diagnostic export: preview parity, redaction, source-free bounds."""
import json
from pathlib import Path

import pytest

from attackmap.artifact_manifest import (
    MANIFEST_FILENAME, generated_artifact_names, write_artifact_manifest,
)
from attackmap.artifact_publisher import generation_dir, publish_generation, write_diagnostic
from attackmap.diagnostics_export import (
    EXPORT_FILENAME, collect_diagnostic_export, export_diagnostics,
)
from attackmap.safe_fs import safe_write_text

SOURCE_MARKER = "SOURCE_EXCERPT_MARKER_7c3f"


def stage(base: Path, run: str, created: str) -> Path:
    folder = generation_dir(base, run)
    report = {"scan": {"root": SOURCE_MARKER}, "findings": [], "attack_paths": [],
              "attack_surfaces": [], "exploitability": [], "suppressed_findings": []}
    safe_write_text(folder, folder / "attackmap-report.json", json.dumps(report))
    safe_write_text(folder, folder / "run-manifest.json", json.dumps({"stages": []}))
    write_artifact_manifest(folder, run, "1.0", "repo", "repo", [], 0, "succeeded", report)
    manifest = json.loads((folder / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    manifest["created_at"] = created
    safe_write_text(folder, folder / MANIFEST_FILENAME, json.dumps(manifest, indent=2) + "\n")
    publish_generation(base, run)
    return folder


def staged_base(base: Path, count: int) -> None:
    for i in range(1, count + 1):
        stage(base, f"g{i:02d}", f"2026-01-{i:02d}T00:00:00+00:00")


def test_preview_lists_generations_current_pins_and_retention(tmp_path):
    from attackmap.retention import pin_generation
    base = tmp_path / "out"
    base.mkdir()
    staged_base(base, 3)
    pin_generation(base, "g01")
    payload = collect_diagnostic_export(base)
    assert payload["schema_version"] == "1.0"
    assert payload["export_type"] == "attackmap_diagnostic_export"
    assert payload["current_generation"] == {"generation": "g03", "state": "valid"}
    assert payload["pinned"] == ["g01"]
    assert payload["generation_count"] == 3
    assert [entry["run_id"] for entry in payload["generations"]] == ["g03", "g02", "g01"]
    newest = payload["generations"][0]
    assert newest["current"] is True and newest["pinned"] is False
    assert newest["status"] == "succeeded" and newest["exit_code"] == 0
    assert newest["context"]["outcome"] == "completed"
    assert any(s["stage_id"] == "publication" for s in newest["context"]["stages"])
    assert payload["retention"]["mode"] == "dry_run_summary"
    assert payload["retention"]["planned_deletion_count"] == 0
    assert payload["terminal_diagnostics"] == []


def test_secrets_in_terminal_diagnostics_are_redacted(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    staged_base(base, 1)
    write_diagnostic(base, "bad-run", state="failed",
                     error="provider call failed api_key=sk-live-1234567890abcdef at "
                           "https://service:hunter2secret123@internal.example/poll")
    payload = collect_diagnostic_export(base)
    dumped = json.dumps(payload)
    assert "sk-live-1234567890abcdef" not in dumped
    assert "hunter2secret123" not in dumped
    entry = next(e for e in payload["terminal_diagnostics"] if e["run_id"] == "bad-run")
    assert entry["state"] == "failed"
    assert "***" in entry["error"]  # masked credential values
    assert payload["current_generation"]["generation"] == "g01"


def test_report_source_content_is_never_read(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    staged_base(base, 1)
    assert (base / "g01" / "attackmap-report.json").is_file()
    dumped = json.dumps(collect_diagnostic_export(base))
    assert SOURCE_MARKER not in dumped


def test_generation_entries_are_bounded(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    staged_base(base, 3)
    payload = collect_diagnostic_export(base, max_generations=2)
    assert [entry["run_id"] for entry in payload["generations"]] == ["g03", "g02"]
    assert payload["generation_count"] == 3


def test_export_file_matches_preview_and_is_recognized_output(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    staged_base(base, 2)
    target = base / EXPORT_FILENAME
    payload, written = export_diagnostics(base, target)
    assert written == target
    assert json.loads(target.read_text(encoding="utf-8")) == payload
    assert EXPORT_FILENAME in generated_artifact_names(base, [EXPORT_FILENAME])
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / EXPORT_FILENAME).write_text('{"notes": "user file"}', encoding="utf-8")
    assert EXPORT_FILENAME not in generated_artifact_names(foreign, [EXPORT_FILENAME])


def test_corrupt_pins_are_reported_without_blocking_export(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    staged_base(base, 1)
    (base / "pinned-generations.json").write_text("{broken", encoding="utf-8")
    payload = collect_diagnostic_export(base)
    assert "error" in payload["pinned"]
    assert payload["retention"]["mode"] == "unavailable"
    assert payload["generation_count"] == 1
    assert payload["current_generation"]["state"] == "valid"


def test_missing_base_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        collect_diagnostic_export(tmp_path / "missing")


def test_cli_preview_and_out_round_trip(tmp_path):
    from typer.testing import CliRunner
    from attackmap.cli import app as cli_app
    base = tmp_path / "out"
    base.mkdir()
    staged_base(base, 1)
    runner = CliRunner()
    result = runner.invoke(cli_app, ["diagnostics", str(base)])
    assert result.exit_code == 0, result.output
    assert "attackmap_diagnostic_export" in result.output
    assert "Diagnostic export written" not in result.output
    out_file = tmp_path / "bundle.json"
    written = runner.invoke(cli_app, ["diagnostics", str(base), "--out", str(out_file)])
    assert written.exit_code == 0, written.output
    assert "Diagnostic export written" in written.output
    assert json.loads(out_file.read_text(encoding="utf-8"))["export_type"] == "attackmap_diagnostic_export"
    missing = runner.invoke(cli_app, ["diagnostics", str(tmp_path / "nope")])
    assert missing.exit_code == 2
