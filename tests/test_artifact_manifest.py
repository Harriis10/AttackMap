"""Tests for artifact manifest and section files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import FormatChecker, validate

from attackmap import __version__
from attackmap.artifact_manifest import (
    ArtifactManifest,
    ArtifactSection,
    SCHEMA_VERSION,
    SECTION_ORDER,
    load_artifact_manifest,
    make_run_id,
    write_artifact_manifest,
)


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "artifact-manifest.schema.json"


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_schema_file_exists_and_declares_required_fields() -> None:
    schema = _schema()
    assert schema["$schema"]
    required = set(schema["required"])
    assert required >= {
        "schema_version",
        "artifact_type",
        "generation_id",
        "engine_version",
        "created_at",
        "exit_state",
        "run_identity",
        "sections",
        "compatibility_exports",
    }


def test_make_run_id_is_unique_and_well_formed() -> None:
    first = make_run_id()
    second = make_run_id()
    assert first != second
    assert "-" in first
    assert len(first) > 16


def test_make_run_id_is_unique_with_frozen_coarse_clock(monkeypatch) -> None:
    from datetime import datetime, timezone
    from uuid import UUID
    import attackmap.artifact_manifest as manifest

    class FrozenClock:
        @staticmethod
        def now(zone):
            assert zone is timezone.utc
            return datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(manifest, "datetime", FrozenClock)
    identifiers = [make_run_id() for _ in range(1000)]
    assert len(set(identifiers)) == len(identifiers)
    for identifier in identifiers:
        timestamp, suffix = identifier.split("-")
        assert timestamp == "20261015T120000"
        assert len(suffix) == 32
        assert UUID(hex=suffix).version == 4


def test_write_manifest_creates_section_files(tmp_path: Path) -> None:
    report_data = {
        "scan": {"root": str(tmp_path), "languages": ["python"]},
        "findings": [{"id": "f-1", "title": "Issue", "severity": "high"}],
        "attack_paths": [{"name": "p1"}],
        "attack_surfaces": [{"name": "s1"}],
        "exploitability": [{"subject": "POST /x", "score": 100}],
        "suppressed_findings": [{"id": "s-1"}],
    }
    manifest_path = write_artifact_manifest(
        output_dir=tmp_path,
        run_id="run-123",
        engine_version=__version__,
        repo_root=str(tmp_path),
        repo_name="repo",
        analyzer_metadata=[{"name": "php-web"}],
        exit_code=0,
        status="succeeded",
        report_data=report_data,
    )
    assert manifest_path == tmp_path / "artifact-manifest.json"
    assert manifest_path.is_file()

    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate(instance=raw, schema=_schema(), format_checker=FormatChecker())

    assert raw["schema_version"] == SCHEMA_VERSION
    assert raw["artifact_type"] == "attackmap_artifact_manifest"
    assert raw["generation_id"] == "run-123"
    assert raw["engine_version"] == __version__
    assert raw["exit_state"] == {"exit_code": 0, "status": "succeeded"}
    assert raw["run_identity"]["repo_root"] == str(tmp_path)
    assert raw["run_identity"]["repo_name"] == "repo"
    assert raw["run_identity"]["analyzers"] == [{"name": "php-web"}]

    section_names = {s["name"]: s for s in raw["sections"]}
    for name, filename, role in SECTION_ORDER:
        assert name in section_names
        section = section_names[name]
        assert section["path"] == filename
        assert section["format"] == "json"
        assert section["role"] == role
        assert section["checksum"]
        section_file = tmp_path / filename
        assert section_file.is_file()
        data = json.loads(section_file.read_text(encoding="utf-8"))
        assert data == report_data[name]

    exports = {e["name"]: e for e in raw["compatibility_exports"]}
    assert "legacy_report" in exports
    assert exports["legacy_report"]["path"] == "attackmap-report.json"


def test_manifest_section_paths_are_relative_to_output(tmp_path: Path) -> None:
    report_data = {
        "scan": {"root": str(tmp_path)},
        "findings": [],
        "attack_paths": [],
        "attack_surfaces": [],
        "exploitability": [],
        "suppressed_findings": [],
    }
    write_artifact_manifest(
        output_dir=tmp_path,
        run_id="r",
        engine_version="0.5.1",
        repo_root=str(tmp_path),
        repo_name="repo",
        analyzer_metadata=[],
        exit_code=0,
        status="succeeded",
        report_data=report_data,
    )
    manifest = json.loads((tmp_path / "artifact-manifest.json").read_text(encoding="utf-8"))
    for section in manifest["sections"]:
        path = tmp_path / section["path"]
        assert path.resolve().is_relative_to(tmp_path.resolve())
        assert ".." not in Path(section["path"]).parts


def test_load_artifact_manifest_round_trips(tmp_path: Path) -> None:
    report_data = {
        "scan": {"root": str(tmp_path)},
        "findings": [],
        "attack_paths": [],
        "attack_surfaces": [],
        "exploitability": [],
        "suppressed_findings": [],
    }
    write_artifact_manifest(
        output_dir=tmp_path,
        run_id="r",
        engine_version="0.5.1",
        repo_root=str(tmp_path),
        repo_name="repo",
        analyzer_metadata=[],
        exit_code=0,
        status="succeeded",
        report_data=report_data,
    )
    loaded = load_artifact_manifest(tmp_path / "artifact-manifest.json")
    assert isinstance(loaded, ArtifactManifest)
    assert loaded.generation_id == "r"
    assert len(loaded.sections) == len(SECTION_ORDER)


def test_dataclass_to_dict_includes_checksum_when_present() -> None:
    section = ArtifactSection(name="x", path="x.json", format="json", role="test", checksum="abc")
    data = section.to_dict()
    assert data["checksum"] == "abc"
    assert "checksum" not in ArtifactSection(
        name="x", path="x.json", format="json", role="test"
    ).to_dict()


def test_manifest_records_failed_exit_state(tmp_path: Path) -> None:
    """The manifest records the terminal exit code and status string."""
    report_data = {
        "scan": {"root": str(tmp_path)},
        "findings": [],
        "attack_paths": [],
        "attack_surfaces": [],
        "exploitability": [],
        "suppressed_findings": [],
    }
    write_artifact_manifest(
        output_dir=tmp_path,
        run_id="r",
        engine_version="0.5.1",
        repo_root=str(tmp_path),
        repo_name="repo",
        analyzer_metadata=[],
        exit_code=1,
        status="failed",
        report_data=report_data,
    )
    manifest = json.loads((tmp_path / "artifact-manifest.json").read_text(encoding="utf-8"))
    assert manifest["exit_state"]["exit_code"] == 1
    assert manifest["exit_state"]["status"] == "failed"


def _snapshot_report_data(repo: Path, snapshot_files: dict[str, str],
                          snapshot_id: str = "snap-1") -> dict:
    return {
        "scan": {"root": str(repo), "scan_snapshot": {
            "snapshot_id": snapshot_id, "files": snapshot_files,
            "total_size": 8, "index_config": {"max_file_bytes": 2000000,
                                              "index_byte_budget": 0},
            "config_identity": "cfg",
        }},
        "findings": [], "attack_paths": [], "attack_surfaces": [],
        "exploitability": [], "suppressed_findings": [],
    }


def test_manifest_records_verified_snapshot_identity(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    snapshot_files = {"a.py": hashlib.sha256(b"x = 1\n").hexdigest()}
    report_data = _snapshot_report_data(repo, snapshot_files)
    write_artifact_manifest(
        output_dir=tmp_path / "out", run_id="r", engine_version="0.5.1",
        repo_root=str(repo), repo_name="repo",
        analyzer_metadata=[{"name": "python-web", "version": "0.1.0"}],
        exit_code=0, status="succeeded",
        report_data=report_data,
    )
    manifest = json.loads((tmp_path / "out" / "artifact-manifest.json").read_text(encoding="utf-8"))
    assert manifest["run_identity"]["analyzer_identity"]
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["verification"]["state"] == "verified"
    # Config identity is derived from the captured index config, not trusted
    # from the report channel: it is recomputed on rehydration.
    from attackmap.index import ScanSnapshot
    expected = ScanSnapshot.from_identity(report_data["scan"]["scan_snapshot"])
    assert snapshot["config_identity"] == expected.config_identity
    assert "snapshot_state" not in manifest["exit_state"]


def test_manifest_marks_drifted_snapshot_incomplete(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    snapshot_files = {"a.py": hashlib.sha256(b"x = 1\n").hexdigest()}
    # Mid-publication drift: the file changed after the scan captured it.
    (repo / "a.py").write_text("x = 1\nATTACK = True\n", encoding="utf-8")
    write_artifact_manifest(
        output_dir=tmp_path / "out", run_id="r", engine_version="0.5.1",
        repo_root=str(repo), repo_name="repo", analyzer_metadata=[],
        exit_code=0, status="succeeded",
        report_data=_snapshot_report_data(repo, snapshot_files),
    )
    manifest = json.loads((tmp_path / "out" / "artifact-manifest.json").read_text(encoding="utf-8"))
    snapshot = manifest["run_identity"]["snapshot"]
    assert snapshot["verification"]["state"] == "drifted"
    assert snapshot["verification"]["changed"] == ["a.py"]
    assert snapshot["incomplete"] is True
    assert "a.py" in snapshot["limitation"]
    assert manifest["exit_state"]["snapshot_state"] == "incomplete"
    # The engine-owned status string is preserved.
    assert manifest["exit_state"]["status"] == "succeeded"


def test_manifest_without_snapshot_identity_has_no_snapshot_block(tmp_path: Path) -> None:
    """Back-compat: reports without a snapshot carry no verification block."""
    write_artifact_manifest(
        output_dir=tmp_path, run_id="r", engine_version="0.5.1",
        repo_root=str(tmp_path), repo_name="repo", analyzer_metadata=[],
        exit_code=0, status="succeeded",
        report_data={"scan": {"root": str(tmp_path)}, "findings": [], "attack_paths": [],
                     "attack_surfaces": [], "exploitability": [], "suppressed_findings": []},
    )
    manifest = json.loads((tmp_path / "artifact-manifest.json").read_text(encoding="utf-8"))
    assert "snapshot" not in manifest["run_identity"]
    assert manifest["run_identity"]["analyzer_identity"] == hashlib.sha256(b"[]").hexdigest()
