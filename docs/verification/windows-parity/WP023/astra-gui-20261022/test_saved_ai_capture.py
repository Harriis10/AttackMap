"""Offline evidence-binding checks. No subprocess, application or provider calls."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("saved_ai_capture_tests_target",
                                            Path(__file__).with_name("saved_ai_capture.py"))
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def generation(tmp_path):
    folder = tmp_path / "generation-1"
    folder.mkdir()
    data = {"attackmap-report.json": b'{"scan":{}}', "run-manifest.json": b'{}',
            "defensive-review-llm.md": b"Saved model output",
            "defensive-review-llm.meta.json": b'{}'}
    rows = []
    for name, content in data.items():
        (folder / name).write_bytes(content)
        rows.append(dict(path=name, size_bytes=len(content), checksum=hashlib.sha256(content).hexdigest()))
    manifest = dict(artifact_type="attackmap_artifact_manifest", generation_id=folder.name,
                    exit_state=dict(status="succeeded"), sections=rows, compatibility_exports=[])
    (folder / "artifact-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return folder, manifest


def test_generation_pins_selected_and_all_inventory(tmp_path):
    folder, _ = generation(tmp_path)
    result = capture.generation_identity(folder / "attackmap-report.json", "review")
    assert result["generation"] == folder.name
    assert len(result["files"]) == 4
    assert result["selected_artifact"] == result["files"]["defensive-review-llm.md"]


def test_generation_rejects_same_size_tamper(tmp_path):
    folder, _ = generation(tmp_path)
    (folder / "defensive-review-llm.md").write_bytes(b"Other model output")
    with pytest.raises(ValueError, match="checksum mismatch"):
        capture.generation_identity(folder / "attackmap-report.json", "review")


@pytest.mark.parametrize("mutation", ("generation", "duplicate", "traversal", "missing_metadata"))
def test_generation_rejects_binding_errors(tmp_path, mutation):
    folder, manifest = generation(tmp_path)
    if mutation == "generation":
        manifest["generation_id"] = "another-generation"
    elif mutation == "duplicate":
        manifest["sections"].append(manifest["sections"][0])
    elif mutation == "traversal":
        manifest["sections"][0]["path"] = "../attackmap-report.json"
    else:
        manifest["sections"].pop()
    (folder / "artifact-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        capture.generation_identity(folder / "attackmap-report.json", "review")


def test_capture_rejects_wrong_mode_before_pixel_guard(tmp_path, monkeypatch):
    manifest = dict(aiMode="hunt", providerCalled=False, selectedReportSha256="pinned")
    (tmp_path / "capture-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    def forbidden(*args):
        raise AssertionError("Pixel guard must not run for wrong mode")
    monkeypatch.setattr(capture.gui, "captures_check", forbidden)
    plan = dict(mode="review", inputs=dict(generation=dict(files={"attackmap-report.json": {"sha256": "pinned"}})))
    with pytest.raises(ValueError, match="Wrong saved mode"):
        capture.verify_capture(tmp_path, plan)
