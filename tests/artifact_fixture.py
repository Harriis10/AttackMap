"""Complete deterministic artifact generations for UI fake workers."""
import json

from attackmap.artifact_manifest import write_artifact_manifest
from attackmap.safe_fs import safe_write_text


def write_generation(folder, report=None):
    folder.mkdir(parents=True, exist_ok=True)
    data = {"scan": {"root": "fixture-repository"}, "findings": [], "attack_paths": [],
            "attack_surfaces": [], "exploitability": [], "suppressed_findings": []}
    if report:
        data.update(report)
    safe_write_text(folder, folder / "attackmap-report.json", json.dumps(data))
    safe_write_text(folder, folder / "run-manifest.json", json.dumps({"stages": []}))
    write_artifact_manifest(folder, folder.name, "1.0", data["scan"]["root"], "fixture", [], 0,
                            "succeeded", data)
