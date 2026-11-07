"""Generate reviewed 1.2 schemas and separate synthetic fixtures; never touch WP002 bytes."""
import hashlib
import json
from pathlib import Path

from attackmap.run_contract import (
    SUPPORTED_SCHEMA_VERSIONS, RunRequest, RunProgress, RunTerminal, RunArtifactManifest,
    ScanOptionsV12,
)

ROOT = Path(__file__).resolve().parents[4]
for name, model in (("request", RunRequest), ("progress", RunProgress),
                    ("terminal", RunTerminal), ("manifest", RunArtifactManifest)):
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["properties"]["schema_version"]["enum"] = list(SUPPORTED_SCHEMA_VERSIONS)
    (ROOT / "schemas" / f"run-{name}.schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

folder = ROOT / "tests/fixtures/desktop-options-v12"
folder.mkdir(parents=True, exist_ok=True)
base = dict(schema_version="1.2", run_id="wp004-synthetic", repository_id="opaque-repository-id",
            generation=2, revision=0, repository_path="C:/parity/repository",
            output_path="C:/parity/reports")
sentinels = dict(baseline="C:/parity/baseline.json", suppress_file="C:/parity/suppressions.yml",
                 fail_on_new_high=True, fail_on_new_suppression=True, strict_suppressions=True,
                 isolated_analyzers=True, time_budget_seconds=17, timeout_seconds=37)
for name, options in (("defaults", ScanOptionsV12()), ("sentinels", ScanOptionsV12(**sentinels))):
    payload = RunRequest(**base, options=options).model_dump(mode="json")
    (folder / f"request-{name}.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
entries = [{"path": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
           for path in sorted(folder.glob("request-*.json"))]
(folder / "manifest.json").write_text(json.dumps({"schema_version": "1.2", "synthetic": True,
    "entries": entries, "new_field_sentinels": {key: value for key, value in sentinels.items() if key != "timeout_seconds"},
    "limitations": ["No real scan/provider or consumer-native acceptance.", "WP002 fixture bytes remain unchanged."]}, indent=2) + "\n", encoding="utf-8")
print("Generated 1.2 schemas and separate synthetic options fixtures")
