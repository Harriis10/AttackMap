"""Check (or explicitly regenerate) model-derived fleet/run JSON Schemas."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))

from attackmap.run_contract import (  # noqa: E402
    RunRequest, RunProgress, RunTerminal, RunArtifactManifest, SUPPORTED_SCHEMA_VERSIONS,
)
from attackmap.desktop_fleet import FleetRunRequest, FleetChildEvent, FleetTerminal  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    models = {"request": RunRequest, "progress": RunProgress, "terminal": RunTerminal,
              "manifest": RunArtifactManifest, "fleet-request": FleetRunRequest,
              "fleet-child": FleetChildEvent, "fleet-terminal": FleetTerminal}
    mismatches = []
    for name, model in models.items():
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        if not name.startswith("fleet-"):
            schema["properties"]["schema_version"]["enum"] = list(SUPPORTED_SCHEMA_VERSIONS)
        path = ROOT / "schemas" / f"run-{name}.schema.json"
        if args.write:
            path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        elif not path.is_file() or json.loads(path.read_text(encoding="utf-8")) != schema:
            mismatches.append(path.name)
    if mismatches:
        print("Schema mismatch: " + ", ".join(mismatches))
        return 1
    print("Seven run/fleet schemas synchronized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
