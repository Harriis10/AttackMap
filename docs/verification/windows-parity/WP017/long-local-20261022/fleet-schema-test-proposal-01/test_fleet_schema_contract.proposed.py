"""Published fleet schema must track the complete deterministic model contract."""
import json
from pathlib import Path

from attackmap.desktop_fleet import FleetRunRequest


def test_published_fleet_request_schema_matches_model():
    root = Path(__file__).resolve().parents[1]
    actual = json.loads((root / "schemas/run-fleet-request.schema.json").read_text(encoding="utf-8"))
    expected = FleetRunRequest.model_json_schema()
    expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    assert actual == expected
