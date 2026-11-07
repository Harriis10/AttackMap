"""Small evidence contract check; no product execution or network."""
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    data = json.loads((root / "baseline.json").read_text(encoding="utf-8-sig"))
    assert data["schema_version"] == 1
    assert len(data["source"]["head"]) == 40
    assert data["source"]["declared_version"] == "1.5.1"
    selected, newer = data["packages"]
    assert selected["package_id"] == "dev-20261019192050-b678aee2"
    assert newer["package_id"] == "dev-20261019201436-7d3584c4"
    assert all(item["zip_sidecar_match"] for item in data["packages"])
    assert all(item["file_count"] > 0 for item in data["packages"])
    engine = data["selected_engine"]
    assert engine["module_count"] == selected["engine"]["analyzer_count"] == 21
    assert engine["version"] == selected["engine"]["version"]
    for probe in (engine["version_probe"], engine["modules_probe"]):
        assert probe["exit_code"] == 0
        assert hashlib.sha256((root / probe["stdout_file"]).read_bytes()).hexdigest() == probe["stdout_sha256"]
    installed = data["installed"]
    if installed["selection_status"] == "selection_and_listed_payload_verified":
        assert installed["package_id"] == selected["package_id"]
        assert installed["engine_sha256"] == selected["exe_sha256"]
        assert installed["manifest_sha256"] == selected["manifest_sha256"]
        assert installed["listed_payload_hashes_match"]
        assert installed["strict_existing_installer_validation"].startswith("FAIL")
        assert installed["extra_files"] == ["app/engine-guard-smoke.json", "app/scan-smoke.json"]
    assert all(item["exists"] for item in data["historical_evidence"])
    assert data["historical_relocation_validation"]
    assert all(item["exists"] and item["match"] for item in data["historical_relocation_validation"])
    assert data["accepted_m3"]["package_id"] != selected["package_id"]
    assert data["accepted_m3"]["deferred_unverified"]
    assert data["unsupported_claims"]
    print("PASS WP001 evidence contract; package integrity and runtime probes only")


if __name__ == "__main__":
    main()
