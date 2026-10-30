"""Actual batch2 source/frozen discovery through bounded, owned process jobs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import verify_batch as batch

ROOT = batch.ROOT
OUT = batch.EVIDENCE
FREEZE = batch.WORK / "engine-final"
ENGINE = FREEZE / "dist/attackmap/attackmap.exe"


def save(name, payload):
    path = OUT / name
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, indent=2) + "\n")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def probe(label, executable, prefix):
    rows, processes = {}, []
    for name, arguments in (("catalog", ["modules", "--catalog-json"]),
                            ("modules", ["modules", "--json"]),
                            ("profiles", ["modules", "--profiles-json"]),
                            ("capabilities", ["capabilities"])):
        folder = batch.run(f"catalog-probe-{label}-{name}-01", [executable, *prefix, *arguments],
                           timeout=120, environment={"PYTHONPATH": str(ROOT / "src")})
        process = json.loads((folder / "process.json").read_text(encoding="utf-8"))
        assert process["exit_code"] == 0 and process["exited"] and not process["timed_out"]
        assert process["owned_job_assigned"] and process["owned_tree_cleanup_verified"]
        payload = json.loads((folder / "stdout.log").read_text(encoding="utf-8-sig"))
        save(f"{label}-{name}.json", payload)
        rows[name] = payload
        processes.append({"name": name, "evidence": str(folder.relative_to(ROOT)), **process})
    assert isinstance(rows["modules"], list)
    assert rows["modules"] == rows["catalog"]["modules"] == rows["capabilities"]["modules"]
    assert rows["profiles"]["analyzer_profiles"] == rows["catalog"]["analyzer_profiles"]
    for name in ("engine_identity", "analyzer_catalog", "analyzer_profiles"):
        assert rows["catalog"][name] == rows["capabilities"][name]
    assert "1.5" in rows["capabilities"]["desktop"]["schema_versions"]
    assert "analyzer_profile" in rows["capabilities"]["desktop"]["scan_options_by_schema"]["1.5"]
    identity = rows["catalog"]["engine_identity"]
    assert identity["sha256"] == sha(executable)
    assert Path(identity["path"]).resolve() == executable.resolve()
    catalog = rows["catalog"]["analyzer_catalog"]
    assert catalog["scope"] == "installed_discovery" and not catalog["discovery_errors"]
    assert {row["status"] for row in catalog["candidates"]} <= {"effective", "shadowed"}
    plugins = [row for row in catalog["candidates"] if row["origin"] == "plugin"]
    assert all(row["official_package"] is True for row in plugins)
    assert all(row["provenance"]["content_verified"] is False for row in catalog["candidates"])
    profiles = rows["catalog"]["analyzer_profiles"]["profiles"]
    return {
        "executable": str(executable), "engine_identity": identity,
        "module_count": len(rows["modules"]), "candidate_count": len(catalog["candidates"]),
        "official_plugin_candidates": len(plugins),
        "official_packages": sorted(row["package"]["name"] for row in plugins),
        "effective_names": catalog["effective_order"],
        "shadowed": sorted(row["name"] for row in catalog["candidates"] if row["status"] == "shadowed"),
        "available_profiles": sorted(row["qualified_name"] for row in profiles if row["available"]),
        "profile_availability": {row["qualified_name"]: row["available"] for row in profiles},
        "supported_run_schemas": rows["capabilities"]["desktop"]["schema_versions"],
        "plugin_pin_statuses": sorted({row["provenance"]["pin_status"] for row in plugins}),
        "plugin_source_kinds": sorted({row["provenance"]["installed_source"]["kind"] for row in plugins}),
        "processes": processes,
    }


def verify_build_origins():
    proof_path = FREEZE / "build-proof.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    assert sha(ENGINE) == proof["exe_sha256"]
    source_root = (FREEZE / "source/src").resolve()
    origins = []
    for module, value, kind in proof["core_origins"]:
        origin = Path(value).resolve()
        assert origin.is_relative_to(source_root), (module, "core origin outside captured source")
        relative = origin.relative_to(source_root)
        current = ROOT / "src" / relative
        assert origin.is_file() and current.is_file()
        frozen_source_sha = sha(origin)
        assert frozen_source_sha == sha(current), (module, "current source differs from frozen build input")
        origins.append({"module": module, "kind": kind, "captured_origin": str(origin),
                        "source_sha256": frozen_source_sha, "current_source_matches": True})
    names = {row["module"] for row in origins}
    assert {"attackmap.analyzer_catalog", "attackmap.analyzer_profiles", "attackmap.analyzer_run_ledger",
            "attackmap.analyzers", "attackmap.pipeline", "attackmap.models", "attackmap.run_contract"} <= names
    return {"build_proof": str(proof_path.relative_to(ROOT)), "build_proof_sha256": sha(proof_path),
            "exe_sha256": proof["exe_sha256"], "core_origin_count": len(origins),
            "core_origins": origins, "analyzer_run_ledger_origin_verified": True}


if __name__ == "__main__":
    before = sha(ENGINE)
    build = verify_build_origins()
    source = probe("source", ROOT / ".venv/Scripts/python.exe", ["-B", "-m", "attackmap"])
    frozen = probe("frozen", ENGINE, [])
    assert source["module_count"] == source["candidate_count"] == 9
    assert source["official_plugin_candidates"] == 0 and source["shadowed"] == []
    assert frozen["module_count"] == 21 and frozen["candidate_count"] == 24
    assert frozen["official_plugin_candidates"] == 15 and len(set(frozen["official_packages"])) == 15
    assert frozen["shadowed"] == ["omeka-s", "php-laminas", "php-web"]
    assert frozen["available_profiles"] == ["automatic@1.0", "node-atproto@1.0", "php-laminas-omeka@1.0", "python@1.0"]
    assert sha(ENGINE) == before == build["exe_sha256"]
    save("catalog-verification.json", {
        "scope": "Actual source and fresh batch2 frozen discovery; no scan, provider response, native UI, package or release acceptance",
        "source": source, "frozen": frozen, "build": build,
        "executable_unchanged": True, "checks_passed": True,
    })
    print(json.dumps({"source_modules": source["module_count"], "frozen_modules": frozen["module_count"],
                      "frozen_candidates": frozen["candidate_count"], "official_plugins": frozen["official_plugin_candidates"],
                      "shadowed": frozen["shadowed"], "schema15": True,
                      "analyzer_run_ledger_origin_verified": True, "checks_passed": True}))
