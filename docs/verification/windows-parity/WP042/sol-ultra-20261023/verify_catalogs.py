"""Read actual source and fresh frozen discovery; keep identities separate."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
FREEZE = ROOT / ".tmp/wp042-sol-ultra-20261023/frozen-engine-final"


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def probe(label, executable, prefix):
    rows = {}
    for name, args in (("catalog", ["modules", "--catalog-json"]),
                       ("modules", ["modules", "--json"]),
                       ("profiles", ["modules", "--profiles-json"]),
                       ("capabilities", ["capabilities"])):
        command = [str(executable), *prefix, *args]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=120)
        assert result.returncode == 0, (command, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        save(OUT / f"{label}-{name}.json", payload)
        rows[name] = payload
    assert rows["modules"] == rows["catalog"]["modules"] == rows["capabilities"]["modules"]
    assert rows["catalog"]["analyzer_profiles"] == rows["profiles"]["analyzer_profiles"]
    for name in ("engine_identity", "analyzer_catalog", "analyzer_profiles"):
        assert rows["catalog"][name] == rows["capabilities"][name]
    catalog = rows["catalog"]["analyzer_catalog"]
    assert not catalog["discovery_errors"]
    assert {r["status"] for r in catalog["candidates"]} <= {"effective", "shadowed"}
    return {"executable": str(executable), "module_count": len(rows["modules"]),
            "candidate_count": len(catalog["candidates"]),
            "effective_names": catalog["effective_order"],
            "shadowed": [r["name"] for r in catalog["candidates"] if r["status"] == "shadowed"],
            "available_profiles": [r["qualified_name"] for r in rows["catalog"]["analyzer_profiles"]["profiles"] if r["available"]],
            "engine_identity": rows["catalog"]["engine_identity"]}


if __name__ == "__main__":
    executable = FREEZE / "dist/attackmap/attackmap.exe"
    proof = json.loads((FREEZE / "build-proof.json").read_text(encoding="utf-8"))
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == proof["exe_sha256"]
    origins = {row[0] for row in proof["core_origins"]}
    assert {"attackmap.analyzer_catalog", "attackmap.analyzer_profiles"} <= origins
    source = probe("source", ROOT / ".venv/Scripts/python.exe", ["-m", "attackmap"])
    frozen = probe("frozen", executable, [])
    assert source["module_count"] == 9 and not source["shadowed"]
    assert frozen["module_count"] == 21 and frozen["candidate_count"] == 24
    assert sorted(frozen["shadowed"]) == ["omeka-s", "php-laminas", "php-web"]
    assert len(frozen["available_profiles"]) == 4
    save(OUT / "catalog-verification.json", {"scope": "Actual source and new frozen discovery only; no scan/provider/GUI acceptance",
        "source": source, "frozen": frozen, "checks_passed": True})
    print(json.dumps({"source_modules": source["module_count"], "frozen_modules": frozen["module_count"],
                      "frozen_shadowed": frozen["shadowed"], "checks_passed": True}))
