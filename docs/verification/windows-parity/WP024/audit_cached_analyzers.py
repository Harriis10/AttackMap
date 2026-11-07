"""Read-only cache provenance audit; never installs, copies or modifies cached wheels."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib
import zipfile
from email.parser import BytesParser

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def audit(repo: Path, cache: Path):
    config = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    required = {}
    for value in config["project"]["optional-dependencies"]["all"]:
        match = re.fullmatch(r"(attackmap-analyzer-[\w-]+) @ git\+(.+)@([a-f0-9]{40})", value)
        if match:
            name, url, commit = match.groups()
            required[name] = {"url": url, "commit": commit, "requirement": value}
    if len(required) != 15:
        raise ValueError("Expected all 15 explicitly pinned analyzer requirements.")
    matches = {name: [] for name in required}
    for origin in cache.rglob("origin.json"):
        record = json.loads(origin.read_text(encoding="utf-8"))
        vcs = record.get("vcs_info", {})
        for name, pin in required.items():
            if record.get("url") != pin["url"] or vcs.get("commit_id") != pin["commit"]:
                continue
            for wheel in origin.parent.glob("*.whl"):
                with zipfile.ZipFile(wheel) as archive:
                    metadata_names = [p for p in archive.namelist() if p.endswith(".dist-info/METADATA")]
                    if len(metadata_names) != 1:
                        raise ValueError("Ambiguous wheel metadata: " + str(wheel))
                    metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
                    if metadata["Name"].lower().replace("_", "-") != name:
                        continue
                    matches[name].append({"wheel": str(wheel), "wheel_sha256": digest(wheel),
                        "origin": str(origin), "origin_sha256": digest(origin), "version": metadata["Version"]})
    missing = [name for name, entries in matches.items() if not entries]
    return {"scope": "Cached wheel origin claims matched to current pinned requirements; not independent Git source-to-wheel reproduction", "pyproject_sha256": digest(repo / "pyproject.toml"), "requirements": required,
            "matching_cached_wheels": matches, "missing": missing, "all_pins_cached": not missing}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to overwrite existing audit evidence.")
    result = audit(args.repo.resolve(), args.cache.resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"required": len(result["requirements"]), "missing": result["missing"], "all_pins_cached": result["all_pins_cached"]}))
