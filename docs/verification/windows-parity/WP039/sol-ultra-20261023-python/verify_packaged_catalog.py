"""Inspect an already-created unsigned package, offline and without installation."""
from __future__ import annotations
import argparse, ast, hashlib, importlib.metadata, importlib.util, json, re, zipfile
from pathlib import Path

from candidate import CANDIDATE, OUT, ROOT, WORK, run
from verify_candidate import ENGINE, FREEZE, NATIVE

def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))

def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def save(path, payload):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, indent=2) + "\n")

def declared_pins():
    tree = ast.parse((CANDIDATE / "src/attackmap/plugins_lock.py").read_text(encoding="utf-8"))
    rows = [node for node in tree.body if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "OFFICIAL_PLUGINS"]
    assert len(rows) == 1
    pins = ast.literal_eval(rows[0].value)
    assert len(pins) == 15
    return {pin["package"]: pin for pin in pins}

def verify_zip(path, manifest, manifest_path):
    expected = {"app/" + row["path"]: row for row in manifest["files"]}
    expected.update({row["path"]: row for row in manifest["deployment_files"]})
    expected["package-manifest.json"] = {"size_bytes": manifest_path.stat().st_size, "sha256": sha(manifest_path)}
    seen = set()
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            name = entry.filename.replace("\\", "/")
            assert not name.startswith("/") and not {"..", "."}.intersection(name.split("/"))
            if entry.is_dir() or name.endswith("/"):
                continue
            assert name not in seen and name in expected
            seen.add(name)
            assert entry.file_size == expected[name]["size_bytes"]
            digest = hashlib.sha256()
            total = 0
            with archive.open(entry) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    total += len(block)
                    assert total <= expected[name]["size_bytes"]
                    digest.update(block)
            assert total == expected[name]["size_bytes"] and digest.hexdigest() == expected[name]["sha256"].lower()
    assert seen == set(expected)
    return len(seen)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="packaged-catalog-final")
    parser.add_argument("--package-location", type=Path, default=OUT / "package-location.json")
    args = parser.parse_args()
    if not args.package_location.is_file():
        raise SystemExit("Package not available; run only after root has produced package-location.json.")
    location = read(args.package_location)
    package = Path(location["package"]).resolve()
    manifest_path = package / "package-manifest.json"
    assert sha(manifest_path) == location["manifest_sha256"]
    assert sha(Path(location["zip"])) == location["zip_sha256"]
    manifest = read(manifest_path)
    assert manifest["profile"] == "RequiredBundled" and manifest["engine"]["bundled"] is True
    assert manifest["engine"]["executable"] == "app/engine/attackmap.exe"
    executable = package / manifest["engine"]["executable"]
    packaged_engine = executable.parent
    assert executable.resolve().is_relative_to(package)
    # The existing verifier checks all native/engine files and unexpected entries.
    spec = importlib.util.spec_from_file_location("package_sbom_verifier", CANDIDATE / "tools/generate_release_sbom.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verification = verifier.verify_package(package, manifest)
    zip_files_verified = verify_zip(Path(location["zip"]), manifest, manifest_path)
    native_proof = read(OUT / "native-analyzers-03-build-proof.json")
    native_packaged = {row["path"]: row["sha256"] for row in manifest["files"] if not row["path"].startswith("engine/")}
    native_expected = {name.replace("\\", "/"): digest for name, digest in native_proof["payload"].items()
                       if Path(name).suffix.lower() not in {".pdb", ".log"}
                       and "smoke" not in Path(name).name.lower() and not Path(name).name.lower().startswith("spike-error")}
    assert native_packaged == native_expected
    assert all(sha(NATIVE.parent / name) == digest for name, digest in native_expected.items())
    proof_path = WORK / "frozen-qualification/engine-verification.json"
    proof = read(proof_path)
    assert sha(executable) == sha(ENGINE) == proof["exe_sha256"]
    assert manifest["engine"]["verification_sha256"] == sha(proof_path)
    lock_path = FREEZE / "release-lock.json"
    assert manifest["engine"]["release_lock_sha256"] == proof["release_lock_sha256"] == sha(lock_path)
    for key in ("source_checksums_sha256", "release_inputs_sha256", "analyzer_requirements_sha256"):
        assert manifest["engine"][key] == proof[key] == read(lock_path)[key]
    expected_payload = {row["path"]: {key: row[key] for key in ("size_bytes", "sha256")} for row in proof["payload_files"]}
    packaged_payload = {row["path"].removeprefix("engine/"): {key: row[key] for key in ("size_bytes", "sha256")}
                        for row in manifest["files"] if row["path"].startswith("engine/")}
    assert packaged_payload == expected_payload
    frozen_payload = {path.relative_to(ENGINE.parent).as_posix(): {"size_bytes": path.stat().st_size, "sha256": sha(path)}
                      for path in ENGINE.parent.rglob("*") if path.is_file() and path.name != "engine-verification.json"}
    assert frozen_payload == expected_payload
    sbom_path = OUT / "package-sbom/release-sbom.json"
    sbom = read(sbom_path)
    assert sbom["package_id"] == manifest["package_id"] and sbom["signing"]["status"] == "unsigned"
    assert sbom["verification"]["package_manifest_sha256"] == sha(manifest_path)
    assert sbom["files"] == sorted(manifest["files"], key=lambda row: row["path"].casefold())
    assert sbom["file_count"] == len(manifest["files"]) == verification["files_verified"]
    pins = declared_pins()
    dependencies = sbom["python_dependencies"]
    assert dependencies["status"] == "known"
    sbom_official_names = []
    for line in dependencies["packages"]:
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:==|\s*@)", line)
        if match and match.group(1).lower().replace("_", "-").startswith("attackmap-analyzer-"):
            sbom_official_names.append(match.group(1).lower().replace("_", "-"))
    assert len(sbom_official_names) == 15 and set(sbom_official_names) == set(pins)
    distributions = {}
    for distribution in importlib.metadata.distributions(path=[str(packaged_engine / "_internal")]):
        name = distribution.metadata.get("Name", "").lower().replace("_", "-")
        if name.startswith("attackmap-analyzer-"):
            assert name not in distributions
            distributions[name] = {"version": distribution.version,
                "entry_points": sorted(entry.name for entry in distribution.entry_points if entry.group == "attackmap.analyzers")}
    assert set(distributions) == set(pins) and len(distributions) == 15
    for name, pin in pins.items():
        assert distributions[name]["version"] == pin["version"]
        assert distributions[name]["entry_points"] == sorted(pin["entry_points"])
    rows = {}
    for name, arguments in (("modules", ["modules", "--json"]), ("catalog", ["modules", "--catalog-json"]),
                            ("profiles", ["modules", "--profiles-json"]), ("capabilities", ["capabilities"])):
        folder = run(args.label + "-" + name, [executable, *arguments], timeout=120)
        process = read(folder / "process.json")
        assert process["exit_code"] == 0 and process["exited"] and not process["timed_out"]
        assert process["owned_job_assigned"] and process["owned_tree_cleanup_verified"]
        payload = read(folder / "stdout.log")
        save(OUT / (args.label + "-" + name + ".json"), payload)
        rows[name] = payload
    catalog = rows["catalog"]["analyzer_catalog"]
    assert rows["modules"] == rows["catalog"]["modules"] == rows["capabilities"]["modules"]
    assert len(rows["modules"]) == 21 and len(catalog["candidates"]) == 24
    assert not catalog["discovery_errors"] and {row["status"] for row in catalog["candidates"]} <= {"effective", "shadowed"}
    for row in catalog["candidates"]:
        implementation = row["implementation"]
        if implementation["source_file"] is not None:
            source = Path(implementation["source_file"]).resolve()
            assert source.is_relative_to(packaged_engine.resolve())
            if implementation["source_sha256"] is not None:
                assert sha(source) == implementation["source_sha256"]
    assert sorted(row["name"] for row in catalog["candidates"] if row["status"] == "shadowed") == ["omeka-s", "php-laminas", "php-web"]
    plugins = [row for row in catalog["candidates"] if row["origin"] == "plugin"]
    assert len(plugins) == 15 and {row["package"]["name"] for row in plugins} == set(pins)
    for row in plugins:
        pin = pins[row["package"]["name"]]
        assert row["official_package"] is True and row["package"]["version"] == pin["version"]
        assert row["provenance"]["declared_pin"] == pin
        assert row["provenance"]["content_verified"] is False  # Wheel metadata is not Git attestation.
    for key in ("engine_identity", "analyzer_catalog", "analyzer_profiles"):
        assert rows["catalog"][key] == rows["capabilities"][key]
    assert rows["catalog"]["engine_identity"]["sha256"] == sha(executable)
    assert Path(rows["catalog"]["engine_identity"]["path"]).resolve() == executable.resolve()
    assert rows["profiles"]["analyzer_profiles"] == rows["catalog"]["analyzer_profiles"]
    profiles = rows["catalog"]["analyzer_profiles"]["profiles"]
    assert sorted(row["qualified_name"] for row in profiles if row["available"]) == ["automatic@1.0", "node-atproto@1.0", "php-laminas-omeka@1.0", "python@1.0"]
    assert "1.5" in rows["capabilities"]["desktop"]["schema_versions"]
    assert "analyzer_profile" in rows["capabilities"]["desktop"]["scan_options_by_schema"]["1.5"]
    # Ensure the immutable package was not changed by discovery.
    assert verifier.verify_package(package, manifest) == verification
    payload = {"passed": True, "scope": "Actual packaged executable inventory and payload/SBOM integrity; unsigned development only, no installation/clean-host/manual/provider/release acceptance",
        "package": str(package), "package_id": manifest["package_id"], "package_manifest_sha256": sha(manifest_path),
        "zip_sha256": location["zip_sha256"], "sbom_sha256": sha(sbom_path), "package_verification": verification,
        "zip_files_verified": zip_files_verified, "zip_payload_equal_to_manifest": True,
        "native_payload_equal_to_captured_build": True, "native_payload_file_count": len(native_expected),
        "engine_sha256": sha(executable), "frozen_payload_files_equal": True, "engine_payload_file_count": len(expected_payload),
        "official_distributions": distributions, "effective_analyzers": 21, "catalog_candidates": 24,
        "shadowed": ["omeka-s", "php-laminas", "php-web"], "declared_pins": pins,
        "pin_content_attestation": "unverified; observed source/wheel/payload identity is separate from declared Git pin",
        "available_profiles": sorted(row["qualified_name"] for row in profiles if row["available"])}
    save(OUT / (args.label + "-verification.json"), payload)
    print(json.dumps({"passed": True, "package_id": manifest["package_id"], "official_distributions": 15,
                      "effective": 21, "candidates": 24, "engine_payload_file_count": len(expected_payload)}))

if __name__ == "__main__":
    main()
