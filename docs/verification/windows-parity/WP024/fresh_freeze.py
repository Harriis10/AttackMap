"""Create a new immutable input snapshot and optionally freeze it after root release.

Never modifies retained artifacts or upgrades an old verification record.
Runtime capability/scan/action verification is a separate mandatory next step.
"""
from __future__ import annotations
import argparse
import ast
import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-released", action="store_true", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--freeze-python", type=Path, required=True)
    parser.add_argument("--dotnet", type=Path, required=True)
    parser.add_argument("--analyzer-audit", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    repo, base, python = args.repo.resolve(), args.output.resolve(), args.freeze_python.resolve()
    if base.exists():
        raise SystemExit("Choose a new output directory; existing evidence is immutable.")
    if not python.is_file():
        raise SystemExit("Freeze Python executable missing.")
    spec = importlib.util.spec_from_file_location("release_lock", repo / "tools/generate_release_lock.py")
    lock_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(lock_module)
    inputs = lock_module.release_inputs(repo)
    audit = json.loads(args.analyzer_audit.read_text(encoding="utf-8"))
    if not audit.get("all_pins_cached") or audit.get("pyproject_sha256") != lock_module.sha256_file(repo / "pyproject.toml"):
        raise RuntimeError("Analyzer cache audit does not match current pyproject. Audit the new exact pins before building.")
    wheels = []
    for name, entries in audit["matching_cached_wheels"].items():
        entry = entries[0]
        wheel = args.wheelhouse.resolve() / Path(entry["wheel"]).name
        if not wheel.is_file() or lock_module.sha256_file(wheel) != entry["wheel_sha256"]:
            raise RuntimeError("Task wheelhouse changed: " + name)
        wheels.append({"name": name, "path": str(wheel), "sha256": entry["wheel_sha256"]})
    base.mkdir(parents=True)
    installed_check = '''import hashlib,importlib.metadata as m,json,pathlib,sys,zipfile
rows=[]
for item in json.loads(sys.argv[1]):
 dist=m.distribution(item['name']); files={}
 with zipfile.ZipFile(item['path']) as archive:
  for member in archive.namelist():
   if member.endswith('/') or member.endswith('.dist-info/RECORD'): continue
   expected=archive.read(member); actual=pathlib.Path(dist.locate_file(member)).read_bytes()
   if actual != expected: raise RuntimeError('Installed analyzer differs from pinned wheel: '+item['name']+'/'+member)
   files[member]=hashlib.sha256(actual).hexdigest()
 rows.append(dict(name=item['name'],version=dist.version,wheel_sha256=item['sha256'],files=files))
pathlib.Path(sys.argv[2]).write_text(json.dumps(rows,indent=2)+'\\n',encoding='utf-8')
print('Installed analyzer bytes match pinned cached wheels:',len(rows))
'''
    subprocess.run([str(python), "-c", installed_check, json.dumps(wheels), str(base / "analyzer-installed-attestation.json")], check=True, timeout=300)
    source = base / "source"
    for relative, expected in inputs["release_inputs"].items():
        original, target = repo / relative, source / relative
        if lock_module.sha256_file(original) != expected:
            raise RuntimeError("Input changed before snapshot: " + relative)
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(original, target)
        if lock_module.sha256_file(target) != expected:
            raise RuntimeError("Snapshot byte mismatch: " + relative)
    if lock_module.release_inputs(repo) != inputs or lock_module.release_inputs(source) != inputs:
        raise RuntimeError("Source changed during snapshot or snapshot incomplete.")
    lock, lock_path = lock_module.generate_lock(source, base, python.parent.parent, args.dotnet.resolve())
    if any(lock["toolchain"][tool]["version"] == "unknown" for tool in ("python", "pyinstaller", "dotnet_sdk")):
        raise RuntimeError("Known Python/PyInstaller/.NET identities are mandatory.")
    (base / "source-checksums.json").write_bytes(lock_module.canonical_source_checksums_bytes(lock["source_checksums"]))
    env = dict(os.environ, PYTHONPATH=str(source / "src"), PYINSTALLER_CONFIG_DIR=str(base / "ownedcache"), PYTHONDONTWRITEBYTECODE="1")
    assertion = "import pathlib,sys,attackmap; assert pathlib.Path(attackmap.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve()); print(attackmap.__file__)"
    check = subprocess.run([str(python), "-c", assertion, str(source)], cwd=source, env=env, capture_output=True, text=True, timeout=180)
    save(base / "environment-check.json", {"exit_code": check.returncode, "stdout": check.stdout, "stderr": check.stderr})
    check.check_returncode()
    argv = [str(python), "-m", "PyInstaller", str(source / "installer/attackmap.spec"), "--noconfirm", "--distpath", str(base / "dist"), "--workpath", str(base / "build")]
    save(base / "prepared.json", {"scope": "Fresh immutable snapshot; no runtime acceptance", "argv": argv,
        "release_lock_sha256": lock_module.sha256_file(lock_path), "source_checksums_sha256": lock["source_checksums_sha256"],
        "release_inputs_sha256": lock["release_inputs_sha256"], "analyzer_requirements_sha256": lock["analyzer_requirements_sha256"], "build_requested": args.build})
    if not args.build:
        print("Prepared only; no freeze executed:", base); return
    start = time.monotonic()
    with (base / "build.log").open("wb") as log:
        process = subprocess.Popen(argv, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
        save(base / "build-handle.json", {"pid": process.pid, "argv": argv, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()})
        code = process.wait()
    save(base / "build-exit.json", {"exit_code": code, "seconds": time.monotonic()-start})
    if code:
        raise SystemExit(code)
    rows = []
    def walk(value):
        if isinstance(value, (tuple, list)):
            if len(value) > 2 and isinstance(value[0], str) and (value[0] == "attackmap" or value[0].startswith("attackmap.")) and isinstance(value[1], str) and value[1].endswith(".py"):
                rows.append(value[:3])
            for item in value:
                walk(item)
    walk(ast.literal_eval((base / "build/attackmap/Analysis-00.toc").read_text(encoding="utf-8")))
    required = {"attackmap.desktop_worker", "attackmap.desktop_actions", "attackmap.desktop_ai", "attackmap.desktop_fleet", "attackmap.scan_service", "attackmap.artifact_publisher"}
    if not required <= {row[0] for row in rows}:
        raise RuntimeError("Required native broker modules missing from frozen TOC.")
    if any(not Path(row[1]).resolve().is_relative_to(source / "src/attackmap") for row in rows):
        raise RuntimeError("Frozen core module originated outside immutable snapshot.")
    if lock_module.release_inputs(source) != inputs or lock_module.release_inputs(repo) != inputs:
        raise RuntimeError("Source changed during build; this freeze must not be packaged against current sources.")
    payload = [{"path": p.relative_to(base / "dist/attackmap").as_posix(), "size_bytes": p.stat().st_size, "sha256": lock_module.sha256_file(p)} for p in sorted((base / "dist/attackmap").rglob("*")) if p.is_file()]
    save(base / "build-proof.json", {"scope": "Actual fresh freeze provenance; runtime capability/scan/action checks still required", "core_origins": rows, "payload_files": payload, "exe_sha256": lock_module.sha256_file(base / "dist/attackmap/attackmap.exe"), "release_lock_sha256": lock_module.sha256_file(lock_path)})
    print("Frozen; runtime verification still required:", base)

if __name__ == "__main__":
    main()
