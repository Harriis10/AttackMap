"""Bounded WP042 batch2 verification; each command owns its process tree and output."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
EVIDENCE = Path(__file__).resolve().parent
WORK = ROOT / ".tmp/wp042-sol-ultra-20261023-batch2"
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as native
import generate_release_lock as locks


def run(label, command, timeout=600, environment=None):
    command = [str(arg) for arg in command]
    folder = EVIDENCE / label
    folder.mkdir()
    env = native.child_environment(folder)
    env.update(DOTNET_ROOT=str(ROOT / ".tools/dotnet"), DOTNET_CLI_HOME=str(ROOT / ".tools/dotnet-home"),
               NUGET_PACKAGES=str(ROOT / ".tools/nuget-packages"), DOTNET_CLI_TELEMETRY_OPTOUT="1",
               MSBUILDDISABLENODEREUSE="1", PYTHONDONTWRITEBYTECODE="1")
    env.update(environment or {})
    native.save(folder / "command.json", command)
    native.launch([str(arg) for arg in command], folder, env, timeout)
    return folder


def build_native(label):
    before = locks.release_inputs(ROOT)
    output = WORK / label
    native.require(not output.exists(), "Use new native publish directory")
    folder = run(label, [ROOT / ".tools/dotnet/dotnet.exe", "publish",
        ROOT / "desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj", "--no-restore",
        "-c", "Release", "-r", "win-x64", "--self-contained", "true", "-o", output,
        "-p:NuGetAudit=false", "-p:UseSharedCompilation=false", "-nodeReuse:false"], 600)
    after = locks.release_inputs(ROOT)
    native.save(folder / "build-proof.json", dict(inputs_before=before, inputs_after=after,
        inputs_unchanged=before == after, output=str(output),
        payload={p.relative_to(output).as_posix(): native.sha(p) for p in output.rglob("*") if p.is_file()},
        scope="Actual native publish; visual and selected-engine runtime checks are separate"))
    native.require(before == after, "Sources changed during native publish")


def build_engine(label):
    freeze = WORK / label
    native.require(not freeze.exists(), "Use a fresh freeze")
    run(label, [ROOT / ".venv/Scripts/python.exe", ROOT / "docs/verification/windows-parity/WP024/fresh_freeze.py",
        "--root-released", "--repo", ROOT, "--output", freeze,
        "--freeze-python", ROOT / ".tools/wp024-freeze-venv/Scripts/python.exe",
        "--dotnet", ROOT / ".tools/dotnet/dotnet.exe",
        "--analyzer-audit", ROOT / "docs/verification/windows-parity/WP024/cached-analyzer-audit-2026-10-21.json",
        "--wheelhouse", ROOT / ".tools/wp024-wheelhouse", "--build"], 1200)


def native_smoke(label, native_directory, engine):
    output = WORK / label
    output.mkdir(parents=True)
    run(label, [native_directory / "AttackMap.NativeSpike.exe", "--analyzer-smoke", output,
        "--engine", engine, "--analyzer-profile", "node-atproto@1.0", "--native-scan",
        "--repository", r"C:\tmp\juice-shop"], 900)
    proof = native.read(output / "analyzer-smoke.json")
    native.require(proof.get("failure") is None and proof["result"]["passed"], "Native analyzer journey failed")
    native.save(EVIDENCE / (label + "-proof.json"), proof)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["build-native", "build-engine", "native-smoke"])
    parser.add_argument("--label", required=True)
    parser.add_argument("--native", type=Path)
    parser.add_argument("--engine", type=Path)
    args = parser.parse_args()
    WORK.mkdir(exist_ok=True)
    if args.operation == "build-native": build_native(args.label)
    elif args.operation == "build-engine": build_engine(args.label)
    else: native_smoke(args.label, args.native.resolve(), args.engine.resolve())
    print(json.dumps(dict(operation=args.operation, label=args.label, passed=True)))
