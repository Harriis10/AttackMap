"""New-only fleet graph checkpoint. Builds an explicitly captured source, never live edits."""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[5]
EVIDENCE = Path(__file__).resolve().parent / "candidate"
WORK = ROOT / ".tmp/wp043-fleet16-20261023"
SOURCE = WORK / "candidate-source-01"
FREEZE = WORK / "engine-captured-01"
NATIVE = WORK / "native-captured-01"
ATTEMPT = "01"
sys.path.insert(0, str(ROOT / "tools"))
import generate_release_lock as locks
import run_wp017_native_modes as runner


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def run(label, command, timeout):
    folder = EVIDENCE / label
    folder.mkdir(parents=True)
    environment = runner.child_environment(WORK / "process-environments" / label)
    environment.update(DOTNET_ROOT=str(ROOT / ".tools/dotnet"),
        DOTNET_CLI_HOME=str(WORK / "candidate-dotnet-home"),
        NUGET_PACKAGES=str(WORK / "native/packages"),
        DOTNET_CLI_TELEMETRY_OPTOUT="1", MSBUILDDISABLENODEREUSE="1",
        PYTHONDONTWRITEBYTECODE="1")
    save(folder / "command.json", [str(value) for value in command])
    runner.launch([str(value) for value in command], folder, environment, timeout)
    return folder


def capture():
    runner.require(not SOURCE.exists(), "Choose a new captured-source path")
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    before = locks.release_inputs(ROOT)
    SOURCE.mkdir()
    for relative, expected in before["release_inputs"].items():
        original, destination = ROOT / relative, SOURCE / relative
        runner.require(locks.sha256_file(original) == expected, "Source changed before copy: " + relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        runner.require(locks.sha256_file(destination) == expected, "Captured source byte mismatch: " + relative)
    after = locks.release_inputs(ROOT)
    captured = locks.release_inputs(SOURCE)
    proof = dict(kind="immutable-independent-release-input-checkpoint", started=started,
        ended=datetime.datetime.now(datetime.timezone.utc).isoformat(), source=str(SOURCE),
        inputs=before, current_inputs_unchanged=after == before, captured_inputs_match=captured == before,
        scope="Both binaries must be built from this capture. Later live checkout edits are not included.")
    save(EVIDENCE / f"source-capture-{ATTEMPT}.json", proof)
    runner.require(after == before and captured == before, "Concurrent source change; use a fresh capture")


def engine():
    run(f"engine-captured-{ATTEMPT}", [ROOT / ".venv/Scripts/python.exe", "-B",
        ROOT / "docs/verification/windows-parity/WP024/fresh_freeze.py", "--root-released",
        "--repo", SOURCE, "--output", FREEZE,
        "--freeze-python", ROOT / ".tools/wp024-freeze-venv/Scripts/python.exe",
        "--dotnet", ROOT / ".tools/dotnet/dotnet.exe",
        "--analyzer-audit", ROOT / "docs/verification/windows-parity/WP024/cached-analyzer-audit-2026-10-21.json",
        "--wheelhouse", ROOT / ".tools/wp024-wheelhouse", "--build"], 1200)


def native():
    before = locks.release_inputs(SOURCE)
    folder = run(f"native-captured-{ATTEMPT}", [ROOT / ".tools/dotnet/dotnet.exe", "publish",
        SOURCE / "desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj",
        "--artifacts-path", WORK / f"native-captured-build-{ATTEMPT}", "-c", "Release", "-r", "win-x64",
        "--self-contained", "true", "-o", NATIVE, "-m:1", "-p:BuildInParallel=false",
        "-p:RestoreFallbackFolders=" + str(ROOT / ".tools/nuget-packages"), "-p:NuGetAudit=false",
        "-p:UseSharedCompilation=false", "-nodeReuse:false", "--ignore-failed-sources"], 900)
    after = locks.release_inputs(SOURCE)
    save(folder / "build-proof.json", dict(inputs_before=before, inputs_after=after,
        inputs_unchanged=before == after, output=str(NATIVE),
        payload={path.relative_to(NATIVE).as_posix(): locks.sha256_file(path)
            for path in NATIVE.rglob("*") if path.is_file()},
        scope="Actual self-contained native publish from the independent source checkpoint; UI acceptance separate"))
    runner.require(before == after, "Captured native source changed")


def qualify_engine():
    spec = importlib.util.spec_from_file_location("fresh_graph_engine_qualification",
        ROOT / "docs/verification/windows-parity/RESUME-2026-10-22/astra-high/qualify_fresh_engine.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = SOURCE
    output = WORK / f"frozen-runtime-{ATTEMPT}"
    module.qualify(FREEZE, output)
    durable = EVIDENCE / f"frozen-runtime-{ATTEMPT}"
    durable.mkdir()
    shutil.copyfile(output / "engine-verification.json", durable / "engine-verification.json")
    for name in ("version", "modules", "capabilities", "scan", "compare"):
        (durable / name).mkdir()
        for filename in ("started.json", "process.json", "stdout.log", "stderr.log"):
            path = output / name / filename
            if path.is_file(): shutil.copyfile(path, durable / name / filename)


def smoke():
    output = WORK / f"native-fleet-smoke-{ATTEMPT}"
    output.mkdir()
    build_path = EVIDENCE / f"native-captured-{ATTEMPT}/build-proof.json"
    native_build = runner.read(build_path)
    engine_build_path = FREEZE / "build-proof.json"
    engine_build = runner.read(engine_build_path)
    def hashes(folder):
        return {path.relative_to(folder).as_posix(): locks.sha256_file(path)
            for path in folder.rglob("*") if path.is_file()}
    native_before = hashes(NATIVE)
    engine_before = hashes(FREEZE / "dist/attackmap")
    runner.require(native_before == native_build["payload"], "Native payload differs before runtime")
    runner.require(engine_before == {row["path"]: row["sha256"] for row in engine_build["payload_files"]}, "Engine payload differs before runtime")
    folder = run(f"native-fleet-smoke-{ATTEMPT}", [NATIVE / "AttackMap.NativeSpike.exe", "--fleet-graph-smoke", output,
        "--roots-json", WORK / "integration/corpus-manifest.json", "--engine",
        FREEZE / "dist/attackmap/attackmap.exe", "--keep-open"], 1440)
    proof = runner.read(output / "fleet-graph-smoke.json")
    save(EVIDENCE / f"native-fleet-smoke-{ATTEMPT}-proof.json", proof)
    runner.require(proof.get("passed") and proof.get("failure") is None, "Native fleet graph smoke failed")
    native_after, engine_after = hashes(NATIVE), hashes(FREEZE / "dist/attackmap")
    binding = dict(passed=native_before == native_after and engine_before == engine_after,
        native_directory=str(NATIVE), native_executable=str(NATIVE / "AttackMap.NativeSpike.exe"),
        engine_executable=str(FREEZE / "dist/attackmap/attackmap.exe"),
        native_build_proof_sha256=locks.sha256_file(build_path), engine_build_proof_sha256=locks.sha256_file(engine_build_path),
        native_payload=native_before, engine_payload=engine_before,
        native_payload_unchanged=native_before == native_after, engine_payload_unchanged=engine_before == engine_after,
        runtime_proof_sha256=locks.sha256_file(EVIDENCE / f"native-fleet-smoke-{ATTEMPT}-proof.json"),
        command_proof_sha256=locks.sha256_file(folder / "started.json"),
        process=runner.read(folder / "process.json"),
        release_inputs_sha256=native_build["inputs_before"]["release_inputs_sha256"],
        scope="Actual command path plus complete before/after native and engine payload hashes, matching immutable build proofs; not manual or clean-host acceptance")
    save(EVIDENCE / f"native-fleet-smoke-{ATTEMPT}-binding.json", binding)
    runner.require(binding["passed"], "Native/engine payload changed during runtime")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["capture", "engine", "native", "qualify-engine", "smoke"])
    parser.add_argument("--attempt", choices=["01", "02", "03"], default="01")
    arguments = parser.parse_args()
    operation, ATTEMPT = arguments.operation, arguments.attempt
    SOURCE = WORK / f"candidate-source-{ATTEMPT}"
    FREEZE = WORK / f"engine-captured-{ATTEMPT}"
    NATIVE = WORK / f"native-captured-{ATTEMPT}"
    {"capture": capture, "engine": engine, "native": native,
     "qualify-engine": qualify_engine, "smoke": smoke}[operation]()
    print(json.dumps(dict(operation=operation, passed=True)))
