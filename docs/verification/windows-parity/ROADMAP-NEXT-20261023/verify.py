"""Scoped native QA from a new immutable capture; retained engine, no provider calls."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).resolve().parent
WORK = ROOT / ".tmp/roadmap-next-20261023"
SOURCE = WORK / "source-01"
NATIVE = WORK / "native-01"
ATTEMPT = "01"
RUNTIME_ATTEMPT = "01"
ENGINE = ROOT / ".tmp/wp043-fleet16-20261023/engine-captured-02/dist/attackmap"
sys.path.insert(0, str(ROOT / "tools"))
import generate_release_lock as locks
import run_wp017_native_modes as runner


def save(path, value):
    runner.save(path, value)


def hashes(path):
    return {file.relative_to(path).as_posix(): locks.sha256_file(file)
            for file in sorted(path.rglob("*")) if file.is_file()}


def run(label, command, timeout):
    folder = EVIDENCE / label
    folder.mkdir()
    environment = runner.child_environment(WORK / "environments" / label)
    environment.update(DOTNET_ROOT=str(ROOT / ".tools/dotnet"),
        DOTNET_CLI_HOME=str(WORK / "dotnet-home"),
        NUGET_PACKAGES=str(ROOT / ".tmp/wp043-fleet16-20261023/native/packages"),
        DOTNET_CLI_TELEMETRY_OPTOUT="1", MSBUILDDISABLENODEREUSE="1",
        PYTHONDONTWRITEBYTECODE="1")
    arguments = [str(value) for value in command]
    save(folder / "command.json", arguments)
    runner.launch(arguments, folder, environment, timeout)
    return folder


def capture():
    WORK.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location("fleet_capture",
        ROOT / "docs/verification/windows-parity/WP043/fleet16-20261023/qualify_candidate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SOURCE, module.EVIDENCE, module.ATTEMPT = SOURCE, EVIDENCE, "next" + ATTEMPT
    module.capture()


def publish():
    before = locks.release_inputs(SOURCE)
    folder = run("native-publish-" + ATTEMPT, [ROOT / ".tools/dotnet/dotnet.exe", "publish",
        SOURCE / "desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj",
        "--artifacts-path", WORK / ("build-" + ATTEMPT), "-c", "Release", "-r", "win-x64",
        "--self-contained", "true", "-o", NATIVE, "-m:1", "-p:BuildInParallel=false",
        "-p:RestoreFallbackFolders=" + str(ROOT / ".tools/nuget-packages"),
        "-p:NuGetAudit=false", "-p:UseSharedCompilation=false", "-nodeReuse:false",
        "--ignore-failed-sources"], 900)
    after = locks.release_inputs(SOURCE)
    save(folder / "build-proof.json", dict(inputs_before=before, inputs_after=after,
        inputs_unchanged=before == after, output=str(NATIVE), payload=hashes(NATIVE),
        scope="New native capture; retained engine used only for scoped UI QA, no same-source package acceptance"))
    runner.require(before == after, "Captured source changed during publish")


def smoke():
    output = WORK / ("fleet-smoke-" + RUNTIME_ATTEMPT)
    output.mkdir()
    native_before, engine_before = hashes(NATIVE), hashes(ENGINE)
    run("native-fleet-" + RUNTIME_ATTEMPT, [NATIVE / "AttackMap.NativeSpike.exe", "--fleet-graph-smoke", output,
        "--roots-json", ROOT / ".tmp/wp043-fleet16-20261023/integration/corpus-manifest.json",
        "--engine", ENGINE / "attackmap.exe", "--evidence-journey"], 1440)
    proof = runner.read(output / "fleet-graph-smoke.json")
    save(EVIDENCE / ("fleet-smoke-proof-" + RUNTIME_ATTEMPT + ".json"), proof)
    native_after, engine_after = hashes(NATIVE), hashes(ENGINE)
    binding = dict(native_directory=str(NATIVE), engine_directory=str(ENGINE),
        native_payload=native_before, engine_payload=engine_before,
        native_payload_unchanged=native_before == native_after,
        retained_engine_payload_unchanged=engine_before == engine_after,
        source="Native publish from this batch; retained frozen source02 engine",
        accepted_same_source_package=False, accepted_manual_ui=False)
    save(EVIDENCE / ("fleet-runtime-binding-" + RUNTIME_ATTEMPT + ".json"), binding)
    runner.require(proof.get("passed") and proof.get("failure") is None, "Fleet evidence journey failed")
    runner.require(native_before == native_after and engine_before == engine_after, "QA payload changed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["capture", "publish", "smoke"])
    parser.add_argument("--attempt", choices=["01", "02", "03"], default="01")
    parser.add_argument("--runtime-attempt", choices=["01", "02", "03", "04", "05"])
    args = parser.parse_args()
    ATTEMPT = args.attempt
    RUNTIME_ATTEMPT = args.runtime_attempt or ATTEMPT
    SOURCE, NATIVE = WORK / ("source-" + ATTEMPT), WORK / ("native-" + ATTEMPT)
    globals()[args.operation]()
