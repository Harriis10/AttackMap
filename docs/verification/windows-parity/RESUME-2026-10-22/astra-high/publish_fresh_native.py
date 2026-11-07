"""Publish the full native product into a new directory and bind all current inputs."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import generate_release_lock as lock_tool
import run_wp017_native_modes as native


def inputs():
    result = lock_tool.release_inputs(ROOT)
    result["native_extra_inputs"] = {
        name: native.sha(ROOT / name) for name in (
            "desktop/windows/fixtures/findings.json",
            "desktop/windows/AttackMap.NativeSpike/obj/project.assets.json")}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    publish, output = args.publish.resolve(), args.output.resolve()
    native.require(not publish.exists() and not output.exists(), "Use fresh publish and evidence paths")
    native.require(publish.is_relative_to(ROOT) and output.is_relative_to(ROOT), "Outputs must be inside workspace")
    output.mkdir(parents=True)
    before = inputs()
    native.save(output / "build-inputs-before.json", before)
    env = native.child_environment(output)
    env.update(DOTNET_ROOT=str(ROOT / ".tools/dotnet"), DOTNET_CLI_HOME=str(ROOT / ".tools/dotnet-home"),
        NUGET_PACKAGES=str(ROOT / ".tools/nuget-packages"), DOTNET_NOLOGO="1", DOTNET_CLI_TELEMETRY_OPTOUT="1",
        MSBUILDDISABLENODEREUSE="1")
    arguments = [str(ROOT / ".tools/dotnet/dotnet.exe"), "publish",
        str(ROOT / "desktop/windows/AttackMap.NativeSpike/AttackMap.NativeSpike.csproj"),
        "-c", "Release", "-r", "win-x64", "--self-contained", "true", "--no-restore",
        "-p:UseSharedCompilation=false", "-nodeReuse:false", "-o", str(publish)]
    native.launch(arguments, output, env, 600)
    after = inputs()
    native.save(output / "build-inputs-after.json", after)
    native.require(before == after, "Source or resolved dependencies changed during publish")
    artifacts = {name: dict(sha256=native.sha(publish / name), bytes=(publish / name).stat().st_size)
        for name in ("AttackMap.NativeSpike.exe", "AttackMap.NativeSpike.dll")}
    native.save(output / "native-build.json", dict(build_id=publish.name,
        inputs_unchanged=True, release_inputs_sha256=before["release_inputs_sha256"],
        inputs=before["release_inputs"], native_extra_inputs=before["native_extra_inputs"], artifacts=artifacts,
        scope="Actual full native publish bound to unchanged release sources; GUI/runtime acceptance separate"))
    print(json.dumps(dict(passed=True, publish=str(publish), proof=str(output / "native-build.json"), artifacts=artifacts)))
