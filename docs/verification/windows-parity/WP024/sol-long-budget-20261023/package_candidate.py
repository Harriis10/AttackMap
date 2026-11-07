"""Create one new RequiredBundled package and SBOM from the verified fresh pair."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as native
import generate_release_lock as locks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--publish", type=Path, required=True)
    args = parser.parse_args()
    output, packages = args.output.resolve(), args.packages.resolve()
    for path in (output, packages):
        native.require(path.is_relative_to(ROOT) and not path.exists(), "Use a new workspace directory")
    freeze, proof, publish = args.freeze.resolve(), args.proof.resolve(), args.publish.resolve()
    for path in (freeze, proof, publish):
        native.require(path.is_relative_to(ROOT) and path.is_dir(), "Existing workspace input directory required")
    release_lock = freeze / "release-lock.json"
    before = locks.release_inputs(ROOT)
    lock = native.read(release_lock)
    build = native.read(proof / "native-build/native-build.json")
    for key in ("source_checksums_sha256", "release_inputs_sha256", "analyzer_requirements_sha256"):
        native.require(before[key] == lock[key], "Stale release input: " + key)
    native.require(build["release_inputs_sha256"] == before["release_inputs_sha256"], "Native/source identity mismatch")
    for name, row in build["artifacts"].items():
        native.require(native.sha(publish / name) == row["sha256"] and (publish / name).stat().st_size == row["bytes"], "Native publish changed")
    output.mkdir(parents=True)
    native.save(output / "inputs-before.json", before)
    env = native.child_environment(output)
    command = [r"C:\Program Files\PowerShell\7\pwsh.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        str(ROOT / "tools/package_native_windows.ps1"), "-Profile", "RequiredBundled",
        "-PublishDirectory", str(publish), "-OutputDirectory", str(packages),
        "-EngineDirectory", str(freeze / "dist/attackmap"),
        "-EngineVerificationPath", str(proof / "runtime/engine-verification.json"),
        "-ReleaseLockPath", str(release_lock), "-SourceRoot", str(ROOT),
        "-PythonExecutable", str(ROOT / ".venv/Scripts/python.exe")]
    native.save(output / "command.json", command)
    native.launch(command, output, env, 900)
    stages = list(packages.glob("dev-*/package-manifest.json"))
    native.require(len(stages) == 1, "Expected one newly created package")
    stage = stages[0].parent
    identity = native.package_identity(stage / "app/AttackMap.NativeSpike.exe", native.sha(stages[0]), release_lock)
    for name, row in build["artifacts"].items():
        native.require(native.sha(stage / "app" / name) == row["sha256"], "Packaged native differs from qualified publish")
    archive = stage.with_suffix(".zip")
    digest_line = archive.with_suffix(".zip.sha256").read_text(encoding="ascii").strip()
    native.require(digest_line == native.sha(archive) + "  " + archive.name, "Archive digest mismatch")
    after = locks.release_inputs(ROOT)
    native.save(output / "inputs-after.json", after)
    native.require(before == after, "Release inputs changed while packaging")
    native.save(output / "package-verification.json", identity)
    sbom_log = output / "sbom-command"
    sbom_log.mkdir()
    native.launch([str(ROOT / ".venv/Scripts/python.exe"), str(ROOT / "tools/generate_release_sbom.py"),
        "--package", str(stage), "--output", str(output / "sbom"), "--engine-venv", str(ROOT / ".tools/wp024-freeze-venv")],
        sbom_log, env, 120)
    sbom = native.read(output / "sbom/release-sbom.json")
    native.require(sbom["python_dependencies"]["status"] == "known", "SBOM dependency inventory unavailable")
    native.require(native.package_identity(stage / "app/AttackMap.NativeSpike.exe", native.sha(stages[0]), release_lock) == identity, "Package changed during SBOM")
    summary = dict(passed=True, package=str(stage), archive=native.record(archive), manifest=native.record(stages[0]),
        release_lock=native.record(release_lock), inputs_unchanged=True,
        sbom=native.record(output / "sbom/release-sbom.json"), python_dependencies=sbom["python_dependencies"]["package_count"],
        scope="RequiredBundled unsigned package and SBOM; installation/native runtime acceptance is separate",
        accepted_clean_host=False, accepted_release=False)
    native.save(output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
