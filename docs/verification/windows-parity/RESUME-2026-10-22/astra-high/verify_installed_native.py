"""Opt-in actual CMD installation and full native bundled scan; new workspace roots only.

Default is read-only preflight. --run requires a reviewed manifest pin. No cleanup,
upgrade, provider generation, or human/clean-host/release acceptance is performed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools"))
import run_wp017_native_modes as native

EXPECTED_ENGINE_SHA256 = "f4ce2e74446198e667cef7e134dbd74654d5e03ec9d9efcaa364235c2cf11107"
DEFAULT_NATIVE_PROOF = ROOT / "docs/verification/windows-parity/WP024/astra-fresh-20261022/native-build/native-build.json"
STARTUP_LIMIT = (
    "Normal --verify-portable-startup was not requested: its normal settings/provider/recent-repository "
    "and window persistence use Environment.GetFolderPath(LocalApplicationData). On .NET 8 Windows "
    "this resolves through SHGetKnownFolderPath, so environment variables alone do not establish a "
    "private Windows profile. The parity journey explicitly selects private settings/recent files."
)


def workspace(value):
    path = native.local_path(Path(value).absolute())
    native.require(path != ROOT and path.is_relative_to(ROOT), "Path must stay inside this workspace: " + str(path))
    return path


def disjoint(left, right):
    native.require(not left.is_relative_to(right) and not right.is_relative_to(left), "Overlapping input/output roots")


def fingerprint(path):
    return dict(size_bytes=path.stat().st_size, sha256=native.sha(path))


def verify_tree(folder, expected):
    """Verify exact files and directories, including hidden entries and link aliases."""
    native.local_path(folder)
    directories, folded = set(), set()
    for name in expected:
        native.relative_name(name)
        native.require(name.casefold() not in folded, "Case-aliased inventory")
        folded.add(name.casefold())
        directories.update(str(p) for p in PurePosixPath(name).parents if str(p) != ".")
    actual = set()
    for current, dirs, files in os.walk(folder, followlinks=False):
        for name in dirs + files:
            path = Path(current) / name
            native.no_link(path)
            relative = path.relative_to(folder).as_posix()
            if path.is_dir():
                native.require(relative in directories, "Unexpected installed directory: " + relative)
            else:
                native.require(relative in expected, "Unexpected installed file: " + relative)
                native.require(path.stat().st_nlink == 1, "Hard-linked installed file: " + relative)
                native.require(fingerprint(path) == expected[relative], "Installed payload mismatch: " + relative)
                actual.add(relative)
    native.require(actual == expected.keys(), "Installed files missing")
    return len(actual)


def preflight(args):
    native.require(os.name == "nt", "Windows is required")
    stage, lock, seed = (workspace(value) for value in (args.stage, args.release_lock, args.seed))
    install, output, native_proof = (workspace(value) for value in (args.install_root, args.output, args.native_proof))
    native.require(stage.is_dir() and seed.is_file() and native_proof.is_file(), "Missing package, seed or native proof")
    native.require(not install.exists() and not output.exists(), "Installation and evidence roots must be new")
    disjoint(install, output)
    for destination in (install, output):
        for source in (stage, lock, seed, native_proof):
            disjoint(destination, source)
    # CMD CALL reparses its arguments. Reject shell metacharacters rather than
    # attempting to escape user-controlled path text across two parsing passes.
    for path in (stage, install):
        native.require(not any(char in str(path) for char in '%!&^()'), "CMD installer paths cannot contain shell metacharacters")
    native.require(isinstance(native.read(seed).get("scan"), dict), "Seed must be a canonical report")
    package = native.package_identity(stage / "app" / native.APP_NAME, args.manifest_sha256, lock)
    native.require(Path(package["manifest"]["path"]) == stage / "package-manifest.json"
                   and package["release_lock"] is not None, "Only RequiredBundled production stages are supported")
    native.require(package["identities"]["engine/attackmap.exe"]["sha256"] == EXPECTED_ENGINE_SHA256,
                   "Unexpected engine; this evidence helper pins the reviewed fresh engine")
    build, release = native.read(native_proof), native.read(lock)
    native.require(build.get("inputs_unchanged") is True and build.get("inputs") == release.get("release_inputs")
                   and build.get("release_inputs_sha256") == release.get("release_inputs_sha256"), "Native build/source lock mismatch")
    for name in (native.APP_NAME, "AttackMap.NativeSpike.dll"):
        row = build["artifacts"][name]
        native.require(fingerprint(stage / "app" / name) == dict(size_bytes=row["bytes"], sha256=row["sha256"]),
                       "Native executable/DLL differ from the reviewed build")
    for name, digest in build["native_extra_inputs"].items():
        path = workspace(ROOT / native.relative_name(name))
        native.require(native.sha(path) == digest, "Native linked fixture/resolved assets changed")
    native.require(native.local_path(native.REPOSITORY).is_dir(), "Juice Shop repository unavailable")
    return dict(stage=str(stage), install_root=str(install), output=str(output), package=package,
                seed=native.record(seed), native_build=native.record(native_proof),
                repository=str(native.REPOSITORY), explicit_installed_engine=True,
                explicit_engine_reason="MainWindow.ParitySmoke.cs:49 requires --engine for --native-scan.",
                normal_startup=dict(executed=False, reason=STARTUP_LIMIT),
                scope="Preflight only; no installer/native/provider process started")


def verify_install(plan):
    stage, install = Path(plan["stage"]), Path(plan["install_root"])
    manifest_path = stage / "package-manifest.json"
    manifest = native.read(manifest_path)
    package_id = plan["package"]["package_id"]
    current_path = native.local_path(install / "current.json")
    native.require(native.read(current_path) == {"package_id": package_id}, "Installed current pointer mismatch")
    owner = native.local_path(install / ".attackmap-development-install")
    native.require(owner.read_text(encoding="utf-8-sig").strip() == "AttackMap development package ownership v1", "Missing installer ownership marker")
    version = install / "versions" / package_id
    installed_manifest = native.local_path(version / "package-manifest.json")
    native.require(native.sha(installed_manifest) == plan["package"]["manifest"]["sha256"], "Installed manifest differs from reviewed package")
    prefix = "versions/" + package_id + "/"
    expected = {prefix + "app/" + row["path"]: {key: row[key] for key in ("size_bytes", "sha256")}
                for row in manifest["files"]}
    expected[prefix + "package-manifest.json"] = fingerprint(manifest_path)
    expected["current.json"], expected[owner.name] = fingerprint(current_path), fingerprint(owner)
    count = verify_tree(install, expected)
    return dict(passed=True, package_id=package_id, files_verified=count, expected=expected,
                current=native.record(current_path), manifest=native.record(installed_manifest),
                app=str(version / "app" / native.APP_NAME), engine=str(version / "app/engine/attackmap.exe"))


def verify_scan(folder, plan):
    smoke_path = native.bound_inside(folder / "parity-smoke.json", folder)
    smoke = native.read(smoke_path)
    result = smoke.get("result") or {}
    native.require(smoke.get("failure") is None, "Native smoke failed")
    for key in ("passed", "capabilitiesChecked", "scanCompleted", "progressTerminal", "isolatedOutput"):
        native.require(result.get(key) is True, "Native result missing " + key)
    native.require(result.get("personalSettingsRead") is False and result.get("progressState") == "completed"
                   and result.get("aiDisplay") is None, "Unexpected native settings/AI/progress state")
    report_root = folder / "reports"
    request_path = native.bound_inside(report_root / "native-request.json", folder)
    request = native.read(request_path)
    run_id = result.get("run")
    native.require(isinstance(run_id, str) and bool(re.fullmatch(r"[a-f0-9]{32}", run_id)), "Invalid native run identity")
    native.require(request.get("run_id") == run_id and request.get("repository_path") == plan["repository"]
                   and request.get("repository_id") == plan["repository"] and request.get("output_path") == str(report_root), "Request identity mismatch")
    options = request["options"]
    native.require(options.get("cve") is False and options.get("timeout_seconds") == 1200
                   and not (options.get("provider") or {}).get("enable_ai", False), "AI/CVE enabled or wrong timeout")
    report = native.bound_inside(result["report"], report_root)
    native.require(report == report_root / run_id / "attackmap-report.json" and native.sha(report) == result["reportHash"], "Wrong displayed report")
    canonical = native.read(report)
    native.require(Path(canonical["scan"]["root"]) == Path(plan["repository"]) and isinstance(canonical.get("findings"), list), "Canonical report identity/schema mismatch")
    manifest_path = native.bound_inside(report.parent / "artifact-manifest.json", folder)
    manifest = native.read(manifest_path)
    native.require(manifest.get("generation_id") == run_id and manifest.get("exit_state", {}).get("status") == "succeeded", "Generation did not succeed")
    seen = set()
    for row in manifest.get("sections", []) + manifest.get("compatibility_exports", []):
        name = native.relative_name(row["path"])
        native.require("/" not in name and name not in seen, "Unsafe/duplicate generation artifact")
        seen.add(name)
        path = native.bound_inside(report.parent / name, folder)
        native.require(fingerprint(path) == dict(size_bytes=row["size_bytes"], sha256=row["checksum"]), "Generation artifact changed")
    native.require({report.name, "run-manifest.json"} <= seen, "Incomplete generation inventory")
    pointer_path = native.bound_inside(report_root / "current-generation.json", folder)
    pointer = native.read(pointer_path)
    native.require(pointer.get("generation") == run_id and pointer.get("manifest_sha256") == native.sha(manifest_path), "Atomic generation pointer mismatch")
    native.require(native.read(report.parent / "run-manifest.json").get("desktop_ai", {}).get("model_output_available") is not True,
                   "Unexpected generated AI output")
    return dict(passed=True, run_id=run_id, request=native.record(request_path), report=native.record(report),
                artifact_manifest=native.record(manifest_path), current_generation=native.record(pointer_path),
                smoke=native.record(smoke_path), artifacts_verified=len(seen), ai_requested=False, cve_requested=False)


def execute(plan):
    output, stage = Path(plan["output"]), Path(plan["stage"])
    output.mkdir(parents=True)
    native.save(output / "preflight.json", plan)
    try:
        install_log = output / "installer"
        install_log.mkdir()
        environment = native.child_environment(install_log)
        system = Path(environment["SYSTEMROOT"])
        powershell = system / "System32/WindowsPowerShell/v1.0"
        native.require((powershell / "powershell.exe").is_file(), "Windows PowerShell unavailable")
        environment["PATH"] += ";" + str(powershell)
        environment["ATTACKMAP_INSTALL_NONINTERACTIVE"] = "1"
        for part in environment["PATH"].split(";"):
            native.require(not any((Path(part) / name).exists() for name in ("python.exe", "python3.exe", "pwsh.exe")), "Python/pwsh unexpectedly on installer PATH")
        native.save(install_log / "environment.json", dict(PATH=environment["PATH"], noninteractive=True,
                    launcher=str(stage / "Install-AttackMap.cmd"), expected_shell="Windows PowerShell 5.1"))
        # CALL avoids CMD's leading quoted-command special case. Metacharacters
        # were rejected in preflight; every dynamic path remains one quoted argv.
        native.launch([str(system / "System32/cmd.exe"), "/d", "/c", "call", str(stage / "Install-AttackMap.cmd"),
                       "-Mode", "Install", "-InstallRoot", plan["install_root"]], install_log, environment, 300)
        installed = verify_install(plan)
        native.save(output / "installed-before.json", installed)
        folder = output / "native"
        folder.mkdir()
        environment = native.child_environment(folder)
        for part in environment["PATH"].split(";"):
            native.require(not (Path(part) / "python.exe").exists(), "Python unexpectedly on native PATH")
        native.require(native.record(Path(plan["seed"]["path"])) == plan["seed"], "Seed changed before scan")
        native.launch([installed["app"], "--parity-smoke", plan["seed"]["path"], str(folder),
                       "--engine", installed["engine"], "--native-scan", "--repository", plan["repository"]],
                      folder, environment, 1500)
        scan = verify_scan(folder, plan)
        native.require(verify_install(plan) == installed, "Installed payload/current pointer changed during native run")
        lock = plan["package"]["release_lock"]["path"]
        native.require(native.package_identity(stage / "app" / native.APP_NAME, plan["package"]["manifest"]["sha256"], lock) == plan["package"],
                       "Original package/source lock changed")
        native.require(native.record(Path(plan["native_build"]["path"])) == plan["native_build"], "Native build proof changed")
        summary = dict(passed=True, scope="Actual CMD install plus installed full native bundled-engine scan on developer Windows",
                       package_id=installed["package_id"], installation=installed, scan=scan,
                       original_stage_unchanged=True, installed_payload_unchanged=True, explicit_installed_engine=True,
                       normal_startup=plan["normal_startup"],
                       limitations=["Parity scan requires explicit installed engine; it does not prove automatic startup discovery.",
                                    "Automated native journey; no human GUI/accessibility, clean-host, signing or release acceptance.",
                                    "AI and CVE disabled in emitted request; no provider generation was requested."],
                       installer_process=native.record(install_log / "process.json"), native_process=native.record(folder / "process.json"))
        native.save(output / "summary.json", summary)
        return summary
    except BaseException as error:
        native.save(output / "failure.json", dict(passed=False, error=str(error), artifacts_preserved=True))
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stage", "release-lock", "seed", "install-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--native-proof", type=Path, default=DEFAULT_NATIVE_PROOF)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--run", action="store_true")
    arguments = parser.parse_args()
    native.require(not arguments.run or arguments.manifest_sha256 is not None, "--run requires reviewed --manifest-sha256")
    plan = preflight(arguments)
    print(json.dumps(execute(plan) if arguments.run else plan, ensure_ascii=False, indent=2))
