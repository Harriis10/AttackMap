"""Create a new unsigned portable preview from a verified RequiredBundled stage.

Evidence-owned helper: no build, installer, engine, GUI, provider or network runs.
All provenance comes from explicit inputs; original stage and ZIP stay untouched.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import sys
import traceback
import zipfile


class PackageError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PackageError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_relative(value):
    require(isinstance(value, str) and value and "\\" not in value and ":" not in value,
            "Expected a nonempty relative forward-slash path")
    require(not PurePosixPath(value).is_absolute() and not PureWindowsPath(value).drive,
            "Absolute or drive-qualified entries are refused")
    parts = value.split("/")
    for part in parts:
        require(part not in ("", ".", "..") and part == part.strip() and not part.endswith("."),
                "Empty, traversal, ambiguous or trailing-dot path component")
        require(not any(ord(char) < 32 or char in '<>"|?*' for char in part), "Unsafe Windows path character")
        stem = part.split(".")[0].upper()
        require(stem not in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
                and not re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem), "Reserved Windows device path")
    return value


def unredirected(path, *, must_exist=True):
    path = Path(os.path.abspath(path))
    require(not str(path).startswith(("\\\\", "//")), "Use an absolute local path, not UNC")
    for part in [path, *path.parents]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            require(part != path or not must_exist, f"Missing input: {path}")
            continue
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024), f"Redirected path refused: {part}")
    require(not must_exist or path.exists(), f"Missing input: {path}")
    return path


def record(path):
    path = unredirected(path)
    require(path.is_file(), f"Expected a regular file: {path}")
    before = path.stat()
    digest = sha(path)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns, before.st_ino) ==
            (after.st_size, after.st_mtime_ns, after.st_ino), f"File changed during hashing: {path}")
    return {"size_bytes": after.st_size, "sha256": digest}


def inventory(root):
    root = unredirected(root)
    require(root.is_dir(), f"Expected directory: {root}")
    files, directories, folded = {}, [], set()
    for directory, subdirs, names in os.walk(root, followlinks=False):
        for name in sorted([*subdirs, *names]):
            path = Path(directory) / name
            unredirected(path)
            relative = safe_relative(path.relative_to(root).as_posix())
            require(relative.casefold() not in folded, f"Duplicate Windows entry: {relative}")
            folded.add(relative.casefold())
            if path.is_dir():
                directories.append(relative)
            else:
                require(stat.S_ISREG(path.lstat().st_mode), f"Non-regular input: {relative}")
                files[relative] = record(path)
    return {"files": dict(sorted(files.items())), "directories": sorted(directories)}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    path = unredirected(path)
    require(path.is_file() and path.stat().st_size <= 64 * 1024 * 1024, "JSON proof missing or larger than 64 MiB")
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(PackageError("Nonfinite JSON value")))


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def load_tool(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module


def hashes(value):
    require(isinstance(value, dict) and value, "Expected a nonempty path/hash inventory")
    result, folded = {}, set()
    for name, digest in value.items():
        safe_relative(name)
        require(name.casefold() not in folded and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
                "Duplicate or malformed path/hash inventory")
        folded.add(name.casefold())
        result[name] = digest
    return result


def source_digests(value):
    return {key: value[key] for key in ("source_checksums_sha256", "release_inputs_sha256", "analyzer_requirements_sha256")}


def zip_inventory(path, expected):
    """Re-read every ZIP member's actual bytes; CRC alone is insufficient."""
    names, directories, files, folded = [], [], {}, set()
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            require(not entry.flag_bits & 1, "Encrypted portable ZIP member refused")
            is_directory = entry.is_dir()
            name = safe_relative(entry.filename[:-1] if is_directory else entry.filename)
            require(name not in names and name.casefold() not in folded, "Duplicate/case-colliding ZIP entry")
            names.append(name)
            folded.add(name.casefold())
            require(not stat.S_ISLNK(entry.external_attr >> 16), "ZIP symlink refused")
            require(name == "AttackMap-Windows" or name.startswith("AttackMap-Windows/"), "ZIP entry outside portable root")
            relative = name.removeprefix("AttackMap-Windows/")
            if is_directory:
                if name != "AttackMap-Windows":
                    directories.append(relative)
                continue
            require(name != "AttackMap-Windows", "Portable root cannot be a file")
            require(relative in expected["files"] and entry.file_size == expected["files"][relative]["size_bytes"], "Unexpected ZIP entry or size")
            with archive.open(entry) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            files[relative] = {"size_bytes": entry.file_size, "sha256": digest}
    observed = {"files": dict(sorted(files.items())), "directories": sorted(directories)}
    require(observed == expected, "Portable ZIP contents differ from the complete portable inventory")
    return {"files_verified": len(files), "directories_verified": len(directories),
            "bytes_verified": sum(item["size_bytes"] for item in files.values())}


def validate_runtime(binding, runtime, started, native_build, engine_build, paths, stage_files, release_inputs):
    require(binding.get("passed") is True and binding.get("native_payload_unchanged") is True
            and binding.get("engine_payload_unchanged") is True, "Runtime payload binding did not pass unchanged")
    require(runtime.get("passed") is True and runtime.get("failure") is None
            and runtime.get("result", {}).get("passed") is True, "Native runtime proof did not pass")
    for field, key in (("native_build_proof_sha256", "native_build_proof"), ("engine_build_proof_sha256", "engine_build_proof"),
                       ("runtime_proof_sha256", "native_runtime_proof"), ("command_proof_sha256", "runtime_command")):
        require(binding.get(field) == sha(paths[key]), f"Runtime binding hash mismatch: {field}")
    process = binding.get("process", {})
    require(type(process.get("exit_code")) is int and process["exit_code"] == 0
            and process.get("exited") is True and process.get("timed_out") is False
            and process.get("owned_job_assigned") is True and process.get("owned_tree_cleanup_verified") is True
            and process.get("pid") == started.get("pid"), "Native runtime process/cleanup did not pass")
    require(binding.get("release_inputs_sha256") == release_inputs["release_inputs_sha256"], "Runtime belongs to another source capture")
    native_map = hashes(native_build["payload"])
    engine_rows = engine_build["payload_files"]
    require(isinstance(engine_rows, list) and len({row["path"].casefold() for row in engine_rows}) == len(engine_rows), "Duplicate engine build entry")
    engine_map = hashes({row["path"]: row["sha256"] for row in engine_rows})
    require(hashes(binding["native_payload"]) == native_map and hashes(binding["engine_payload"]) == engine_map,
            "Runtime payload inventory differs from the exact build proofs")
    native_directory = unredirected(binding["native_directory"])
    native_executable = unredirected(binding["native_executable"])
    engine_executable = unredirected(binding["engine_executable"])
    require(native_executable == native_directory / "AttackMap.NativeSpike.exe"
            and Path(native_build["output"]).absolute() == native_directory, "Native runtime executable is not the built executable")
    argv = started.get("arguments", [])
    require(isinstance(argv, list) and argv and Path(argv[0]).absolute() == native_executable
            and argv.count("--engine") == 1, "Runtime command does not identify the exact native executable/engine")
    engine_position = argv.index("--engine") + 1
    require(engine_position < len(argv) and Path(argv[engine_position]).absolute() == engine_executable
            and Path(runtime["result"]["engine"]).absolute() == engine_executable,
            "Runtime command/proof engine paths differ")
    require(sha(native_executable) == native_map["AttackMap.NativeSpike.exe"]
            and sha(engine_executable) == engine_map["attackmap.exe"], "Tested executable changed after runtime")
    # A stage omits PDB/log/smoke files by shipping policy; every retained byte
    # must nevertheless match the corresponding tested complete payload.
    for name, value in stage_files.items():
        if name.startswith("engine/"):
            expected = engine_map.get(name.removeprefix("engine/"))
        else:
            expected = native_map.get(name)
        require(value["sha256"] == expected, f"Stage file was not part of the tested exact payload: {name}")
    require({name.removeprefix("engine/"): value["sha256"] for name, value in stage_files.items() if name.startswith("engine/")} == engine_map,
            "Bundled engine is not the complete tested engine payload")
    require(native_build.get("inputs_unchanged") is True and native_build["inputs_before"] == native_build["inputs_after"],
            "Native build source inputs changed")
    require(native_build["inputs_before"]["release_inputs"] == release_inputs["release_inputs"],
            "Native build inventory differs from SourceRoot")
    # fresh_freeze build-proof binds source through its exact release-lock SHA;
    # direct source digest fields belong to the runtime engine verification.
    for observed in (native_build["inputs_before"], native_build["inputs_after"]):
        require(source_digests(observed) == source_digests(release_inputs), "Build provenance belongs to another source capture")
    return {"native_executable_sha256": native_map["AttackMap.NativeSpike.exe"],
            "native_dll_sha256": native_map["AttackMap.NativeSpike.dll"], "engine_executable_sha256": engine_map["attackmap.exe"],
            "native_payload_files": len(native_map), "engine_payload_files": len(engine_map),
            "native_payload_unchanged": True, "engine_payload_unchanged": True,
            "process": process, "native_runtime_passed": True}


def package(options):
    names = ("stage", "source_root", "release_lock", "native_build_proof", "engine_build_proof",
             "native_runtime_proof", "runtime_binding", "runtime_command")
    paths = {name: unredirected(getattr(options, name)) for name in names}
    output = unredirected(options.output, must_exist=False)
    require(not output.exists() and output.parent.is_dir(), "Choose a new output directory under an existing caller-owned parent")
    for name in ("stage", "source_root"):
        require(not output.is_relative_to(paths[name]) and not paths[name].is_relative_to(output), "Output must be outside source/stage trees")
    lock = read_json(paths["release_lock"])
    require(lock.get("schema_version") == 1 and lock.get("signing", {}).get("status") == "unsigned", "Expected unsigned development release lock")
    locked_files = hashes(lock["release_inputs"])
    for name in ("generate_release_lock.py", "generate_release_sbom.py"):
        tool = unredirected(paths["source_root"] / "tools" / name)
        require(sha(tool) == locked_files.get("tools/" + name), "Captured verifier differs from release lock")
    lock_tool = load_tool(paths["source_root"] / "tools/generate_release_lock.py", "portable_release_lock")
    sbom_tool = load_tool(paths["source_root"] / "tools/generate_release_sbom.py", "portable_release_sbom")
    inputs = lock_tool.release_inputs(paths["source_root"])
    require(source_digests(inputs) == source_digests(lock) and inputs["release_inputs"] == lock["release_inputs"], "SourceRoot differs from the supplied release lock")
    # Validate all paths before the existing verifier can traverse them.
    stage_before = inventory(paths["stage"])
    strict_manifest = read_json(paths["stage"] / "package-manifest.json")
    manifest = sbom_tool.load_manifest(paths["stage"])
    require(manifest == strict_manifest and manifest.get("profile") == "RequiredBundled"
            and manifest.get("engine", {}).get("bundled") is True
            and manifest.get("signing", {}).get("status") == "unsigned", "Expected an actual unsigned RequiredBundled package stage")
    require(paths["stage"].name == manifest["package_id"], "Stage directory does not match its generated package identity")
    original_zip = unredirected(options.stage_zip or paths["stage"].parent / (manifest["package_id"] + ".zip"))
    require(original_zip.is_file(), "Original RequiredBundled ZIP is required for preservation verification")
    stage_zip_before = record(original_zip)
    verification = sbom_tool.verify_package(paths["stage"], manifest)
    require(verification["package_manifest_sha256"] == stage_before["files"]["package-manifest.json"]["sha256"], "Stage manifest changed")
    app_before = inventory(paths["stage"] / "app")
    require(app_before["files"] == {row["path"]: {"size_bytes": row["size_bytes"], "sha256": row["sha256"]} for row in manifest["files"]}, "Stage app differs from complete manifest")
    native_runtime = manifest.get("native_runtime", {})
    require(native_runtime.get("dotnet_self_contained") is True and native_runtime.get("windows_app_sdk_self_contained") is True,
            "Portable preview requires the bundled .NET/Windows App SDK runtime")
    runtime_names = {name.casefold() for name in app_before["files"]}
    for name in ("AttackMap.NativeSpike.exe", "AttackMap.NativeSpike.dll", "AttackMap.NativeSpike.runtimeconfig.json",
                 "coreclr.dll", "hostfxr.dll", "hostpolicy.dll", "Microsoft.UI.Xaml.dll", "engine/attackmap.exe", "engine/_internal/base_library.zip"):
        require(name.casefold() in runtime_names, f"Required portable runtime file missing: {name}")
    require(any(re.fullmatch(r"engine/(?:_internal/)?python3[0-9]+\.dll", name) for name in app_before["files"]), "Frozen embedded Python runtime missing")
    engine_meta = manifest["engine"]
    require(engine_meta.get("runtime_kind") == "Frozen" and source_digests(engine_meta) == source_digests(inputs)
            and engine_meta.get("release_lock_sha256") == sha(paths["release_lock"]), "Bundled engine is not bound to this source/release lock")
    proof_paths = {name: path for name, path in paths.items() if name not in ("stage", "source_root")}
    proofs_before = {name: record(path) for name, path in proof_paths.items()}
    native_build, engine_build = read_json(paths["native_build_proof"]), read_json(paths["engine_build_proof"])
    require(engine_build.get("release_lock_sha256") == sha(paths["release_lock"]), "Engine build uses another release lock")
    runtime = validate_runtime(read_json(paths["runtime_binding"]), read_json(paths["native_runtime_proof"]),
        read_json(paths["runtime_command"]), native_build, engine_build, paths, app_before["files"], inputs)
    portable_reserved = {"portable-manifest.json", "Spustit-AttackMap.bat", "CTETE-ME.txt", "provenance"}
    require(not {name.split("/")[0].casefold() for name in [*app_before["files"], *app_before["directories"]]} & {name.casefold() for name in portable_reserved},
            "Stage app collides with portable metadata/launcher paths")
    output.mkdir()
    try:
        portable = output / "AttackMap-Windows"
        portable.mkdir()
        for relative in app_before["directories"]:
            (portable / relative).mkdir(parents=True, exist_ok=True)
        for relative, expected in app_before["files"].items():
            source, destination = paths["stage"] / "app" / relative, portable / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as reader, destination.open("xb") as writer:
                shutil.copyfileobj(reader, writer, 1024 * 1024)
            require(record(destination) == expected, f"Copied app byte mismatch: {relative}")
        require(inventory(portable) == app_before, "Copied app inventory differs before additions")
        provenance = portable / "provenance"
        provenance.mkdir()
        shutil.copyfile(paths["stage"] / "package-manifest.json", provenance / "required-bundled-package-manifest.json")
        shutil.copyfile(paths["release_lock"], provenance / "release-lock.json")
        require(record(provenance / "required-bundled-package-manifest.json") == stage_before["files"]["package-manifest.json"]
                and record(provenance / "release-lock.json") == proofs_before["release_lock"],
                "Copied provenance bytes differ from the verified inputs")
        write_json(provenance / "source.json", {"source_root": str(paths["source_root"]), **source_digests(inputs),
            "release_lock_sha256": sha(paths["release_lock"]), "required_bundled_package_id": manifest["package_id"],
            "required_bundled_manifest_sha256": verification["package_manifest_sha256"], "source_files": len(inputs["release_inputs"]),
            "original_stage_zip": stage_zip_before, "input_proofs": {key: {"path": str(proof_paths[key]), **value} for key, value in proofs_before.items()}})
        write_json(provenance / "native-runtime.json", {**runtime, "binding_sha256": sha(paths["runtime_binding"]),
            "runtime_proof_sha256": sha(paths["native_runtime_proof"]), "command_proof_sha256": sha(paths["runtime_command"]),
            "native_build_proof_sha256": sha(paths["native_build_proof"]), "engine_build_proof_sha256": sha(paths["engine_build_proof"]),
            "scope": "Verified exact native/engine runtime pair; no installation, clean-host, OS appearance, accessibility, signing or release acceptance"})
        launcher = '@echo off\r\nsetlocal\r\ncd /d "%~dp0"\r\nstart "AttackMap" "%~dp0AttackMap.NativeSpike.exe"\r\n'
        (portable / "Spustit-AttackMap.bat").write_bytes(launcher.encode("ascii"))
        readme = """AttackMap — přenosný vývojový náhled pro Windows x64

Rozbalte celý ZIP do zapisovatelné místní složky. Zachovejte všechny soubory
a podsložky. Spusťte Spustit-AttackMap.bat nebo AttackMap.NativeSpike.exe.
Lokální engine/attackmap.exe se vybírá automaticky při přenosném spuštění.
Pozdější výslovný výběr enginu v nastavení aplikace zůstává podporovaný.

Balíček obsahuje vlastní .NET, Windows App SDK a zmrazený Python engine.
Samostatná instalace .NET ani Pythonu pro tento balíček není potřeba.
Interaktivní graf potřebuje dostupný Microsoft Edge WebView2 Runtime.
Při jeho nedostupnosti aplikace nabízí nativní vektorový diagram.
Tento archiv WebView2 neinstaluje a nic automaticky nestahuje.

Jde o nepodepsaný vývojový náhled, nikoli veřejný release candidate.
Hashe dokládají shodu bajtů, nikoli ověřeného vydavatele. Vytvoření tohoto
archivu neprokazuje instalaci, čistý počítač, úplnou offline distribuci,
ruční ovládání, Narrator ani vzhled operačního systému. Původní ověřený
RequiredBundled balíček zůstává beze změny. Zkrácený původ zdrojů,
release locku a skutečného nativního běhu je ve složce provenance.
"""
        (portable / "CTETE-ME.txt").write_bytes(readme.replace("\n", "\r\n").encode("utf-8-sig"))
        marker = {"schema_version": 1, "kind": "portable-development-preview", "package_id": manifest["package_id"],
            "channel": "unsigned-development", "signing": {"status": "unsigned"}, "release_candidate": False,
            "runtime": {"engine": "engine/attackmap.exe", "dotnet_included": True, "python_included": True,
                        "webview2": "External runtime needed for interactive graph; native vector fallback available"},
            "source": source_digests(inputs), "source_package_manifest_sha256": verification["package_manifest_sha256"],
            "release_lock_sha256": sha(paths["release_lock"]), "native_runtime_binding_sha256": sha(paths["runtime_binding"]),
            "manual_acceptance": False, "clean_host_acceptance": False, "installation_acceptance": False}
        write_json(portable / "portable-manifest.json", marker)
        require((portable / "portable-manifest.json").stat().st_size <= 1024 * 1024, "Portable marker exceeds the app parser limit")
        complete = inventory(portable)
        write_json(output / "portable-inventory.json", complete)
        archive_path = output / ("AttackMap-Windows-" + manifest["package_id"] + ".zip")
        with zipfile.ZipFile(archive_path, "x", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            archive.write(portable, "AttackMap-Windows/")
            for relative in complete["directories"]:
                archive.write(portable / relative, "AttackMap-Windows/" + relative + "/")
            for relative in complete["files"]:
                archive.write(portable / relative, "AttackMap-Windows/" + relative)
        zip_proof = zip_inventory(archive_path, complete)
        require(inventory(portable) == complete, "Portable output changed during archiving")
        require(inventory(paths["stage"]) == stage_before and record(original_zip) == stage_zip_before,
                "Original RequiredBundled stage or ZIP changed; no preserved-input claim")
        require(lock_tool.release_inputs(paths["source_root"]) == inputs, "SourceRoot changed during packaging")
        require({name: record(path) for name, path in proof_paths.items()} == proofs_before, "Explicit provenance changed during packaging")
        zip_record = record(archive_path)
        with Path(str(archive_path) + ".sha256").open("x", encoding="ascii") as stream:
            stream.write(zip_record["sha256"] + "  " + archive_path.name + "\n")
        result = {"kind": "portable-development-preview-packaging-proof", "passed": True,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(), "output": str(output), "portable_folder": str(portable),
            "archive": {"path": archive_path.name, **zip_record}, "zip_verified": zip_proof,
            "complete_inventory": {"path": "portable-inventory.json", **record(output / "portable-inventory.json")},
            "portable_manifest": record(portable / "portable-manifest.json"), "source": source_digests(inputs),
            "source_package_id": manifest["package_id"], "package_verification": verification,
            "original_stage_unchanged": True, "original_zip_unchanged": True, "source_root_unchanged": True,
            "exact_tested_payload_binding": True, "input_proofs": proofs_before,
            "helper": {"path": str(Path(__file__).absolute()), **record(Path(__file__))},
            "signing": "unsigned", "release_candidate": False, "builds_run": 0, "gui_runs": 0, "scans_run": 0,
            "live_provider_calls": 0, "installations": 0, "clean_host_acceptance": False, "manual_acceptance": False}
        write_json(output / "portable-proof.json", result)
        return result
    except BaseException:
        failure = output / "packaging-failure.json"
        if not failure.exists():
            write_json(failure, {"passed": False, "traceback": traceback.format_exc(), "scope": "Partial new output preserved; original inputs were not intentionally modified"})
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name, help_text in (
        ("stage", "Real tools/package_native_windows.ps1 RequiredBundled stage"),
        ("source-root", "Immutable source capture used for both binaries and release lock"),
        ("release-lock", "Exact engine-bound release-lock.json"),
        ("native-build-proof", "Candidate native build-proof.json with exact payload and stable inputs"),
        ("engine-build-proof", "Frozen build-proof.json with payload_files and release/source hashes"),
        ("native-runtime-proof", "Successful fleet-graph-smoke proof JSON"),
        ("runtime-binding", "Successful native-fleet-smoke binding companion with before/after hashes"),
        ("runtime-command", "Exact runtime started.json whose SHA is in the binding"),
        ("output", "New output directory under an existing caller-owned parent")):
        parser.add_argument("--" + name, type=Path, required=True, help=help_text)
    parser.add_argument("--stage-zip", type=Path, help="Original stage ZIP; defaults to adjacent <package_id>.zip")
    options = parser.parse_args(argv)
    try:
        result = package(options)
    except (PackageError, OSError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print("Portable packaging refused: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps({key: result[key] for key in ("passed", "archive", "zip_verified", "original_stage_unchanged", "exact_tested_payload_binding")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
