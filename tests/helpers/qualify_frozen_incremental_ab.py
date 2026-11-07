"""Build two test-only PyInstaller probes and prove shared-cache invalidation.

No product build or release is produced. The only build-B mutation is an
equivalent dictionary copy in the staged per-file extractor; repository source
and the analyzed repository are never changed.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def source_manifest(package: Path) -> dict[str, str]:
    return {path.relative_to(package).as_posix(): sha(path)
            for path in sorted(package.rglob("*")) if path.is_file() and "__pycache__" not in path.parts}


def mutate_extractor(path: Path) -> dict:
    source = path.read_text(encoding="utf-8")
    function = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == "_analyze_indexed_file")
    statement = function.body[-1]
    if not isinstance(statement, ast.Return) or ast.unparse(statement.value) != "(signals, csrf_protected)":
        raise RuntimeError("Unexpected extractor return; review the test-only mutation")
    lines = source.splitlines(keepends=True)
    if statement.lineno != statement.end_lineno:
        raise RuntimeError("Expected a single-line extractor return")
    before = lines[statement.lineno - 1].strip()
    lines[statement.lineno - 1] = "    return signals.copy(), csrf_protected\n"
    path.write_text("".join(lines), encoding="utf-8")
    return dict(file="scanner.py", function=function.name, line=statement.lineno,
                before=before, after=lines[statement.lineno - 1].strip(),
                scope="Only the isolated build-B source; equivalent dictionary copy")


def core_origins(toc_path: Path, package: Path) -> dict[str, str]:
    origins = {}

    def visit(value):
        if isinstance(value, (tuple, list)):
            if (len(value) == 3 and isinstance(value[0], str) and
                    (value[0] == "attackmap" or value[0].startswith("attackmap.")) and
                    isinstance(value[1], str) and isinstance(value[2], str) and value[2].startswith("PYMODULE")):
                origin = Path(value[1]).resolve()
                if not origin.is_relative_to(package.resolve()):
                    raise RuntimeError(f"Core module escaped staged source: {value}")
                origins[value[0]] = str(origin)
            for child in value:
                visit(child)

    visit(ast.literal_eval(toc_path.read_text(encoding="utf-8")))
    if "attackmap.scanner" not in origins or "attackmap.incremental" not in origins:
        raise RuntimeError("Missing core origins in actual PyInstaller analysis")
    return origins


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    repo, output = args.repo.resolve(), args.output.resolve()
    if not repo.is_dir() or output == repo or repo in output.parents:
        raise RuntimeError("Use an existing repository and external output directory")
    output.mkdir(parents=True, exist_ok=False)
    inputs = output / "inputs"
    inputs.mkdir()
    probe = inputs / "frozen_incremental_probe.py"
    shutil.copy2(Path(__file__).with_name(probe.name), probe)
    shutil.copy2(__file__, inputs / Path(__file__).name)
    package = output / "source/src/attackmap"
    shutil.copytree(root / "src/attackmap", package,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
    module_tree = ast.parse((package / "incremental.py").read_text(encoding="utf-8"))
    modules = next(ast.literal_eval(node.value) for node in module_tree.body
                   if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_ENGINE_MODULES"
                                                          for t in node.targets))
    if "scanner" not in modules:
        raise RuntimeError("The mutated extractor module is outside the real cache identity")
    commands = []

    def run(label: str, command: list[str]) -> str:
        start = time.monotonic()
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=600)
        (output / f"{label}.stdout.log").write_text(result.stdout, encoding="utf-8")
        (output / f"{label}.stderr.log").write_text(result.stderr, encoding="utf-8")
        commands.append(dict(label=label, command=command, cwd=str(root), returncode=result.returncode,
                             seconds=round(time.monotonic() - start, 3)))
        save(output / "commands.json", commands)
        if result.returncode:
            raise RuntimeError(f"{label} failed with {result.returncode}; inspect preserved logs")
        print(f"{label}: PASS ({commands[-1]['seconds']}s)", flush=True)
        return result.stdout

    toolchain = dict(python=run("python-version", [str(args.python), "--version"]).strip(),
                     pyinstaller=run("pyinstaller-version", [str(args.python), "-m", "PyInstaller", "--version"]).strip())
    builds = {}
    scans = {}
    cache = output / "shared-cache"
    for label in ("a", "b"):
        if label == "b":
            mutation = mutate_extractor(package / "scanner.py")
            save(output / "build-b-mutation.json", mutation)
        manifest = source_manifest(package)
        save(output / f"build-{label}-source.json", manifest)
        shutil.copy2(package / "scanner.py", inputs / f"scanner-build-{label}.py")
        build = output / f"build-{label}"
        build.mkdir()
        name = f"wp033-probe-{label}"
        command = [str(args.python), "-m", "PyInstaller", "--noconfirm", "--clean", "--noupx",
                   "--onedir", "--console", "--name", name, "--paths", str(package.parent),
                   "--distpath", str(build / "dist"), "--workpath", str(build / "work"),
                   "--specpath", str(build), "--add-data", f"{package / 'taint_sinks.yaml'};attackmap"]
        for module in modules:
            command.extend(["--hidden-import", "attackmap." + module.replace("/", ".")])
        run(f"build-{label}", [*command, str(probe)])
        executable = build / f"dist/{name}/{name}.exe"
        origins = core_origins(build / f"work/{name}/Analysis-00.toc", package)
        builds[label] = dict(executable=str(executable), executable_sha256=sha(executable),
                             source_manifest=f"build-{label}-source.json", core_origins=origins,
                             pyz_sha256=sha(build / f"work/{name}/PYZ-00.pyz"))
        if source_manifest(package) != manifest:
            raise RuntimeError("Staged source changed while freezing")
        for mode in (("cold", "warm", "full") if label == "a" else ("upgrade", "warm", "full")):
            key = f"{label}-{mode}"
            command = [str(executable), "--mode", mode, "--repo", str(repo), "--cache", str(cache)]
            if label == "b" and mode != "upgrade":
                command.extend(["--reference-mode", "upgrade"])
            scans[key] = json.loads(run(key, command))
            save(output / f"{key}.json", scans[key])

    a_source = json.loads((output / "build-a-source.json").read_text(encoding="utf-8"))
    b_source = json.loads((output / "build-b-source.json").read_text(encoding="utf-8"))
    changed_sources = [name for name in a_source.keys() | b_source.keys() if a_source.get(name) != b_source.get(name)]
    changed_modules = [name for name in scans["a-cold"]["module_code"]
                       if scans["a-cold"]["module_code"][name] != scans["b-upgrade"]["module_code"][name]]
    if changed_sources != ["scanner.py"] or changed_modules != ["scanner"]:
        raise RuntimeError(f"Unexpected A/B identity differences: {changed_sources}, {changed_modules}")
    if len({proof["result_sha256"] for proof in scans.values()}) != 1:
        raise RuntimeError("A/B incremental and non-incremental results differ")
    if scans["a-cold"]["cache_after"] != scans["b-upgrade"]["cache_before"]:
        raise RuntimeError("Build B did not receive the preserved populated A cache")
    if scans["b-upgrade"]["cache_after"]["entry_generations"] != [scans["b-upgrade"]["cache_after"]["generation"]]:
        raise RuntimeError("Build B retained foreign cache generations")
    proof = dict(scope="WP033 test-only two-frozen-build invalidation; no product/release qualification",
                 passed=True, repository=str(repo), toolchain=toolchain, builds=builds, scans=scans,
                 changed_sources=changed_sources, changed_identity_modules=changed_modules,
                 shared_cache=str(cache / "per-file-cache.json"), provider_calls=0,
                 limitations=["Only the per-file scan is covered; no whole-pipeline/native round-trip",
                              "Controlled semantics-preserving extractor change in build B only",
                              "WP033 mutation matrix, C34 performance and release gates remain open"])
    save(output / "qualification.json", proof)
    print(json.dumps(dict(passed=True, qualification=str(output / "qualification.json"))))


if __name__ == "__main__":
    main()
