"""Read-only paired direct extraction/merge, excluding whole-repository passes."""
from __future__ import annotations
import argparse, hashlib, inspect, json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
CORE = ROOT / ".tmp/wp042-sol-ultra-20261023-batch2/engine-final/source/src"
DJANGO = ROOT / ".tmp/wp039-python-20261023/django-cases"
PYTHON = ROOT / ".tools/wp024-freeze-venv/Scripts/python.exe"

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

def worker(label, output):
    import faulthandler
    faulthandler.dump_traceback_later(90, exit=True)
    import attackmap
    from attackmap.analyzers import BuiltinPythonWebAnalyzer, BuiltinPythonServiceAnalyzer, merge_analyzer_results
    from attackmap.index import clear_pinned_index
    from attackmap_analyzer_python import PythonAnalyzer
    assert Path(attackmap.__file__).resolve().is_relative_to(CORE.resolve())
    fixtures = json.loads((OUT / "upstream-route-fixtures.json").read_text(encoding="utf-8"))
    for row in json.loads((DJANGO / "oracle-manifest.json").read_text(encoding="utf-8")):
        row["observed_file_sha256"] = {}
        for relative, digest in row["files"].items():
            raw = (DJANGO / row["name"] / relative).read_bytes()
            row["observed_file_sha256"][relative] = hashlib.sha256(raw).hexdigest()
            assert digest in {hashlib.sha256(raw).hexdigest(), hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()}
        fixtures["oracle-" + row["name"]] = {**row, "root": str(DJANGO / row["name"])}
    result = {"label": label, "scope": "direct analyzer extraction and core merge; no pipeline or whole-repo passes", "origins": {
        "core": attackmap.__file__, "plugin": inspect.getfile(PythonAnalyzer)}, "fixtures": {}}
    for name, fixture in fixtures.items():
        print(label + " " + name, flush=True)
        root = Path(fixture["root"])
        roles = {}
        skip_builtin = name in {"fastapi-multi-mount", "flask-multi-mount"}
        for role, analyzer in (("plugin_only", PythonAnalyzer()), ("builtin_web", BuiltinPythonWebAnalyzer()),
                               ("builtin_service", BuiltinPythonServiceAnalyzer())):
            if skip_builtin and role != "plugin_only":
                continue
            clear_pinned_index()
            roles[role] = analyzer.analyze(root)
        if not skip_builtin:
            roles["priority_merged"] = merge_analyzer_results([roles[key] for key in ("plugin_only", "builtin_web", "builtin_service")], root=root)
        result["fixtures"][name] = {key: value for key, value in fixture.items() if key not in {"files", "sha256"}}
        if skip_builtin:
            result["fixtures"][name]["baseline_builtin_extraction"] = "NOT RUN: retained baseline _python_route_prefixes loops for conflicting mounts; prior 90s timeout retained"
        result["fixtures"][name]["roles"] = {role: scan.model_dump(mode="json") for role, scan in roles.items()}
        result["fixtures"][name]["route_projection"] = {role: [{key: getattr(row, key, None) for key in ("path", "method", "file", "line", "auth", "guards")} for row in scan.routes] for role, scan in roles.items()}
        save(output, result)
    clear_pinned_index()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.output)
        return
    fetched = json.loads((OUT / "upstream-fetch.json").read_text(encoding="utf-8"))
    variants = {"installed": None, **{key: Path(row["source_root"]) / "src" for key, row in fetched["archives"].items()}}
    outcomes = {}
    for label, source in variants.items():
        output = OUT / f"upstream-direct-{label}.json"
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(str(path) for path in (source, CORE) if path is not None), PYTHONDONTWRITEBYTECODE="1")
        command = [str(PYTHON), "-B", str(Path(__file__).resolve()), "--worker", label, "--output", str(output)]
        done = subprocess.run(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=100)
        (OUT / f"upstream-direct-{label}.stdout.log").write_bytes(done.stdout)
        (OUT / f"upstream-direct-{label}.stderr.log").write_bytes(done.stderr)
        assert done.returncode == 0, (label, done.stderr.decode("utf-8", errors="replace"))
        outcomes[label] = json.loads(output.read_text(encoding="utf-8"))
        expected_origin = ROOT / ".tools/wp024-freeze-venv/Lib/site-packages" if source is None else source
        assert Path(outcomes[label]["origins"]["plugin"]).resolve().is_relative_to(expected_origin.resolve())
    projections = {label: {name: row["route_projection"] for name, row in value["fixtures"].items()} for label, value in outcomes.items()}
    assert projections["installed"] == projections["pinned"]
    summary = {"scope": outcomes["installed"]["scope"], "fixture_count": len(projections["installed"]), "variants": {}}
    for label, value in outcomes.items():
        checks = {}
        for name, item in value["fixtures"].items():
            checks[name] = {}
            for role, rows in item["route_projection"].items():
                by_path = {row["path"]: row["auth"] for row in rows}
                expected = item.get("expected_overlay_auth", {})
                paths = item.get("expected_mounted_paths", list(expected))
                forbidden = item.get("forbidden_mounted_paths", item.get("forbidden_overlay_paths", []))
                checks[name][role] = {"paths": by_path, "missing": sorted(set(paths) - set(by_path)), "auth_mismatches": {path: {"expected": auth, "actual": by_path[path]} for path, auth in expected.items() if path in by_path and auth != by_path[path]}, "forbidden_present": sorted(set(forbidden) & set(by_path))}
        summary["variants"][label] = checks
    summary["installed_pinned_route_projections_identical"] = True
    save(OUT / "upstream-direct-comparison.json", summary)
    print(json.dumps({"fixtures": summary["fixture_count"], "variants": len(variants), "installed_pinned_route_projections_identical": True}))

if __name__ == "__main__":
    main()
