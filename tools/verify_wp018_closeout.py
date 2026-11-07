"""Real source/frozen fleet qualification; no providers, GUI or network opt-ins.

Desktop schema 1.4 always emits all formats. CLI format parity is therefore a
separate matrix. A fresh output directory is mandatory; failed evidence stays.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from attackmap.artifact_publisher import current_generation, validate_generation
from attackmap.desktop_fleet import FleetRepository, FleetRunRequest, FleetTerminal, child_run_id, repository_set_id
from attackmap.fleet import fleet_repo_ids


def require(value, message):
    if not value:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scan_semantics(scan):
    """Normalize only the three independently measured ledger clock paths."""
    result = deepcopy(scan)
    ledger = result.get("analyzer_run_ledger")
    if ledger is None:
        return result
    for row in ledger["entries"]:
        clocks = [(row, key) for key in ("detect_duration_ms", "analysis_duration_ms") if row.get(key) is not None]
        events = row.get("lifecycle_events", [])
        elapsed = [event["elapsed_ms"] for event in events]
        clocks.extend((event, "elapsed_ms") for event in events)
        for record, key in clocks:
            value = record[key]
            require(type(value) in (int, float) and math.isfinite(value) and value >= 0, f"Invalid ledger clock {key}")
            record[key] = 0.0
        require(elapsed == sorted(elapsed), "Reversed lifecycle clocks")
    return result


def report_semantics(report):
    """The report contains two exact embedded copies of its structured scan."""
    result = deepcopy(report)
    scan = result["scan"]
    copies = [result["defensive_review_json"]["raw_structured_signals"],
        result["review_context_pack"]["attackmap_review_json"]["raw_structured_signals"]]
    for container in copies:
        require(container["scan"] == scan, "Embedded structured scan differs from canonical scan")
        container["scan"] = scan_semantics(container["scan"])
    result["scan"] = scan_semantics(scan)
    return result


def fixture_roots(base):
    roots = []
    for number in range(16):
        # Include spaces, Czech Unicode and repeated basename in every matrix.
        root = base / ("služba dvě" if number == 1 else f"service {number:02d}") / "same"
        root.mkdir(parents=True)
        (root / "service.yaml").write_text(f"name: service-{number:02d}\nport: {8100 + number}\n", encoding="utf-8")
        (root / "docker-compose.yml").write_text(f"services:\n  api:\n    image: example/service-{number:02d}:1\n    ports: ['{8100 + number}:8080']\n", encoding="utf-8")
        roots.append(root)
    return roots


def input_hashes(roots):
    result = {}
    for root in roots:
        for folder, directories, names in os.walk(root):
            directories[:] = sorted(name for name in directories if name not in {".git", "node_modules", ".venv", "venv", "__pycache__", ".cache"})
            for name in sorted(names):
                path = Path(folder) / name
                if path.is_file() and not path.is_symlink():
                    result[str(path)] = sha(path)
    return result


def production_inputs():
    paths = sorted((ROOT / "src" / "attackmap").rglob("*.py")) + sorted((ROOT / "schemas").rglob("*.json"))
    return {str(path.relative_to(ROOT)): sha(path) for path in paths}


def job_memory(job):
    """Read OS high-water counters, without imposing a memory limit."""
    import ctypes
    from ctypes import wintypes
    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
            ("flags", wintypes.DWORD), ("min_working", ctypes.c_size_t), ("max_working", ctypes.c_size_t),
            ("active_limit", wintypes.DWORD), ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", ctypes.c_ulonglong * 6), ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t), ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]
    info = Extended()
    if not job._kernel.QueryInformationJobObject(job.handle, 9, ctypes.byref(info), ctypes.sizeof(info), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return {"peak_job_memory_bytes": info.peak_job_memory, "peak_process_memory_bytes": info.peak_process_memory,
        "source": "Windows JobObjectExtendedLimitInformation high-water counters", "memory_limit_enforced": False}


def launch(argv, folder, allowance):
    """Keep stdin open until process exit; contain the entire owned Windows tree."""
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("OPENAI_", "ANTHROPIC_", "ATTACKMAP_")):
            env.pop(key)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    started = time.monotonic()
    job = None
    process = None
    record = {"argv": argv, "stdin_held_open": True, "timeout_seconds": allowance}
    try:
        if os.name == "nt":
            from attackmap.execution.windows import WindowsProcessJob
            job = WindowsProcessJob()
        with (folder / "stdout.jsonl").open("wb") as out, (folder / "stderr.log").open("wb") as err:
            process = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=out, stderr=err,
                creationflags=0x08000004 if job else 0)
            record["pid"] = process.pid
            if job:
                job.attach_and_resume(process)
            code = process.wait(timeout=allowance)
            process.stdin.close()
            deadline = time.monotonic() + 15
            while job and job.active() and time.monotonic() < deadline:
                time.sleep(.1)
            record.update(exit_code=code, job_active_after_exit=job.active() if job else None)
            if job:
                record["memory"] = job_memory(job)
            require(not job or record["job_active_after_exit"] == 0, "Owned descendants survived normal exit")
            require(code == 0, f"Process exit {code}; inspect retained stderr")
    finally:
        if job:
            if job.active():
                job.terminate()
                record["emergency_job_termination"] = True
            record["job_active_final"] = job.active()
            job.close()
        elif process and process.poll() is None:
            process.kill()
        if process:
            process.wait(timeout=15)
        record["elapsed_seconds"] = time.monotonic() - started
        save(folder / "process.json", record)
    return record


def collect(base, roots):
    generation = current_generation(base)
    require(generation is not None, f"Parent generation not published/valid: {base}")
    parent = validate_generation(generation)
    children = []
    for slug, root in zip(fleet_repo_ids(roots), roots):
        child = current_generation(generation / slug)
        require(child is not None, f"Missing valid child: {slug}")
        manifest = validate_generation(child)
        report = read(child / "attackmap-report.json")
        require(Path(report["scan"]["root"]).resolve() == root.resolve(), "Child root identity mismatch")
        require(Path(manifest["run_identity"]["repo_root"]).resolve() == root.resolve(), "Child manifest root identity mismatch")
        for name, key in (("defensive-review.json", "defensive_review_json"), ("review-context-pack.json", "review_context_pack")):
            require(read(child / name) == report[key], f"Auxiliary JSON differs from canonical report: {name}")
        report = report_semantics(report)
        children.append({"slug": slug, "root": str(root), "report": report,
            "generation_inventory": sorted(p.name for p in child.iterdir() if p.is_file()),
            "presentation_hashes": {p.name: sha(p) for p in child.iterdir() if p.suffix in {".md", ".dot", ".sarif"}},
            "manifest_path": str(child / "artifact-manifest.json"),
            "manifest_sha256": sha(child / "artifact-manifest.json"), "generation_id": manifest["generation_id"]})
    return generation, parent, children


def comparable(children):
    return [{key: row[key] for key in ("slug", "root", "report", "generation_inventory", "presentation_hashes")} for row in children]


def parent_semantics(generation, children):
    result = read(generation / "fleet-summary.json")
    require(result["repo_count"] == len(children) and not result["failed"], "Parent summary count/failures mismatch")
    expected = {child["slug"]: child for child in children}
    require({row["repo_id"] for row in result["repos"]} == set(expected), "Summary repository identities mismatch")
    # Only these documented output-location fields vary between independent runs.
    # Validate their exact owning destination before replacing it with its slug.
    for rows in (result["repos"], result["fleet_architecture"]["repositories"]):
        require(len(rows) == len(children) and {row["repo_id"] for row in rows} == set(expected), "Parent repository cardinality/identities mismatch")
        for row in rows:
            child = expected[row["repo_id"]]
            require(Path(row["report_dir"]).resolve() == (generation / child["slug"]).resolve(), "Parent report directory not bound to child")
            require(os.path.normcase(str(Path(row["root"]).resolve())) == os.path.normcase(str(Path(child["root"]).resolve())), "Parent root not bound to child")
            row["report_dir"] = child["slug"]
    return {"summary": result, "inventory": sorted(path.name for path in generation.iterdir() if path.is_file())}


def desktop_matrix(prefix, output, roots, timeout, budget, worker_counts=(1, 2, 4), modules=("config",)):
    results = []
    baseline = None
    for workers in worker_counts:
        folder = output / f"desktop16-w{workers}"
        folder.mkdir()
        repositories = [FleetRepository(repository_id=f"repo-{i:02d}", repository_path=str(root)) for i, root in enumerate(roots)]
        request = FleetRunRequest(run_id=f"desktop16-w{workers}", repository_id=repository_set_id(repositories), generation=1,
            revision=0, repositories=repositories, output_path=str(folder / "reports"), modules=list(modules), max_workers=workers,
            options={"timeout_seconds": timeout, "time_budget_seconds": budget, "isolated_analyzers": True})
        request_file = folder / "request.json"
        save(request_file, request.model_dump(mode="json"))
        launch([*prefix, "--request", str(request_file)], folder, timeout + 60)
        events = [json.loads(line) for line in (folder / "stdout.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        terminal_rows = [row for row in events if row.get("kind") == "fleet_terminal"]
        require(len(terminal_rows) == 1, "Exactly one fleet terminal required")
        terminal = FleetTerminal.model_validate(terminal_rows[0])
        require(terminal.fleet_outcome == "succeeded" and terminal.artifact_readiness == "ready", "Fleet not complete/ready")
        for key in ("run_id", "repository_id", "generation"):
            require(getattr(terminal, key) == getattr(request, key), "Terminal request identity mismatch")
        require(len(terminal.children) == len(roots), "Missing requested children")
        for repository, row in zip(repositories, terminal.children):
            require(row.child_repository_id == repository.repository_id and row.child_repository_path == repository.repository_path
                and row.child_run_id == child_run_id(request, repository) and row.state == "completed", "Child request identity mismatch")
            require(sha(Path(row.manifest_path)) == row.manifest_sha256, "Terminal manifest hash mismatch")
        require(sha(Path(terminal.index_path)) == terminal.index_sha256, "Index hash mismatch")
        generation, manifest, children = collect(Path(request.output_path), roots)
        require(manifest["generation_id"] == request.run_id, "Wrong published parent")
        require(Path(terminal.index_path).resolve() == (generation / "desktop-fleet.json").resolve(), "Terminal index not in published parent")
        for repository, row, child in zip(repositories, terminal.children, children):
            require(child["generation_id"] == child_run_id(request, repository)
                and row.child_output_id == child["slug"]
                and Path(row.manifest_path).resolve() == Path(child["manifest_path"]).resolve()
                and row.manifest_sha256 == child["manifest_sha256"], "Terminal child not bound to collected generation")
        saved = read(generation / "desktop-request.json")
        expected = request.model_copy(update={"output_path": str(generation)}).model_dump(mode="json")
        require(saved == expected, "Persisted request differs from selected request")
        semantics = {"children": comparable(children), "parent": parent_semantics(generation, children)}
        if baseline is None:
            baseline = semantics
        require(semantics == baseline, "Desktop serial/parallel report semantics/inventory mismatch")
        result = {"workers": workers, "children": children, "parent_manifest_sha256": sha(generation / "artifact-manifest.json"),
            "selected_request_verified": True, "terminal_verified": True, "serial_parallel_equal": len(worker_counts) > 1}
        save(folder / "verification.json", result)
        results.append(result)
    return results


def cli_matrix(prefix, output, roots, timeout, budget, modules=("config",)):
    results = []
    for format_name in ("all", "json", "markdown"):
        baseline = None
        for workers in (1, 2):
            folder = output / f"cli-{format_name}-w{workers}"
            folder.mkdir()
            base = folder / "reports"
            argv = [*prefix, "analyze", *map(str, roots), "--output", str(base), "--format", format_name,
                "--fleet-workers", str(workers), "--isolated-analyzers", "--time-budget-seconds", str(budget),
                "--run-id", f"cli-{format_name}-w{workers}", "--progress-format", "json"]
            for module in modules:
                argv.extend(["--module", module])
            launch(argv, folder, timeout + 60)
            generation, manifest, children = collect(base, roots)
            inventory = {slug: sorted(p.name for p in (base / slug).iterdir() if p.is_file()) for slug in fleet_repo_ids(roots)}
            for child in children:
                files = inventory[child["slug"]]
                require(("attackmap-report.json" in files) == (format_name in {"all", "json"}), "JSON presentation selection lost")
                require(("architecture.md" in files) == (format_name in {"all", "markdown"}), "Markdown presentation selection lost")
                child_generation = Path(child["manifest_path"]).parent
                for name in files:
                    canonical = child_generation / name
                    if canonical.is_file():
                        require(sha(base / child["slug"] / name) == sha(canonical), "Compatibility export differs from canonical generation")
            semantics = {"children": comparable(children), "compatibility_inventory": inventory, "parent": parent_semantics(generation, children)}
            if baseline is None:
                baseline = semantics
            require(semantics == baseline, f"CLI {format_name} serial/parallel semantics/inventory mismatch")
            result = {"format": format_name, "workers": workers, "children": children, "compatibility_inventory": inventory,
                "parent_manifest_sha256": sha(generation / "artifact-manifest.json"), "serial_parallel_equal": True}
            save(folder / "verification.json", result)
            results.append(result)
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    engine = parser.add_mutually_exclusive_group(required=True)
    engine.add_argument("--python", type=Path)
    engine.add_argument("--engine", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--suite", choices=("all", "cli-parity", "desktop16"), default="all")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--budget", type=int, default=60)
    parser.add_argument("--repository", type=Path, help="Read-only real repository replacing the first synthetic root")
    parser.add_argument("--workers", type=int, nargs="+", choices=(1, 2, 4), default=[1, 2, 4], help="Desktop concurrency matrix; CLI remains 1/2")
    parser.add_argument("--modules", nargs="*", default=["config"], help="Explicit analyzer modules; empty means Automatic without installation")
    args = parser.parse_args(argv)
    require(30 <= args.budget < args.timeout <= 86400, "Require 30 <= per-child soft budget < overall allowance <= 86400")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    engine_path = (args.engine or args.python).resolve(strict=True)
    identity = {"path": str(engine_path), "sha256": sha(engine_path), "kind": "frozen" if args.engine else "source"}
    source_inputs = production_inputs() if args.python else None
    save(output / "production-inputs-before.json", source_inputs)
    save(output / "verifier-identity.json", {"path": str(Path(__file__).resolve()), "sha256": sha(Path(__file__))})
    save(output / "inputs.json", {"engine": identity, "suite": args.suite, "timeout": args.timeout, "budget": args.budget,
        "modules": args.modules, "selection": "explicit" if args.modules else "Automatic", "repository": str(args.repository) if args.repository else None})
    roots = fixture_roots(output / "fixtures")
    if args.repository:
        real_repository = args.repository.resolve(strict=True)
        require(real_repository.is_dir() and output != real_repository and not output.is_relative_to(real_repository), "Outputs must be outside the real repository")
        roots[0] = real_repository
    before = input_hashes(roots)
    save(output / "fixture-hashes-before.json", before)
    result = {"passed": False, "engine": identity, "modules": args.modules, "selection": "explicit" if args.modules else "Automatic",
        "scope": "subprocess fleet qualification; not C27/maturity, manual or release acceptance"}
    try:
        if args.suite in {"all", "cli-parity"}:
            prefix = [str(engine_path)] if args.engine else [str(engine_path), "-m", "attackmap"]
            result["cli"] = cli_matrix(prefix, output, roots[:3], args.timeout, args.budget, args.modules)
        if args.suite in {"all", "desktop16"}:
            prefix = [str(engine_path), "desktop-worker"] if args.engine else [str(engine_path), "-m", "attackmap.desktop_worker"]
            result["desktop"] = desktop_matrix(prefix, output, roots, args.timeout, args.budget, tuple(dict.fromkeys(args.workers)), args.modules)
        require(before == input_hashes(roots), "Source fixtures changed")
        require(sha(engine_path) == identity["sha256"], "Engine changed during qualification")
        after = production_inputs() if args.python else None
        save(output / "production-inputs-after.json", after)
        require(source_inputs == after, "Production source/schema inputs changed during qualification")
        result.update(passed=True, fixtures_unchanged=True, engine_unchanged=True)
    except Exception as error:
        result["error"] = str(error)
    save(output / "summary.json", result)
    print(json.dumps({key: value for key, value in result.items() if key not in {"cli", "desktop"}}, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
