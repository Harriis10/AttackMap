"""Real Windows desktop-fleet failure/cancel/EOF verification, without a GUI.

Uses caller-selected source Python or a fresh frozen engine. All fixtures and
evidence are created under a new output directory. No production hooks or mocks.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from attackmap.desktop_fleet import FleetRepository, FleetRunRequest, FleetTerminal, repository_set_id, child_run_id
from attackmap.fleet import fleet_repo_ids
from attackmap.artifact_publisher import validate_generation, current_generation, CURRENT_POINTER
from run_wp017_native_modes import WindowsJob, inherited_error_mode, launch


def require(value, message):
    if not value:
        raise RuntimeError(message)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def census():
    """OS Toolhelp inventory, not a self-reported worker list."""
    class Entry(ctypes.Structure):
        _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("pid", w.DWORD),
                    ("heap", ctypes.c_size_t), ("module", w.DWORD), ("threads", w.DWORD),
                    ("parent", w.DWORD), ("priority", w.LONG), ("flags", w.DWORD),
                    ("exe", w.WCHAR * 260)]
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    api.CreateToolhelp32Snapshot.restype = w.HANDLE
    api.Process32FirstW.argtypes = api.Process32NextW.argtypes = [w.HANDLE, ctypes.POINTER(Entry)]
    api.Process32FirstW.restype = api.Process32NextW.restype = w.BOOL
    api.CloseHandle.argtypes = [w.HANDLE]
    handle = api.CreateToolhelp32Snapshot(2, 0)
    require(handle != ctypes.c_void_p(-1).value, "Process census failed")
    rows = []
    try:
        entry = Entry()
        entry.size = ctypes.sizeof(entry)
        found = api.Process32FirstW(handle, ctypes.byref(entry))
        while found:
            rows.append(dict(pid=entry.pid, parent_pid=entry.parent, executable=entry.exe))
            found = api.Process32NextW(handle, ctypes.byref(entry))
    finally:
        api.CloseHandle(handle)
    return rows


def descendants(rows, root):
    owned = {root}
    while True:
        expanded = owned | {row["pid"] for row in rows if row["parent_pid"] in owned}
        if expanded == owned:
            return [row for row in rows if row["pid"] in owned]
        owned = expanded


def run_case(engine, frozen, folder, scenario, large_files, seed_previous=False):
    folder.mkdir()
    good, other = folder / "fixtures/good same", folder / "fixtures/Žluťoučký same"
    for root in (good, other):
        root.mkdir(parents=True)
        (root / "config.json").write_text('{"debug":true,"host":"0.0.0.0"}\n', encoding="utf-8")
    output = folder / "results"
    output.mkdir()
    environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    temp = folder / "temp"
    temp.mkdir()
    environment.update(TEMP=str(temp), TMP=str(temp))
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"):
        environment.pop(name, None)
    previous = None
    previous_files = {}
    if seed_previous:
        seed_logs = folder / "seed"
        seed_logs.mkdir()
        seed_argv = [str(engine), *([] if frozen else ["-m", "attackmap"]), "analyze", str(good), str(other),
                     "--output", str(output), "--module", "config", "--fleet-workers", "2", "--format", "json"]
        launch(seed_argv, seed_logs, environment, 180)
        previous = current_generation(output)
        require(previous is not None, "Seed did not publish a valid previous fleet generation")
        validate_generation(previous)
        previous_files = {str(p.relative_to(previous)): sha(p) for p in previous.rglob("*") if p.is_file()}
        sentinel = (output / CURRENT_POINTER).read_bytes()
        save(folder / "previous-generation.json", dict(path=str(previous), current_sha256=sha(output / CURRENT_POINTER), files=previous_files))
    else:
        sentinel = b'{"previous":"wp018-preserve-current"}\n'
        (output / CURRENT_POINTER).write_bytes(sentinel)
    # Real local config input provides time to observe active descendants.
    if scenario != "failure":
        body = json.dumps({"debug": True, "padding": "x" * 16000})
        for index in range(large_files):
            (other / f"config-{index:05}.json").write_text(body, encoding="utf-8")
    fixture_before = {str(p.relative_to(folder)): sha(p) for root in (good, other) for p in root.iterdir()}
    repositories = [FleetRepository(repository_id=name, repository_path=str(path))
                    for name, path in (("good", good), ("other", other))]
    request = FleetRunRequest(run_id="wp018-" + scenario, repository_id=repository_set_id(repositories),
                             generation=1, revision=0, repositories=repositories, output_path=str(output),
                             modules=["config"], max_workers=1 if scenario == "failure" else 2,
                             options={"timeout_seconds": 3, "time_budget_seconds": None} if scenario == "timeout"
                             else {"timeout_seconds": 180, "time_budget_seconds": 60})
    request_path = folder / "request.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    argv = [str(engine), *([] if frozen else ["-m", "attackmap.desktop_worker"]),
            *(["desktop-worker"] if frozen else []), "--request", str(request_path)]
    events, pending, observed = [], queue.Queue(), {}
    job = WindowsJob()
    process = None
    parked = other.with_name(other.name + " parked")
    action = scenario == "timeout"
    natural_active = None
    try:
        with (folder / "stderr.log").open("wb") as errors:
            with inherited_error_mode():
                process = subprocess.Popen(argv, cwd=ROOT, env=environment, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=errors, creationflags=subprocess.CREATE_NO_WINDOW | 4)
            save(folder / "started.json", dict(pid=process.pid, argv=argv, suspended_before_job_assignment=True))
            job.assign(process)
            job.resume(process)
            def read():
                for line in process.stdout:
                    pending.put(line)
                pending.put(None)
            reader = threading.Thread(target=read, daemon=True)
            reader.start()
            deadline = time.monotonic() + 200
            good_complete = False
            while time.monotonic() < deadline:
                rows = descendants(census(), process.pid)
                for row in rows:
                    observed[row["pid"]] = row
                try:
                    line = pending.get(timeout=0.05)
                except queue.Empty:
                    if process.poll() is not None:
                        break
                    continue
                if line is None:
                    break
                row = json.loads(line)
                events.append(row)
                with (folder / "events.jsonl").open("ab") as log:
                    log.write(line)
                if row.get("kind") == "fleet_child" and row.get("child_repository_id") == "good":
                    good_complete |= row.get("state") == "completed"
                    if scenario == "failure" and row.get("state") == "running" and not action:
                        # Both broker preflights have passed. Make the second
                        # caller-owned root unavailable before serial admission.
                        other.rename(parked)
                        action = True
                if scenario in {"cancel", "eof"} and good_complete and not action:
                    require(len(observed) >= 3, "No real broker/engine descendant was observed")
                    save(folder / "control-census.json", rows)
                    if scenario == "cancel":
                        process.stdin.write(b"cancel\n")
                        process.stdin.flush()
                    else:
                        process.stdin.close()
                    action = True
            process.wait(timeout=15)
            reader.join(timeout=5)
            require(not reader.is_alive(), "Event reader failed to join")
            natural_active = job.active()
            # Allow final descendant process teardown, without triggering cleanup.
            limit = time.monotonic() + 5
            while job.active() and time.monotonic() < limit:
                time.sleep(0.05)
            natural_active = job.active()
            save(folder / "observed-processes.json", list(observed.values()))
            post = census()
            save(folder / "post-exit-census.json", post)
            require(action, "Controlled failure/cancellation was not triggered")
            require(process.returncode == 0, f"Broker exited {process.returncode}")
            require(natural_active == 0, "Owned processes survived ordinary broker exit")
            require(not ({row["pid"] for row in post} & observed.keys()), "An observed owned PID survived exit")
            terminals = [row for row in events if row.get("kind") == "fleet_terminal"]
            require(len(terminals) == 1, "Expected exactly one fleet terminal")
            terminal = terminals[0]
            FleetTerminal.model_validate(terminal)
            require(all(terminal[key] == getattr(request, key) for key in
                        ("schema_version", "run_id", "repository_id", "generation")), "Parent identity changed")
            require([row["revision"] for row in events] == sorted({row["revision"] for row in events}),
                    "Event revisions are not strictly increasing")
            expected_outcome = "partial" if scenario == "failure" else "failed" if scenario == "timeout" else "cancelled"
            require(terminal["fleet_outcome"] == expected_outcome, "Incorrect fleet outcome")
            require(terminal["artifact_readiness"] == "unavailable", "Incomplete fleet appeared ready")
            require((output / CURRENT_POINTER).read_bytes() == sentinel, "Previous current changed")
            if previous is not None:
                require(current_generation(output) == previous, "Previous generation no longer current")
                validate_generation(previous)
                require(previous_files == {str(p.relative_to(previous)): sha(p) for p in previous.rglob("*") if p.is_file()},
                        "Previous published generation bytes changed")
            children = terminal["children"]
            expected_slugs = fleet_repo_ids([Path(row.repository_path) for row in repositories])
            for row, repository, slug in zip(children, repositories, expected_slugs):
                require(row["child_repository_id"] == repository.repository_id
                        and row["child_repository_path"] == repository.repository_path
                        and row["child_run_id"] == child_run_id(request, repository)
                        and row["child_output_id"] == slug, "Ordered child identity changed")
            completed = [row for row in children if row["state"] == "completed"]
            if scenario != "timeout":
                require(any(row["child_repository_id"] == "good" for row in completed), "Successful sibling lost")
            for row in completed:
                manifest = Path(row["manifest_path"])
                expected_manifest = output / request.run_id / row["child_output_id"] / row["child_run_id"] / "artifact-manifest.json"
                require(manifest == expected_manifest, "Sibling manifest escaped the exact selected generation")
                require(sha(manifest) == row["manifest_sha256"], "Sibling manifest hash changed")
                validated = validate_generation(manifest.parent)
                require(validated["generation_id"] == row["child_run_id"]
                        and os.path.normcase(validated["run_identity"]["repo_root"]) == os.path.normcase(row["child_repository_path"]),
                        "Sibling manifest belongs to another child")
                report = json.loads((manifest.parent / "attackmap-report.json").read_text(encoding="utf-8"))
                require(os.path.normcase(report["scan"]["root"]) == os.path.normcase(row["child_repository_path"]), "Sibling report root mismatch")
            require(len(children) == 2 and any(row["state"] != "completed" for row in children), "Incomplete child missing")
            index = Path(terminal["index_path"])
            require(sha(index) == terminal["index_sha256"], "Diagnostic index hash mismatch")
            require(json.loads(index.read_text())["children"] == children, "Index children disagree with terminal")
            result = dict(passed=True, scenario=scenario, frozen=frozen, terminal=terminal,
                broker_exit_code=process.returncode, natural_job_active=natural_active,
                observed_processes=list(observed.values()), current_preserved=True,
                current_scope="Valid prior published fleet and every generation byte preserved" if previous else "Exact invalid sentinel bytes preserved; not a qualified prior generation",
                engine=dict(path=str(engine), sha256=sha(engine), argv=argv, runtime="frozen" if frozen else "source-python",
                            command_kind_verified=(argv[1] == "desktop-worker" if frozen else argv[1:3] == ["-m", "attackmap.desktop_worker"])),
                sibling_manifests_verified=len(completed))
            save(folder / "result.json", result)
            return result
    finally:
        if process is not None and process.stdin and not process.stdin.closed:
            process.stdin.close()
        job.cleanup()
        job.close()
        if process is not None:
            process.wait(timeout=10)
        if parked.exists():
            parked.rename(other)
        fixture_after = {str(p.relative_to(folder)): sha(p) for root in (good, other) for p in root.iterdir()}
        save(folder / "fixture-integrity.json", dict(unchanged=fixture_before == fixture_after,
             before_files=len(fixture_before), after_files=len(fixture_after)))
        require(fixture_before == fixture_after, "Fixture contents changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--frozen", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--large-files", type=int, default=256)
    parser.add_argument("--scenario", choices=["all", "failure", "cancel", "eof", "timeout"], default="all")
    parser.add_argument("--seed-previous", action="store_true", help="First publish a real tiny fleet and verify preservation")
    args = parser.parse_args()
    require(os.name == "nt", "Windows process proof requires Windows")
    require(not args.output.exists() and args.engine.is_file(), "Use an existing engine and fresh output")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True)
    results = []
    try:
        for scenario in (["failure", "cancel", "eof", "timeout"] if args.scenario == "all" else [args.scenario]):
            results.append(run_case(args.engine.resolve(), args.frozen, args.output / scenario, scenario, args.large_files, args.seed_previous))
        save(args.output / "summary.json", dict(passed=True, cases=results))
        print(json.dumps(dict(passed=True, cases=len(results), output=str(args.output))))
    except Exception as error:
        save(args.output / "failure.json", dict(passed=False, error=str(error), completed_cases=results))
        raise


if __name__ == "__main__":
    main()
