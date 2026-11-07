#!/usr/bin/env python
"""WP034 prepared campaign. Default is plan-only; --run explicitly starts one case.

Fresh child per engine run; generation stays in the parent. No analyzer, topology,
coverage or engine-budget override. Sampled private bytes are a lower bound;
Windows lifetime peak working set/commit counters are reported separately.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import faulthandler
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
TWO_GIB = 2 * 1024**3
EXPECTED_PYTHON = ROOT / ".tools" / "wp024-freeze-venv" / "Scripts" / "python.exe"


def scope() -> dict:
    from attackmap.analyzers import get_available_modules, get_registered_analyzers
    import attackmap
    modules = sorted((item.model_dump(mode="json") for item in get_available_modules()),key=lambda item:item["name"])
    code = hashlib.sha256()
    packages = set()
    for analyzer in get_registered_analyzers():
        module = sys.modules.get(type(analyzer).__module__.split(".")[0])
        packages.update(Path(path).resolve() for path in getattr(module,"__path__",[]))
    for package in sorted(packages):
        for file in sorted(package.rglob("*.py")):
            code.update(str(file).encode()); code.update(hashlib.sha256(file.read_bytes()).digest())
    return {"python_executable":str(Path(sys.executable).resolve()),"python_version":platform.python_version(),
            "python_sha256":hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            "engine_module":str(Path(attackmap.__file__).resolve()),"engine_version":attackmap.__version__,
            "pythonpath":os.environ.get("PYTHONPATH"),"discovered_module_count":len(modules),"discovered_modules":modules,
            "analyzer_packages":list(map(str,sorted(packages))),"analyzer_code_sha256":code.hexdigest(),
            "selection":"Default detect/applicability and opt-in policy; no analyzer count or topology reduction"}


def memory(handle: int = -1) -> dict:
    if os.name != "nt":
        return {"available": False, "reason": "Windows process counters required"}
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in (
                "peak_ws", "ws", "quota_peak_paged", "quota_paged", "quota_peak_nonpaged",
                "quota_nonpaged", "commit", "peak_commit", "private")]

    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    api = ctypes.WinDLL("psapi.dll", use_last_error=True).GetProcessMemoryInfo
    api.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    api.restype = wintypes.BOOL
    if not api(wintypes.HANDLE(handle), ctypes.byref(counters), counters.cb):
        return {"available": False, "winerror": ctypes.get_last_error()}
    return {"available": True, "peak_working_set_bytes": int(counters.peak_ws),
            "working_set_bytes": int(counters.ws), "peak_commit_bytes": int(counters.peak_commit),
            "private_bytes": int(counters.private)}


def write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def source_identity(root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in (root / "src" / "attackmap").rglob("*")
                   if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc") + [
        root / "pyproject.toml", root / "tools" / "measure_memory_admission.py", root / "tools" / "gen_stress_repo.py"]
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def job_process_ids(job) -> list[int]:
    """Read only the owned job's live process identities, including launchers."""
    from ctypes import wintypes
    for capacity in (16, 64, 256, 1024, 4096):
        class ProcessIds(ctypes.Structure):
            _fields_ = [("assigned", wintypes.DWORD), ("listed", wintypes.DWORD),
                        ("pids", ctypes.c_size_t * capacity)]
        info = ProcessIds()
        if job._kernel.QueryInformationJobObject(job.handle, 3, ctypes.byref(info), ctypes.sizeof(info), None):
            return [int(info.pids[i]) for i in range(info.listed)]
        if ctypes.get_last_error() != 234:
            raise ctypes.WinError(ctypes.get_last_error())
    raise RuntimeError("Owned job exceeds bounded process inventory")


def sample_owned_tree(job, handles: dict) -> dict:
    from ctypes import wintypes
    kernel = job._kernel
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    live = job_process_ids(job)
    rows = {}
    for pid in live:
        if pid not in handles:
            handle = kernel.OpenProcess(0x0410, False, pid)  # query/read only
            if handle:
                handles[pid] = handle
        if pid in handles:
            rows[str(pid)] = memory(int(handles[pid]))
    valid = [row for row in rows.values() if row.get("available")]
    return {"live_pids": live, "processes": rows,
            "complete": len(valid) == len(live),
            "private_bytes": sum(row["private_bytes"] for row in valid),
            "working_set_bytes": sum(row["working_set_bytes"] for row in valid)}


def snapshot_source(folder: Path) -> tuple[Path, str]:
    """Copy core plus packaged assets/tools; fail if a source changes mid-copy."""
    snapshot = folder / "source"
    before = source_identity()
    shutil.copytree(ROOT / "src", snapshot / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (snapshot / "tools").mkdir()
    for name in ("gen_stress_repo.py", "measure_memory_admission.py"):
        shutil.copy2(ROOT / "tools" / name, snapshot / "tools" / name)
    shutil.copy2(ROOT / "pyproject.toml", snapshot / "pyproject.toml")
    if before != source_identity() or before != source_identity(snapshot):
        raise RuntimeError("Core changed during snapshot capture")
    manifest = {path.relative_to(snapshot).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(snapshot.rglob("*")) if path.is_file()}
    write(folder / "source-manifest.json", manifest)
    return snapshot, before


def worker(folder: Path) -> int:
    if not (folder / ".wp034-owned.json").is_file():
        raise ValueError("Worker requires a campaign-owned fixture directory")
    write(folder / "runtime-identity.json", {"pid": os.getpid(), "parent_pid": os.getppid(),
          "sys_executable": sys.executable, "engine_source": str(ROOT)})
    from attackmap import pipeline
    from attackmap.analyzers import get_analyzer_metadata
    from attackmap.index import RepoIndex
    admitted_scope = scope()
    if admitted_scope["discovered_module_count"] != 21:
        raise ValueError("WP034 campaign requires the agreed 21-module discovery scope")

    captured = []
    original_build = RepoIndex.build

    def measured_build(cls, *args, **kwargs):
        (folder / "stage.txt").write_text("capture_snapshot", encoding="ascii")
        build_started = time.perf_counter()
        index = original_build(*args, **kwargs)
        captured.append({"seconds":time.perf_counter()-build_started,
                         "accepted_utf8_files": len(index.files), "accepted_utf8_bytes": index.total_bytes,
                         "captured_sdk_files": len(index.sources), "captured_sdk_bytes": index.captured_source_bytes,
                         "resource_limit_scopes": list(index.resource_limit_scopes),
                         "resource_limit_event_count": len(index.resource_limit_events)})
        (folder / "stage.txt").write_text("detect_analyzers", encoding="ascii")
        return index

    RepoIndex.build = classmethod(measured_build)
    original_phase = pipeline._diagnostic_phase

    @contextlib.contextmanager
    def phase(state, name):
        (folder / "stage.txt").write_text(name, encoding="ascii")
        with original_phase(state, name):
            yield

    pipeline._diagnostic_phase = phase
    started = time.perf_counter()
    try:
        state = pipeline.run_scan(pipeline.AnalyzeOptions(repo_path=folder / "repo", output=folder / "reports",
            atomic_output=False, no_progress=True, echo=lambda *args, **kwargs: None))
        scan = state.scan
        event_rows = [event.model_dump(mode="json") for event in getattr(scan,"resource_limit_events",[])]
        payload = {
            "exit_code": state.exit_code, "outcome": state.scan_outcome,
            "scope": admitted_scope,
            "wall_seconds": time.perf_counter() - started,
            "index_builds": captured,
            "analyzers": [{"name": get_analyzer_metadata(a).name,"version": get_analyzer_metadata(a).version} for a in state.analyzers],
            "signal_counts": {name: len(value) for name in getattr(scan,"model_fields",{})
                if isinstance(value := getattr(scan,name),list)},
            "graph_and_findings": {"surfaces": len(state.surfaces),"findings": len(state.findings),"paths": len(state.paths)},
            "limitations": list(getattr(scan,"limitations",[])), "resource_limit_events": event_rows,
            "resource_limit_scopes": getattr(scan,"resource_limit_scopes",[]),
            "resource_limit_reporting": getattr(scan,"resource_limit_reporting","unknown"),
            "analyzer_errors": [error.model_dump(mode="json") for error in getattr(scan,"analyzer_errors",[])],
            "stages": [{"name": stage.name,"milliseconds": stage.milliseconds} for stage in state.timings],
            "memory_final": memory(), "default_engine_options": True,
            "measurement_notes": ["Private bytes sampled externally; no exact OS private-byte high-water counter claimed.",
                "Instrumentation adds scalar index counts and stage-file writes; engine scans and source structures are unchanged."]}
        write(folder / "worker-result.json",payload)
        return state.exit_code
    except BaseException as error:
        write(folder / "worker-error.json",{"error_type": type(error).__name__,"message": str(error),"memory_final": memory(),"index_builds": captured})
        raise


def plan() -> dict:
    return {"mode": "prepared_not_executed", "counts": [10000,50000,100000],
        "fixture": "tools/gen_stress_repo.py deterministic Flask route/auth/config/subprocess template; exact generated bytes declared",
        "engine": "fresh immutable source-copy subprocess using .tools/wp024-freeze-venv/Scripts/python.exe, PYTHONPATH=snapshot/src, 21 discovered modules; default applicability and coverage/time budgets retained",
        "metrics": ["OS lifetime peak working set", "OS lifetime peak process commit", "50ms sampled private bytes by stage", "accepted UTF8/raw SDK bytes and files", "analyzer identities", "signals/surfaces/paths/findings", "typed partial scopes/errors", "source fingerprint before/after"],
        "sequence": "Wait for root-confirmed AI audit and WP035 source checkpoints; only10k authorized next. Review terminal result before any larger size or fleet concurrency.",
        "acceptance": "<2GiB measured default-scope memory plus accepted counts/bytes and honest typed partial status; timeout/kill/nonzero/unknown counters never prove acceptance",
        "limitations": "Default engine owned-process tree only; fleet sibling admission and cancel-under-load require separate controlled campaigns. Private-byte samples are lower bounds; job commit and per-process OS lifetime counters are separate. Not a runtime-edge or real-repository corpus proof."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true")
    parser.add_argument("--count",type=int,choices=(10000,50000,100000),default=10000)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--hard-timeout",type=int,default=3600)
    parser.add_argument("--abort-memory-bytes",type=int,default=3*1024**3,
        help="Campaign safety stop; not a product resource default. Crossing aborts owned job and never proves acceptance")
    parser.add_argument("--scope-preflight",action="store_true",help="Inventory interpreter/modules only; no fixture or scan")
    parser.add_argument("--worker",type=Path,help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        folder = args.worker.resolve()
        with (folder / "timed-python-stacks.log").open("x", encoding="utf-8") as trace:
            faulthandler.enable(file=trace, all_threads=True)
            faulthandler.dump_traceback_later(60, repeat=True, file=trace)
            try:
                return worker(folder)
            finally:
                faulthandler.cancel_dump_traceback_later()
                faulthandler.disable()
    if args.scope_preflight:
        print(json.dumps(scope(),indent=2)); return 0
    if not args.run:
        print(json.dumps(plan(),indent=2)); return 0
    if os.name != "nt" or args.output is None or args.hard_timeout < 1:
        parser.error("Run needs Windows, a fresh --output directory and positive --hard-timeout")
    if Path(sys.executable).resolve() != EXPECTED_PYTHON.resolve() or Path(os.environ.get("PYTHONPATH", "")).resolve() != (ROOT / "src").resolve():
        parser.error("Run requires the wp024-freeze-venv interpreter and PYTHONPATH set exactly to repo/src")
    admitted_scope = scope()
    if admitted_scope["discovered_module_count"] != 21 or args.abort_memory_bytes <= TWO_GIB:
        parser.error("Run requires 21 discovered modules and campaign safety ceiling above the 2GiB criterion")
    folder = args.output.resolve()
    if folder.exists():
        parser.error("Output must be a fresh task-owned directory; no overwrite or cleanup is performed")
    folder.mkdir(parents=True)
    write(folder / ".wp034-owned.json",{"kind":"wp034-memory-campaign","count":args.count})
    from gen_stress_repo import generate_fixture
    snapshot, before = snapshot_source(folder)
    fixture = generate_fixture(folder / "repo",args.count)
    write(folder / "fixture.json",fixture)
    command = [sys.executable,str(snapshot / "tools" / "measure_memory_admission.py"),"--worker",str(folder)]
    child_env = dict(os.environ, PYTHONPATH=str(snapshot / "src"), PYTHONDONTWRITEBYTECODE="1")
    sampled_peak_private = 0
    samples = 0
    stage_peaks = {}
    started = time.perf_counter()
    timed_out = False
    memory_aborted = False
    peak_job_commit = 0
    handles = {}
    process_peaks = {}
    tree_samples_incomplete = 0
    from attackmap.execution.windows import WindowsProcessJob
    from attackmap.analyzer_host import _query_job_peak_memory
    job = WindowsProcessJob()
    with (folder / "stdout.log").open("w",encoding="utf-8") as stdout, (folder / "stderr.log").open("w",encoding="utf-8") as stderr, (folder / "owned-tree-samples.ndjson").open("x",encoding="utf-8") as samples_log:
        process = subprocess.Popen(command,stdout=stdout,stderr=stderr,cwd=snapshot,env=child_env,creationflags=0x00000004)
        try:
            job.attach_and_resume(process)
        except BaseException:
            process.kill(); process.wait(timeout=15); job.close(); raise
        try:
            while process.poll() is None:
                sample = sample_owned_tree(job, handles)
                if not sample["complete"]:
                    tree_samples_incomplete += 1
                for pid, row in sample["processes"].items():
                    if row.get("available"):
                        peaks = process_peaks.setdefault(pid, {})
                        for metric in ("private_bytes", "peak_commit_bytes", "peak_working_set_bytes"):
                            peaks[metric] = max(peaks.get(metric, 0), row[metric])
                peak_job_commit = max(peak_job_commit,_query_job_peak_memory(job.handle))
                if sample["processes"]:
                    samples += 1
                    sampled_peak_private = max(sampled_peak_private,sample["private_bytes"])
                    try: stage = (folder / "stage.txt").read_text(encoding="ascii")
                    except OSError: stage = "startup_or_unknown"
                    peak = stage_peaks.setdefault(stage,{"sampled_private_bytes":0,"sampled_working_set_bytes":0})
                    peak["sampled_private_bytes"] = max(peak["sampled_private_bytes"],sample["private_bytes"])
                    peak["sampled_working_set_bytes"] = max(peak["sampled_working_set_bytes"],sample["working_set_bytes"])
                samples_log.write(json.dumps({"elapsed_seconds":time.perf_counter()-started,
                    "stage":stage if sample["processes"] else "startup_or_unknown", **sample}) + "\n")
                if samples % 20 == 0:
                    samples_log.flush()
                if max(peak_job_commit,sample["private_bytes"],sample["working_set_bytes"]) >= args.abort_memory_bytes:
                    memory_aborted = True
                    job.terminate(); process.wait(timeout=15); break
                if time.perf_counter() - started > args.hard_timeout:
                    timed_out = True
                    job.terminate(); process.wait(timeout=15); break
                time.sleep(0.05)
            code = process.wait()
            peak_job_commit = max(peak_job_commit, _query_job_peak_memory(job.handle))
            # Handles retain exited processes' OS lifetime peaks, even if a last
            # high-water update happened between the final sample and exit.
            for pid, handle in handles.items():
                row = memory(int(handle))
                if row.get("available"):
                    peaks = process_peaks.setdefault(str(pid), {})
                    for metric in ("private_bytes", "peak_commit_bytes", "peak_working_set_bytes"):
                        peaks[metric] = max(peaks.get(metric, 0), row[metric])
        except BaseException:
            try: job.terminate(); process.wait(timeout=15)
            finally:
                for handle in handles.values():
                    job._kernel.CloseHandle(handle)
                job.close()
            raise
    cleanup_started = time.monotonic()
    while job.active() and time.monotonic() - cleanup_started < 15:
        time.sleep(0.05)
    cleanup_verified = job.active() == 0
    if not cleanup_verified:
        job.terminate()
    for handle in handles.values():
        job._kernel.CloseHandle(handle)
    job.close()
    after = source_identity(snapshot)
    after_scope = scope()
    analyzer_code_stable = admitted_scope["analyzer_code_sha256"] == after_scope["analyzer_code_sha256"]
    result = json.loads((folder / "worker-result.json").read_text()) if (folder / "worker-result.json").exists() else None
    manifest = json.loads((folder / "source-manifest.json").read_text())
    assets_stable = all(hashlib.sha256((snapshot / relative).read_bytes()).hexdigest() == digest for relative,digest in manifest.items())
    summary = {"schema_version":2,"fixture":fixture,"scope_preflight":admitted_scope,"command":command,"source_snapshot":str(snapshot),"source_before":before,"source_after":after,"source_stable":before==after and assets_stable,"analyzer_code_stable":analyzer_code_stable,
        "host":{"platform":platform.platform(),"python":platform.python_version(),"cpu_count":os.cpu_count()},
        "budget_environment":{k:v for k,v in os.environ.items() if k.startswith("ATTACKMAP_") and any(word in k for word in ("LIMIT","BUDGET","WORKER","MEMORY"))},
        "exit_code":code,"hard_timeout":timed_out,"cleanup_verified":cleanup_verified,"samples":samples,"sample_period_seconds":0.05,
        "campaign_safety_memory_ceiling_bytes":args.abort_memory_bytes,"campaign_memory_aborted":memory_aborted,"peak_owned_job_commit_bytes":peak_job_commit or None,
        "sampled_peak_private_bytes":sampled_peak_private if samples else None,"stage_sampled_peaks":stage_peaks,"worker":result,
        "sampling_basis":"sum of live owned-job process private/working-set counters; all launcher/runtime descendant PIDs queried from job membership",
        "process_peaks":process_peaks,"tree_samples_incomplete":tree_samples_incomplete,
        "memory_threshold_bytes":TWO_GIB,"acceptance":"requires review of actual counters, coverage/default budget exhaustion and source stability; not auto-approved",
        "notes":plan()["limitations"]}
    write(folder / "campaign-result.json",summary)
    print(json.dumps({"result":str(folder / "campaign-result.json"),"exit_code":code,"timed_out":timed_out,"source_stable":before==after}))
    return 1 if timed_out or memory_aborted or not cleanup_verified or before != after or not assets_stable or not analyzer_code_stable else code


if __name__ == "__main__":
    raise SystemExit(main())
