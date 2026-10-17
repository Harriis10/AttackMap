"""C09 process-supervision platform proof campaign (AM010, Windows host).

Runs the roadmap C09 measurement as a standalone, repeatable campaign instead
of a one-shot pytest fixture:

- 50 real start/cancel cycles against a real parent/child worker tree whose
  processes both ignore graceful termination (SIGBREAK), contained by the
  shipped WindowsProcessJob supervisor path.
- Per cycle it measures the acknowledgement latency callers actually observe
  (``ProcessSupervisor.request_cancel()`` return), the externally probed
  worker-tree death time, and the verified-completion time (``wait()`` return,
  which upper-bounds admission release).
- One 20-way simultaneous-start admission check: exactly one worker launch,
  and the slot stays occupied after acknowledgement until termination is
  verified.
- Writes a JSON evidence record (raw samples, thresholds, host context) to
  ``.pytest_cache/c09-campaign/evidence.json`` and exits non-zero when any
  C09 threshold is breached.

Measured layer, stated honestly: the core ``attackmap.execution`` supervisor.
The desktop HTTP ``/api/cancel`` adapter acknowledges by returning its state
snapshot after dispatching verified cleanup on a background thread; that
adapter is exercised separately in tests/test_ui_supervision.py and is not
remeasured here. This campaign is Windows-only by design (Job Object path).
"""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / ".pytest_cache/c09-campaign/evidence.json"
ACK_BUDGET_S = 0.250  # C09: UI acknowledgement p95 <= 250 ms
EXIT_BUDGET_S = 5.0   # C09: controlled worker tree exits within 5 s

WORKER_SOURCE = """import os, signal, subprocess, sys, time
from pathlib import Path
signal.signal(signal.SIGBREAK, signal.SIG_IGN)
if len(sys.argv) > 2:
    ready = Path(sys.argv[1])
    pending = ready.with_suffix(".tmp")
    pending.write_text(str(os.getpid()))
    os.replace(pending, ready)
else:
    subprocess.Popen([sys.executable, __file__, sys.argv[1], "child"])
while True:
    time.sleep(0.01)
"""

try:
    from attackmap.execution import ProcessSupervisor
    import attackmap.execution as _execution_module
except ImportError:  # direct source checkout without an installed package
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from attackmap.execution import ProcessSupervisor
    import attackmap.execution as _execution_module


def _winapi():
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel


_KERNEL = None


def is_alive(pid: int) -> bool:
    """External liveness probe, independent of the supervisor's own handles."""
    global _KERNEL
    if _KERNEL is None:
        _KERNEL = _winapi()
    handle = _KERNEL.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    try:
        from ctypes import wintypes

        code = wintypes.DWORD()
        ok = bool(_KERNEL.GetExitCodeProcess(handle, ctypes.byref(code)))
        return ok and code.value == 259  # STILL_ACTIVE
    finally:
        _KERNEL.CloseHandle(handle)


def wait_for(predicate, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def nearest_rank(samples: list[float], pct: float) -> float:
    ordered = sorted(samples)
    return ordered[max(1, math.ceil(pct / 100.0 * len(ordered))) - 1]


def host_context() -> dict[str, object]:
    return {
        "os": platform.platform(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "processor_identifier": os.environ.get("PROCESSOR_IDENTIFIER", ""),
        "logical_processors": os.cpu_count(),
        "python": sys.version.replace("\n", " "),
        "python_executable": sys.executable,
    }


def run_cancel_cycle(supervisor, worker: Path, tmp: Path, cycle: int) -> dict[str, object]:
    """One supervised start/cancel cycle against the ignoring-graceful tree."""
    ready = tmp / f"child-{cycle}.pid"
    if not supervisor.start([sys.executable, str(worker), str(ready)]):
        return {"cycle": cycle, "start_ok": False, "error": "admission refused a free slot"}
    try:
        if not wait_for(ready.exists):
            return {"cycle": cycle, "start_ok": True, "error": "controlled child never signalled readiness"}
        child = int(ready.read_text())
        parent = supervisor._proc.pid
        preconditions = {"parent_alive": is_alive(parent), "child_alive": is_alive(child)}
        t0 = time.monotonic()
        acknowledged = supervisor.request_cancel()
        ack_s = time.monotonic() - t0
        # Slot must remain occupied after acknowledgement until exit is verified.
        slot_held = acknowledged and supervisor.running and not supervisor.start(
            [sys.executable, str(worker), tmp / f"probe-{cycle}.pid"]
        )
        tree_dead_s = None
        while time.monotonic() - t0 < EXIT_BUDGET_S:
            if not is_alive(parent) and not is_alive(child):
                tree_dead_s = time.monotonic() - t0
                break
            time.sleep(0.01)
        verified = supervisor.wait(EXIT_BUDGET_S)
        verified_s = time.monotonic() - t0
        return {
            "cycle": cycle,
            "start_ok": True,
            "acknowledged": acknowledged,
            "ack_s": round(ack_s, 6),
            "slot_held_after_ack": slot_held,
            "parent_pid": parent,
            "child_pid": child,
            "preconditions": preconditions,
            "tree_dead_s": None if tree_dead_s is None else round(tree_dead_s, 6),
            "verified_completion_s": round(verified_s, 6),
            "verified_completion": verified,
            "running_after_wait": supervisor.running,
            "parent_dead_after_wait": not is_alive(parent),
            "child_dead_after_wait": not is_alive(child),
        }
    finally:
        if supervisor.running:
            supervisor.request_cancel()
            if not supervisor.wait(7):
                raise RuntimeError(f"cycle {cycle}: worker cleanup was not verified")


def run_admission_check(supervisor, worker: Path, tmp: Path, simultaneous: int) -> dict[str, object]:
    """simultaneous concurrent start requests must launch exactly one worker."""
    ready = tmp / "admission-child.pid"
    argv = [sys.executable, str(worker), str(ready)]
    real_popen = _execution_module.subprocess.Popen
    launches: list[object] = []

    def counting_popen(*args, **kwargs):
        launches.append(kwargs.get("args", args))
        return real_popen(*args, **kwargs)

    gate = threading.Barrier(simultaneous)
    results: list[bool] = []

    def start_one(_):
        gate.wait(timeout=10)
        return supervisor.start(argv)

    _execution_module.subprocess.Popen = counting_popen
    try:
        with ThreadPoolExecutor(max_workers=simultaneous) as pool:
            results = list(pool.map(start_one, range(simultaneous)))
    finally:
        _execution_module.subprocess.Popen = real_popen

    record: dict[str, object] = {
        "simultaneous_requests": simultaneous,
        "admitted": results.count(True),
        "refused": results.count(False),
        "popen_launches": len(launches),
        "exactly_one_launch": results.count(True) == 1 and len(launches) == 1,
    }
    if not record["exactly_one_launch"]:
        if supervisor.running:
            supervisor.request_cancel()
            supervisor.wait(7)
        return record

    try:
        if not wait_for(ready.exists):
            record["error"] = "admitted worker's controlled child never signalled readiness"
            return record
        child = int(ready.read_text())
        parent = supervisor._proc.pid
        record["parent_pid"] = parent
        record["child_pid"] = child
        record["both_alive_before_cancel"] = is_alive(parent) and is_alive(child)
        t0 = time.monotonic()
        acknowledged = supervisor.request_cancel()
        ack_s = time.monotonic() - t0
        slot_held = acknowledged and supervisor.running and not supervisor.start(argv)
        verified = supervisor.wait(EXIT_BUDGET_S)
        verified_s = time.monotonic() - t0
        record.update({
            "acknowledged": acknowledged,
            "ack_s": round(ack_s, 6),
            "slot_held_after_ack": slot_held,
            "verified_completion": verified,
            "verified_completion_s": round(verified_s, 6),
            "running_after_wait": supervisor.running,
            "parent_dead_after_wait": not is_alive(parent),
            "child_dead_after_wait": not is_alive(child),
        })
    finally:
        if supervisor.running:
            supervisor.request_cancel()
            if not supervisor.wait(7):
                raise RuntimeError("admission check: worker cleanup was not verified")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cycles", type=int, default=50, help="start/cancel cycles (default 50)")
    parser.add_argument("--simultaneous", type=int, default=20, help="concurrent admission starts (default 20)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="evidence JSON path")
    args = parser.parse_args()

    if os.name != "nt":
        print("c09_campaign: Windows-only campaign (Job Object supervision path).", file=sys.stderr)
        return 2

    started_utc = datetime.now(timezone.utc).isoformat()
    campaign_t0 = time.monotonic()
    tmp = Path(tempfile.mkdtemp(prefix="c09-campaign-"))
    worker = tmp / "controlled.py"
    worker.write_text(WORKER_SOURCE, encoding="utf-8")

    supervisor = ProcessSupervisor()
    admission = run_admission_check(supervisor, worker, tmp, args.simultaneous)
    samples = []
    for cycle in range(args.cycles):
        samples.append(run_cancel_cycle(supervisor, worker, tmp, cycle))
        if samples[-1].get("error") or not samples[-1].get("start_ok"):
            break
    # Release proof: after the last verified exit the slot must admit again.
    release_ok = supervisor.start([sys.executable, "-c", "pass"])
    if release_ok:
        release_ok = supervisor.wait(10) and not supervisor.running
    campaign_s = time.monotonic() - campaign_t0

    completed = [s for s in samples if s.get("start_ok") and not s.get("error")]
    acks = [s["ack_s"] for s in completed]
    tree_dead = [s["tree_dead_s"] for s in completed if s["tree_dead_s"] is not None]
    verified = [s["verified_completion_s"] for s in completed]
    stats = {
        "ack_s": {"p50": round(nearest_rank(acks, 50), 6), "p95": round(nearest_rank(acks, 95), 6),
                  "max": round(max(acks), 6)} if acks else None,
        "tree_dead_s": {"p50": round(nearest_rank(tree_dead, 50), 6), "p95": round(nearest_rank(tree_dead, 95), 6),
                        "max": round(max(tree_dead), 6)} if tree_dead else None,
        "verified_completion_s": {"p50": round(nearest_rank(verified, 50), 6),
                                  "p95": round(nearest_rank(verified, 95), 6),
                                  "max": round(max(verified), 6)} if verified else None,
    }

    checks = {
        "campaign_completed_all_cycles": len(completed) == args.cycles,
        "admission_exactly_one_launch": bool(admission["exactly_one_launch"]),
        "admission_slot_held_after_ack": bool(admission.get("slot_held_after_ack")),
        "admission_tree_verified_dead": bool(
            admission.get("verified_completion") and admission.get("parent_dead_after_wait")
            and admission.get("child_dead_after_wait")
        ),
        "ack_p95_within_250ms": bool(acks) and nearest_rank(acks, 95) <= ACK_BUDGET_S,
        "all_tree_deaths_observed_within_5s": len(tree_dead) == args.cycles and max(tree_dead) <= EXIT_BUDGET_S,
        "all_verified_completions_within_5s": len(verified) == args.cycles and max(verified) <= EXIT_BUDGET_S,
        "slot_held_every_cycle": all(s.get("slot_held_after_ack") for s in completed),
        "all_trees_verified_dead_every_cycle": all(
            s.get("verified_completion") and s.get("parent_dead_after_wait") and s.get("child_dead_after_wait")
            for s in completed
        ),
        "slot_released_after_verified_exit": release_ok,
    }
    evidence = {
        "schema": "c09-campaign/1",
        "criterion": "C09 Process supervision (AM010) - Windows platform proof",
        "started_utc": started_utc,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "campaign_wall_s": round(campaign_s, 3),
        "host_context": host_context(),
        "acknowledgement_layer": (
            "attackmap.execution.ProcessSupervisor.request_cancel() return-to-caller latency; "
            "the same primitive the desktop /api/cancel adapter dispatches on a background thread "
            "before returning its CANCELLING state snapshot. No HTTP round trip is measured here."
        ),
        "fixture": (
            "Real process tree: python parent spawns python child; both ignore SIGBREAK "
            "(graceful termination ignored), forcing forced Job Object termination. "
            "Same pattern as tests/test_execution_supervision.py::test_fifty_cancel_cycles."
        ),
        "thresholds": {
            "ack_p95_max_s": ACK_BUDGET_S,
            "tree_exit_max_s": EXIT_BUDGET_S,
            "simultaneous_starts": args.simultaneous,
            "cycles": args.cycles,
        },
        "admission_check": admission,
        "cycles_requested": args.cycles,
        "cycles_completed": len(completed),
        "samples": samples,
        "stats": stats,
        "checks": checks,
        "passed": all(checks.values()),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"c09 campaign: {len(completed)}/{args.cycles} cycles completed in {campaign_s:.1f}s")
    if stats["ack_s"]:
        print(f"  ack           p50={stats['ack_s']['p50']:.6f}s p95={stats['ack_s']['p95']:.6f}s "
              f"max={stats['ack_s']['max']:.6f}s (budget p95<={ACK_BUDGET_S}s)")
    if stats["tree_dead_s"]:
        print(f"  tree death    p50={stats['tree_dead_s']['p50']:.6f}s p95={stats['tree_dead_s']['p95']:.6f}s "
              f"max={stats['tree_dead_s']['max']:.6f}s (budget max<={EXIT_BUDGET_S}s)")
    if stats["verified_completion_s"]:
        print(f"  verified exit p50={stats['verified_completion_s']['p50']:.6f}s "
              f"p95={stats['verified_completion_s']['p95']:.6f}s "
              f"max={stats['verified_completion_s']['max']:.6f}s")
    print(f"  admission: admitted={admission['admitted']}/{args.simultaneous} "
          f"launches={admission['popen_launches']} slot_held_after_ack={admission.get('slot_held_after_ack')}")
    for name, ok in checks.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"evidence: {args.out}")
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
