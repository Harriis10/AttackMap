#!/usr/bin/env python
"""C35 stress measurement harness: per-stage p50/p95 and PEAK MEMORY.

Generates a deterministic fixture at run time (temp dir, never committed), runs
the engine IN-PROCESS against it N times, and reports:
  - per-stage p50/p95 milliseconds across repeats (from run-manifest.json)
  - peak resident memory of the measuring process (which is the engine process)
  - the elapsed-time-budget check overhead
  - host context (OS, CPU count, total RAM) so numbers can be qualified

Peak memory on Windows uses ctypes GetProcessMemoryInfo (PeakWorkingSetSize) —
stdlib only, no new dependencies. PeakWorkingSetSize is the process-lifetime
peak: with --repeat N > 1 it is the max across all runs (monotonic), so it is
reported once, not per run. On Linux the fallback is
resource.getrusage(RUSAGE_SELF).ru_maxrss.

No universal repositories-per-second claim is made or implied: these numbers
describe this fixture on this host only.

Usage:
    python tools/measure_stress.py --count 10000 --repeat 3 [--keep] [--json-out F]
"""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import platform
import shutil
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_stress_repo import generate_fixture  # noqa: E402

TWO_GIB = 2 * 1024 * 1024 * 1024


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _windows_memory() -> tuple[int | None, int | None]:
    """(PeakWorkingSetSize, WorkingSetSize) in bytes for this process.

    Argtypes must be declared (HANDLE is a 64-bit pseudo-handle on x64); an
    untyped windll call silently truncates it and the API fails.
    """
    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
    psapi = ctypes.WinDLL("psapi.dll")
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    if not psapi.GetProcessMemoryInfo(
        wintypes.HANDLE(-1), ctypes.byref(counters), counters.cb
    ):
        return None, None
    return int(counters.PeakWorkingSetSize), int(counters.WorkingSetSize)


def _linux_peak_rss() -> int | None:
    try:
        import resource

        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
    except (ImportError, AttributeError):
        return None


def peak_memory_bytes() -> int | None:
    if sys.platform == "win32":
        peak, _ = _windows_memory()
        return peak
    return _linux_peak_rss()


def working_set_bytes() -> int | None:
    if sys.platform == "win32":
        _, current = _windows_memory()
        return current
    return None


def total_ram_bytes() -> int | None:
    if sys.platform == "win32":
        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=False)
        kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
        kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
        if kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
    try:
        info = Path("/proc/meminfo").read_text(encoding="ascii").splitlines()
        for line in info:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def host_context() -> dict:
    return {
        "os": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "total_ram_bytes": total_ram_bytes(),
        "peak_memory_method": (
            "ctypes GetProcessMemoryInfo PeakWorkingSetSize (in-process, process-lifetime peak)"
            if sys.platform == "win32"
            else "resource.getrusage ru_maxrss"
        ),
    }


def percentile(samples: list[float], fraction: float) -> float | None:
    """Linear-interpolated percentile (inclusive), honest at any sample count."""
    if not samples:
        return None
    data = sorted(samples)
    if len(data) == 1:
        return data[0]
    rank = (len(data) - 1) * fraction
    low, high = math.floor(rank), math.ceil(rank)
    if low == high:
        return data[low]
    return data[low] + (data[high] - data[low]) * (rank - low)


def budget_check_overhead_ns(checks: int = 100_000) -> float | None:
    from attackmap.pipeline import TimeBudget

    budget = TimeBudget(seconds=60)
    start = time.perf_counter()
    for _ in range(checks):
        budget.check("overhead_probe")
    return (time.perf_counter() - start) / checks * 1e9


def run_once(repo: Path, output: Path, *, time_budget_seconds: int | None) -> dict:
    from attackmap.pipeline import AnalyzeOptions, run_scan

    started = time.perf_counter()
    state = run_scan(AnalyzeOptions(
        repo_path=repo,
        output=output,
        atomic_output=False,
        no_progress=True,
        time_budget_seconds=time_budget_seconds,
        echo=lambda *args, **kwargs: None,
    ))
    wall_seconds = time.perf_counter() - started
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    return {
        "wall_seconds": round(wall_seconds, 3),
        "exit_code": state.exit_code,
        "stages": {s["name"]: s["milliseconds"] for s in manifest.get("stages", [])},
        "files_scanned": manifest.get("files_scanned"),
        "findings_by_severity": manifest.get("findings_by_severity"),
        "time_budget": manifest.get("time_budget"),
        "working_set_after_bytes": working_set_bytes(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=10000,
                        help="fixture file count (10000 measured tonight; 50000/100000 supported)")
    parser.add_argument("--repeat", type=int, default=3, help="measurement runs (p50/p95 sample count)")
    parser.add_argument("--time-budget", type=int, default=None,
                        help="explicit --time-budget-seconds for the engine (default: engine default)")
    parser.add_argument("--keep", action="store_true", help="keep the generated fixture and reports")
    parser.add_argument("--json-out", type=Path, default=None, help="also write the summary JSON here")
    args = parser.parse_args(argv)

    workdir = Path(tempfile.mkdtemp(prefix="attackmap-stress-"))
    repo = workdir / "repo"
    reports = workdir / "reports"
    try:
        gen_started = time.perf_counter()
        declared = generate_fixture(repo, args.count)
        gen_seconds = round(time.perf_counter() - gen_started, 3)

        runs = [run_once(repo, reports / f"run_{i}", time_budget_seconds=args.time_budget)
                for i in range(args.repeat)]
        peak = peak_memory_bytes()

        stage_names: dict[str, list[float]] = {}
        for run in runs:
            for name, ms in run["stages"].items():
                stage_names.setdefault(name, []).append(ms)
        stage_stats = {
            name: {
                "p50_ms": round(percentile(values, 0.50) or 0, 1),
                "p95_ms": round(percentile(values, 0.95) or 0, 1),
                "samples": len(values),
            }
            for name, values in sorted(stage_names.items())
        }
        overhead = budget_check_overhead_ns()
        summary = {
            "fixture": {**declared, "generation_seconds": gen_seconds},
            "runs": runs,
            "stage_stats": stage_stats,
            "wall_seconds": {
                "p50": round(percentile([r["wall_seconds"] for r in runs], 0.50) or 0, 3),
                "p95": round(percentile([r["wall_seconds"] for r in runs], 0.95) or 0, 3),
            },
            "peak_memory_bytes": peak,
            "peak_memory_below_2gib": (peak < TWO_GIB) if peak is not None else None,
            "budget_check_overhead_ns_per_check": round(overhead, 1) if overhead else None,
            "host": host_context(),
            "notes": [
                "PeakWorkingSetSize is the measuring process's lifetime peak (the engine runs "
                "in-process): with repeat > 1 it is the max across runs, reported once.",
                "Numbers describe this fixture on this host only; no repositories-per-second "
                "claim is made.",
            ],
        }
        text = json.dumps(summary, indent=2)
        print(text)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(text + "\n", encoding="utf-8")
        return 0
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
