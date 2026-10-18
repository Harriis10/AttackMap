"""One-command contributor setup verifier (AM051 / C37 delivery efficiency).

Checks the core setup path a new contributor is expected to follow:

1. Python interpreter version is inside the supported range (3.11 - 3.13).
2. Optionally creates a fresh virtualenv (``--fresh``). By default an
   existing ``.venv`` (or the path given with ``--venv``) is reused.
3. Installs the project editable with the ``dev`` extra (``--skip-install``
   to reuse an already-installed environment).
4. Runs a fast, representative focused-suite subset and requires it to pass.
5. Prints elapsed time per stage and writes a JSON timing record under
   ``.pytest_cache/`` (configurable with ``--output``).

Exit code is non-zero when any executed stage fails. Skipped stages are
recorded as skipped and never reported as measured time.

The 30-minute budget refers to roadmap criterion C37 ("a new contributor can
build the core and run its focused suite within 30 minutes, excluding
prerequisite tool downloads"). This script measures only what it executes;
prerequisite downloads (Python, git, dotnet SDK, NuGet packages) are excluded
by definition.
"""
from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Supported interpreter range: requires-python >= 3.11 in pyproject.toml and
# the CI matrix tests 3.11/3.12/3.13. Newer interpreters get a warning, not a
# failure, because the project does not declare an upper bound.
MIN_PYTHON = (3, 11)
MAX_TESTED_PYTHON = (3, 13)

# Fast, representative focused-suite subset (~a few seconds on this host).
# Covers the run-contract golden fixtures, both desktop client fixture
# suites, the UI contract adapter and core finding-identity semantics.
# Kept independent of the scanner import chain so the subset validates the
# setup rather than in-progress feature work; the full CI matrix gates code.
FOCUSED_SUITE = [
    "tests/test_run_contract.py",
    "tests/test_ui_contract_adapter.py",
    "tests/test_desktop_workflow_fixtures.py",
    "tests/test_desktop_reference.py",
    "tests/test_finding_identity.py",
]

DEFAULT_VENV = REPO_ROOT / ".venv"
DEFAULT_OUTPUT_DIR = REPO_ROOT / ".pytest_cache" / "setup-verification"

# Outcome per stage: "passed", "failed", "skipped" or "warning".
STAGES: list[dict] = []


def record_stage(name: str, outcome: str, seconds: float, detail: str) -> None:
    STAGES.append(
        {"stage": name, "outcome": outcome, "seconds": round(seconds, 3), "detail": detail}
    )
    label = f"{seconds:7.2f}s" if outcome != "skipped" else "   --   "
    print(f"  [{outcome:>7}] {label} {name}: {detail}")


def run_timed(name: str, cmd: list[str], *, cwd: Path = REPO_ROOT) -> tuple[float, subprocess.CompletedProcess]:
    start = time.perf_counter()
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return time.perf_counter() - start, proc


def venv_python(venv_dir: Path) -> Path:
    return venv_dir / "Scripts" / "python.exe" if sys.platform == "win32" else venv_dir / "bin" / "python"


def stage_python_check(interpreter: Path) -> bool:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [str(interpreter), "-c", "import sys; print(sys.version_info[:3])"],
            capture_output=True, text=True, timeout=60,
        )
    except OSError as exc:
        record_stage("python-check", "failed", time.perf_counter() - start, f"cannot run {interpreter}: {exc}")
        return False
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        record_stage("python-check", "failed", elapsed, proc.stderr.strip() or "interpreter check failed")
        return False
    version = tuple(json.loads(proc.stdout.strip().replace("(", "[").replace(")", "]")))
    if version < MIN_PYTHON:
        record_stage(
            "python-check", "failed", elapsed,
            f"Python { '.'.join(map(str, version)) } is older than the required 3.11",
        )
        return False
    if version[:2] > MAX_TESTED_PYTHON:
        record_stage(
            "python-check", "warning", elapsed,
            f"Python { '.'.join(map(str, version)) } is newer than the CI-tested range (3.11-3.13); it may work but is unverified",
        )
        return True
    record_stage("python-check", "passed", elapsed, f"Python { '.'.join(map(str, version)) } within supported range 3.11-3.13")
    return True


def stage_venv_create(venv_dir: Path) -> bool:
    if venv_dir.exists():
        record_stage("venv-create", "failed", 0.0, f"{venv_dir} already exists; remove it or drop --fresh")
        return False
    elapsed, proc = run_timed("venv-create", [sys.executable, "-m", "venv", str(venv_dir)])
    if proc.returncode != 0:
        record_stage("venv-create", "failed", elapsed, (proc.stderr or proc.stdout).strip()[:400])
        return False
    record_stage("venv-create", "passed", elapsed, f"created virtualenv at {venv_dir}")
    return True


def stage_install(interpreter: Path, extras: str) -> bool:
    requirement = f".[{extras}]" if extras else "."
    elapsed, proc = run_timed(
        "install",
        [str(interpreter), "-m", "pip", "install", "--disable-pip-version-check", "-e", requirement],
    )
    tail = "\n".join((proc.stdout or "").splitlines()[-3:])
    if proc.returncode != 0:
        record_stage("install", "failed", elapsed, (tail or proc.stderr.strip()[-400:]))
        return False
    record_stage("install", "passed", elapsed, f"pip install -e {requirement} ({tail.splitlines()[-1] if tail else 'ok'})")
    return True


def stage_focused_suite(interpreter: Path) -> tuple[bool, str]:
    elapsed, proc = run_timed(
        "focused-suite",
        [str(interpreter), "-m", "pytest", *FOCUSED_SUITE, "-q", "--tb=short"],
    )
    summary = ""
    for line in (proc.stdout or "").splitlines():
        if line.strip().startswith(("passed", "failed", "error")) or " passed" in line or " failed" in line or " error" in line:
            summary = line.strip()
    if proc.returncode != 0:
        record_stage("focused-suite", "failed", elapsed, summary or "pytest failed (see output above)")
        print(proc.stdout)
        return False, summary
    record_stage("focused-suite", "passed", elapsed, f"pytest focused subset: {summary}")
    return True, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fresh", action="store_true",
                        help="create a new virtualenv at --venv (refuses to overwrite an existing one)")
    parser.add_argument("--venv", type=Path, default=DEFAULT_VENV,
                        help=f"virtualenv location (default: {DEFAULT_VENV})")
    parser.add_argument("--extras", default="dev",
                        help="dependency extra to install together with the editable package (default: dev; empty string for none)")
    parser.add_argument("--skip-install", action="store_true",
                        help="do not run pip install; reuse the already-installed environment")
    parser.add_argument("--skip-suite", action="store_true",
                        help="do not run the focused pytest subset (version checks only)")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"JSON timing record path (default: {DEFAULT_OUTPUT_DIR}/verify-setup-<timestamp>.json)")
    parser.add_argument("--budget-minutes", type=float, default=30.0,
                        help="wall-clock budget the executed stages are compared against (default: 30, per roadmap C37)")
    args = parser.parse_args(argv)

    venv_dir = args.venv.resolve()
    print(f"AttackMap setup verification (repo: {REPO_ROOT})")
    print(f"virtualenv: {venv_dir}{' (fresh)' if args.fresh else ''}\n")

    started = time.perf_counter()
    ok = True

    if args.fresh:
        ok = stage_venv_create(venv_dir) and ok
        interpreter = venv_python(venv_dir)
    else:
        if not venv_dir.exists():
            print(f"error: {venv_dir} does not exist; pass --fresh to create it")
            return 2
        interpreter = venv_python(venv_dir)

    ok = stage_python_check(interpreter) and ok

    if args.skip_install:
        record_stage("install", "skipped", 0.0, "--skip-install: reusing already-installed environment (no install time measured)")
    else:
        ok = stage_install(interpreter, args.extras) and ok

    if args.skip_suite:
        record_stage("focused-suite", "skipped", 0.0, "--skip-suite: focused subset not run")
        suite_summary = ""
    else:
        suite_ok, suite_summary = stage_focused_suite(interpreter)
        ok = suite_ok and ok

    total = time.perf_counter() - started

    measured = [s for s in STAGES if s["outcome"] != "skipped"]
    measured_seconds = sum(s["seconds"] for s in measured)
    budget_seconds = args.budget_minutes * 60

    record: dict = {
        "record_type": "setup-verification",
        "criterion": "C37 delivery efficiency (machine-measured portion)",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repository": str(REPO_ROOT),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_reporter": platform.python_version(),
        },
        "interpreter": str(interpreter),
        "fresh_venv": args.fresh,
        "focused_suite_files": FOCUSED_SUITE,
        "stages": STAGES,
        "measured_stage_seconds_total": round(measured_seconds, 3),
        "wall_seconds_total": round(total, 3),
        "budget_minutes": args.budget_minutes,
        "within_budget": measured_seconds <= budget_seconds,
        "all_executed_stages_passed": ok,
        "notes": (
            "Timings cover only executed stages. Prerequisite tool downloads "
            "(Python, git, .NET SDK, NuGet packages) are excluded per C37. "
            "A skipped install stage means dependency install time was not "
            "measured by this run, not that it is zero."
        ),
    }

    output = args.output
    if output is None:
        DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = DEFAULT_OUTPUT_DIR / f"verify-setup-{stamp}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2), encoding="utf-8")

    print()
    print(f"executed stages:   {len(measured)} ({', '.join(s['stage'] for s in measured)})")
    print(f"measured stage time: {measured_seconds:.2f}s of {args.budget_minutes:.0f}-minute budget")
    print(f"wall time (this run): {total:.2f}s")
    print(f"timing record:       {output}")
    if not ok:
        print("result: FAILED (see failed stages above)")
        return 1
    print("result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
