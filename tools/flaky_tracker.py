"""Minimal flaky-test tracking scaffold (AM051 / C37 delivery efficiency).

Records per-run pytest outcomes into a JSONL log and prints a per-test
flakiness summary (runs, failures). Standard library only - no new
dependencies.

Intended weekly loop for the C37 eight-week tracking window:

    # produce machine-readable output (any focused or broad suite):
    .venv/Scripts/python.exe -m pytest tests/test_run_contract.py -q -rA --tb=no > run1.txt
    python tools/flaky_tracker.py record run1.txt
    python tools/flaky_tracker.py summary

Input formats understood by ``record``:

- Pytest console output from ``pytest --tb=no -q`` (use ``-rA`` so every
  test gets a ``PASSED/FAILED/...`` summary line; with plain ``-ra`` only
  failures, errors and skips are recorded, so passes are not counted).
- Optionally, a ``pytest-json-report`` JSON file via ``--json`` when that
  plugin happens to be installed; it is preferred when given. The plugin is
  NOT a requirement and is never installed by this tool.

The log is append-only JSONL (default ``.pytest_cache/flaky-log.jsonl``);
delete the file to start a new window. This tool records what happened; it
does not claim any eight-week trend until that window has actually elapsed
and been measured.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = REPO_ROOT / ".pytest_cache" / "flaky-log.jsonl"

# "FAILED tests/test_x.py::test_y - KeyError: 'a'" / "SKIPPED [reason] tests/..."
OUTCOME_RE = re.compile(
    r"^\s*(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\b\s*(?:\[[^\]]*\]\s*)?(\S+)"
)
# Final counts line, e.g. "3 failed, 174 passed, 2 skipped in 1.23s"
COUNTS_RE = re.compile(r"(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed|warnings?)\b")
DURATION_RE = re.compile(r"\bin\s+(\d+(?:\.\d+)?)s\b")
FAILING_OUTCOMES = {"failed", "error"}


def parse_pytest_text(text: str) -> dict:
    counts: dict[str, int] = {}
    duration = None
    tests: dict[str, str] = {}
    for line in text.splitlines():
        match = OUTCOME_RE.match(line)
        if match:
            tests[match.group(2)] = match.group(1).lower()
            continue
        found_kinds = COUNTS_RE.findall(line)
        if found_kinds:
            for count, kind in found_kinds:
                kind = kind[:-1] if kind.endswith("s") else kind
                counts[kind] = counts.get(kind, 0) + int(count)
            if duration is None:
                found = DURATION_RE.search(line)
                if found:
                    duration = float(found.group(1))
    return {"counts": counts, "duration_s": duration, "tests": tests}


def parse_pytest_json_report(data: dict) -> dict:
    tests: dict[str, str] = {}
    for entry in data.get("tests", []):
        nodeid = entry.get("nodeid")
        outcome = entry.get("outcome")
        if nodeid and outcome:
            tests[nodeid] = str(outcome).lower()
    return {
        "counts": {k: int(v) for k, v in data.get("summary", {}).items() if isinstance(v, int)},
        "duration_s": data.get("duration"),
        "tests": tests,
    }


def cmd_record(args: argparse.Namespace) -> int:
    run: dict = {
        "record_type": "pytest-run",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": None,
        "duration_s": None,
        "counts": {},
        "tests": {},
    }
    if args.json:
        run["source"] = str(args.json)
        run.update(strip_none(parse_pytest_json_report(json.loads(Path(args.json).read_text(encoding="utf-8")))))
    elif args.outputs:
        for name in args.outputs:
            parsed = parse_pytest_text(Path(name).read_text(encoding="utf-8", errors="replace"))
            if run["source"] is None:
                run["source"] = name
            run["duration_s"] = parsed["duration_s"] if parsed["duration_s"] is not None else run["duration_s"]
            for kind, count in parsed["counts"].items():
                run["counts"][kind] = run["counts"].get(kind, 0) + count
            for nodeid, outcome in parsed["tests"].items():
                run["tests"][nodeid] = outcome
    else:
        print("error: provide pytest output files (and/or --json); see --help")
        return 2

    if not run["tests"] and not run["counts"]:
        print("error: no pytest results recognized in the given input "
              "(use `pytest -q -rA --tb=no` so every test has a summary line)")
        return 1

    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(run) + "\n")
    total = sum(run["counts"].values())
    print(f"recorded run from {run['source']}: {len(run['tests'])} per-test outcomes, "
          f"counts {run['counts']} (duration {run['duration_s']}s) -> {args.log}")
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    if not args.log.exists():
        print(f"no runs recorded yet (log not found: {args.log})")
        return 0
    runs = []
    for line in args.log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            runs.append(json.loads(line))

    per_test: dict[str, dict] = {}
    runs_with_failures = 0
    for run in runs:
        failed_this_run = False
        for nodeid, outcome in (run.get("tests") or {}).items():
            entry = per_test.setdefault(
                nodeid, {"runs": 0, "failures": 0, "skips": 0, "outcomes": {}}
            )
            entry["runs"] += 1
            if outcome in FAILING_OUTCOMES:
                entry["failures"] += 1
                failed_this_run = True
            elif outcome in {"skipped"}:
                entry["skips"] += 1
            entry["outcomes"][outcome] = entry["outcomes"].get(outcome, 0) + 1
        if failed_this_run:
            runs_with_failures += 1

    rows = [row for row in per_test.items() if row[1]["runs"] >= args.min_runs]
    rows.sort(key=lambda row: (-row[1]["failures"], -row[1]["runs"], row[0]))

    print(f"runs recorded: {len(runs)}; runs containing at least one failure/error: {runs_with_failures}")
    print(f"distinct tests seen: {len(per_test)}; shown (>= {args.min_runs} run(s)): {len(rows)}")
    if rows:
        print()
        print(f"{'failures/runs':>13}  skip  test")
        for nodeid, entry in rows[: args.limit]:
            outcome_mix = ",".join(f"{k}x{v}" for k, v in sorted(entry["outcomes"].items()))
            print(f"{entry['failures']}/{entry['runs']:>6}  {entry['skips']:>4}  {nodeid}  [{outcome_mix}]")
    flaky = [nodeid for nodeid, entry in per_test.items() if entry["failures"] and entry["runs"] > entry["failures"]]
    if flaky:
        print(f"\nflaky candidates (failed at least once but not every run): {len(flaky)}")
        for nodeid in flaky[: args.limit]:
            entry = per_test[nodeid]
            print(f"  {nodeid}: {entry['failures']} failure(s) in {entry['runs']} run(s)")
    else:
        print("\nflaky candidates: none recorded")
    return 0


def strip_none(parsed: dict) -> dict:
    return {k: v for k, v in parsed.items() if v is not None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG,
                        help=f"JSONL run log (default: {DEFAULT_LOG})")
    sub = parser.add_subparsers(dest="command", required=True)

    record = sub.add_parser("record", help="append one run's results to the log")
    record.add_argument("outputs", nargs="*",
                        help="pytest console output files (from `pytest -q -rA --tb=no`)")
    record.add_argument("--json", type=Path, default=None,
                        help="optional pytest-json-report JSON file (preferred when given)")
    record.set_defaults(func=cmd_record)

    summary = sub.add_parser("summary", help="print per-test flakiness summary from the log")
    summary.add_argument("--min-runs", type=int, default=1,
                         help="only show tests recorded in at least this many runs (default: 1)")
    summary.add_argument("--limit", type=int, default=30, help="max rows to print (default: 30)")
    summary.set_defaults(func=cmd_summary)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
