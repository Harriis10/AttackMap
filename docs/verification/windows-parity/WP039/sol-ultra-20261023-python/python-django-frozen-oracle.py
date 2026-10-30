"""Bounded frozen-executable oracle. Default mode prepares commands only.

Execution requires --execute and the released executable's expected SHA-256.
This invokes deterministic analysis only; no AI/install/CVE/network options.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


ROOT = Path(__file__).resolve().parents[5]
EVIDENCE = Path(__file__).resolve().parent
MEMBERS = {"python", "python-web", "config", "python-service", "default"}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path):
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError(f"JSON evidence exceeds 32 MiB bound: {path.name}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def semantics(routes):
    return sorted((route["path"], route["method"], route["file"], route["auth"]) for route in routes)


def load_fixtures(fixtures: Path):
    manifest = read_json(fixtures / "oracle-manifest.json")
    if len(manifest) != 17 or len({row["name"] for row in manifest}) != 17:
        raise ValueError("Expected the frozen seventeen-case oracle manifest")
    for row in manifest:
        if not re.fullmatch(r"[a-z0-9-]+", row["name"]):
            raise ValueError("Invalid case identity")
        case = (fixtures / row["name"]).resolve()
        for rel, expected in row["files"].items():
            source = (case / rel).resolve()
            if not source.is_relative_to(case) or sha(source) != expected:
                raise ValueError(f"Fixture hash mismatch: {row['name']}/{rel}")
    return manifest


def command(engine: Path, fixture: Path, output: Path, name: str):
    return [str(engine), "analyze", str(fixture), "--analyzer-profile", "python@1.0",
            "--output", str(output), "--format", "json", "--strict-analyzers",
            "--trusted-analyzers-only", "--no-progress", "--time-budget-seconds", "45",
            "--run-id", "django-oracle-" + name]


def inspect_case(output: Path, definition, source_case):
    pointer = read_json(output / "current-generation.json")
    generation = pointer["generation"]
    if not isinstance(generation, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", generation) or generation in {".", ".."}:
        raise ValueError("Invalid published generation identity")
    folder = (output / generation).resolve()
    if not folder.is_relative_to(output.resolve()):
        raise ValueError("Published generation escapes output directory")
    manifest_path = folder / "artifact-manifest.json"
    if sha(manifest_path) != pointer["manifest_sha256"]:
        raise ValueError("Published manifest checksum mismatch")
    manifest = read_json(manifest_path)
    if (manifest["generation_id"] != generation or manifest["exit_state"].get("exit_code") != 0
            or manifest["exit_state"].get("status") != "succeeded"):
        raise ValueError("Generation did not publish a successful exit state")
    report_path = folder / "attackmap-report.json"
    run_path = folder / "run-manifest.json"
    report = read_json(report_path)
    run = read_json(run_path)
    scan = report["scan"]
    routes = scan["routes"]
    failures = []
    for path, expected in definition["expected_overlay_auth"].items():
        actual = [route["auth"] for route in routes if route["path"] == path]
        if not actual or any(value != expected for value in actual):
            failures.append(f"Supported route/auth expectation {path}: {expected}, got {actual}")
    ledger = scan.get("analyzer_run_ledger")
    if not isinstance(ledger, dict) or ledger != run.get("analyzer_run_ledger"):
        failures.append("Report/run analyzer ledgers absent or different")
        ledger = ledger if isinstance(ledger, dict) else {}
    entries = ledger.get("entries", [])
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        failures.append("Malformed analyzer ledger entries")
        entries = []
    if (ledger.get("profile_id") != "python@1.0" or ledger.get("selection_mode") != "explicit"
            or ledger.get("inventory_scope") != "supplied_candidates"
            or ledger.get("resolution_complete") is not True or ledger.get("execution_complete") is not True
            or len(entries) != len(MEMBERS) or {entry.get("name") for entry in entries} != MEMBERS):
        failures.append("Exact profile membership/resolution/terminal-ledger contract mismatch")
    for entry in entries:
        if entry.get("execution") == "failed" or entry.get("error") is not None:
            failures.append(f"Analyzer failure: {entry.get('name')}")
        if entry.get("name") in {"python", "python-web", "python-service"} and entry.get("execution") != "succeeded":
            failures.append(f"Target Python layer did not succeed: {entry.get('name')}")
    if scan.get("analyzer_errors") or run.get("analyzer_errors") or run.get("time_budget", {}).get("exceeded") is True:
        failures.append("Analyzer errors or deterministic time-budget breach")
    profile_parity = semantics(routes) == semantics(source_case["lanes"]["python_profile"]["routes"])
    if not profile_parity:
        failures.append("Frozen/source exact-profile route semantics differ")
    forbidden = definition["forbidden_overlay_paths"]
    # The pinned plugin can retain these; report separately from the overlay oracle.
    residuals = [route for route in routes if route["path"] in forbidden]
    return {"failures": failures, "supported_subset_pass": not failures,
            "source_profile_semantics_equal": profile_parity, "known_profile_residual_routes": residuals,
            "routes": routes, "limitations": scan.get("limitations", []),
            "analyzer_run_ledger": ledger, "generation": generation,
            "report_path": str(report_path), "report_sha256": sha(report_path),
            "run_manifest_sha256": sha(run_path), "artifact_manifest_sha256": sha(manifest_path)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, default=ROOT / ".tmp/wp039-python-20261023/engine-analyzers-final/dist/attackmap/attackmap.exe")
    parser.add_argument("--fixtures", type=Path, default=ROOT / ".tmp/wp039-python-20261023/django-cases")
    parser.add_argument("--source-oracle", type=Path, default=EVIDENCE / "python-django-after-stable-profile.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-engine-sha256")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    engine, fixtures, output = args.engine.resolve(), args.fixtures.resolve(), args.output.resolve()
    if not output.is_relative_to(EVIDENCE.resolve()) and not output.is_relative_to((ROOT / ".tmp/wp039-python-20261023").resolve()):
        raise ValueError("Output must stay in this task's leased evidence or temporary directory")
    definitions = load_fixtures(fixtures)
    source = read_json(args.source_oracle)
    source_cases = {row["name"]: row for row in source["cases"]}
    plan = {"scope": "Actual frozen executable, deterministic seventeen-case profile subset; no framework runtime, AI, installation or release acceptance.",
            "state": "prepared_only", "engine": str(engine), "output": str(output),
            "case_count": len(definitions), "profile_id": "python@1.0", "expected_members": sorted(MEMBERS),
            "fixture_manifest_sha256": sha(fixtures / "oracle-manifest.json"),
            "source_oracle_sha256": sha(args.source_oracle),
            "commands": [command(engine, fixtures / row["name"], output / row["name"], row["name"]) for row in definitions]}
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return
    if not args.expected_engine_sha256 or sha(engine).lower() != args.expected_engine_sha256.lower():
        raise ValueError("Execution requires the released executable's matching expected SHA-256")
    output.mkdir(parents=True, exist_ok=False)
    plan.update(state="running", engine_sha256=sha(engine), started_at=datetime.now(timezone.utc).isoformat(), results=[])
    write_json(output / "summary.json", plan)
    environment = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "ATTACKMAP_INCREMENTAL"):
        environment.pop(key, None)
    environment["NO_COLOR"] = "1"
    started = time.monotonic()
    for row, argv in zip(definitions, plan["commands"]):
        case_output = output / row["name"]
        log = output / (row["name"] + ".process.json")
        entry = {"name": row["name"], "command": argv, "failures": []}
        remaining = 600 - (time.monotonic() - started)
        if remaining <= 0:
            entry["failures"] = ["Whole-run 600-second deadline reached; case not executed"]
        else:
            tick = time.monotonic()
            try:
                process = subprocess.run(argv, cwd=ROOT, env=environment, capture_output=True,
                                         timeout=min(90, remaining), check=False)
                write_json(log, {"command": argv, "exit_code": process.returncode,
                                 "stdout": process.stdout.decode("utf-8", errors="replace"),
                                 "stderr": process.stderr.decode("utf-8", errors="replace")})
                entry["exit_code"] = process.returncode
                if process.returncode:
                    entry["failures"] = [f"Frozen command exited {process.returncode}"]
                else:
                    entry.update(inspect_case(case_output, row, source_cases[row["name"]]))
            except subprocess.TimeoutExpired as error:
                write_json(log, {"command": argv, "timeout": True,
                                 "stdout": (error.stdout or b"").decode("utf-8", errors="replace"),
                                 "stderr": (error.stderr or b"").decode("utf-8", errors="replace")})
                entry["failures"] = ["Bounded frozen command timed out"]
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                entry["failures"] = [f"Evidence validation failed ({type(error).__name__}): {error}"]
            entry["elapsed_seconds"] = round(time.monotonic() - tick, 3)
        plan["results"].append(entry)
        write_json(output / "summary.json", plan)
        print(json.dumps({"case": row["name"], "failures": entry["failures"], "completed": len(plan["results"])}), flush=True)
    if sha(engine) != plan["engine_sha256"]:
        plan["engine_changed_during_run"] = True
    plan.update(state="passed" if all(not row["failures"] for row in plan["results"]) and not plan.get("engine_changed_during_run") else "failed",
                elapsed_seconds=round(time.monotonic() - started, 3),
                pass_count=sum(not row["failures"] for row in plan["results"]))
    write_json(output / "summary.json", plan)
    print(json.dumps({"state": plan["state"], "pass_count": plan["pass_count"], "cases": len(definitions), "output": str(output)}), flush=True)
    raise SystemExit(0 if plan["state"] == "passed" else 1)


if __name__ == "__main__":
    main()
