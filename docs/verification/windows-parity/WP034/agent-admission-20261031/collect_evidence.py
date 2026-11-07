"""Retain small, exact metadata from this slice's own disposable scans."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
FINAL_TEMP = Path("C:/tmp/wp034-input-final-20261031")
BASELINE_TEMP = Path("C:/tmp/wp034-head-baseline-20261031/test_fleet_real_workers_match_0")


def save(name, data):
    (HERE / name).write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def differences(first, second, path=""):
    if isinstance(first, dict) and isinstance(second, dict):
        return [entry for key in sorted(first.keys() | second.keys())
                for entry in differences(first.get(key), second.get(key), path + "/" + key)]
    if isinstance(first, list) and isinstance(second, list) and len(first) == len(second):
        return [entry for index, (one, two) in enumerate(zip(first, second))
                for entry in differences(one, two, path + "/" + str(index))]
    return [] if first == second else [{"path": path, "serial": first, "parallel": second}]


for index, total in enumerate((32, 1)):
    output = FINAL_TEMP / f"test_actual_scanner_serial_opt{index}" / "out"
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((output / "fleet-summary.json").read_text(encoding="utf-8"))
    save(f"production-budget-{total}.json", {
        "source_output": str(output), "provider_calls": 0,
        "run_manifest": manifest,
        "fleet_architecture_coverage": summary["fleet_architecture"]["coverage"],
        "repository_statuses": [{"repo_id": row["repo_id"], "status": row["status"]}
                                for row in summary["fleet_architecture"]["repositories"]],
    })

ledgers = []
for workers in (1, 2):
    reports = (BASELINE_TEMP / f"out-{workers}").rglob("attackmap-report.json")
    data = next(json.loads(path.read_text(encoding="utf-8")) for path in reports
                if json.loads(path.read_text(encoding="utf-8"))["scan"]["root"].endswith("service one"))
    ledgers.append(data["scan"]["analyzer_run_ledger"])
save("baseline-ledger-differences.json", differences(*ledgers))

suite = ET.parse(HERE / "final.xml").getroot().find("testsuite")
paths = ("src/attackmap/scan_service.py", "tests/test_fleet_input_budget.py", "docs/resource-limits.md")
save("completion.json", {
    "scope": "WP034 opt-in fixed fleet captured-input quotas; no C35/peak-memory/release acceptance",
    "head": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
    "runtime": {"python": sys.version, "platform": platform.platform(), "machine": platform.machine()},
    "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths},
    "tracked_scope_diff_sha256": hashlib.sha256(subprocess.check_output(
        ["git", "-C", str(ROOT), "diff", "--", *paths])).hexdigest(),
    "final_suite": dict(suite.attrib), "provider_calls": 0,
    "known_regression": "3 serial/parallel raw analyzer ledger parity failures; HEAD scan_service reproduces [all]",
    "qualification": {"c35": False, "scale_10k_50k_100k": False, "peak_below_2gib": False,
                      "native_package_release": False},
})
