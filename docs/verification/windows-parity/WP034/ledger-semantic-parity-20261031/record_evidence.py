"""Read captured baseline artifacts and record the isolated parity-test patch."""
from __future__ import annotations

from collections import Counter
import difflib
import hashlib
import json
from pathlib import Path
import platform
import runpy
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from attackmap.artifact_publisher import current_generation


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def differences(left, right, path=""):
    if type(left) is not type(right):
        return [{"path": path, "serial": left, "parallel": right}]
    if isinstance(left, dict):
        result = []
        for key in sorted(left.keys() | right.keys()):
            if key not in left or key not in right:
                result.append({"path": path + "/" + key, "missing_in": "serial" if key not in left else "parallel"})
            else:
                result.extend(differences(left[key], right[key], path + "/" + key))
        return result
    if isinstance(left, list):
        if len(left) != len(right):
            return [{"path": path, "serial_length": len(left), "parallel_length": len(right)}]
        return [item for index, pair in enumerate(zip(left, right))
                for item in differences(*pair, path + "/" + str(index))]
    return [] if left == right else [{"path": path, "serial": left, "parallel": right}]


semantics = runpy.run_path(str(ROOT / "tests/test_fleet_parallelism.py"))["_scan_semantics"]
audit = []
for index, output_format in enumerate(("all", "json", "markdown")):
    base = ROOT / "artifacts/wp034-ledger-semantic-parity-20261031/baseline-temp" / f"test_fleet_real_workers_match_{index}"
    parents = [current_generation(base / f"out-{workers}") for workers in (1, 2)]
    assert all(parent is not None for parent in parents)
    for repo in ("service-one", "slu-ba-dv"):
        reports = [current_generation(parent / repo) / "attackmap-report.json" for parent in parents]
        scans = [json.loads(path.read_text(encoding="utf-8"))["scan"] for path in reports]
        raw = differences(*scans)
        projected = differences(*(semantics(scan) for scan in scans))
        audit.append({"format": output_format, "repo_id": repo,
                      "reports": [str(path.relative_to(ROOT)) for path in reports],
                      "raw_difference_count": len(raw),
                      "raw_difference_fields": dict(Counter(item["path"].rsplit("/", 1)[-1] for item in raw)),
                      "semantic_difference_count": len(projected), "raw_differences": raw,
                      "semantic_differences": projected})
save("baseline-projection-audit.json", audit)
assert all(row["semantic_difference_count"] == 0 for row in audit)

source = ROOT / "tests/test_fleet_parallelism.py"
before = (OUT / "test_fleet_parallelism.before.py.txt").read_text(encoding="utf-8")
after = source.read_text(encoding="utf-8")
patch = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                  fromfile="a/tests/test_fleet_parallelism.py",
                                  tofile="b/tests/test_fleet_parallelism.py"))
(OUT / "owned-change.patch").write_text(patch, encoding="utf-8")
save("completion.json", {
    "task_id": "WP034", "owner": "/root/ledger_parity_fix",
    "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "final_commit_or_diff_hash": hashlib.sha256((OUT / "owned-change.patch").read_bytes()).hexdigest(),
    "paths_changed": ["tests/test_fleet_parallelism.py", str(OUT.relative_to(ROOT))],
    "leases_released": True,
    "tests_executed": {label: json.loads((OUT / f"{label}.summary.json").read_text())
                       for label in ("baseline", "focused", "fleet-regression")},
    "tests_not_executed": ["live provider", "Juice Shop", "C35 10k/50k/100k memory",
                           "native/UI", "frozen/package", "cross-platform", "release"],
    "live_provider_calls": 0, "manual_checks": "No GUI/manual acceptance performed",
    "package_id": None, "run_ids": ["baseline", "focused", "fleet-regression"],
    "evidence": ["baseline.xml", "focused.xml", "fleet-regression.xml", "baseline-projection-audit.json"],
    "limitations": ["Test-only semantic parity correction; WP034 and C35 remain IN_PROGRESS/open",
                    "Existing WP035 changes preserved; no production changes",
                    "Host-only pytest mkdir 0o700 -> 0o777 ACL workaround"],
    "next_action": "Independent review, then root updates shared planning documents",
    "python": sys.version, "platform": platform.platform(),
    "test_file_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in [ROOT / "src/attackmap" / name for name in (
                          "analyzer_run_ledger.py", "analyzers.py", "models.py", "pipeline.py", "scan_service.py")]},
    "wp035_hunk_unchanged": before[before.index('@pytest.mark.parametrize("isolated", [False, True])'):] ==
                             after[after.index('@pytest.mark.parametrize("isolated", [False, True])'):],
    "baseline_comparisons": [{key: value for key, value in row.items()
                              if key not in ("raw_differences", "semantic_differences")} for row in audit],
})
print(json.dumps(json.loads((OUT / "completion.json").read_text()), indent=2))
