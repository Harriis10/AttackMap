"""Compare complete deterministic reports for equal analyzer selections."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
RUNS = ROOT / ".tmp/wp042-sol-ultra-20261023"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_run(name):
    matches = list((RUNS / name).glob("*/attackmap-report.json"))
    assert len(matches) == 1, (name, matches)
    path = matches[0]
    report = json.loads(path.read_text(encoding="utf-8"))
    manifest = json.loads((path.parent / "run-manifest.json").read_text(encoding="utf-8"))
    assert not manifest["time_budget"]["exceeded"]
    assert not manifest["analyzer_errors"]
    assert not manifest["llm_usage"]
    return path, report, manifest


def compare(label, before, after):
    a, first, first_manifest = read_run(before)
    b, second, second_manifest = read_run(after)
    equal = first == second
    analyzers_equal = first_manifest["analyzers"] == second_manifest["analyzers"]
    scan = second["scan"]
    result = {"label": label, "before_report": str(a), "after_report": str(b),
              "before_sha256": digest(a), "after_sha256": digest(b),
              "complete_report_json_equal": equal, "normalization": "none",
              "executed_analyzers_equal": analyzers_equal,
              "executed_analyzers": second_manifest["analyzers"],
              "files_scanned": scan["files_scanned"], "routes": len(scan["routes"]),
              "external_calls": len(scan["external_calls"]), "datastores": len(scan["databases"]),
              "findings": len(second["findings"]), "limitations": scan["limitations"],
              "provider_calls": 0, "time_budget_exceeded": False, "analyzer_errors": []}
    assert equal and analyzers_equal, result
    return result


if __name__ == "__main__":
    pairs = [compare("source automatic", "baseline-scan", "source-verified-final"),
             compare("frozen automatic", "frozen-baseline-scan", "frozen-final-scan"),
             compare("frozen explicit modules versus versioned Node profile", "frozen-explicit-node-baseline", "frozen-node-profile-scan")]
    proof = json.loads((RUNS / "frozen-engine-final/build-proof.json").read_text(encoding="utf-8"))
    result = {"scope": "Actual deterministic Juice Shop scans; no AI, native UI, release or accuracy/maturity acceptance",
              "target": "C:\\tmp\\juice-shop", "comparisons": pairs,
              "new_frozen_engine_sha256": proof["exe_sha256"],
              "old_frozen_engine_sha256": "574497f7c4ae3c8859edb5506c0538c8cba99dc70436f29857dbec6240aa81f5",
              "all_equal": True}
    (OUT / "juice-shop-verification.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"comparisons": len(pairs), "all_complete_reports_equal": True,
                      "counts": [{"label": p["label"], "routes": p["routes"], "findings": p["findings"]} for p in pairs]}))
