"""Run bounded deterministic Juice Shop checks and compare the preceding batch."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import verify_batch as batch

ROOT, OUT, WORK = batch.ROOT, batch.EVIDENCE, batch.WORK
PREVIOUS = ROOT / ".tmp/wp042-sol-ultra-20261023"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def report_path(folder):
    paths = [path for path in folder.rglob("attackmap-report.json") if path.parent != folder]
    assert len(paths) == 1, (folder, paths)
    return paths[0]


def scan(label):
    executable = ([ROOT / ".venv/Scripts/python.exe", "-m", "attackmap"] if label == "source"
                  else [WORK / "engine-final/dist/attackmap/attackmap.exe"])
    batch.run(label + "-scan", [*executable, "analyze", r"C:\tmp\juice-shop", "--format", "json",
                               "--no-progress", "--output", WORK / (label + "-scan")], 600)


def compare(label, previous, current):
    before_path = report_path(PREVIOUS / previous)
    after_path = report_path(current)
    before, after = read(before_path), read(after_path)
    before_manifest = read(before_path.parent / "run-manifest.json")
    manifest = read(after_path.parent / "run-manifest.json")
    normalized = copy.deepcopy(after)
    ledger = normalized["scan"].pop("analyzer_run_ledger")
    assert ledger == manifest["analyzer_run_ledger"]
    assert normalized["defensive_review_json"]["raw_structured_signals"]["scan"].pop("analyzer_run_ledger") == ledger
    assert normalized["review_context_pack"]["attackmap_review_json"]["raw_structured_signals"]["scan"].pop("analyzer_run_ledger") == ledger
    assert ledger["resolution_complete"] and ledger["execution_complete"]
    assert not manifest["analyzer_errors"] and not manifest["llm_usage"]
    assert not manifest["time_budget"]["exceeded"]
    entries = ledger["entries"]
    selected = [entry for entry in entries if entry["selection"] == "selected"]
    assert selected and all(entry["execution"] == "succeeded" for entry in selected)
    equality = normalized == before
    selected_equal = before_manifest["analyzers"] == manifest["analyzers"]
    result = dict(label=label, before_report=str(before_path), after_report=str(after_path),
                  before_sha256=sha(before_path), after_sha256=sha(after_path),
                  comparison_normalization="Remove only additive analyzer_run_ledger from scan and its identical copies in defensive_review_json.raw_structured_signals.scan and review_context_pack.attackmap_review_json.raw_structured_signals.scan",
                  report_equal_after_additive_ledger_removal=equality,
                  legacy_selected_analyzers_equal=selected_equal,
                  selected_analyzers=manifest["analyzers"],
                  ledger=ledger, report_manifest_ledger_equal=True,
                  routes=len(after["scan"]["routes"]), findings=len(after["findings"]),
                  files_scanned=after["scan"]["files_scanned"], limitations=after["scan"]["limitations"],
                  live_provider_calls=0, analyzer_errors=[], time_budget_exceeded=False)
    assert equality and selected_equal, result
    return result


def verify():
    pairs = [compare("source Automatic", "source-verified-final", WORK / "source-scan"),
             compare("frozen Automatic", "frozen-final-scan", WORK / "frozen-scan"),
             compare("native frozen Node profile", "frozen-node-profile-scan", WORK / "native-final-run4/reports")]
    assert pairs[0]["ledger"]["selection_mode"] == pairs[1]["ledger"]["selection_mode"] == "automatic"
    assert pairs[2]["ledger"]["profile_id"] == "node-atproto@1.0"
    proof = read(WORK / "engine-final/build-proof.json")
    value = dict(scope="Actual deterministic source/frozen/native Juice Shop runs; no AI, release or maturity acceptance",
                 target=r"C:\tmp\juice-shop", comparisons=pairs, new_engine_sha256=proof["exe_sha256"], passed=True)
    (OUT / "juice-shop-verification.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(passed=True, counts=[{k: row[k] for k in ("label", "routes", "findings")} for row in pairs])))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["source", "frozen", "verify"])
    args = parser.parse_args()
    verify() if args.operation == "verify" else scan(args.operation)
