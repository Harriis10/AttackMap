"""Runtime checks bound to this captured source, never the concurrent fleet tree."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

from candidate import CANDIDATE, ROOT, OUT, WORK, run, save
from verify_native import sha

FREEZE = WORK / "engine-analyzers-final"
ENGINE = FREEZE / "dist/attackmap/attackmap.exe"
NATIVE = WORK / "native-analyzers-03/publish/AttackMap.NativeSpike.exe"


def report(folder):
    candidates = [path for path in folder.rglob("attackmap-report.json") if path.parent != folder]
    assert len(candidates) == 1, candidates
    return candidates[0]


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def source():
    run("source-final-juice", [ROOT / ".venv/Scripts/python.exe", "-m", "attackmap", "analyze", r"C:\tmp\juice-shop",
        "--format", "json", "--progress-format", "json", "--output", WORK / "source-final-juice"], source=CANDIDATE)


def qualify():
    path = ROOT / "docs/verification/windows-parity/RESUME-2026-10-22/astra-high/qualify_fresh_engine.py"
    spec = importlib.util.spec_from_file_location("frozen_qualification", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = CANDIDATE
    # Use the same captured lock algorithm that produced the immutable build.
    # The moving root's tool has since added a fixture to its digest scope.
    lock_spec = importlib.util.spec_from_file_location("candidate_release_lock", CANDIDATE / "tools/generate_release_lock.py")
    lock_module = importlib.util.module_from_spec(lock_spec)
    lock_spec.loader.exec_module(lock_module)
    module.lock_tool = lock_module
    module.qualify(FREEZE, WORK / "frozen-qualification")


def native(label, scan=True):
    output = WORK / label
    output.mkdir()
    argv = [NATIVE, "--analyzer-smoke", output, "--engine", ENGINE, "--analyzer-profile", "node-atproto@1.0",
            "--discovery-fixture", OUT / "native-discovery-issues-fixture.json"]
    if scan:
        argv += ["--native-scan", "--repository", r"C:\tmp\juice-shop"]
    run(label, argv, timeout=900)
    proof = read(output / "analyzer-smoke.json")
    save(label + "-proof.json", proof)
    assert proof.get("failure") is None and proof["result"]["passed"], proof.get("failure")


def normalize(value):
    value = copy.deepcopy(value)
    ledger = value["scan"].pop("analyzer_run_ledger")
    assert value["defensive_review_json"]["raw_structured_signals"]["scan"].pop("analyzer_run_ledger") == ledger
    assert value["review_context_pack"]["attackmap_review_json"]["raw_structured_signals"]["scan"].pop("analyzer_run_ledger") == ledger
    return value, ledger


def compare(label, before_folder, after_folder):
    before_path, after_path = report(before_folder), report(after_folder)
    before, _ = normalize(read(before_path))
    after, ledger = normalize(read(after_path))
    manifest = read(after_path.parent / "run-manifest.json")
    assert ledger == manifest["analyzer_run_ledger"]
    assert ledger["schema_version"] == "1.1" and ledger["resolution_complete"] and ledger["execution_complete"]
    assert before == after, label + " report changed beyond ledger"
    assert not manifest["analyzer_errors"] and not manifest["llm_usage"] and not manifest["time_budget"]["exceeded"]
    for entry in ledger["entries"]:
        assert entry["detect_duration_ms"] is not None and entry["lifecycle_events"]
        elapsed = [event["elapsed_ms"] for event in entry["lifecycle_events"]]
        assert elapsed == sorted(elapsed)
        if entry["selection"] == "selected":
            assert entry["execution"] == "succeeded" and entry["analysis_duration_ms"] is not None
            assert entry["signal_counts"] is not None
    return dict(label=label, before=str(before_path), after=str(after_path), before_sha256=sha(before_path), after_sha256=sha(after_path),
        whole_report_equal_excluding_three_identical_ledgers=True, report_manifest_ledger_equal=True,
        routes=len(after["scan"]["routes"]), findings=len(after["findings"]), ledger=ledger)


def comparison(native_label):
    rows = [compare("source Automatic", WORK / "source-baseline-juice", WORK / "source-final-juice"),
            compare("frozen Automatic", WORK / "baseline-juice", WORK / "frozen-qualification/reports"),
            compare("native Node profile", ROOT / ".tmp/wp042-sol-ultra-20261023-batch2/native-final-run4/reports", WORK / native_label / "reports")]
    save("juice-shop-verification.json", dict(passed=True, comparisons=rows, engine_sha256=sha(ENGINE),
         normalization="Remove only scan.analyzer_run_ledger and its two identical raw_structured_signals copies from BOTH reports",
         scope="Actual source/frozen/native deterministic scans; provider calls zero; captured analyzer slice excludes concurrent fleet changes"))


if __name__ == "__main__":
    operation = sys.argv[1]
    if operation == "source": source()
    elif operation == "qualify": qualify()
    elif operation == "native": native(sys.argv[2])
    elif operation == "preview": native(sys.argv[2], False)
    elif operation == "compare": comparison(sys.argv[2])
    else: raise SystemExit("Unknown operation")
