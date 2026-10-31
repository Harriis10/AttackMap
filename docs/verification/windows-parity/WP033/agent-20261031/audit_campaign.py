"""Validate retained WP033 records and bind the result to current source bytes."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[5]
OUT = ROOT / "artifacts/wp033-mutation-campaign-20261031/final"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def junit(path: Path) -> dict:
    suite = ET.parse(path).getroot()
    cases = suite.findall(".//testcase")
    skipped = [case for case in cases if case.find("skipped") is not None]
    failures = [case for case in cases if case.find("failure") is not None]
    errors = [case for case in cases if case.find("error") is not None]
    return {"tests": len(cases), "passed": len(cases) - len(skipped) - len(failures) - len(errors),
        "skipped": len(skipped), "failures": len(failures), "errors": len(errors),
        "expected_failures": [{"name": case.attrib["name"], "message": case.find("skipped").attrib.get("message")}
            for case in skipped if case.find("skipped").attrib.get("type") == "pytest.xfail"],
        "seconds": sum(float(node.attrib.get("time", 0)) for node in suite.findall("testsuite")),
        "sha256": sha(path)}


def main() -> None:
    paths = sorted((OUT / "sequences").glob("sequence-*.json"))
    rows = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    assert len(rows) == 100
    assert {row["sequence"] for row in rows} == set(range(100))
    assert all(row["seed"] == 2026103100 + row["sequence"] and row["status"] == "PASS" for row in rows)
    assert all(len(row["mutations"]) == 3 and len(row["checkpoints"]) == 6 for row in rows)
    points = [point for row in rows for point in row["checkpoints"]]
    assert len(points) == 600
    assert all(point["full_sha256"] == point["incremental_sha256"] for point in points)
    assert all(point["findings"] and point["observations"] and point["scanned_files"] for point in points)
    assert all(not point["incremental_extractor_calls"] for point in points if point["checkpoint"] in {"warm", "final-warm"})
    mutations = [point for point in points if "mutation" in point]
    assert len(mutations) == 300
    kinds = Counter(point["mutation"]["kind"] for point in mutations)
    assert set(kinds) == {"edit", "add", "rename", "delete", "dependency", "config", "policy", "analyzer_upgrade", "corruption"}
    for point in mutations:
        if point["mutation"]["kind"] in {"policy", "analyzer_upgrade", "corruption"}:
            assert point["incremental_extractor_calls"]
    corruption = Counter(point["mutation"]["corruption"] for point in mutations if point["mutation"]["kind"] == "corruption")
    assert set(corruption) == {"truncated_json", "foreign_schema", "bad_checksum", "invalid_payload"}
    campaign, regression = junit(OUT / "campaign.xml"), junit(OUT / "regression.xml")
    assert campaign["passed"] == 100 and campaign["skipped"] == campaign["failures"] == campaign["errors"] == 0
    assert regression["failures"] == regression["errors"] == 0 and len(regression["expected_failures"]) == 1
    gap = json.loads((OUT / "phases/phase-excerpt-transient-open-gap.json").read_text(encoding="utf-8"))
    assert gap["snapshot_raw_source_sha256"] != gap["captured_live_source_sha256"]
    assert gap["published_snapshot"]["verification"]["state"] == "verified"
    assert "incomplete" not in gap["published_snapshot"]
    owned = [ROOT / "tests/test_wp033_mutation_campaign.py", ROOT / "tests/test_wp033_mutation_phases.py", Path(__file__)]
    source_paths = sorted((ROOT / "src/attackmap").rglob("*.py")) + owned
    source = {path.relative_to(ROOT).as_posix(): sha(path) for path in source_paths}
    (OUT / "source-sha256.json").write_text(json.dumps(source, indent=2) + "\n", encoding="utf-8")
    evidence_paths = paths + sorted((OUT / "phases").glob("*.json")) + [OUT / "campaign.xml", OUT / "regression.xml", OUT / "source-sha256.json"]
    evidence = {path.relative_to(ROOT).as_posix(): sha(path) for path in evidence_paths}
    (OUT / "evidence-sha256.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    summary = {"status": "SOURCE_MUTATION_CAMPAIGN_PASS_WITH_OPEN_EXCERPT_BINDING_GAP",
        "sequence_count": len(rows), "mutation_count": len(mutations), "comparison_count": len(points),
        "actual_scan_runs": 2 * len(points), "mandatory_warm_reuse_checks": 200,
        "mutation_families": dict(sorted(kinds.items())), "corruption_modes": dict(sorted(corruption.items())),
        "runtime_engine_identity_count": len({row["runtime_engine_identity"] for row in rows}),
        "findings_per_comparison": {"min": min(point["findings"] for point in points), "max": max(point["findings"] for point in points)},
        "observations_per_comparison": {"min": min(point["observations"] for point in points), "max": max(point["observations"] for point in points)},
        "campaign_junit": campaign, "focused_regression_junit": regression,
        "provider_calls": 0, "platform": platform.platform(), "python": sys.version,
        "source_manifest_sha256": sha(OUT / "source-sha256.json"), "evidence_manifest_sha256": sha(OUT / "evidence-sha256.json"),
        "scope": "Actual deterministic built-in analysis, whole-repository passes and finding translation in disposable repositories; no external plugin installation.",
        "analyzer_upgrade_qualification": "Disposable physical source-byte identity mutation plus actual declared built-in producer version change. Changed running extractor semantics and installed/frozen upgrade acceptance are not proven by this campaign.",
        "phases": {"capture": "PASS pinned read bytes; persistent drift incomplete", "detection": "PASS pinned analyzer/whole-repo outputs; persistent drift incomplete",
            "publication": "PASS mutation after scan.json write becomes incomplete", "excerpt_after_capture": "PASS immutable spans; persistent drift incomplete",
            "excerpt_before_capture": "LIVE bytes, not snapshot-pinned; persistent drift incomplete", "excerpt_transient_revert": "KNOWN GAP; strict expected failure, not acceptance"},
        "open_gates": ["whole WP033", "excerpt/snapshot byte binding", "installed plugin upgrade", "final source/frozen/native round-trip", "C34 20 repetitions/mode on documented reference platform", "release/clean-host/unsupported-OS"]}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
