"""Evidence comparison must ignore clocks without hiding semantic changes."""
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest


_SPEC = importlib.util.spec_from_file_location(
    "wp018_closeout_verifier", Path(__file__).resolve().parents[1] / "tools/verify_wp018_closeout.py"
)
verifier = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(verifier)


@pytest.fixture
def scan():
    return {"root": "C:/fixtures/service", "routes": [{"path": "/health"}],
            "analyzer_run_ledger": {"entries": [{
                "name": "config", "version": "1", "execution_mode": "isolated",
                "detect_duration_ms": 1.0, "analysis_duration_ms": 2.0,
                "provenance": {"implementation_sha256": "abc", "elapsed_ms": 8},
                "lifecycle_events": [{"state": "started", "elapsed_ms": 0},
                                     {"state": "completed", "elapsed_ms": 3}],
            }]}}


def test_only_ledger_clocks_are_normalized_without_mutating_input(scan):
    before = deepcopy(scan)
    alternate = deepcopy(scan)
    row = alternate["analyzer_run_ledger"]["entries"][0]
    row["detect_duration_ms"], row["analysis_duration_ms"] = 12, 30
    row["lifecycle_events"][1]["elapsed_ms"] = 55
    assert verifier.scan_semantics(scan) == verifier.scan_semantics(alternate)
    assert scan == before


@pytest.mark.parametrize("change", ["origin", "clock_shaped_provenance", "state", "missing_event", "missing_analyzer", "route"])
def test_semantic_tamper_survives_normalization(scan, change):
    altered = deepcopy(scan)
    row = altered["analyzer_run_ledger"]["entries"][0]
    if change == "origin":
        row["provenance"]["implementation_sha256"] = "different"
    elif change == "clock_shaped_provenance":
        row["provenance"]["elapsed_ms"] = 99
    elif change == "state":
        row["lifecycle_events"][1]["state"] = "failed"
    elif change == "missing_event":
        row["lifecycle_events"].pop()
    elif change == "missing_analyzer":
        altered["analyzer_run_ledger"]["entries"].clear()
    else:
        altered["routes"][0]["path"] = "/admin"
    assert verifier.scan_semantics(altered) != verifier.scan_semantics(scan)


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), True, "1"])
def test_invalid_clock_cannot_be_hidden(scan, value):
    scan["analyzer_run_ledger"]["entries"][0]["analysis_duration_ms"] = value
    with pytest.raises(ValueError, match="Invalid ledger clock"):
        verifier.scan_semantics(scan)


def test_reversed_lifecycle_clock_rejected(scan):
    scan["analyzer_run_ledger"]["entries"][0]["lifecycle_events"][0]["elapsed_ms"] = 10
    with pytest.raises(ValueError, match="Reversed lifecycle clocks"):
        verifier.scan_semantics(scan)


def test_missing_and_unknown_clock_remain_distinct(scan):
    unknown = deepcopy(scan)
    missing = deepcopy(scan)
    unknown["analyzer_run_ledger"]["entries"][0]["analysis_duration_ms"] = None
    del missing["analyzer_run_ledger"]["entries"][0]["analysis_duration_ms"]
    assert verifier.scan_semantics(unknown) != verifier.scan_semantics(missing)


def _report(scan):
    return {"scan": deepcopy(scan),
            "defensive_review_json": {"raw_structured_signals": {"scan": deepcopy(scan)}},
            "review_context_pack": {"attackmap_review_json": {
                "raw_structured_signals": {"scan": deepcopy(scan)}}}}


def test_report_normalizes_exact_copies_without_hiding_independent_copy_tamper(scan):
    first, alternate = _report(scan), _report(scan)
    copies = [alternate["scan"], alternate["defensive_review_json"]["raw_structured_signals"]["scan"],
              alternate["review_context_pack"]["attackmap_review_json"]["raw_structured_signals"]["scan"]]
    for copy in copies:
        copy["analyzer_run_ledger"]["entries"][0]["analysis_duration_ms"] = 20
    assert verifier.report_semantics(first) == verifier.report_semantics(alternate)
    alternate["defensive_review_json"]["raw_structured_signals"]["scan"]["routes"][0]["path"] = "/other"
    with pytest.raises(ValueError, match="Embedded structured scan differs"):
        verifier.report_semantics(alternate)


def test_report_rejects_internally_inconsistent_clocks_before_normalizing(scan):
    report = _report(scan)
    report["defensive_review_json"]["raw_structured_signals"]["scan"]["analyzer_run_ledger"]["entries"][0]["analysis_duration_ms"] = 30
    with pytest.raises(ValueError, match="Embedded structured scan differs"):
        verifier.report_semantics(report)


@pytest.mark.parametrize("change", ["duplicate_summary", "missing_graph", "duplicate_graph"])
def test_parent_repository_rows_require_exact_cardinality(monkeypatch, change):
    generation = Path(__file__).parent
    children = [{"slug": slug, "root": str(generation / "fixtures" / slug)} for slug in ("one", "two")]
    rows = [{"repo_id": child["slug"], "root": child["root"],
             "report_dir": str(generation / child["slug"])} for child in children]
    summary = {"repo_count": 2, "failed": [], "repos": deepcopy(rows),
               "fleet_architecture": {"repositories": deepcopy(rows)}}
    if change == "duplicate_summary":
        summary["repos"].append(deepcopy(rows[0]))
    elif change == "missing_graph":
        summary["fleet_architecture"]["repositories"].clear()
    else:
        summary["fleet_architecture"]["repositories"] = [deepcopy(rows[0]), deepcopy(rows[0])]
    monkeypatch.setattr(verifier, "read", lambda _: summary)
    with pytest.raises(ValueError):
        verifier.parent_semantics(generation, children)
