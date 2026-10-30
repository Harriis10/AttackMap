from __future__ import annotations

from copy import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from attackmap import analyzers as registry
from attackmap.analyzer_contracts import AnalyzerMetadata
from attackmap.analyzer_host import HOST_INPUT_INVALID, HOST_TIMEOUT, IsolatedOutcome
from attackmap.analyzer_run_ledger import AnalyzerLifecycleEvent, AnalyzerRunLedger, analyzer_run_identity
from attackmap.models import Route, ScanResult


PRIVATE = "LEDGER_PRIVATE_SOURCE token=unknown C:/private/source.py"


class Plugin:
    def __init__(self, name="example", *, priority=20, enabled=True, detection=True, failure=None):
        self.name = name
        self.metadata = AnalyzerMetadata(name=name, version="2.0.0", priority=priority, enabled_by_default=enabled)
        self.detection = detection
        self.failure = failure
        self.detect_calls = 0
        self.analysis_calls = 0

    def detect(self, root):
        self.detect_calls += 1
        value = self.detection(self.detect_calls) if callable(self.detection) else self.detection
        if isinstance(value, Exception):
            raise value
        return value

    def analyze(self, root):
        self.analysis_calls += 1
        if self.failure is not None:
            raise self.failure
        return ScanResult(root=str(root), routes=[Route(path="/same", method="GET", file="app.py", line=1)])


@pytest.fixture(autouse=True)
def no_whole_repo_passes(monkeypatch):
    monkeypatch.setattr(registry, "run_repo_passes", lambda *args, **kwargs: None)


def test_selection_is_pending_and_flaky_detector_is_not_called_again(tmp_path):
    plugin = Plugin(detection=lambda count: count == 1)
    plan = registry.resolve_analyzer_run(tmp_path, [plugin], profile_id="python@1")
    row = plan.ledger.entries[0]

    assert row.selection == "selected" and row.applicability == "applicable"
    assert row.execution == "not_started" and row.analysis_started is False
    assert row.detect_duration_ms >= 0 and row.analysis_duration_ms is None and row.signal_counts is None
    assert [(event.stage, event.state) for event in row.lifecycle_events] == [
        ("detect", "started"), ("detect", "applicable"), ("selection", "selected")]
    assert plan.ledger.execution_complete is False
    assert plan.ledger.inventory_scope == "supplied_candidates"
    result = registry.analyze_repository(tmp_path, run_plan=plan)

    assert plugin.detect_calls == plugin.analysis_calls == 1
    assert result.analyzer_run_ledger.entries[0].execution == "succeeded"
    assert result.analyzer_run_ledger.profile_id == "python@1"
    assert result.analyzer_run_ledger is not plan.ledger
    assert result.analyzer_run_ledger.execution_complete is True


def test_automatic_decisions_distinguish_opt_in_unmatched_and_detect_error(tmp_path, monkeypatch):
    candidates = [Plugin("opt-in", enabled=False), Plugin("unmatched", detection=False),
                  Plugin("detect-error", detection=ValueError(PRIVATE)), Plugin("good")]
    monkeypatch.setattr(registry, "get_registered_analyzers", lambda: candidates)
    hints = []

    plan = registry.resolve_analyzer_run(tmp_path, opt_in_matches=hints)
    rows = {row.name: row for row in plan.ledger.entries}

    assert [item.name for item in plan.analyzers] == ["good"]
    assert hints == ["opt-in"]
    assert plan.ledger.inventory_scope == "registered_candidates"
    assert (rows["opt-in"].applicability, rows["opt-in"].skip_reason) == ("applicable", "opt_in")
    assert (rows["unmatched"].applicability, rows["unmatched"].skip_reason) == ("unmatched", "unmatched")
    assert rows["detect-error"].applicability == "detect_error"
    assert rows["detect-error"].error.model_dump() == {"stage": "detect", "error_type": "ValueError"}
    assert all(rows[name].selection == "skipped" and rows[name].analysis_started is False for name in ("opt-in", "unmatched", "detect-error"))
    assert PRIVATE not in plan.ledger.model_dump_json()
    assert all(row.detect_duration_ms >= 0 for row in rows.values())
    assert all(rows[name].analysis_duration_ms is None and rows[name].signal_counts is None for name in ("opt-in", "unmatched", "detect-error"))
    assert rows["detect-error"].lifecycle_events[1].error_type == "ValueError"
    assert all(item.detect_calls == 1 for item in candidates)


def test_explicit_opt_in_still_runs_and_public_list_api_is_preserved(tmp_path):
    plugin = Plugin(enabled=False)
    selected = registry.resolve_run_analyzers(tmp_path, analyzers=[plugin])
    assert isinstance(selected, list) and selected == [plugin]
    result = registry.analyze_repository(tmp_path, analyzers=[plugin])
    assert result.analyzer_run_ledger.selection_mode == "explicit"
    assert result.analyzer_run_ledger.entries[0].execution == "succeeded"


def test_analysis_failure_does_not_erase_sibling_success_or_merge_priority(tmp_path):
    early = Plugin("early", priority=0)
    late = Plugin("late", priority=50)
    broken = Plugin("broken", failure=RuntimeError(PRIVATE))
    result = registry.analyze_repository(tmp_path, analyzers=[late, broken, early])
    rows = {row.name: row for row in result.analyzer_run_ledger.entries}

    assert result.routes[0].source_analyzer == "early"
    assert rows["early"].execution == rows["late"].execution == "succeeded"
    assert rows["broken"].selection == "selected" and rows["broken"].execution == "failed"
    assert rows["broken"].analysis_started is True
    assert rows["broken"].error.model_dump() == {"stage": "analysis", "error_type": "RuntimeError"}
    assert rows["broken"].analysis_duration_ms >= 0 and rows["broken"].signal_counts is None
    assert rows["broken"].lifecycle_events[-1].state == "failed"
    assert rows["early"].signal_counts.routes == rows["late"].signal_counts.routes == 1
    assert len(result.routes) == 1  # Per-analyzer extraction counts precede the core merge.
    assert result.analyzer_errors[0].analyzer == "broken"
    assert PRIVATE not in result.analyzer_run_ledger.model_dump_json()
    assert str(tmp_path) not in result.analyzer_run_ledger.model_dump_json()


def test_strict_failure_keeps_pending_siblings_and_never_claims_completion(tmp_path):
    plan = registry.resolve_analyzer_run(tmp_path, [Plugin("broken", priority=0, failure=RuntimeError(PRIVATE)), Plugin("later")])
    with pytest.raises(RuntimeError, match="LEDGER_PRIVATE_SOURCE"):
        registry.analyze_repository(tmp_path, run_plan=plan, strict=True)
    assert [row.execution for row in plan.ledger.entries] == ["failed", "not_started"]
    assert plan.ledger.execution_complete is False
    assert plan.ledger.entries[0].analysis_duration_ms >= 0
    assert plan.ledger.entries[0].lifecycle_events[-1].state == "failed"
    assert plan.ledger.entries[1].analysis_duration_ms is None
    with pytest.raises(ValueError, match="already consumed"):
        registry.analyze_repository(tmp_path, run_plan=plan)


def test_plan_rejects_a_different_capture_even_for_the_same_root(tmp_path):
    plugin = Plugin()
    plan = registry.resolve_analyzer_run(tmp_path, [plugin])
    with pytest.raises(ValueError, match="repository capture"):
        registry.analyze_repository(tmp_path, run_plan=plan, index=copy(plan.index))
    assert plugin.analysis_calls == 0
    result = registry.analyze_repository(tmp_path, run_plan=plan)
    assert result.analyzer_run_ledger.entries[0].execution == "succeeded"
    with pytest.raises(ValueError, match="already consumed"):
        registry.analyze_repository(tmp_path, run_plan=plan)


def test_new_scan_uses_new_detection_instead_of_reusing_previous_plan(tmp_path):
    plugin = Plugin(detection=lambda count: count == 1)
    first = registry.analyze_repository(tmp_path, analyzers=[plugin])
    second = registry.analyze_repository(tmp_path, analyzers=[plugin])
    assert plugin.detect_calls == 2 and plugin.analysis_calls == 1
    assert first.analyzer_run_ledger.entries[0].execution == "succeeded"
    assert second.analyzer_run_ledger.entries[0].applicability == "unmatched"
    assert second.analyzer_run_ledger.entries[0].execution == "skipped"


def test_all_unmatched_is_terminal_without_claiming_any_analysis(tmp_path):
    plugin = Plugin(detection=False)
    result = registry.analyze_repository(tmp_path, analyzers=[plugin])
    assert result.routes == [] and plugin.analysis_calls == 0
    assert result.analyzer_run_ledger.execution_complete is True
    row = result.analyzer_run_ledger.entries[0]
    assert row.selection == "skipped" and row.execution == "skipped" and row.analysis_started is False


@pytest.mark.parametrize("successful", [True, False])
def test_isolated_outcome_distinguishes_host_request_from_analyzer_execution(tmp_path, monkeypatch, successful):
    plugin = Plugin()
    class Bundle:
        def __init__(self, index):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    monkeypatch.setattr("attackmap.snapshot_transport.SnapshotBundle", Bundle)
    calls = []
    def isolated(analyzer, root, **kwargs):
        calls.append(analyzer)
        return (IsolatedOutcome(analyzer=analyzer.name, result=ScanResult(root=str(root))) if successful else
                IsolatedOutcome(analyzer=analyzer.name, error_type=HOST_TIMEOUT, message=PRIVATE))
    monkeypatch.setattr(registry, "run_isolated_analyzer", isolated)

    result = registry.analyze_repository(tmp_path, analyzers=[plugin], isolated_analyzers=True)
    row = result.analyzer_run_ledger.entries[0]

    assert calls == [plugin] and plugin.analysis_calls == 0
    assert row.execution_mode == "isolated"
    assert row.execution == ("succeeded" if successful else "failed")
    assert row.analysis_started is (True if successful else None)
    assert row.analysis_duration_ms >= 0
    assert row.lifecycle_events[-2].state == "requested"
    assert row.lifecycle_events[-1].state == ("succeeded" if successful else "failed")
    assert (row.signal_counts is not None) is successful
    assert PRIVATE not in result.analyzer_run_ledger.model_dump_json()


def test_captured_input_failure_does_not_claim_host_or_analyzer_started(tmp_path, monkeypatch):
    from attackmap.snapshot_transport import SnapshotInputError
    def unavailable(index):
        raise SnapshotInputError(PRIVATE)
    monkeypatch.setattr("attackmap.snapshot_transport.SnapshotBundle", unavailable)
    monkeypatch.setattr(registry, "run_isolated_analyzer", lambda *args, **kwargs: pytest.fail("host must not run"))

    result = registry.analyze_repository(tmp_path, analyzers=[Plugin()], isolated_analyzers=True)
    row = result.analyzer_run_ledger.entries[0]

    assert row.analysis_started is False and row.execution == "failed"
    assert row.error.model_dump() == {"stage": "captured_input", "error_type": HOST_INPUT_INVALID}
    assert row.analysis_duration_ms is None and row.signal_counts is None
    assert [event.state for event in row.lifecycle_events if event.stage == "analysis"] == ["failed"]


def test_actual_discovery_origin_is_retained_without_another_entry_point_load(tmp_path, monkeypatch):
    loads = []
    dist = SimpleNamespace(name="attackmap-analyzer-python", version="9.8.7",
        read_text=lambda name: json.dumps({"url": "file:///private/build.whl", "archive_info": {}}))
    entry = SimpleNamespace(name="python", value="example:Plugin", dist=dist,
        load=lambda: loads.append(True) or Plugin("python"))
    plugin = registry._load_discovered_analyzer(entry)
    monkeypatch.setattr(registry, "entry_points", lambda: pytest.fail("must not rediscover"))

    identity = analyzer_run_identity(plugin)
    result = registry.analyze_repository(tmp_path, analyzers=[plugin])
    row = result.analyzer_run_ledger.entries[0]

    assert loads == [True]
    assert row.origin == "plugin" and row.package == {"name": dist.name, "version": "9.8.7"}
    assert row.implementation_sha256 == identity["implementation_sha256"]
    assert row.provenance["pin_status"] == "unverified"
    assert "private" not in row.model_dump_json() and "source_file" not in row.implementation


def test_supplied_name_collision_never_borrows_builtin_origin(tmp_path):
    result = registry.analyze_repository(tmp_path, analyzers=[Plugin("php-web")])
    row = result.analyzer_run_ledger.entries[0]
    assert row.name == "php-web" and row.origin == "supplied"
    assert row.package is None
    assert row.implementation["qualname"] == "Plugin"


def test_supplied_subclass_is_its_own_implementation_not_builtin_provenance():
    class Customized(registry.BuiltinPythonWebAnalyzer):
        pass
    identity = analyzer_run_identity(Customized())
    assert identity["origin"] == "supplied" and identity["package"] is None
    assert identity["implementation"]["qualname"].endswith("Customized")


def test_plan_rejects_other_repository_and_conflicting_instances_without_consuming(tmp_path):
    plan = registry.resolve_analyzer_run(tmp_path, [Plugin()])
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(ValueError, match="Captured index does not belong"):
        registry.analyze_repository(other, run_plan=plan)
    with pytest.raises(ValueError, match="not both"):
        registry.analyze_repository(tmp_path, run_plan=plan, analyzers=[])
    assert registry.analyze_repository(tmp_path, run_plan=plan).analyzer_run_ledger.execution_complete is True


@pytest.mark.parametrize("declared", [True, False])
def test_metadata_default_version_is_unknown_unless_explicitly_declared(tmp_path, declared):
    plugin = Plugin()
    metadata = {"name": plugin.name, "enabled_by_default": True}
    if declared:
        metadata["version"] = "0.1.0"
    plugin.metadata = AnalyzerMetadata(**metadata)
    result = registry.analyze_repository(tmp_path, analyzers=[plugin])
    assert result.analyzer_run_ledger.entries[0].version == ("0.1.0" if declared else None)


def test_monotonic_timing_order_counts_and_safe_live_progress(tmp_path, monkeypatch):
    from itertools import count
    ticks = count(0, 0.125)
    monkeypatch.setattr("attackmap.analyzer_run_ledger.time.monotonic", lambda: next(ticks))
    class Progress:
        labels = []
        def stage(self, label):
            self.labels.append(label)
        def done(self):
            pass
    progress = Progress()
    result = registry.analyze_repository(tmp_path, analyzers=[Plugin()], progress=progress)
    row = result.analyzer_run_ledger.entries[0]
    assert result.analyzer_run_ledger.schema_version == "1.1"
    assert row.detect_duration_ms == 125.0
    assert row.analysis_duration_ms == 250.0
    assert row.signal_counts.model_dump() == {"routes": 1, "external_calls": 0, "databases": 0, "auth_hints": 0, "secret_hints": 0}
    elapsed = [event.elapsed_ms for event in row.lifecycle_events]
    assert elapsed == sorted(elapsed) and elapsed[0] >= 0
    assert progress.labels == ["Analyzer example detect started", "Analyzer example detect applicable", "Analyzer example selected",
                               "Analyzer example analysis started", "Analyzer example succeeded (250.0 ms)"]
    assert str(tmp_path) not in json.dumps(progress.labels)


def test_legacy_ledger_loads_with_absent_details_and_events_are_bounded(tmp_path):
    plan = registry.resolve_analyzer_run(tmp_path, [Plugin()])
    payload = plan.ledger.model_dump()
    payload["schema_version"] = "1.0"
    row = payload["entries"][0]
    for key in ("detect_duration_ms", "analysis_duration_ms", "signal_counts", "lifecycle_events"):
        row.pop(key)
    restored = AnalyzerRunLedger.model_validate(payload)
    assert restored.schema_version == "1.0"
    assert restored.entries[0].signal_counts is None and restored.entries[0].lifecycle_events == []
    for _ in range(100):
        plan.observe(plan.ledger.entries[0], "analysis", "failed", error_type=PRIVATE)
    assert len(plan.ledger.entries[0].lifecycle_events) == 16
    assert plan.ledger.entries[0].lifecycle_events[-1].error_type == "Exception"


@pytest.mark.parametrize("value", [-1.0, float("inf"), float("nan")])
def test_nonfinite_or_negative_observed_times_are_rejected(value):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        AnalyzerLifecycleEvent(stage="analysis", state="started", elapsed_ms=value)


def test_provenance_failure_is_timed_and_recorded_before_strict_raise(tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise ValueError(PRIVATE)
    monkeypatch.setattr(registry, "_stamp_provenance", broken)
    plan = registry.resolve_analyzer_run(tmp_path, [Plugin()])
    with pytest.raises(ValueError, match="LEDGER_PRIVATE_SOURCE"):
        registry.analyze_repository(tmp_path, run_plan=plan, strict=True)
    row = plan.ledger.entries[0]
    assert row.execution == "failed" and row.analysis_duration_ms >= 0
    assert row.signal_counts is None and row.lifecycle_events[-1].error_type == "ValueError"
    assert PRIVATE not in plan.ledger.model_dump_json()


def test_detection_and_selection_stage_feed_is_ordered_and_private(tmp_path, monkeypatch):
    from io import StringIO
    from attackmap.progress import JsonScanProgress
    candidates = [Plugin("detect-error", detection=ValueError(PRIVATE)), Plugin("good"),
                  Plugin("opt-in", enabled=False), Plugin("unmatched", detection=False)]
    monkeypatch.setattr(registry, "get_registered_analyzers", lambda: candidates)
    stream = StringIO()
    progress = JsonScanProgress(stream=stream)
    plan = registry.resolve_analyzer_run(tmp_path, progress=progress)
    labels = [json.loads(line)["label"] for line in stream.getvalue().splitlines()]
    assert labels == [
        "Analyzer detect-error detect started", "Analyzer detect-error detect failed (ValueError)", "Analyzer detect-error skipped (detect_error)",
        "Analyzer good detect started", "Analyzer good detect applicable", "Analyzer good selected",
        "Analyzer opt-in detect started", "Analyzer opt-in detect applicable", "Analyzer opt-in skipped (opt_in)",
        "Analyzer unmatched detect started", "Analyzer unmatched detect unmatched", "Analyzer unmatched skipped (unmatched)"]
    assert PRIVATE not in stream.getvalue() and str(tmp_path) not in stream.getvalue()
    registry.analyze_repository(tmp_path, run_plan=plan, progress=progress)
    assert all(candidate.detect_calls == 1 for candidate in candidates)
    assert stream.getvalue().count('"event": "done"') == 1
