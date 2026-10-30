from __future__ import annotations

import json

import pytest

from attackmap import analyzers as registry
from attackmap.analyzer_contracts import AnalyzerMetadata
from attackmap.models import ScanResult
from attackmap.pipeline import AnalyzeOptions, TimeBudget, run_scan


class CountingPlugin:
    def __init__(self, name="counting", *, enabled=True, detection=True, failure=False):
        self.name = name
        self.metadata = AnalyzerMetadata(name=name, version="1.2.3", enabled_by_default=enabled)
        self.detection = detection
        self.failure = failure
        self.detect_calls = 0
        self.analysis_calls = 0

    def detect(self, root):
        self.detect_calls += 1
        if isinstance(self.detection, Exception):
            raise self.detection
        return self.detection and self.detect_calls == 1

    def analyze(self, root):
        self.analysis_calls += 1
        if self.failure:
            raise RuntimeError("PIPELINE_LEDGER_PRIVATE C:/private/source.py")
        return ScanResult(root=str(root), scanned_files=["app.py"], files_scanned=1)


def _run(tmp_path, *, plugins, monkeypatch, explicit=True, profile_id=None):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(registry, "get_registered_analyzers", lambda: plugins)
    output = tmp_path / "reports"
    state = run_scan(AnalyzeOptions(repo_path=repo, output=output, analyzers=plugins if explicit else None,
        analyzer_profile_id=profile_id, atomic_output=False, output_format="json", no_suppress=True,
        no_progress=True, progress_format="none", echo=lambda *args, **kwargs: None))
    report = json.loads((output / "attackmap-report.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    return state, report, manifest


def test_pipeline_detects_once_and_report_manifest_share_observed_outcomes(tmp_path, monkeypatch):
    plugin = CountingPlugin()
    state, report, manifest = _run(tmp_path, plugins=[plugin], monkeypatch=monkeypatch, profile_id="python@1")
    ledger = report["scan"]["analyzer_run_ledger"]

    assert plugin.detect_calls == plugin.analysis_calls == 1
    assert ledger == manifest["analyzer_run_ledger"] == state.scan.analyzer_run_ledger.model_dump(mode="json")
    assert ledger["profile_id"] == "python@1" and ledger["selection_mode"] == "explicit"
    assert ledger["entries"][0]["execution"] == "succeeded"
    assert ledger["schema_version"] == "1.1"
    assert ledger["entries"][0]["detect_duration_ms"] >= 0
    assert ledger["entries"][0]["analysis_duration_ms"] >= 0
    assert ledger["entries"][0]["signal_counts"]["routes"] == 0
    assert manifest["analyzers"] == [{"name": "counting", "version": "1.2.3"}]


def test_pipeline_preserves_automatic_skips_and_detect_error_without_claiming_success(tmp_path, monkeypatch):
    plugins = [CountingPlugin("opt-in", enabled=False), CountingPlugin("unmatched", detection=False),
               CountingPlugin("detect-error", detection=ValueError("PIPELINE_LEDGER_PRIVATE")), CountingPlugin("good")]
    state, report, manifest = _run(tmp_path, plugins=plugins, monkeypatch=monkeypatch, explicit=False)
    ledger = manifest["analyzer_run_ledger"]
    rows = {row["name"]: row for row in ledger["entries"]}

    assert [item.name for item in state.analyzers] == ["good"]
    assert rows["good"]["execution"] == "succeeded"
    assert rows["opt-in"]["skip_reason"] == "opt_in"
    assert rows["unmatched"]["applicability"] == "unmatched"
    assert rows["detect-error"]["applicability"] == "detect_error"
    assert all(item.analysis_calls == (1 if item.name == "good" else 0) for item in plugins)
    assert all(item.detect_calls == 1 for item in plugins)
    assert "PIPELINE_LEDGER_PRIVATE" not in json.dumps(ledger)


def test_all_unmatched_publishes_decisions_and_retains_empty_legacy_selected_list(tmp_path, monkeypatch):
    plugin = CountingPlugin(detection=False)
    state, report, manifest = _run(tmp_path, plugins=[plugin], monkeypatch=monkeypatch)
    assert state.analyzers == [] and manifest["analyzers"] == []
    assert manifest["analyzer_run_ledger"]["entries"][0]["execution"] == "skipped"
    assert manifest["analyzer_run_ledger"]["execution_complete"] is True
    assert plugin.detect_calls == 1 and plugin.analysis_calls == 0


def test_selected_analysis_failure_remains_failed_in_both_artifacts(tmp_path, monkeypatch):
    plugin = CountingPlugin(failure=True)
    state, report, manifest = _run(tmp_path, plugins=[plugin], monkeypatch=monkeypatch)
    row = manifest["analyzer_run_ledger"]["entries"][0]
    assert row["selection"] == "selected" and row["execution"] == "failed"
    assert row["analysis_started"] is True
    assert report["scan"]["analyzer_run_ledger"] == manifest["analyzer_run_ledger"]
    assert len(manifest["analyzers"]) == 1
    assert "PIPELINE_LEDGER_PRIVATE" not in json.dumps(manifest["analyzer_run_ledger"])


def test_deadline_before_scan_records_selected_but_unexecuted_analyzer(tmp_path, monkeypatch):
    def deadline(self, stage):
        if stage == "scan_and_merge" or self.exceeded_stage is not None:
            self.exceeded_stage = self.exceeded_stage or stage
            return True
        return False
    monkeypatch.setattr(TimeBudget, "check", deadline)
    plugin = CountingPlugin()
    state, report, manifest = _run(tmp_path, plugins=[plugin], monkeypatch=monkeypatch)
    row = manifest["analyzer_run_ledger"]["entries"][0]
    assert plugin.detect_calls == 1 and plugin.analysis_calls == 0
    assert row["selection"] == "selected" and row["execution"] == "skipped"
    assert row["skip_reason"] == "pipeline_deadline" and row["analysis_started"] is False
    assert row["analysis_duration_ms"] is None and row["signal_counts"] is None
    assert row["lifecycle_events"][-1]["state"] == "skipped"
    assert report["scan"]["analyzer_run_ledger"] == manifest["analyzer_run_ledger"]


@pytest.mark.parametrize("selection_failure", [True, False])
def test_selection_progress_exists_before_detection_and_stops_on_failure(tmp_path, monkeypatch, selection_failure):
    class Progress:
        def __init__(self):
            self.labels = []
            self.done_calls = 0
        def stage(self, label):
            self.labels.append(label)
        def begin(self, *args, **kwargs):
            pass
        def advance(self, *args, **kwargs):
            pass
        def done(self):
            self.done_calls += 1
    progress = Progress()
    monkeypatch.setattr("attackmap.pipeline.create_progress", lambda *args, **kwargs: progress)
    if selection_failure:
        def unavailable(*args, **kwargs):
            progress.stage("Analyzer discovery started")
            raise ValueError("PIPELINE_LEDGER_PRIVATE")
        monkeypatch.setattr("attackmap.pipeline.resolve_run_analyzers", unavailable)
        with pytest.raises(ValueError, match="PIPELINE_LEDGER_PRIVATE"):
            _run(tmp_path, plugins=[CountingPlugin()], monkeypatch=monkeypatch)
        assert progress.labels == ["Analyzer discovery started"]
    else:
        _run(tmp_path, plugins=[CountingPlugin()], monkeypatch=monkeypatch)
        assert progress.labels[:3] == ["Analyzer counting detect started", "Analyzer counting detect applicable", "Analyzer counting selected"]
        assert "Analyzer counting analysis started" in progress.labels
    assert progress.done_calls == 1
    assert "PIPELINE_LEDGER_PRIVATE" not in json.dumps(progress.labels)
