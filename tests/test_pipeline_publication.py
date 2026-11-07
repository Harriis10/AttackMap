"""Execution success survives a nonauthoritative export failure after commit."""
import json

import pytest

from artifact_fixture import write_generation
from attackmap.artifact_publisher import current_generation, generation_dir, publish_generation, validate_generation
from attackmap.pipeline import AnalyzeOptions, RunState, run_scan
from attackmap.safe_fs import safe_write_text


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_export_failure_keeps_successful_generation_and_policy(tmp_path, monkeypatch, exit_code, error_type):
    base = tmp_path / "reports"
    old = generation_dir(base, "old")
    write_generation(old)
    publish_generation(base, "old")
    warnings = []
    options = AnalyzeOptions(repo_path=tmp_path, output=base, run_id="new",
                             echo=lambda text, **kwargs: warnings.append(text))

    def fake_scan(staged, **kwargs):
        write_generation(staged.output)
        path = staged.output / "artifact-manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["exit_state"] = {"exit_code": exit_code,
                                  "status": "policy_failed" if exit_code else "succeeded"}
        safe_write_text(staged.output, path, json.dumps(manifest))
        return RunState(options=staged, exit_code=exit_code)

    def fail_export(output_base, folder, **kwargs):
        assert current_generation(output_base) == folder
        raise error_type("secret export error detail")

    monkeypatch.setattr("attackmap.pipeline._run_scan", fake_scan)
    monkeypatch.setattr("attackmap.artifact_publisher.export_compatibility", fail_export)
    state = run_scan(options)
    assert state.exit_code == exit_code
    assert state.options is options
    assert current_generation(base) == base / "new"
    validate_generation(old)
    assert state.errors
    assert not list(base.glob("diagnostics/**/terminal-diagnostic.json"))
    assert not (base / "new" / "terminal-diagnostic.json").exists()
    assert warnings
    assert "secret export error detail" not in " ".join(warnings)


@pytest.mark.parametrize("failure", [ValueError("startup"), KeyboardInterrupt()])
def test_failure_diagnostic_has_engine_scan_interval(tmp_path, monkeypatch, failure):
    values = iter(["2026-10-15T10:00:00+00:00", "2026-10-15T10:00:02+00:00"])
    monkeypatch.setattr("attackmap.pipeline._engine_utc_now", lambda: next(values))
    def fail(options, **kwargs):
        raise failure
    monkeypatch.setattr("attackmap.pipeline._run_scan", fail)
    options = AnalyzeOptions(repo_path=tmp_path, output=tmp_path / "out", run_id="failed")
    with pytest.raises(type(failure)):
        run_scan(options)
    doc = json.loads((options.output / "diagnostics/failed/terminal-diagnostic.json").read_text())
    assert doc["scan_timing"] == {
        "schema_version": "1.0", "clock": "engine_utc", "scope": "analysis_pipeline_before_publication",
        "started_at": "2026-10-15T10:00:00+00:00", "finished_at": "2026-10-15T10:00:02+00:00",
        "outcome": "cancelled" if isinstance(failure, KeyboardInterrupt) else "failed"}
    assert current_generation(options.output) is None


def test_publication_failure_preserves_completed_analysis_interval(tmp_path, monkeypatch):
    values = iter(["2026-10-15T10:00:00+00:00", "2026-10-15T10:00:02+00:00"])
    monkeypatch.setattr("attackmap.pipeline._engine_utc_now", lambda: next(values))
    def complete(options, *, state):
        state.finish_scan("completed")
        return state
    def fail(*args):
        raise OSError("publication unavailable")
    monkeypatch.setattr("attackmap.pipeline._run_scan", complete)
    monkeypatch.setattr("attackmap.artifact_publisher.publish_generation", fail)
    options = AnalyzeOptions(repo_path=tmp_path, output=tmp_path / "out", run_id="publish-failed")
    with pytest.raises(OSError):
        run_scan(options)
    doc = json.loads((options.output / "diagnostics/publish-failed/terminal-diagnostic.json").read_text())
    assert doc["state"] == "failed"
    assert doc["scan_timing"]["outcome"] == "completed"
    assert doc["scan_timing"]["finished_at"] == "2026-10-15T10:00:02+00:00"


@pytest.mark.parametrize("cancel", [False, True])
def test_real_pipeline_failure_retains_timing_and_no_current(tmp_path, monkeypatch, cancel):
    def fail_analysis(*args, **kwargs):
        if cancel:
            raise KeyboardInterrupt()
        raise RuntimeError("synthetic analyzer failure")
    monkeypatch.setattr("attackmap.pipeline.analyze_repository", fail_analysis)
    options = AnalyzeOptions(repo_path=tmp_path, output=tmp_path / "out", run_id="analysis-failed", no_progress=True)
    with pytest.raises(KeyboardInterrupt if cancel else RuntimeError):
        run_scan(options)
    doc = json.loads((options.output / "diagnostics/analysis-failed/terminal-diagnostic.json").read_text())
    assert doc["scan_timing"]["started_at"]
    assert doc["scan_timing"]["finished_at"]
    assert doc["scan_timing"]["outcome"] == ("cancelled" if cancel else "failed")
    assert current_generation(options.output) is None


def test_configuration_failure_records_timing_when_output_writable(tmp_path):
    from attackmap.application_errors import AnalysisConfigurationError
    options = AnalyzeOptions(repo_path=tmp_path, output=tmp_path / "out", run_id="invalid", fail_on_new_high=True)
    with pytest.raises(AnalysisConfigurationError):
        run_scan(options)
    doc = json.loads((options.output / "diagnostics/invalid/terminal-diagnostic.json").read_text())
    assert doc["scan_timing"]["outcome"] == "failed"
    assert doc["scan_timing"]["finished_at"]


@pytest.mark.parametrize("fail", [False, True])
def test_optional_ai_tail_precedes_scan_end_timestamp(tmp_path, monkeypatch, fail):
    from types import SimpleNamespace
    (tmp_path / "app.py").write_text("print('synthetic')")
    ai_called = False
    def clock():
        return "2026-10-15T10:00:02+00:00" if ai_called else "2026-10-15T10:00:00+00:00"
    def review(*args, **kwargs):
        nonlocal ai_called
        ai_called = True
        if fail:
            raise RuntimeError("synthetic AI tail failure")
        return SimpleNamespace(markdown="Synthetic model assessment", usage={}, backend="fake", model="fake", stop_reason="stop")
    monkeypatch.setattr("attackmap.pipeline._engine_utc_now", clock)
    monkeypatch.setattr("attackmap.pipeline.generate_llm_review", review)
    options = AnalyzeOptions(repo_path=tmp_path, output=tmp_path / "out", run_id="ai-tail", llm=True, no_progress=True)
    if fail:
        with pytest.raises(RuntimeError):
            run_scan(options)
        doc = json.loads((options.output / "diagnostics/ai-tail/terminal-diagnostic.json").read_text())
    else:
        run_scan(options)
        doc = json.loads((current_generation(options.output) / "run-manifest.json").read_text())
    assert ai_called
    assert doc["scan_timing"]["started_at"] == "2026-10-15T10:00:00+00:00"
    assert doc["scan_timing"]["finished_at"] == "2026-10-15T10:00:02+00:00"
    assert doc["scan_timing"]["outcome"] == ("failed" if fail else "completed")

@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows junction semantics')
def test_atomic_pipeline_rejects_junction_before_stage_or_engine(tmp_path, monkeypatch):
    import os
    import subprocess
    from attackmap.safe_fs import UnsafePathError
    target = tmp_path / 'outside'
    target.mkdir()
    junction = tmp_path / 'junction'
    result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(target)], capture_output=True)
    if result.returncode:
        pytest.skip('Junction creation unavailable')
    monkeypatch.setattr('attackmap.pipeline._run_scan', lambda *_a, **_k: pytest.fail('engine must not start'))
    monkeypatch.setattr('attackmap.artifact_publisher.generation_dir', lambda *_a: pytest.fail('stage must not allocate'))
    try:
        with pytest.raises(UnsafePathError):
            run_scan(AnalyzeOptions(repo_path=tmp_path, output=junction / 'reports'))
        assert list(target.iterdir()) == []
    finally:
        os.rmdir(junction)
