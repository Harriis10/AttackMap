import json
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from attackmap.diagnostics import (
    DiagnosticContext, DiagnosticCoverage, DiagnosticResources, context_from_run_manifest,
    fleet_diagnostic, merge_diagnostic_context, scan_diagnostic, startup_diagnostic, unknown_diagnostic,
)
from attackmap.models import ResourceLimitEvent, ScanResult


def event(identity="a", **kwargs):
    return ResourceLimitEvent(event_id=identity * 64, category="file_bytes", producer="repo_index",
                              limit=10, unit="bytes", action="skipped_file", observed_bytes=20, **kwargs)


def test_startup_context_is_unknown_not_zero_and_excludes_requested_text():
    context = startup_diagnostic("select_analyzers", duration_milliseconds=1.25,
                                 requested_analyzers=["SECRET_CANARY/private.py"])
    assert context.stages[0].duration_milliseconds == 1.25
    assert context.coverage.status == context.resource_events.status == "not_started"
    assert context.coverage.accepted_file_count is None
    assert context.analyzers.requested_count == 1 and not context.analyzers.items
    assert "SECRET_CANARY" not in context.model_dump_json()
    assert context.policy_outcome == "not_evaluated"


@pytest.mark.parametrize("metadata", [[None], [42], ["bad"], [{"name": "private/source.py"}], [{"name": None}]])
def test_malformed_metadata_is_partial_without_replacing_failure(metadata):
    context = startup_diagnostic("select_analyzers", analyzer_metadata=metadata)
    assert context.outcome == "failed" and context.analyzers.status == "partial"
    assert not context.analyzers.items


def test_legacy_projection_preserves_fractional_timing_but_never_guesses_versions():
    context = context_from_run_manifest({"stages": [None, {"name": "scan_and_merge", "milliseconds": 1.25}],
        "analyzers": [None, {"name": "python", "version": "1.0"}], "files_scanned": 99}, outcome="failed")
    assert context.stages[0].duration_milliseconds == 1.25
    assert context.analyzers.items[0].version is None
    assert context.coverage.status == "unknown" and context.coverage.accepted_file_count is None


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), True, "2"])
def test_untrusted_timing_is_not_promoted(value):
    context = context_from_run_manifest({"stages": [{"name": "scan_and_merge", "milliseconds": value}]}, outcome="failed")
    assert not context.stages


def test_resources_are_actual_scoped_subset_and_coverage_is_only_enumeration():
    scan = ScanResult(root="private/repo", files_scanned=5, scanned_files=["a.py", "a.py"],
        resource_limit_events=[event()], resource_limit_scopes=["repo_index.file_bytes"], resource_limit_reporting="partial")
    coverage, resources = scan_diagnostic(scan)
    assert coverage.accepted_file_count == 1 and coverage.legacy_files_scanned_count == 5
    assert "not language" in coverage.scope_notice
    assert resources.status == "partial" and resources.items == [event()]
    assert resources.scopes == ["repo_index.file_bytes"]
    assert "other limits remain unknown" in resources.scope_notice
    assert "private" not in resources.model_dump_json()


def test_equal_partial_merge_keeps_events_and_known_numeric_facts():
    first = DiagnosticContext(coverage=DiagnosticCoverage(status="partial", accepted_file_count=5),
        resource_events=DiagnosticResources(status="partial", scopes=["repo_index.file_bytes"], items=[event()]))
    second = DiagnosticContext(coverage=DiagnosticCoverage(status="partial", limitation_count=2),
        resource_events=DiagnosticResources(status="partial", scopes=["repo_index.index_bytes"], items=[event("b")]))
    merged = merge_diagnostic_context(first, second)
    assert merged.coverage.accepted_file_count == 5 and merged.coverage.limitation_count == 2
    assert len(merged.resource_events.items) == 2
    assert set(merged.resource_events.scopes) == {"repo_index.file_bytes", "repo_index.index_bytes"}
    assert len(merge_diagnostic_context(merged, second).resource_events.items) == 2


def test_fleet_keeps_known_child_context_and_unknown_admission():
    scan = ScanResult(root="PRIVATE", scanned_files=["a.py"], files_scanned=1)
    first = fleet_diagnostic(duration_milliseconds=1, outcome="cancelled", requested_count=2,
        children=[{"index": 0, "outcome": "completed", "scan": scan}, {"index": 1, "outcome": "unknown"}])
    assert first.fleet.status == "partial" and first.fleet.completed_count == 1
    assert first.fleet.cancelled_count == 0 and first.coverage.status == "unknown"
    sparse = fleet_diagnostic(duration_milliseconds=2, outcome="cancelled", requested_count=2,
                             children=[{"index": 0, "outcome": "unknown"}])
    merged = merge_diagnostic_context(first, sparse)
    assert merged.fleet.children[0].coverage.accepted_file_count == 1
    assert merged.fleet.children[0].outcome == "completed"
    assert merged.fleet.completed_count == 1
    assert "PRIVATE" not in merged.model_dump_json()


def test_context_schema_fixture_and_additive_outer_legacy_reader():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/diagnostic-context.schema.json").read_text())
    fixture = json.loads((root / "fixtures/diagnostics/startup.json").read_text())
    jsonschema.validate(fixture, schema)
    assert DiagnosticContext.model_validate(fixture).context_version == "1.0"
    from attackmap.artifact_publisher import write_diagnostic
    # Old top-level readers still use schema/run/state/readiness; context is additive.
    outer = {"schema_version": "1.1", "run_id": "one", "state": "failed", "artifact_readiness": "unavailable", "diagnostic_context": fixture}
    assert {key: outer[key] for key in ("schema_version", "run_id", "state", "artifact_readiness")} == {
        "schema_version": "1.1", "run_id": "one", "state": "failed", "artifact_readiness": "unavailable"}
    with pytest.raises(ValidationError):
        DiagnosticContext.model_validate({**fixture, "context_version": "2.0"})


def test_reported_array_truncation_is_disclosed():
    metadata = [{"name": f"analyzer-{i}", "version_status": "unknown"} for i in range(130)]
    context = startup_diagnostic("select_analyzers", analyzer_metadata=metadata)
    assert len(context.analyzers.items) == 128 and context.analyzers.truncated
    assert context.analyzers.status == "partial"


@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.parametrize("atomic", [False, True])
def test_real_pipeline_midstage_failure_retains_actual_stage_and_no_exception_text(tmp_path, monkeypatch, cancel, atomic):
    from attackmap import pipeline
    from attackmap.analyzers import AnalyzerMetadata
    class Analyzer:
        name = "diagnostic-fixture"
        metadata = AnalyzerMetadata(name=name, version="1.2.3")
    def fail(*args, **kwargs):
        raise KeyboardInterrupt("SOURCE_SECRET_SENTINEL") if cancel else RuntimeError("SOURCE_SECRET_SENTINEL")
    monkeypatch.setattr(pipeline, "analyze_repository", fail)
    output = tmp_path / "output"
    with pytest.raises(KeyboardInterrupt if cancel else RuntimeError):
        pipeline.run_scan(pipeline.AnalyzeOptions(repo_path=tmp_path, output=output, run_id="attempt",
            analyzers=[Analyzer()], atomic_output=atomic, echo=lambda *args, **kwargs: None))
    diagnostic = json.loads((output / "diagnostics/attempt/terminal-diagnostic.json").read_text())
    context = DiagnosticContext.model_validate(diagnostic["diagnostic_context"])
    stage = next(stage for stage in context.stages if stage.stage_id == "scan_and_merge")
    assert stage.outcome == ("cancelled" if cancel else "failed") and stage.duration_milliseconds >= 0
    assert context.analyzers.items[0].version == "1.2.3"
    assert context.coverage.accepted_file_count is None and context.policy_outcome == "not_evaluated"
    assert "SOURCE_SECRET_SENTINEL" not in json.dumps(diagnostic)
    assert not (output / "current-generation.json").exists()


def test_real_fake_ai_tail_cancel_is_not_mislabeled_publish(tmp_path, monkeypatch):
    from attackmap import pipeline
    def cancel(*args, **kwargs):
        raise KeyboardInterrupt("AI_SECRET_SENTINEL")
    monkeypatch.setattr(pipeline, "generate_llm_review", cancel)
    (tmp_path / "app.py").write_text("print('local synthetic fixture')\n")
    output = tmp_path / "output"
    with pytest.raises(KeyboardInterrupt):
        pipeline.run_scan(pipeline.AnalyzeOptions(repo_path=tmp_path, output=output, run_id="tail", llm=True,
            echo=lambda *args, **kwargs: None))
    diagnostic = json.loads((output / "diagnostics/tail/terminal-diagnostic.json").read_text())
    stages = diagnostic["diagnostic_context"]["stages"]
    assert any(stage["stage_id"] == "llm" and stage["outcome"] == "cancelled" for stage in stages)
    assert not any(stage["stage_id"] == "publish" and stage["outcome"] == "cancelled" for stage in stages)
    assert "AI_SECRET_SENTINEL" not in json.dumps(diagnostic)


def test_completed_policy_failure_is_not_execution_failure(tmp_path):
    from attackmap.pipeline import AnalyzeOptions, RunState, _diagnostic_context, write_run_manifest
    state = RunState(options=AnalyzeOptions(repo_path=tmp_path, output=tmp_path), exit_code=1)
    state.finish_scan("completed")
    context = _diagnostic_context(state, "completed")
    assert context.outcome == "completed" and context.policy_outcome == "failed"
    write_run_manifest(state, tmp_path)
    stored = json.loads((tmp_path / "run-manifest.json").read_text())["diagnostic_context"]
    assert stored["outcome"] == "completed" and stored["policy_outcome"] == "failed"
    assert not (tmp_path / "diagnostics").exists()


def test_schema_exactly_matches_current_typed_model():
    root = Path(__file__).resolve().parents[1]
    assert json.loads((root / "schemas/diagnostic-context.schema.json").read_text()) == DiagnosticContext.model_json_schema()


def test_actual_policy_threshold_publishes_completed_context(tmp_path):
    from attackmap.pipeline import AnalyzeOptions, run_scan
    from attackmap.artifact_publisher import current_generation, validate_generation
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("from flask import Flask, request\nfrom worker import run\napp=Flask(__name__)\n@app.route('/admin/users', methods=['DELETE'])\ndef delete_user():\n    return run(request.get_json())\n")
    (repo / "worker.py").write_text("def run(payload):\n    return eval(payload['expr'])\n")
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"findings": []}')
    output = tmp_path / "reports"
    state = run_scan(AnalyzeOptions(repo_path=repo, output=output, run_id="policy", baseline=str(baseline),
                                  fail_on_new_high=True, echo=lambda *args, **kwargs: None))
    assert state.exit_code != 0
    generation = current_generation(output)
    assert generation is not None
    validate_generation(generation)
    context = json.loads((generation / "run-manifest.json").read_text())["diagnostic_context"]
    assert context["outcome"] == "completed" and context["policy_outcome"] == "failed"
    assert any(stage["stage_id"] == "publication" and stage["duration_milliseconds"] >= 0 for stage in context["stages"])
    assert not (output / "diagnostics").exists()


def test_terminal_outcome_matrix_distinguishes_execution_failure_degraded_coverage_and_policy(tmp_path, monkeypatch):
    """C15: execution failure, degraded coverage and policy failure are three
    distinguishable terminal outcomes, each with a structured diagnostic
    manifest and no source excerpts or exception text."""
    from attackmap.analyzers import BuiltinPythonWebAnalyzer
    from attackmap.artifact_publisher import current_generation
    from attackmap.pipeline import AnalyzeOptions, run_scan

    echo = lambda *args, **kwargs: None
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")

    # (i) Execution failure: the engine dies inside the scan stage.
    def explode(*args, **kwargs):
        raise RuntimeError("EXECUTION_FAILURE_SENTINEL")
    monkeypatch.setattr("attackmap.pipeline.analyze_repository", explode)
    execution_output = tmp_path / "execution"
    with pytest.raises(RuntimeError):
        run_scan(AnalyzeOptions(repo_path=repo, output=execution_output, run_id="execution", echo=echo))
    monkeypatch.undo()
    execution = json.loads((execution_output / "diagnostics/execution/terminal-diagnostic.json")
                           .read_text(encoding="utf-8"))
    execution_context = execution["diagnostic_context"]
    assert "EXECUTION_FAILURE_SENTINEL" not in json.dumps(execution)
    assert execution_context["outcome"] == "failed"
    assert execution_context["policy_outcome"] == "not_evaluated"
    assert execution_context["coverage"]["accepted_file_count"] is None
    assert any(stage["stage_id"] == "scan_and_merge" and stage["outcome"] == "failed"
               for stage in execution_context["stages"])
    assert current_generation(execution_output) is None  # failure publishes nothing

    # (ii) Degraded coverage: one analyzer fails, the scan still completes.
    class BrokenAnalyzer:
        name = "degraded-fixture"
        metadata = BuiltinPythonWebAnalyzer.metadata.model_copy(update={"name": name})
        def detect(self, root): return True
        def analyze(self, root): raise RuntimeError("DEGRADED_COVERAGE_SENTINEL")
    degraded_output = tmp_path / "degraded"
    degraded_state = run_scan(AnalyzeOptions(repo_path=repo, output=degraded_output, run_id="degraded",
        analyzers=[BrokenAnalyzer(), BuiltinPythonWebAnalyzer()], echo=echo))
    assert degraded_state.exit_code == 0
    degraded_context = json.loads((current_generation(degraded_output) / "run-manifest.json")
                                  .read_text(encoding="utf-8"))["diagnostic_context"]
    assert degraded_context["outcome"] == "completed"
    assert degraded_context["policy_outcome"] == "passed"
    assert degraded_context["coverage"]["status"] == "partial"
    assert degraded_context["coverage"]["analyzer_error_count"] == 1
    assert degraded_context["coverage"]["accepted_file_count"] >= 1
    # The structured diagnostic carries counts, never the analyzer's error text.
    assert "DEGRADED_COVERAGE_SENTINEL" not in json.dumps(degraded_context)

    # (iii) Policy failure: the analysis completes and the gate fails it.
    policy_repo = tmp_path / "policy"
    policy_repo.mkdir()
    (policy_repo / "app.py").write_text("from flask import Flask, request\nfrom worker import run\napp=Flask(__name__)\n@app.route('/admin/users', methods=['DELETE'])\ndef delete_user():\n    return run(request.get_json())\n")
    (policy_repo / "worker.py").write_text("def run(payload):\n    return eval(payload['expr'])\n")
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"findings": []}')
    policy_output = tmp_path / "policy-reports"
    policy_state = run_scan(AnalyzeOptions(repo_path=policy_repo, output=policy_output, run_id="matrix-policy",
        baseline=str(baseline), fail_on_new_high=True, echo=echo))
    assert policy_state.exit_code != 0
    policy_context = json.loads((current_generation(policy_output) / "run-manifest.json")
                                .read_text(encoding="utf-8"))["diagnostic_context"]
    assert policy_context["outcome"] == "completed"
    assert policy_context["policy_outcome"] == "failed"
    assert policy_context["coverage"]["status"] == "complete"
    assert policy_context["coverage"]["analyzer_error_count"] == 0

    assert {(context["outcome"], context["policy_outcome"], context["coverage"]["status"])
            for context in (execution_context, degraded_context, policy_context)} == {
        ("failed", "not_evaluated", "unknown"),
        ("completed", "passed", "partial"),
        ("completed", "failed", "complete")}
