"""Observed producer branches and explicitly scoped resource-limit reporting."""
import itertools
from pathlib import Path

import pytest
from pydantic import ValidationError

from attackmap.models import ResourceLimitEvent, ScanResult
from attackmap.analyzer_contracts import AnalyzerMetadata
from attackmap.index import RepoIndex
from attackmap.scanner import scan_files
from attackmap.config_scanner import scan_config_repo
from attackmap.analyzers import analyze_repository, merge_analyzer_results


def event(relative="a.py", **kwargs):
    return ResourceLimitEvent.skipped_file(producer="repo_index", category="file_bytes", relative=relative, limit=10, observed_bytes=11, **kwargs)


def test_event_is_immutable_opaque_and_stable():
    item = event("credentials-SECRET/žluťoučký.py")
    assert item == event("credentials-SECRET/žluťoučký.py")
    assert item != event("other.py")
    assert "SECRET" not in item.model_dump_json()
    with pytest.raises(ValidationError):
        item.limit = 20
    with pytest.raises(ValidationError):
        ResourceLimitEvent.model_validate({**item.model_dump(), "path": "secret"})


@pytest.mark.parametrize("field,value", [("limit", 0), ("limit", True), ("observed_bytes", -1)])
def test_event_rejects_invented_invalid_measurements(field, value):
    payload = event().model_dump()
    payload[field] = value
    with pytest.raises(ValidationError):
        ResourceLimitEvent.model_validate(payload)


def test_index_file_cap_emits_actual_stat_and_scanner_preserves(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "10")
    (tmp_path / "large.py").write_bytes(b"x" * 11)
    index = RepoIndex.build(tmp_path)
    item, = index.resource_limit_events
    assert (item.category, item.producer, item.limit, item.observed_bytes, item.action) == ("file_bytes", "repo_index", 10, 11, "skipped_file")
    result = scan_files(tmp_path, index=index)
    assert result.resource_limit_events == [item]
    assert result.resource_limit_reporting == "complete"
    assert result.resource_limit_scopes == ["repo_index.file_bytes", "repo_index.index_bytes"]
    assert result.scanned_files == []


def test_aggregate_overflow_does_not_claim_all_later_files_skipped(tmp_path, monkeypatch):
    from attackmap import index as module
    paths = [tmp_path / name for name in ("first.py", "overflow.py", "later.py")]
    for path, size in zip(paths, (4, 8, 2)):
        path.write_bytes(b"x" * size)
    monkeypatch.setattr(module, "walk_repo", lambda *args, **kwargs: iter(paths))
    index = RepoIndex.build(tmp_path, max_bytes=6)
    assert [item.rel for item in index.files] == ["first.py", "later.py"]
    item, = index.resource_limit_events
    assert (item.category, item.limit, item.observed_bytes, item.action) == ("index_bytes", 6, 12, "skipped_file")
    assert "files exceeding the remaining budget skipped" in index.limitations[0]
    assert "remaining files skipped" not in index.limitations[0]


@pytest.mark.parametrize("indexed", [False, True])
def test_config_limit_emits_from_actual_branch(tmp_path, monkeypatch, indexed):
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "100")
    monkeypatch.setattr("attackmap.config_scanner._MAX_CONFIG_BYTES", 10)
    (tmp_path / "config.yaml").write_bytes(b"x" * 11)
    result = scan_config_repo(tmp_path, index=RepoIndex.build(tmp_path) if indexed else None)
    item, = result.resource_limit_events
    assert item.producer == "config_scanner" and item.limit == 10
    assert item.observed_bytes == (None if indexed else 11)
    assert result.scanned_files == []
    assert "config_scanner.file_bytes" in result.resource_limit_scopes


def test_merge_preserves_known_subset_legacy_unknown_permutation_and_inputs():
    known = ScanResult(root=".", resource_limit_events=[event(), event("b.py")], resource_limit_reporting="complete", resource_limit_scopes=["repo_index.file_bytes"])
    duplicate = known.model_copy(deep=True)
    legacy = ScanResult(root=".")
    before = [item.model_dump() for item in (known, duplicate, legacy)]
    outputs = [merge_analyzer_results(order).model_dump() for order in itertools.permutations((known, duplicate, legacy))]
    assert all(output == outputs[0] for output in outputs)
    assert outputs[0]["resource_limit_reporting"] == "partial"
    assert len(outputs[0]["resource_limit_events"]) == 2
    assert [item.model_dump() for item in (known, duplicate, legacy)] == before
    assert merge_analyzer_results([legacy]).resource_limit_reporting == "unknown"
    assert ScanResult.model_validate({"root": "."}).resource_limit_reporting == "unknown"


def test_reported_empty_is_only_complete_with_explicit_scope():
    known = ScanResult(root=".", resource_limit_reporting="complete", resource_limit_scopes=["repo_index.file_bytes"])
    merged = merge_analyzer_results([known])
    assert merged.resource_limit_events == [] and merged.resource_limit_reporting == "complete"
    assert merged.resource_limit_scopes == ["repo_index.file_bytes"]
    assert merge_analyzer_results([known, ScanResult(root=".")]).resource_limit_reporting == "partial"


def test_shared_index_events_survive_legacy_plugin(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "10")
    (tmp_path / "large.py").write_bytes(b"x" * 11)
    class Legacy:
        name = "synthetic-legacy"
        metadata = AnalyzerMetadata(name=name)
        def detect(self, root): return True
        def analyze(self, root): return ScanResult(root=str(root))
    monkeypatch.setattr("attackmap.analyzers.run_repo_passes", lambda *args, **kwargs: None)
    result = analyze_repository(tmp_path, analyzers=[Legacy()])
    assert len(result.resource_limit_events) == 1
    assert result.resource_limit_reporting == "partial"
    assert result.resource_limit_scopes == ["repo_index.file_bytes", "repo_index.index_bytes"]


def test_resource_limit_events_reach_published_diagnostic_context(tmp_path, monkeypatch):
    """A real resource-limited run surfaces its events in the published
    diagnostic manifest without the skipped file's path."""
    import json
    from attackmap.analyzers import BuiltinPythonWebAnalyzer
    from attackmap.artifact_publisher import current_generation
    from attackmap.pipeline import AnalyzeOptions, run_scan
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "100")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PRIVATE-SKIPPED.py").write_bytes(b"x" * 101)
    (repo / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    output = tmp_path / "reports"
    state = run_scan(AnalyzeOptions(repo_path=repo, output=output, run_id="limits",
        analyzers=[BuiltinPythonWebAnalyzer()], echo=lambda *args, **kwargs: None))
    assert state.exit_code == 0
    context = json.loads((current_generation(output) / "run-manifest.json")
                         .read_text(encoding="utf-8"))["diagnostic_context"]
    resources = context["resource_events"]
    assert resources["status"] in {"complete", "partial"}
    assert resources["items"] and resources["items"][0]["producer"] == "repo_index"
    assert resources["items"][0]["action"] == "skipped_file"
    assert "repo_index.file_bytes" in resources["scopes"]
    # Enumeration coverage stays complete (no analyzer errors); the skipped
    # file simply never enters it, and its name never enters the diagnostic.
    assert context["coverage"]["status"] == "complete"
    assert context["coverage"]["accepted_file_count"] == 1
    assert "PRIVATE-SKIPPED" not in json.dumps(context)
