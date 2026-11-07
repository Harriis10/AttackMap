"""Parent publication must preserve a valid previous fleet on failure/cancel."""
from pathlib import Path

import pytest

from artifact_fixture import write_generation
from attackmap.artifact_publisher import current_generation, validate_generation
from attackmap.models import ScanResult
from attackmap.pipeline import RunState
from attackmap.scan_service import ScanRequest, execute_scan_request


@pytest.fixture
def fleet_inputs(tmp_path, monkeypatch):
    repos = [tmp_path / "service-a", tmp_path / "service-b"]
    for repo in repos:
        repo.mkdir()
    failed = set()
    def fake_scan(options, **kwargs):
        if options.repo_path.name in failed:
            raise RuntimeError("injected sibling failure")
        scan = ScanResult(root=str(options.repo_path))
        write_generation(options.output, {"scan": scan.model_dump(mode="json")})
        return RunState(options=options, scan=scan)
    monkeypatch.setattr("attackmap.pipeline._run_scan", fake_scan)
    return tmp_path / "reports", repos, failed


def request(base, repos, run_id, **kwargs):
    return ScanRequest(repo_paths=repos, output=base, run_id=run_id,
                       echo=lambda *args, **kwargs: None, **kwargs)


def test_failed_sibling_preserves_previous_parent_and_compatibility_summary(fleet_inputs):
    base, repos, failed = fleet_inputs
    old_summary = execute_scan_request(request(base, repos, "old"))
    assert old_summary.exit_code == 0
    old = current_generation(base)
    previous_flat = (base / "fleet-summary.json").read_bytes()
    failed.add("service-b")
    summary = execute_scan_request(request(base, repos, "new"))
    assert summary.exit_code == 1
    assert current_generation(base) == old
    validate_generation(old)
    assert (base / "fleet-summary.json").read_bytes() == previous_flat
    assert summary.fleet_summary_path.parent == base / "new"
    assert (base / "diagnostics" / "new" / "terminal-diagnostic.json").is_file()


def test_export_failure_does_not_return_stale_flat_summary(fleet_inputs, monkeypatch):
    base, repos, _ = fleet_inputs
    execute_scan_request(request(base, repos, "old"))
    previous_flat = (base / "fleet-summary.json").read_bytes()
    def fail_export(*args, **kwargs):
        raise OSError("injected export failure")
    monkeypatch.setattr("attackmap.artifact_publisher.export_compatibility", fail_export)
    summary = execute_scan_request(request(base, repos, "new"))
    assert summary.exit_code == 0
    assert current_generation(base) == base / "new"
    assert summary.fleet_summary_path.parent == base / "new"
    assert (base / "fleet-summary.json").read_bytes() == previous_flat
    assert not (base / "diagnostics" / "new" / "terminal-diagnostic.json").exists()


def test_cancel_racing_parent_publication_is_cancelled_not_failed(fleet_inputs, monkeypatch):
    from attackmap.artifact_publisher import publish_generation
    base, repos, _ = fleet_inputs
    execute_scan_request(request(base, repos, "old"))
    cancelled = False
    def racing_publish(output_base, run_id, **kwargs):
        nonlocal cancelled
        if Path(output_base) == base:
            cancelled = True
        return publish_generation(output_base, run_id, **kwargs)
    monkeypatch.setattr("attackmap.artifact_publisher.publish_generation", racing_publish)
    summary = execute_scan_request(request(base, repos, "new", cancel_check=lambda: cancelled))
    assert summary.exit_code == 130
    assert current_generation(base) == base / "old"
    import json
    diagnostic = json.loads((base / "diagnostics" / "new" / "terminal-diagnostic.json").read_text())
    assert diagnostic["state"] == "cancelled"


def test_atomic_single_result_never_falls_back_to_stale_flat_report(fleet_inputs, monkeypatch):
    base, repos, _ = fleet_inputs
    execute_scan_request(request(base, repos[:1], "old"))
    old_flat = (base / "attackmap-report.json").read_bytes()
    def corrupt_after_commit(output_base, folder, **kwargs):
        (folder / "findings.json").write_text("corrupted after commit")
        raise OSError("export interrupted")
    monkeypatch.setattr("attackmap.artifact_publisher.export_compatibility", corrupt_after_commit)
    summary = execute_scan_request(request(base, repos[:1], "new"))
    assert current_generation(base) is None
    assert (base / "attackmap-report.json").read_bytes() == old_flat
    assert summary.report_path is None
