"""CLI baseline, desktop comparison and exported Markdown share coverage policy."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.comparison import compare_report_files
from attackmap.finding_identity import finding_id
from attackmap.models import Finding, FindingLocation, ScanResult
from attackmap.recon_to_analysis import AnalysisOutputs

FIXTURES = Path(__file__).parents[1] / "fixtures" / "desktop-workflows"


@pytest.mark.parametrize("filename,uncertain_count,resolved_count", [
    ("current.json", 0, 1), ("partial-coverage.json", 1, 1),
])
def test_cli_matches_desktop_semantics_and_exports_coverage_notes(tmp_path, monkeypatch, filename, uncertain_count, resolved_count):
    import attackmap.pipeline as pipeline
    from attackmap.artifact_publisher import current_generation

    repo = tmp_path / "repo"
    repo.mkdir()
    baseline = json.loads((FIXTURES / "previous.json").read_text(encoding="utf-8"))
    current = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
    baseline["scan"]["root"] = current["scan"]["root"] = str(repo)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    scan = ScanResult.model_validate(current["scan"])
    findings = [Finding.model_validate(row) for row in [*current["findings"], *current["suppressed_findings"]]]
    monkeypatch.setattr(pipeline, "resolve_run_analyzers", lambda *args, **kwargs: [])
    monkeypatch.setattr(pipeline, "analyze_repository", lambda *args, **kwargs: scan.model_copy(deep=True))
    monkeypatch.setattr(pipeline, "translate_recon", lambda *args, **kwargs: AnalysisOutputs([], findings, []))
    output = tmp_path / "reports"
    pr_path = tmp_path / "pr-comment.md"
    result = CliRunner().invoke(app, ["analyze", str(repo), "--output", str(output),
        "--baseline", str(baseline_path), "--suppress-file", str(FIXTURES / "suppressions.yaml"),
        "--pr-comment", str(pr_path), "--no-progress"])
    assert result.exit_code == 0, result.output
    assert f"{resolved_count} resolved" in result.output
    assert f"{uncertain_count} resolution uncertain" in result.output
    assert "analyzer/config version parity is unknown" in result.output
    generation = current_generation(output)
    semantic = compare_report_files(baseline_path, generation / "attackmap-report.json")
    assert semantic["counts"]["resolved"] == resolved_count
    assert semantic["counts"]["resolution_uncertain"] == uncertain_count
    assert semantic["counts"]["newly_suppressed"] == 1
    markdown = (generation / "attackmap-diff.md").read_text(encoding="utf-8")
    pr = pr_path.read_text(encoding="utf-8")
    for exported in (markdown, pr):
        assert f"**{resolved_count} resolved**" in exported
        assert f"**{uncertain_count} resolution uncertain**" in exported
        assert "analyzer/config version parity is unknown" in exported
    if uncertain_count:
        assert "Resolution uncertain due to changed coverage" in markdown
        assert "Resolution uncertain due to changed coverage" in pr
        assert "not included in current scanned coverage" in pr


def test_real_cli_oversize_skip_does_not_claim_resolution(tmp_path, monkeypatch):
    from attackmap.artifact_publisher import current_generation

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "skipped.py").write_bytes(b"x" * 257)
    finding = Finding(title="Synthetic previous finding in skipped source", rule_id="synthetic-coverage",
        severity="high", mitigation="Synthetic recommendation", locations=[FindingLocation(file="skipped.py", line=1)])
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"scan": {"root": str(repo)}, "findings": [
        {"id": finding_id(finding), **finding.model_dump()}]}))
    monkeypatch.setenv("ATTACKMAP_MAX_FILE_BYTES", "256")
    output, pr = tmp_path / "reports", tmp_path / "pr.md"
    result = CliRunner().invoke(app, ["analyze", str(repo), "--output", str(output),
        "--baseline", str(baseline), "--pr-comment", str(pr), "--no-progress"])
    assert result.exit_code == 0, result.output
    assert "0 resolved" in result.output and "1 resolution uncertain" in result.output
    generation = current_generation(output)
    saved = json.loads((generation / "attackmap-report.json").read_text(encoding="utf-8"))
    assert "skipped.py" not in (saved["scan"]["scanned_files"] or [])
    assert "**0 resolved**" in pr.read_text(encoding="utf-8")
    assert "**1 resolution uncertain**" in pr.read_text(encoding="utf-8")
