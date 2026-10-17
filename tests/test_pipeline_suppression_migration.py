"""End-to-end CLI proof that baseline migration aliases keep legacy
title-id suppressions applying after the C13 identity migration (AM014)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.finding_identity import finding_id, legacy_finding_id

runner = CliRunner()

_APP = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return {'id': user_id}\n"
)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "app.py").write_text(_APP, encoding="utf-8")
    return repo


def test_baseline_alias_keeps_legacy_suppression_applied(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    first_out = tmp_path / "first"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(first_out), "--format", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads((first_out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert report["findings"], "fixture repo must produce at least one finding"
    finding = report["findings"][0]

    # Pre-migration baseline: same rule/title, but the recorded id is the
    # legacy title hash instead of the stable rule-entity id.
    stable_id = finding_id(finding)
    legacy_id = legacy_finding_id(finding["title"])
    assert legacy_id != stable_id, "fixture must exercise the migration path"
    baseline = json.loads(json.dumps(report))
    baseline["findings"] = [
        {**f, "id": legacy_id if f is finding else finding_id(f)} for f in baseline["findings"]
    ]
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

    suppress_path = tmp_path / "suppress.yaml"
    suppress_path.write_text(
        f"suppress:\n  - id: {legacy_id}\n    reason: accepted risk, tracked in TICKET-7\n    owner: appsec\n",
        encoding="utf-8",
    )

    second_out = tmp_path / "second"
    result = runner.invoke(
        app,
        [
            "analyze", str(repo), "-o", str(second_out), "--format", "json",
            "--baseline", str(baseline_path), "--suppress-file", str(suppress_path),
        ],
    )
    assert result.exit_code == 0, result.output
    migrated = json.loads((second_out / "attackmap-report.json").read_text(encoding="utf-8"))
    suppressed_rules = {s["rule_id"] for s in migrated["suppressed_findings"]}
    assert finding["rule_id"] in suppressed_rules, (
        "legacy title-id suppression must keep applying through the baseline alias"
    )
    assert finding["rule_id"] not in {f["rule_id"] for f in migrated["findings"]}, (
        "the suppressed finding must not stay active"
    )
    assert "TICKET-7" in json.dumps(migrated["suppressed_findings"])


def test_unaliased_legacy_suppression_stays_visible(tmp_path: Path) -> None:
    """Without a matching baseline record, the legacy id gains no alias and the
    finding honestly reappears as active (never a guessed match)."""
    repo = _repo(tmp_path)
    first_out = tmp_path / "first"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(first_out), "--format", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads((first_out / "attackmap-report.json").read_text(encoding="utf-8"))
    finding = report["findings"][0]
    stale_id = legacy_finding_id("Some unrelated historical title")

    suppress_path = tmp_path / "suppress.yaml"
    suppress_path.write_text(
        f"suppress:\n  - id: {stale_id}\n    reason: stale reference\n",
        encoding="utf-8",
    )

    second_out = tmp_path / "second"
    result = runner.invoke(
        app,
        [
            "analyze", str(repo), "-o", str(second_out), "--format", "json",
            "--suppress-file", str(suppress_path),
        ],
    )
    assert result.exit_code == 0, result.output
    migrated = json.loads((second_out / "attackmap-report.json").read_text(encoding="utf-8"))
    assert finding["rule_id"] in {f["rule_id"] for f in migrated["findings"]}, (
        "unrelated legacy id must not suppress the current finding"
    )
