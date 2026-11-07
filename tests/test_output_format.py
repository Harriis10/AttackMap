"""``--format`` selects which report artifacts are written; ``--version``
reports the single-sourced package version."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

import attackmap
from attackmap.cli import app
from attackmap.models import AttackPath, Finding, ScanResult
from attackmap.report import write_reports

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _norm(output: str) -> str:
    """Strip ANSI + Rich panel borders and collapse whitespace so error text
    matches regardless of terminal width/colour (as in test_fleet.py)."""
    text = _ANSI.sub("", output)
    text = re.sub(r"[│╭╮╰╯─]", " ", text)
    return " ".join(text.split())

_APP = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return {'id': user_id}\n"
)

# Every report directory also gets the #216 output marker.
MARKER = ".attackmap-output"
# Always written by the pipeline, independent of --format.
MANIFEST = "run-manifest.json"

JSON_ARTIFACTS = {
    MARKER,
    "attackmap-report.json",
    "attackmap-report.sarif",
    "defensive-review.json",
    "review-context-pack.json",
}

SECTION_ARTIFACTS = {
    "scan.json",
    "findings.json",
    "attack_paths.json",
    "attack_surfaces.json",
    "exploitability.json",
    "suppressed_findings.json",
    "artifact-manifest.json",
}

CLI_JSON_ARTIFACTS = JSON_ARTIFACTS | SECTION_ARTIFACTS
MARKDOWN_ARTIFACTS = {
    MARKER,
    "architecture.md",
    "attack-surface.md",
    "defensive-review.md",
    "attackmap-exploitability.md",
    "attackmap-paths.md",
    "attackmap-topology.md",
    "attackmap-paths.dot",
    "attackmap-topology.dot",
}


def _write(tmp_path: Path, output_format: str) -> set[str]:
    write_reports(
        tmp_path,
        ScanResult(root=".", languages=["python"], files_scanned=1),
        "# Architecture",
        "# Attack Surface",
        "# Defensive Review",
        [],
        [Finding(title="Issue", severity="medium", mitigation="m")],
        [AttackPath(name="Path", steps=["Entry: /x"], impact="Impact")],
        output_format=output_format,
    )
    return {p.name for p in tmp_path.iterdir()}


@pytest.mark.parametrize(
    ("output_format", "expected"),
    [
        ("all", JSON_ARTIFACTS | MARKDOWN_ARTIFACTS),
        ("json", JSON_ARTIFACTS),
        ("markdown", MARKDOWN_ARTIFACTS),
    ],
)
def test_write_reports_honors_output_format(
    tmp_path: Path, output_format: str, expected: set[str]
) -> None:
    assert _write(tmp_path, output_format) == expected


def test_write_reports_rejects_unknown_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown output format"):
        _write(tmp_path, "html")


def _repo(root: Path, name: str) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "app.py").write_text(_APP, encoding="utf-8")
    return d


def _flat_generation_exports(out: Path) -> set[str]:
    from attackmap.artifact_publisher import current_generation
    generation = current_generation(out)
    assert generation is not None
    assert {p.name for p in out.iterdir() if p.is_dir()} == {generation.name}
    return {p.name for p in out.iterdir() if p.is_file()} - {"current-generation.json"}


def test_cli_format_json_writes_only_machine_readable(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path, "solo")), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert _flat_generation_exports(out) == CLI_JSON_ARTIFACTS | {MANIFEST}


def test_cli_format_markdown_writes_only_human_readable(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["analyze", str(_repo(tmp_path, "solo")), "-o", str(out), "--format", "markdown"]
    )
    assert result.exit_code == 0, result.output
    assert _flat_generation_exports(out) == MARKDOWN_ARTIFACTS | {MANIFEST, "artifact-manifest.json"}


def test_cli_rejects_unknown_format(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", str(_repo(tmp_path, "solo")), "--format", "html"])
    assert result.exit_code != 0
    assert "--format must be one of: all, markdown, json" in _norm(result.output)


def test_fleet_format_json_skips_markdown_summaries(tmp_path: Path) -> None:
    out = tmp_path / "out"
    a, b = _repo(tmp_path, "svcA"), _repo(tmp_path, "svcB")
    result = runner.invoke(app, ["analyze", str(a), str(b), "-o", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-summary.json").exists()
    assert not (out / "fleet-summary.md").exists()
    assert not (out / "fleet-graph.md").exists()
    from attackmap.artifact_publisher import current_generation
    parent = current_generation(out)
    assert parent is not None
    child = current_generation(parent / "svca")
    assert child is not None
    assert (child / "attackmap-report.json").is_file()
    assert {p.name for p in (out / "svca").iterdir() if p.is_file()} == (CLI_JSON_ARTIFACTS | {MANIFEST}) - {".attackmap-output"}


def test_fleet_format_markdown_skips_json_summary(tmp_path: Path) -> None:
    out = tmp_path / "out"
    a, b = _repo(tmp_path, "svcA"), _repo(tmp_path, "svcB")
    result = runner.invoke(app, ["analyze", str(a), str(b), "-o", str(out), "--format", "markdown"])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-summary.md").exists()
    assert (out / "fleet-graph.md").exists()
    assert not (out / "fleet-summary.json").exists()


def test_cli_run_id_is_written_to_artifact_manifest(tmp_path: Path) -> None:
    out = tmp_path / "out"
    run_id = "cli-run-abc-123"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(_repo(tmp_path, "solo")),
            "-o",
            str(out),
            "--format",
            "json",
            "--run-id",
            run_id,
        ],
    )
    assert result.exit_code == 0, result.output
    manifest_path = out / "artifact-manifest.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["generation_id"] == run_id


def test_version_flag_prints_package_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert result.output.strip() == f"attackmap {attackmap.__version__}"


def test_version_is_single_sourced() -> None:
    pyproject = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = pyproject["project"]
    assert "version" not in project, "version must come from attackmap.__version__ only"
    assert "version" in project["dynamic"]
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "attackmap.__version__"}
    assert re.fullmatch(r"\d+\.\d+\.\d+", attackmap.__version__)
