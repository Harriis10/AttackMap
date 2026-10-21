"""Small deterministic checks for the C26 reference generator."""
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path

import pytest

from attackmap.models import Finding, ScanResult

SPEC = importlib.util.spec_from_file_location("desktop_reference", Path(__file__).parents[1] / "tools" / "generate_desktop_reference.py")
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


def test_deterministic_exact_size_canonical_report_and_known_counts():
    raw = generator.build_report(findings=7, observations=11, report_bytes=16_384)
    assert raw == generator.build_report(findings=7, observations=11, report_bytes=16_384)
    assert len(raw) == 16_384 and raw.endswith(b"\n")
    report = json.loads(raw)
    scan = ScanResult.model_validate(report["scan"])
    rows = [Finding.model_validate(row) for row in report["findings"]]
    assert len(rows) == 7 and len(scan.signals) == 11
    assert len({row["id"] for row in report["findings"]}) == 7
    assert len({signal.observation_id for signal in scan.signals}) == 11
    assert scan.files_scanned == 0 and all(signal.confidence == 0 for signal in scan.signals)
    assert all(row["evidence_basis"] == "unknown" and "SYNTHETIC" in row["title"] for row in report["findings"])
    assert report["fixture"]["security_evidence"] is False


@pytest.fixture
def reference_output():
    with tempfile.TemporaryDirectory(prefix="attackmap-reference-test-") as owned:
        output = Path(owned)
        assert not output.resolve().is_relative_to(generator.WORKSPACE)
        yield output


def test_sidecar_hash_metadata_and_identical_rerun(reference_output):
    tmp_path = reference_output
    options = dict(findings=7, observations=11, report_bytes=16_384)
    manifest = generator.generate(tmp_path, **options)
    assert generator.generate(tmp_path, **options) == manifest
    raw = (tmp_path / manifest["report"]).read_bytes()
    assert manifest["sha256"] == hashlib.sha256(raw).hexdigest()
    assert manifest["severity_counts"] == {"high": 3, "medium": 2, "low": 2}
    assert manifest["performance_acceptance"] == "unmeasured"
    assert manifest == json.loads((tmp_path / "desktop-reference-manifest.json").read_bytes())
    assert (tmp_path / "attackmap-report.sha256").read_text().split()[0] == manifest["sha256"]


def test_rejects_different_existing_output_before_other_files_are_written(reference_output):
    tmp_path = reference_output
    path = tmp_path / "attackmap-report.json"
    path.write_bytes(b"user file")
    with pytest.raises(ValueError, match="overwrite"):
        generator.generate(tmp_path, findings=1, observations=1, report_bytes=4096)
    assert path.read_bytes() == b"user file"
    assert not (tmp_path / "desktop-reference-manifest.json").exists()


def test_source_directory_is_not_a_fixture_destination():
    with pytest.raises(ValueError, match=".pytest_cache"):
        generator.generate(generator.WORKSPACE / "src" / "generated-reference")


@pytest.mark.parametrize("options", [{"findings": 0}, {"observations": 0}, {"report_bytes": 1}])
def test_invalid_counts_or_undersized_report_fail(options):
    with pytest.raises(ValueError):
        generator.build_report(**options)
