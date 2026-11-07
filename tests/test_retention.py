"""AM043/C30 generation retention: keep window, soft budget, protection, pins."""
import hashlib
import json
from pathlib import Path

import pytest

from attackmap.artifact_manifest import (
    MANIFEST_FILENAME, PINS_FILENAME, generated_artifact_names, write_artifact_manifest,
)
from attackmap.artifact_publisher import current_generation, generation_dir, publish_generation, write_diagnostic
from attackmap.retention import (
    apply_retention, enumerate_generations, pin_generation, read_pins, retain_after_publish, unpin_generation,
)
from attackmap.safe_fs import safe_write_text


def stage(base: Path, run: str, created: str) -> Path:
    folder = generation_dir(base, run)
    report = {"scan": {"root": "repo"}, "findings": [], "attack_paths": [],
              "attack_surfaces": [], "exploitability": [], "suppressed_findings": []}
    safe_write_text(folder, folder / "attackmap-report.json", json.dumps(report))
    safe_write_text(folder, folder / "run-manifest.json", json.dumps({"stages": []}))
    write_artifact_manifest(folder, run, "1.0", "repo", "repo", [], 0, "succeeded", report)
    manifest = json.loads((folder / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    manifest["created_at"] = created
    safe_write_text(folder, folder / MANIFEST_FILENAME, json.dumps(manifest, indent=2) + "\n")
    publish_generation(base, run)
    return folder


def staged_base(base: Path, count: int) -> list[Path]:
    return [stage(base, f"g{i:02d}", f"2026-01-{i:02d}T00:00:00+00:00") for i in range(1, count + 1)]


def point_to(base: Path, run: str) -> None:
    folder = base / run
    payload = {"generation": run,
               "manifest_sha256": hashlib.sha256((folder / MANIFEST_FILENAME).read_bytes()).hexdigest()}
    (base / "current-generation.json").write_text(json.dumps(payload) + "\n", encoding="utf-8")


def by_reason(actions, reason):
    return sorted(action.run_id for action in actions if action.reason == reason)


def size(base: Path, run: str) -> int:
    return next(record.size_bytes for record in enumerate_generations(base)[0] if record.run_id == run)


def test_keep_window_deletes_only_oldest_unprotected(tmp_path):
    folders = staged_base(tmp_path, 25)
    freed = sum(size(tmp_path, f"g{i:02d}") for i in range(1, 6))
    result = apply_retention(tmp_path, keep_completed=20)
    assert by_reason(result.deleted, "beyond_keep_completed") == [f"g{i:02d}" for i in range(1, 6)]
    assert sorted(by_reason(result.retained, "recent")) == [f"g{i:02d}" for i in range(6, 25)]
    assert by_reason(result.retained, "current") == ["g25"]
    assert result.bytes_freed == freed
    assert freed > 0
    assert not any((tmp_path / f"g{i:02d}").exists() for i in range(1, 6))
    assert current_generation(tmp_path) == tmp_path / "g25"
    assert folders[-1].is_dir()


def test_pointer_named_current_survives_beyond_window(tmp_path):
    staged_base(tmp_path, 6)
    point_to(tmp_path, "g01")
    result = apply_retention(tmp_path, keep_completed=3)
    assert by_reason(result.retained, "current") == ["g01"]
    assert by_reason(result.deleted, "beyond_keep_completed") == ["g02", "g03"]
    assert by_reason(result.retained, "recent") == ["g04", "g05", "g06"]
    assert (tmp_path / "g01").is_dir()
    assert current_generation(tmp_path) == tmp_path / "g01"


def test_pinned_and_active_survive_beyond_window(tmp_path):
    staged_base(tmp_path, 6)
    assert pin_generation(tmp_path, "g01") == {"g01"}
    result = apply_retention(tmp_path, keep_completed=2, active_run_ids=["g02"])
    assert by_reason(result.retained, "pinned") == ["g01"]
    assert by_reason(result.retained, "active") == ["g02"]
    assert by_reason(result.deleted, "beyond_keep_completed") == ["g03", "g04"]
    assert by_reason(result.retained, "current") == ["g06"]
    assert (tmp_path / "g01").is_dir() and (tmp_path / "g02").is_dir()


def test_unpin_allows_deletion_next_pass(tmp_path):
    staged_base(tmp_path, 5)
    pin_generation(tmp_path, "g01")
    apply_retention(tmp_path, keep_completed=2)
    assert (tmp_path / "g01").is_dir()
    assert unpin_generation(tmp_path, "g01") == set()
    result = apply_retention(tmp_path, keep_completed=2)
    assert "g01" in by_reason(result.deleted, "beyond_keep_completed")
    assert not (tmp_path / "g01").exists()


def test_soft_budget_trims_unprotected_then_reports_overage(tmp_path):
    staged_base(tmp_path, 4)
    pin_generation(tmp_path, "g01")
    exact = size(tmp_path, "g01") + size(tmp_path, "g04")
    result = apply_retention(tmp_path, keep_completed=2, soft_budget_bytes=exact)
    assert by_reason(result.deleted, "beyond_keep_completed") == ["g02"]
    assert by_reason(result.deleted, "over_soft_budget") == ["g03"]
    assert result.budget_overage_bytes == 0
    assert current_generation(tmp_path) == tmp_path / "g04"
    # Nothing deletable remains: the protected overage is reported, not deleted.
    tight = apply_retention(tmp_path, keep_completed=2, soft_budget_bytes=size(tmp_path, "g01"))
    assert tight.deleted == []
    assert tight.budget_overage_bytes == size(tmp_path, "g04")
    assert by_reason(tight.retained, "pinned") == ["g01"]
    assert by_reason(tight.retained, "current") == ["g04"]


def test_invalid_leftover_removed_even_inside_window(tmp_path):
    staged_base(tmp_path, 3)
    (tmp_path / "g01" / "attackmap-report.json").unlink()
    result = apply_retention(tmp_path, keep_completed=5)
    assert by_reason(result.deleted, "interrupted_cleanup") == ["g01"]
    assert not (tmp_path / "g01").exists()
    assert current_generation(tmp_path) == tmp_path / "g03"


def test_pointer_named_corrupt_generation_is_never_deleted(tmp_path):
    staged_base(tmp_path, 2)
    point_to(tmp_path, "g01")
    (tmp_path / "g01" / "attackmap-report.json").unlink()
    assert current_generation(tmp_path) is None
    result = apply_retention(tmp_path, keep_completed=1)
    assert result.deleted == []
    assert by_reason(result.retained, "current") == ["g01"]
    assert (tmp_path / "g01").is_dir()


def test_staged_and_foreign_content_untouched(tmp_path):
    staged_base(tmp_path, 1)
    staging = tmp_path / "staging-run"
    staging.mkdir()
    (staging / "partial.json").write_text("{}", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("user file", encoding="utf-8")
    user_dir = tmp_path / "mydir"
    user_dir.mkdir()
    (user_dir / "x.txt").write_text("data", encoding="utf-8")
    write_diagnostic(tmp_path, "failed-run", state="failed")
    result = apply_retention(tmp_path, keep_completed=1)
    assert result.deleted == []
    assert result.non_generation_children == 2  # staging dir and user dir; diagnostics excluded
    assert staging.is_dir() and (tmp_path / "notes.txt").is_file() and user_dir.is_dir()
    assert (tmp_path / "diagnostics" / "failed-run").is_dir()


def test_dry_run_reports_plan_without_deleting(tmp_path):
    staged_base(tmp_path, 4)
    result = apply_retention(tmp_path, keep_completed=1, dry_run=True)
    assert by_reason(result.deleted, "beyond_keep_completed") == ["g01", "g02", "g03"]
    assert result.bytes_freed == 0
    assert all((tmp_path / f"g{i:02d}").is_dir() for i in range(1, 5))
    applied = apply_retention(tmp_path, keep_completed=1)
    assert applied.bytes_freed > 0
    assert not any((tmp_path / f"g{i:02d}").exists() for i in range(1, 4))


def test_corrupt_pins_abort_retention_fail_closed(tmp_path):
    staged_base(tmp_path, 3)
    (tmp_path / PINS_FILENAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        apply_retention(tmp_path, keep_completed=1)
    assert all((tmp_path / f"g{i:02d}").is_dir() for i in range(1, 4))
    warnings = []
    assert retain_after_publish(tmp_path, keep_completed=1, echo=lambda msg, err=False: warnings.append(msg)) is None
    assert warnings and "retention skipped" in warnings[0]
    assert all((tmp_path / f"g{i:02d}").is_dir() for i in range(1, 4))


def test_pin_unpin_validation(tmp_path):
    staged_base(tmp_path, 2)
    with pytest.raises(ValueError):
        pin_generation(tmp_path, "missing-run")
    with pytest.raises(ValueError):
        unpin_generation(tmp_path, "g01")
    pin_generation(tmp_path, "g01")
    pin_generation(tmp_path, "g01")  # idempotent
    payload = json.loads((tmp_path / PINS_FILENAME).read_text(encoding="utf-8"))
    assert payload == {"schema_version": "1.0", "pinned": ["g01"]}
    assert read_pins(tmp_path) == {"g01"}
    with pytest.raises((ValueError, OSError)):  # invalid names fail UnsafePathError
        pin_generation(tmp_path, "../escape")
    unpin_generation(tmp_path, "g01")
    assert read_pins(tmp_path) == set()


def test_staged_generation_cannot_be_pinned(tmp_path):
    staged_base(tmp_path, 1)
    staging = generation_dir(tmp_path, "wip")
    (staging / "attackmap-report.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        pin_generation(tmp_path, "wip")


def test_pins_file_recognized_as_generated_output(tmp_path):
    valid = tmp_path / "base1"
    valid.mkdir()
    (valid / PINS_FILENAME).write_text(json.dumps({"schema_version": "1.0", "pinned": ["g01"]}), encoding="utf-8")
    assert PINS_FILENAME in generated_artifact_names(valid, [PINS_FILENAME])
    foreign = tmp_path / "base2"
    foreign.mkdir()
    (foreign / PINS_FILENAME).write_text(json.dumps({"pinned": ["g01"]}), encoding="utf-8")
    assert PINS_FILENAME not in generated_artifact_names(foreign, [PINS_FILENAME])
    replaced = tmp_path / "base3"
    replaced.mkdir()
    (replaced / PINS_FILENAME).write_text("user notes", encoding="utf-8")
    assert PINS_FILENAME not in generated_artifact_names(replaced, [PINS_FILENAME])


_APP = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return {'id': user_id}\n"
)


def _tiny_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(_APP, encoding="utf-8")
    return repo


def test_two_cli_scans_keep_both_generations_without_warning(tmp_path):
    from typer.testing import CliRunner
    from attackmap.cli import app as cli_app
    repo = _tiny_repo(tmp_path)
    out = tmp_path / "out"
    for _ in range(2):
        result = CliRunner().invoke(cli_app, ["analyze", str(repo), "-o", str(out)])
        assert result.exit_code == 0, result.output
    assert "retention skipped" not in result.output
    _, non_generation = enumerate_generations(out)
    assert non_generation == 0
    assert current_generation(out) is not None


def test_pipeline_retention_failure_never_fails_the_scan(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from attackmap.cli import app as cli_app

    def boom(*args, **kwargs):
        raise RuntimeError("retention bug")

    monkeypatch.setattr("attackmap.retention.apply_retention", boom)
    repo = _tiny_repo(tmp_path)
    out = tmp_path / "out"
    result = CliRunner().invoke(cli_app, ["analyze", str(repo), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "retention skipped" in result.output
    assert current_generation(out) is not None
