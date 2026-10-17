import json
import os
import subprocess
import sys

import pytest

from attackmap.artifact_manifest import write_artifact_manifest
from attackmap.artifact_publisher import (
    current_generation, export_compatibility, generation_dir, publish_generation, validate_generation, write_diagnostic,
)
from attackmap.safe_fs import UnsafePathError, safe_write_text


@pytest.mark.skipif(os.name != "nt", reason="Actual Windows junction destination")
@pytest.mark.parametrize("nested", [False, True])
def test_owned_junction_blocks_diagnostics_and_generation_without_feature_skip(tmp_path, nested):
    import base64
    import stat
    target = tmp_path / "owned-target"
    target.mkdir()
    sentinel = target / "unchanged.txt"
    sentinel.write_bytes(b"owned target must remain unchanged")
    junction = tmp_path / "owned-junction"
    payload = base64.b64encode(json.dumps({"link": str(junction), "target": str(target)}).encode("utf-8")).decode("ascii")
    script = ("$ErrorActionPreference='Stop';$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
              + payload + "'))|ConvertFrom-Json;New-Item -ItemType Junction -Path $p.link -Target $p.target|Out-Null")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                             base64.b64encode(script.encode("utf-16-le")).decode("ascii")], capture_output=True)
    assert result.returncode == 0, "Owned junction creation failed; Windows fixture is required"
    assert junction.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    before = sentinel.read_bytes()
    output = junction / "reports" if nested else junction
    with pytest.raises(UnsafePathError, match="redirected"):
        write_diagnostic(output, "junction-run", state="failed")
    with pytest.raises(UnsafePathError, match="redirected"):
        generation_dir(output, "junction-run")
    from attackmap.artifact_publisher import prepare_output_root
    with pytest.raises(UnsafePathError, match="redirected"):
        prepare_output_root(output)
    assert sentinel.read_bytes() == before
    assert list(target.iterdir()) == [sentinel]
    # Preserve this unique owned junction as evidence; never recursively delete its target.


def test_safe_artifact_path_allows_missing_normal_components(tmp_path):
    from attackmap.artifact_publisher import _safe
    output = tmp_path / "not-created" / "reports"
    assert _safe(output) == output
    path = write_diagnostic(output, "normal", state="failed")
    assert path.is_file()


def test_prepare_output_root_creates_only_marker_and_missing_parents(tmp_path):
    from attackmap.artifact_publisher import prepare_output_root
    from attackmap.safe_fs import OUTPUT_MARKER
    output = tmp_path / "missing-parent" / "reports"
    assert prepare_output_root(output) == output
    assert [path.name for path in output.iterdir()] == [OUTPUT_MARKER]


def test_artifact_lstat_io_failure_is_typed_and_fails_closed(tmp_path, monkeypatch):
    from pathlib import Path
    from attackmap.artifact_publisher import _safe
    real = Path.lstat
    def denied(self):
        if self == tmp_path:
            raise PermissionError("private sentinel")
        return real(self)
    monkeypatch.setattr(Path, "lstat", denied)
    with pytest.raises(UnsafePathError, match="Cannot verify artifact path"):
        _safe(tmp_path / "missing")
    from attackmap.artifact_publisher import prepare_output_root
    def should_not_create(*args, **kwargs):
        raise AssertionError("Output creation preceded validation")
    monkeypatch.setattr("attackmap.artifact_publisher.ensure_output_dir", should_not_create)
    with pytest.raises(UnsafePathError, match="Cannot verify artifact path"):
        prepare_output_root(tmp_path / "missing")


def test_reparse_ancestor_checked_before_descendant(tmp_path, monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace
    from attackmap.artifact_publisher import _safe
    real = Path.lstat
    inspected = []
    def redirected(self):
        inspected.append(self)
        if self == tmp_path:
            return SimpleNamespace(st_mode=0, st_file_attributes=0x400, st_reparse_tag=0)
        assert self != tmp_path / "child", "Traversed redirected ancestor"
        return real(self)
    monkeypatch.setattr(Path, "lstat", redirected)
    with pytest.raises(UnsafePathError, match="redirected"):
        _safe(tmp_path / "child")
    assert tmp_path / "child" not in inspected


def test_diagnostic_fallback_preserves_rich_context_and_safe_timing(tmp_path):
    from attackmap.diagnostics import startup_diagnostic, unknown_diagnostic
    rich = startup_diagnostic("select_analyzers", duration_milliseconds=12.5, requested_analyzers=["python"])
    timing = {"schema_version": "1.0", "clock": "engine_utc", "scope": "analysis_pipeline_before_publication",
              "started_at": "2026-10-15T00:00:00+00:00", "finished_at": "2026-10-15T00:00:01+00:00", "outcome": "failed"}
    path = write_diagnostic(tmp_path, "one", state="failed", context=rich, scan_timing=timing)
    write_diagnostic(tmp_path, "one", state="cancelled", context=unknown_diagnostic("worker", outcome="cancelled"))
    payload = json.loads(path.read_text())
    assert payload["schema_version"] == "1.1" and payload["state"] == "cancelled"
    assert payload["diagnostic_context"]["coverage"]["status"] == "not_started"
    assert payload["diagnostic_context"]["stages"][0]["duration_milliseconds"] == 12.5
    assert payload["scan_timing"] == timing
    payload["scan_timing"] = {"scope": "SECRET_SENTINEL/private/path"}
    path.write_text(json.dumps(payload))
    write_diagnostic(tmp_path, "one", state="failed")
    assert "SECRET_SENTINEL" not in path.read_text()


def test_staged_diagnostic_context_is_bounded_and_recovers_nested_failure(tmp_path):
    from attackmap.diagnostics import startup_diagnostic
    from attackmap.artifact_publisher import diagnostic_context_from_generation
    folder = tmp_path / "one"
    folder.mkdir()
    (folder / "run-manifest.json").write_text(" " * 1_000_001)
    write_diagnostic(folder, "one", state="failed", context=startup_diagnostic("select_analyzers", duration_milliseconds=1.25))
    recovered = diagnostic_context_from_generation(tmp_path, "one", outcome="failed")
    assert recovered.stages[0].duration_milliseconds == 1.25
    assert recovered.coverage.status == "not_started"
    (folder / "run-manifest.json").write_text(json.dumps({"analyzers": [None]}))
    assert diagnostic_context_from_generation(tmp_path, "one", outcome="failed") is not None


def test_staged_context_refuses_redirected_metadata(tmp_path):
    from attackmap.artifact_publisher import diagnostic_context_from_generation
    folder = tmp_path / "one"
    folder.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"stages": []}')
    try:
        (folder / "run-manifest.json").symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    assert diagnostic_context_from_generation(tmp_path, "one", outcome="failed") is None


@pytest.mark.parametrize("change", [{"run_id": "foreign"}, {"schema_version": "9.0"}])
def test_foreign_diagnostic_identity_cannot_supply_context(tmp_path, change):
    from attackmap.diagnostics import startup_diagnostic
    from attackmap.artifact_publisher import diagnostic_context_from_generation
    folder = tmp_path / "one"
    path = write_diagnostic(folder, "one", state="failed", context=startup_diagnostic("select_analyzers", duration_milliseconds=12))
    payload = json.loads(path.read_text())
    path.write_text(json.dumps({**payload, **change}))
    assert diagnostic_context_from_generation(tmp_path, "one", outcome="failed") is None
    write_diagnostic(folder, "one", state="failed")
    stored = json.loads(path.read_text())
    assert not any(stage["duration_milliseconds"] == 12 for stage in stored["diagnostic_context"]["stages"])


def test_reversed_timing_and_foreign_generation_are_not_borrowed(tmp_path):
    from attackmap.diagnostics import startup_diagnostic
    from attackmap.artifact_publisher import diagnostic_context_from_generation
    folder = tmp_path / "one"
    timing = {"schema_version": "1.0", "clock": "engine_utc", "scope": "analysis_pipeline_before_publication",
              "started_at": "2026-10-15T00:00:02+00:00", "finished_at": "2026-10-15T00:00:01+00:00", "outcome": "failed"}
    path = write_diagnostic(folder, "one", state="failed", scan_timing=timing, context=startup_diagnostic("select_analyzers"))
    assert "scan_timing" not in json.loads(path.read_text())
    (folder / "artifact-manifest.json").write_text(json.dumps({"schema_version": "1.1", "generation_id": "foreign"}))
    assert diagnostic_context_from_generation(tmp_path, "one", outcome="failed") is None


def stage(base, run):
    folder = generation_dir(base, run)
    report = {"scan": {"root": "repo"}, "findings": [], "attack_paths": [],
              "attack_surfaces": [], "exploitability": [], "suppressed_findings": []}
    safe_write_text(folder, folder / "attackmap-report.json", json.dumps(report))
    safe_write_text(folder, folder / "run-manifest.json", json.dumps({"stages": []}))
    write_artifact_manifest(folder, run, "1.0", "repo", "repo", [], 0, "succeeded", report)
    return folder


def test_publication_finalizes_timing_and_preserves_previous(tmp_path):
    previous = stage(tmp_path, "previous")
    publish_generation(tmp_path, "previous")
    new = stage(tmp_path, "new")
    publish_generation(tmp_path, "new")
    assert current_generation(tmp_path) == new
    validate_generation(previous)
    timing = json.loads((new / "run-manifest.json").read_text())
    assert timing["stages"][0]["name"] == "publication"
    assert timing["stages"][0]["milliseconds"] >= 0


@pytest.mark.parametrize("point", ["before_validation", "after_validation", "after_timing", "after_manifest", "before_commit"])
@pytest.mark.parametrize("cancel", [False, True])
def test_every_boundary_preserves_current(tmp_path, point, cancel):
    old = stage(tmp_path, "old")
    publish_generation(tmp_path, "old")
    stage(tmp_path, "new")
    reached = False

    def boundary(name):
        nonlocal reached
        if name == point:
            reached = True
            if not cancel:
                raise OSError("injected failure")

    with pytest.raises((OSError, InterruptedError)):
        publish_generation(tmp_path, "new", boundary=boundary, cancelled=lambda: cancel and reached)
    assert reached
    assert current_generation(tmp_path) == old
    write_diagnostic(tmp_path, "new", state="cancelled" if cancel else "failed")
    assert current_generation(tmp_path) == old


@pytest.mark.parametrize("name", ["scan.json", "attackmap-report.json", "run-manifest.json", "artifact-manifest.json"])
def test_corrupt_artifact_cannot_publish(tmp_path, name):
    old = stage(tmp_path, "old")
    publish_generation(tmp_path, "old")
    new = stage(tmp_path, "new")
    (new / name).write_text("{}")
    with pytest.raises(ValueError):
        publish_generation(tmp_path, "new")
    assert current_generation(tmp_path) == old


def test_pointer_and_committed_corruption_fail_closed(tmp_path):
    new = stage(tmp_path, "new")
    publish_generation(tmp_path, "new")
    (new / "findings.json").write_text("bad")
    assert current_generation(tmp_path) is None
    (tmp_path / "current-generation.json").write_text('{"generation":"../outside"}')
    assert current_generation(tmp_path) is None


@pytest.mark.parametrize("name", ["../outside", "a/b", "C:drive", "NUL", "CON.json", "end.", ""])
def test_invalid_names(tmp_path, name):
    with pytest.raises(UnsafePathError):
        generation_dir(tmp_path, name)


def test_symlink_artifact_refused(tmp_path):
    folder = stage(tmp_path, "new")
    target = tmp_path / "outside.json"
    target.write_text("[]")
    path = folder / "findings.json"
    path.unlink()
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    with pytest.raises(UnsafePathError):
        publish_generation(tmp_path, "new")


def test_replace_failure_preserves_current(tmp_path, monkeypatch):
    old = stage(tmp_path, "old")
    publish_generation(tmp_path, "old")
    stage(tmp_path, "new")
    def fail(*args):
        raise OSError("replace denied")
    monkeypatch.setattr("attackmap.artifact_publisher.os.replace", fail)
    with pytest.raises(OSError):
        publish_generation(tmp_path, "new")
    assert current_generation(tmp_path) == old


@pytest.mark.parametrize("filename", ["run-manifest.json", "artifact-manifest.json", "pointer"])
def test_interrupted_write_preserves_current(tmp_path, monkeypatch, filename):
    old = stage(tmp_path, "old")
    publish_generation(tmp_path, "old")
    stage(tmp_path, "new")
    original = safe_write_text
    def interrupted(base, path, text):
        if path.name == filename or (filename == "pointer" and path.name.startswith(".current-")):
            original(base, path, text[:len(text) // 2])
            raise OSError("interrupted write")
        original(base, path, text)
    monkeypatch.setattr("attackmap.artifact_publisher.safe_write_text", interrupted)
    with pytest.raises(OSError):
        publish_generation(tmp_path, "new")
    assert current_generation(tmp_path) == old


def test_compatibility_export_and_generated_pointer(tmp_path):
    from attackmap.artifact_manifest import generated_artifact_names
    folder = stage(tmp_path, "new")
    publish_generation(tmp_path, "new")
    exported = export_compatibility(tmp_path, folder)
    assert tmp_path / "attackmap-report.json" in exported
    assert "current-generation.json" in generated_artifact_names(tmp_path, ["current-generation.json"])
    assert current_generation(tmp_path) == folder
    (tmp_path / "attackmap-report.json").write_text("user source")
    with pytest.raises(ValueError, match="user file"):
        export_compatibility(tmp_path, folder)
    assert (tmp_path / "attackmap-report.json").read_text() == "user source"


def test_invalid_pointer_is_not_generated(tmp_path):
    from attackmap.artifact_manifest import generated_artifact_names
    (tmp_path / "current-generation.json").write_text('{"generation":"invented"}')
    assert not generated_artifact_names(tmp_path, ["current-generation.json"])


def test_fleet_verifies_bound_children(tmp_path):
    from attackmap.artifact_publisher import write_fleet_manifest
    fleet = generation_dir(tmp_path, "fleet-run")
    child = stage(fleet / "service", "child-run")
    publish_generation(fleet / "service", "child-run")
    safe_write_text(fleet, fleet / "fleet-summary.json", json.dumps({"repo_count": 1,
        "repos": [], "cross_repo_links": [], "total_findings": 0}))
    write_fleet_manifest(fleet, "fleet-run", engine_version="1.0", repo_roots=["service"])
    publish_generation(tmp_path, "fleet-run")
    assert current_generation(tmp_path) == fleet
    (child / "findings.json").write_text("corrupt")
    assert current_generation(tmp_path) is None


def test_markdown_exports_can_be_repeated_without_overwriting_user_sources(tmp_path):
    first = stage(tmp_path, "first")
    publish_generation(tmp_path, "first")
    export_compatibility(tmp_path, first, output_format="markdown")
    second = stage(tmp_path, "second")
    publish_generation(tmp_path, "second")
    export_compatibility(tmp_path, second, output_format="markdown")
    assert not (tmp_path / "attackmap-report.json").exists()
    assert (tmp_path / "artifact-manifest.json").exists()


def test_finalized_generations_cannot_be_reused_or_republished(tmp_path):
    stage(tmp_path, "first")
    publish_generation(tmp_path, "first")
    stage(tmp_path, "second")
    publish_generation(tmp_path, "second")
    with pytest.raises(ValueError, match="unique run ID"):
        generation_dir(tmp_path, "first")
    with pytest.raises(ValueError, match="unique run ID"):
        publish_generation(tmp_path, "first")
    assert current_generation(tmp_path).name == "second"
    write_diagnostic(tmp_path, "second", state="failed", error="export failed")
    assert current_generation(tmp_path).name == "second"
    assert not (tmp_path / "second" / "terminal-diagnostic.json").exists()


@pytest.mark.parametrize("point", ["before_validation", "after_validation", "after_timing", "after_manifest", "before_commit"])
def test_process_exit_before_commit_preserves_previous(tmp_path, point):
    old = stage(tmp_path, "old")
    publish_generation(tmp_path, "old")
    stage(tmp_path, "new")
    script = (
        "import os, sys\nfrom pathlib import Path\n"
        "from attackmap.artifact_publisher import publish_generation\n"
        "def boundary(name):\n"
        "    if name == sys.argv[2]: os._exit(99)\n"
        "publish_generation(Path(sys.argv[1]), 'new', boundary=boundary)\n"
    )
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path), point],
                            capture_output=True, timeout=20)
    assert result.returncode == 99, result.stderr.decode(errors="replace")
    assert current_generation(tmp_path) == old


def test_pointer_symlink_cannot_redirect_publication(tmp_path):
    folder = stage(tmp_path, "new")
    victim = tmp_path / "victim"
    victim.write_text("original")
    try:
        (tmp_path / "current-generation.json").symlink_to(victim)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    with pytest.raises(UnsafePathError):
        publish_generation(tmp_path, folder.name)
    assert victim.read_text() == "original"


def test_failed_diagnostics_do_not_become_source_inputs(tmp_path):
    from attackmap.safe_fs import walk_repo
    source = tmp_path / "app.py"
    source.write_text("print('source')")
    diagnostic = write_diagnostic(tmp_path, "failed-run", state="failed", error="parser failed")
    assert diagnostic.is_file()
    assert list(walk_repo(tmp_path)) == [source]


def fleet_stage(base, run):
    from attackmap.artifact_publisher import write_fleet_manifest
    fleet = generation_dir(base, run)
    child = stage(fleet / "service", "child-run")
    (child / "user-source.py").write_text("must not export")
    publish_generation(fleet / "service", "child-run")
    (fleet / "unbound").mkdir()
    (fleet / "unbound" / "secret.txt").write_text("must not export")
    safe_write_text(fleet, fleet / "fleet-summary.json", json.dumps({"repo_count": 1,
        "repos": [], "cross_repo_links": [], "total_findings": 0}))
    safe_write_text(fleet, fleet / "fleet-summary.md", "# Fleet\n")
    write_fleet_manifest(fleet, run, engine_version="1.0", repo_roots=["service"])
    publish_generation(base, run)
    return fleet


@pytest.mark.parametrize("output_format", ["all", "json", "markdown"])
def test_fleet_exports_only_bound_child_artifacts_and_can_repeat(tmp_path, output_format):
    first = fleet_stage(tmp_path, "first")
    export_compatibility(tmp_path, first, output_format=output_format)
    assert (tmp_path / "service" / "artifact-manifest.json").is_file()
    assert (tmp_path / "service" / "attackmap-report.json").exists() == (output_format != "markdown")
    assert not (tmp_path / "service" / "user-source.py").exists()
    assert not (tmp_path / "unbound").exists()
    second = fleet_stage(tmp_path, "second")
    export_compatibility(tmp_path, second, output_format=output_format)
    assert current_generation(tmp_path) == second
    validate_generation(first)


def test_fleet_child_user_file_collision_preflights_entire_export(tmp_path):
    first = fleet_stage(tmp_path, "first")
    export_compatibility(tmp_path, first)
    parent_before = (tmp_path / "artifact-manifest.json").read_bytes()
    user_file = tmp_path / "service" / "attackmap-report.json"
    user_file.write_text("legitimate user source")
    second = fleet_stage(tmp_path, "second")
    with pytest.raises(ValueError, match="user file"):
        export_compatibility(tmp_path, second)
    assert user_file.read_text() == "legitimate user source"
    assert (tmp_path / "artifact-manifest.json").read_bytes() == parent_before
    assert current_generation(tmp_path) == second


def test_fleet_child_symlink_destination_refused(tmp_path):
    fleet = fleet_stage(tmp_path, "first")
    victim = tmp_path / "victim"
    victim.mkdir()
    try:
        (tmp_path / "service").symlink_to(victim, target_is_directory=True)
    except OSError:
        pytest.skip("Host does not grant symlink creation")
    with pytest.raises(UnsafePathError):
        export_compatibility(tmp_path, fleet)
    assert not list(victim.iterdir())


def test_fleet_export_cannot_mutate_retained_generation(tmp_path):
    retained = stage(tmp_path, "service")
    publish_generation(tmp_path, "service")
    before = (retained / "artifact-manifest.json").read_bytes()
    fleet = fleet_stage(tmp_path, "fleet-run")
    with pytest.raises(ValueError, match="immutable generation"):
        export_compatibility(tmp_path, fleet)
    assert (retained / "artifact-manifest.json").read_bytes() == before
    validate_generation(retained)


def test_fleet_export_preserves_unrelated_child_user_file(tmp_path):
    fleet = fleet_stage(tmp_path, "fleet-run")
    destination = tmp_path / "service"
    destination.mkdir()
    user = destination / "application.py"
    user.write_text("user owned source")
    export_compatibility(tmp_path, fleet)
    assert user.read_text() == "user owned source"


def test_diagnostic_legacy_call_omits_scan_timing(tmp_path):
    doc = json.loads(write_diagnostic(tmp_path, "legacy", state="failed").read_text())
    assert "scan_timing" not in doc


def test_diagnostic_additive_scan_timing_preserved(tmp_path):
    timing = {"schema_version": "1.0", "clock": "engine_utc", "scope": "analysis_pipeline_before_publication",
              "started_at": "2026-10-15T10:00:00+00:00", "finished_at": "2026-10-15T10:00:02+00:00", "outcome": "failed"}
    doc = json.loads(write_diagnostic(tmp_path, "timed", state="failed", scan_timing=timing).read_text())
    assert doc["scan_timing"] == timing
