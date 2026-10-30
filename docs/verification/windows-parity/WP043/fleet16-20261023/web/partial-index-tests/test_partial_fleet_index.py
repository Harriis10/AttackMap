"""Staged broker diagnostic hash binding; deterministic files, no scans or processes."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from attackmap import artifact_publisher as publisher
from attackmap.fleet import fleet_repo_ids

REPO = next(parent for parent in Path(__file__).resolve().parents
            if (parent / "pyproject.toml").is_file() and (parent / "src" / "attackmap").is_dir())
sys.path.insert(0, str(REPO / "tests"))
from artifact_fixture import write_generation

STAGED = Path(__file__).parent / "staged" / "desktop_fleet.py"
SPEC = importlib.util.spec_from_file_location("attackmap._staged_partial_fleet_index", STAGED)
fleet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fleet
SPEC.loader.exec_module(fleet)


def request(tmp_path):
    roots = [tmp_path / "left" / "same", tmp_path / "right" / "same"]
    for root in roots:
        root.mkdir(parents=True)
    repositories = [fleet.FleetRepository(repository_id=f"request-{i}", repository_path=str(root))
                    for i, root in enumerate(roots)]
    return fleet.FleetRunRequest(run_id="staged-partial-fixture", generation=8, revision=0,
        repository_id=fleet.repository_set_id(repositories), repositories=repositories,
        output_path=str(tmp_path / "output"))


def child_generations(run, folder, count):
    for slug, repo in list(zip(fleet_repo_ids([Path(item.repository_path) for item in run.repositories]), run.repositories))[:count]:
        base = folder / slug
        child = publisher.generation_dir(base, fleet.child_run_id(run, repo))
        write_generation(child, {"scan": {"root": str(Path(repo.repository_path).resolve())}})
        publisher.publish_generation(base, child.name)


def summary(folder, count=2):
    raw = json.dumps({"repo_count": count, "repos": [{} for _ in range(count)],
                      "cross_repo_links": [], "total_findings": 0}).encode()
    (folder / "fleet-summary.json").write_bytes(raw)
    return raw


def broker(run, folder, monkeypatch, code, mutate=None):
    class Supervisor:
        def start(self, argv, **kwargs):
            if mutate:
                mutate()
            kwargs["on_done"](code, "private output is not included")
            return True
        def request_cancel(self):
            pytest.fail("Unexpected cancellation")
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    events = io.StringIO()
    assert fleet.serve(run, control=io.StringIO(""), events=events) == 0
    return json.loads(events.getvalue().splitlines()[-1])


def test_absent_summary_preserves_exact_old_index_shape(tmp_path):
    run = request(tmp_path); folder = Path(run.output_path); folder.mkdir()
    children = fleet.collect_children(run, folder)
    expected = {**fleet._identity(run), "kind": "fleet_index", "children": [row.model_dump(mode="json") for row in children]}
    assert fleet._index_payload(run, folder, children) == expected
    assert json.loads(fleet.write_index(run, folder, children).read_text()) == expected


def test_partial_index_binds_exact_summary_bytes_and_verified_child(tmp_path):
    run = request(tmp_path); folder = Path(run.output_path); folder.mkdir()
    child_generations(run, folder, 1); raw = summary(folder, 1)
    children = fleet.collect_children(run, folder)
    payload = json.loads(fleet.write_index(run, folder, children).read_text())
    assert children[0].state == "completed" and children[1].state == "skipped"
    assert payload["fleet_summary"] == {"path": "fleet-summary.json", "sha256": hashlib.sha256(raw).hexdigest()}
    assert not (folder / publisher.CURRENT_POINTER).exists()


@pytest.mark.parametrize("change", ["tampered", "missing"])
def test_changed_or_missing_summary_cannot_match_recorded_index(tmp_path, change):
    run = request(tmp_path); folder = Path(run.output_path); folder.mkdir(); summary(folder)
    children = fleet.collect_children(run, folder)
    recorded = json.loads(fleet.write_index(run, folder, children).read_text())
    target = folder / "fleet-summary.json"
    if change == "tampered":
        target.write_bytes(b'{"changed":true}')
        assert hashlib.sha256(target.read_bytes()).hexdigest() != recorded["fleet_summary"]["sha256"]
    else:
        target.unlink()
    assert recorded != fleet._index_payload(run, folder, children)


@pytest.mark.parametrize("kind", ["oversized", "directory"])
def test_unbounded_or_nonregular_summary_refused(tmp_path, monkeypatch, kind):
    folder = tmp_path / "output"; folder.mkdir(); target = folder / "fleet-summary.json"
    if kind == "directory":
        target.mkdir()
    else:
        monkeypatch.setattr(fleet, "_MAX_FLEET_SUMMARY_BYTES", 4); target.write_bytes(b"12345")
    with pytest.raises(ValueError, match="bounded regular"):
        fleet._fleet_summary_reference(folder)


def test_redirected_summary_ancestor_refused(tmp_path):
    destination = tmp_path / "real"; destination.mkdir(); summary(destination)
    alias = tmp_path / "redirected"
    if os.name == "nt":
        created = subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(destination)], capture_output=True, text=True)
        assert created.returncode == 0, created.stderr
    else:
        alias.symlink_to(destination, target_is_directory=True)
    try:
        with pytest.raises(OSError, match="redirected"):
            fleet._fleet_summary_reference(alias)
    finally:
        if os.name == "nt":
            os.rmdir(alias)
        else:
            alias.unlink()


def test_replacement_during_read_refused(tmp_path, monkeypatch):
    folder = tmp_path / "output"; folder.mkdir(); summary(folder)
    real_fstat = fleet.os.fstat; calls = []
    def changed(descriptor):
        value = real_fstat(descriptor); calls.append(1)
        if len(calls) == 2:
            (folder / "fleet-summary.json").write_bytes(b'{"changed":true}')
            value = real_fstat(descriptor)
        return value
    monkeypatch.setattr(fleet.os, "fstat", changed)
    with pytest.raises(ValueError, match="changed while"):
        fleet._fleet_summary_reference(folder)


def test_broker_partial_rewrites_hash_bound_index_and_preserves_current(tmp_path, monkeypatch):
    run = request(tmp_path); folder = publisher.generation_dir(Path(run.output_path), run.run_id)
    child_generations(run, folder, 1); raw = summary(folder, 1)
    pointer = Path(run.output_path) / publisher.CURRENT_POINTER; pointer.write_text("previous sentinel")
    monkeypatch.setattr(publisher, "publish_generation", lambda *args, **kwargs: pytest.fail("Partial fleet must not publish"))
    terminal = broker(run, folder, monkeypatch, 1)
    assert terminal["fleet_outcome"] == "partial" and terminal["artifact_readiness"] == "unavailable"
    assert terminal["state"] == "failed" and terminal["execution_outcome"] == "failed"
    index_bytes = Path(terminal["index_path"]).read_bytes(); payload = json.loads(index_bytes)
    assert terminal["index_sha256"] == hashlib.sha256(index_bytes).hexdigest()
    assert payload["fleet_summary"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert pointer.read_text() == "previous sentinel"


def test_complete_normal_index_uses_same_payload_and_publishes_only_after_manifest(tmp_path, monkeypatch):
    run = request(tmp_path); folder = publisher.generation_dir(Path(run.output_path), run.run_id)
    child_generations(run, folder, 2); summary(folder)
    children = fleet.collect_children(run, folder); fleet.write_index(run, folder, children)
    def finalized():
        publisher.write_fleet_manifest(folder, run.run_id, engine_version="fixture", repo_roots=[repo.repository_path for repo in run.repositories])
    terminal = broker(run, folder, monkeypatch, 0, finalized)
    assert terminal["fleet_outcome"] == "succeeded" and terminal["artifact_readiness"] == "ready"
    assert publisher.current_generation(Path(run.output_path)) == folder


@pytest.mark.parametrize("change", ["tampered", "missing"])
def test_complete_rejects_changed_summary_without_replacing_current(tmp_path, monkeypatch, change):
    run = request(tmp_path); folder = publisher.generation_dir(Path(run.output_path), run.run_id)
    child_generations(run, folder, 2); summary(folder)
    children = fleet.collect_children(run, folder); fleet.write_index(run, folder, children)
    pointer = Path(run.output_path) / publisher.CURRENT_POINTER; pointer.write_text("previous sentinel")
    def mutate():
        publisher.write_fleet_manifest(folder, run.run_id, engine_version="fixture", repo_roots=[repo.repository_path for repo in run.repositories])
        target = folder / "fleet-summary.json"
        target.write_bytes(b'{"changed":true}') if change == "tampered" else target.unlink()
    terminal = broker(run, folder, monkeypatch, 0, mutate)
    assert terminal["fleet_outcome"] == "failed" and terminal["artifact_readiness"] == "unavailable"
    assert terminal["error"] == "Fleet publication failed; previous results were preserved."
    assert pointer.read_text() == "previous sentinel"
