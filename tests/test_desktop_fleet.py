"""Deterministic desktop fleet contract and process-boundary seams; no repo scan."""
import io
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from attackmap import desktop_fleet as fleet
from attackmap.desktop_capabilities import validate_desktop_request
from attackmap.run_contract import RunProgress, accepts_update, parse_run_message
from attackmap import scan_service as service
from attackmap.fleet import FleetScan, fleet_repo_ids
from artifact_fixture import write_generation


def request(tmp_path, **changes):
    roots = [tmp_path / "a space" / "same", tmp_path / "Žluťoučký" / "same"]
    for root in roots:
        root.mkdir(parents=True, exist_ok=True)
    repositories = [fleet.FleetRepository(repository_id=f"repo-{i}", repository_path=str(root))
                    for i, root in enumerate(roots)]
    return fleet.FleetRunRequest.model_validate(dict(run_id="fleet-fixture", generation=7, revision=0,
        repository_id=fleet.repository_set_id(repositories), repositories=repositories,
        output_path=str(tmp_path / "output"), **changes))


def test_set_identity_order_independent_but_not_basename(tmp_path):
    run = request(tmp_path)
    assert fleet.repository_set_id(list(reversed(run.repositories))) == run.repository_id
    assert len(set(fleet_repo_ids([Path(r.repository_path) for r in run.repositories]))) == 2
    assert len({fleet.child_run_id(run, r) for r in run.repositories}) == 2
    other = run.model_copy(update={"generation": 8})
    assert fleet.child_run_id(other, run.repositories[0]) != fleet.child_run_id(run, run.repositories[0])
    fleet.validate_roots(run)
    parsed = validate_desktop_request(run.model_dump(mode="json"))
    assert parsed == run == parse_run_message(run.model_dump(mode="json"))


@pytest.mark.parametrize("options", [
    {"provider": {"enable_ai": True}}, {"provider": {"enable_ai": True, "mode": "hunt"}},
    {"baseline": "C:/baseline.json"}, {"baseline": "C:/baseline.json", "fail_on_new_high": True},
    {"secrets_history": 1}, {"suppress_file": "C:/suppress.yaml"},
    {"provider": {"mode": "hunt"}}, {"provider": {"backend": "cli"}},
])
def test_unsupported_fails_before_admission(tmp_path, options, monkeypatch):
    run = request(tmp_path).model_dump(mode="json")
    run["options"] = options
    monkeypatch.setattr(service, "execute_scan_request", lambda *_: pytest.fail("dispatched"))
    with pytest.raises(ValueError):
        validate_desktop_request(run)


@pytest.mark.parametrize("change", ["root", "id", "set", "workers", "schema", "unknown"])
def test_duplicate_or_unrecognized_admission(tmp_path, change):
    raw = request(tmp_path).model_dump(mode="json")
    if change == "root":
        raw["repositories"][1]["repository_path"] = raw["repositories"][0]["repository_path"]
    elif change == "id":
        raw["repositories"][1]["repository_id"] = raw["repositories"][0]["repository_id"]
    elif change == "set":
        raw["repository_id"] = "fleet:" + "0" * 64
    elif change == "workers":
        raw["max_workers"] = 5
    elif change == "schema":
        raw["schema_version"] = "1.3"
    else:
        raw["repositories"][0]["secret"] = "never accepted"
    with pytest.raises(ValueError):
        validate_desktop_request(raw)


@pytest.mark.parametrize("path", ["relative", "../repo", "//host/share", "\\\\host\\share", "C:/bad\nrepo"])
def test_unsafe_root(path):
    with pytest.raises(ValidationError):
        fleet.FleetRepository(repository_id="id", repository_path=path)


def test_source_and_frozen_broker_are_distinct(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    assert fleet.broker_argv(tmp_path / "request.json")[:3] == [sys.executable, "-m", "attackmap.desktop_worker"]
    monkeypatch.setattr(sys, "frozen", True)
    argv = fleet.broker_argv(tmp_path / "request.json")
    assert argv[:2] == [sys.executable, "desktop-worker"] and "-m" not in argv


def child_generations(run, folder, count=2):
    from attackmap.artifact_publisher import generation_dir, publish_generation
    for slug, repository in list(zip(fleet_repo_ids([Path(r.repository_path) for r in run.repositories]), run.repositories))[:count]:
        base = folder / slug
        child_id = fleet.child_run_id(run, repository)
        child = generation_dir(base, child_id)
        write_generation(child, {"scan": {"root": str(Path(repository.repository_path).resolve())}})
        publish_generation(base, child_id)


def test_partial_index_is_exact_hash_bound_and_noncurrent(tmp_path):
    run = request(tmp_path)
    folder = Path(run.output_path)
    folder.mkdir()
    child_generations(run, folder, 1)
    rows = fleet.collect_children(run, folder, failed={fleet_repo_ids([Path(r.repository_path) for r in run.repositories])[1]})
    assert [row.state for row in rows] == ["completed", "failed"]
    assert rows[0].manifest_sha256 and rows[1].manifest_path is None
    target = fleet.write_index(run, folder, rows)
    assert json.loads(target.read_text())["children"][0]["child_repository_id"] == "repo-0"
    assert not (folder / "current.json").exists()
    Path(rows[0].manifest_path).write_text("tampered")
    assert fleet.collect_children(run, folder)[0].state == "failed"


def test_old_child_generation_cannot_satisfy_new_request(tmp_path):
    run = request(tmp_path)
    folder = Path(run.output_path)
    folder.mkdir()
    child_generations(run, folder)
    later = run.model_copy(update={"generation": 8})
    assert [r.state for r in fleet.collect_children(later, folder)] == ["skipped", "skipped"]
    current = RunProgress(**fleet._identity(run), revision=1, state="running")
    row = fleet.collect_children(later, folder)[0].model_copy(update={"revision": 2})
    assert not accepts_update(current, row)


def test_collecting_missing_children_does_not_allocate_generations(tmp_path):
    run = request(tmp_path)
    folder = Path(run.output_path)
    assert not folder.exists()
    assert [row.state for row in fleet.collect_children(run, folder)] == ["skipped", "skipped"]
    assert not folder.exists()


@pytest.mark.parametrize("workers", [1, 2])
def test_bounded_admission_preserves_success_and_order_on_cancel(tmp_path, monkeypatch, workers):
    repos = [tmp_path / str(i) for i in range(8)]
    cancelled = threading.Event()
    admitted = []
    request = service.ScanRequest(repo_paths=repos, output=tmp_path / "out", max_workers=workers,
        cancel_check=cancelled.is_set, echo=lambda *a, **k: None)
    def worker(request, repo_id, repo_path, *_):
        admitted.append(repo_id)
        cancelled.set()
        return SimpleNamespace(repo_id=repo_id)
    monkeypatch.setattr(service, "_run_fleet_repo_worker", worker)
    result = FleetScan()
    service._run_fleet_parallel(request, [], result, request.output)
    assert 1 <= len(admitted) <= workers
    assert [r.repo_id for r in result.results] == fleet_repo_ids(repos)[:len(admitted)]


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_completion_order_never_changes_core_order(tmp_path, monkeypatch, workers):
    repos = [tmp_path / str(i) for i in range(7)]
    request = service.ScanRequest(repo_paths=repos, output=tmp_path / "out", max_workers=workers,
        echo=lambda *a, **k: None)
    def worker(request, repo_id, repo_path, *_):
        if repo_path.name == "2":
            raise service._FleetRepoError(repo_id, str(repo_path), "fixture failure")
        return SimpleNamespace(repo_id=repo_id)
    monkeypatch.setattr(service, "_run_fleet_repo_worker", worker)
    result = FleetScan()
    service._run_fleet_parallel(request, [], result, request.output)
    ids = fleet_repo_ids(repos)
    assert [r.repo_id for r in result.results] == [id for id in ids if id != ids[2]]
    assert [r["repo_id"] for r in result.failed] == [ids[2]]


def test_terminal_cannot_mask_partial_as_complete(tmp_path):
    run = request(tmp_path)
    rows = fleet.collect_children(run, Path(run.output_path))
    with pytest.raises(ValidationError):
        fleet.FleetTerminal(**fleet._identity(run), revision=4, state="completed", execution_outcome="succeeded",
                            fleet_outcome="partial", children=rows)


def test_engine_reuses_neutral_mapping_without_real_scan(tmp_path, monkeypatch):
    run = request(tmp_path, max_workers=2, options={"recall": True, "isolated_analyzers": True, "time_budget_seconds": 12})
    def execute(request):
        assert request.repo_paths == [Path(r.repository_path) for r in run.repositories]
        assert request.max_workers == 2 and request.fleet_supervised and request.recall
        assert request.isolated_analyzers and request.time_budget_seconds == 12
        assert not request.llm and not request.install_missing and not request.atomic_output
        assert len(set(request.fleet_child_run_ids.values())) == 2
        argv = service._run_fleet_repo_argv(request, request.repo_paths[0], tmp_path / "out", [])
        assert "--isolated-analyzers" in argv and "--time-budget-seconds" in argv
        return service.RunSummary(exit_code=0)
    monkeypatch.setattr(service, "execute_scan_request", execute)
    assert fleet.run_engine(run) == 0


def test_named_profile_isolation_and_allowance_reach_fleet_service(tmp_path, monkeypatch):
    run = request(tmp_path, max_workers=3, options={"analyzer_profile": "node-atproto@1.0",
        "isolated_analyzers": True, "timeout_seconds": 900, "time_budget_seconds": 120})
    def execute(mapped):
        assert mapped.analyzer_profile_id == "node-atproto@1.0" and not mapped.modules
        assert mapped.isolated_analyzers and mapped.time_budget_seconds == 120
        assert mapped.max_workers == 3 and mapped.fleet_timeout_seconds == 900
        argv = service._run_fleet_repo_argv(mapped, mapped.repo_paths[0], tmp_path / "child", [])
        assert argv[argv.index("--analyzer-profile") + 1] == "node-atproto@1.0"
        assert "--isolated-analyzers" in argv
        return service.RunSummary(exit_code=0)
    monkeypatch.setattr(service, "execute_scan_request", execute)
    assert fleet.run_engine(validate_desktop_request(run.model_dump(mode="json"))) == 0


@pytest.mark.parametrize("changes", [
    {"options": {"analyzer_profile": "unknown@1.0"}},
    {"options": {"analyzer_profile": "node-atproto@1.0"}, "modules": ["config"]},
    {"options": {"future_knob": True}},
    {"options": {"fleet_input_byte_budget": 100}},
])
def test_fleet_never_silently_discards_selection_or_unwired_admission(tmp_path, changes):
    with pytest.raises(ValueError):
        request(tmp_path, **changes)


def test_profile_requires_explicit_fleet_capability(tmp_path):
    from attackmap.cli import app
    from attackmap.analyzer_contracts import AnalyzerMetadata
    from attackmap.analyzer_profiles import get_analyzer_profiles
    from attackmap.desktop_capabilities import build_capabilities, preflight_capabilities
    definition = next(item for item in get_analyzer_profiles() if item.name == "node-atproto")
    caps = build_capabilities(app, metadata=[AnalyzerMetadata(name=name) for name in definition.module_names])
    raw = request(tmp_path, options={"analyzer_profile": "node-atproto@1.0"}).model_dump(mode="json")
    assert preflight_capabilities(caps, request=raw)["supported"]
    assert "analyzer_profile" in caps["desktop"]["fleet_by_schema"]["1.4"]["scan_options"]
    del caps["desktop"]["fleet_by_schema"]["1.4"]["scan_options"]
    assert not preflight_capabilities(caps, request=raw)["supported"]
    assert preflight_capabilities(caps, request=request(tmp_path).model_dump(mode="json"))["supported"]
    raw["options"]["analyzer_profile"] = "python@1.0"
    assert not preflight_capabilities(caps, request=raw)["supported"]


@pytest.mark.parametrize("version", ["1.0", "1.1", "1.2", "1.3"])
def test_existing_request_defaults_and_bytes_unchanged(version):
    from attackmap.run_contract import CURRENT_SCHEMA_VERSION, RunRequest
    raw = dict(schema_version=version, run_id="old", repository_id="one", generation=1,
               revision=0, kind="request", repository_path="C:/repo", output_path="C:/out")
    before = RunRequest.model_validate(raw).model_dump_json()
    after = validate_desktop_request(raw).model_dump_json()
    assert before == after
    assert json.loads(after)["schema_version"] == version
    assert CURRENT_SCHEMA_VERSION == "1.2" and "repositories" not in json.loads(after)


def test_broker_partial_preserves_previous_current_and_rejects_stale_progress(tmp_path, monkeypatch):
    from attackmap.artifact_publisher import generation_dir
    run = request(tmp_path)
    folder = generation_dir(Path(run.output_path), run.run_id)
    child_generations(run, folder, 1)
    current = Path(run.output_path) / "current.json"
    current.write_text("previous sentinel")
    calls = []
    class Supervisor:
        def start(self, argv, **kwargs):
            calls.append(argv)
            row = fleet.collect_children(run, folder)[0].model_copy(update={"generation": 6, "state": "running",
                "manifest_path": None, "manifest_sha256": None})
            kwargs["on_progress"]({"event": "fleet_child", "child": row.model_dump(mode="json")})
            kwargs["on_done"](1, "private-secret-tail")
            return True
        def request_cancel(self):
            pytest.fail("No cancellation expected")
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    events = io.StringIO()
    assert fleet.serve(run, control=io.StringIO(""), events=events) == 0
    rows = [parse_run_message(json.loads(line)) for line in events.getvalue().splitlines()]
    terminal = rows[-1]
    assert terminal.fleet_outcome == "partial" and terminal.state == "failed"
    assert terminal.artifact_readiness == "unavailable"
    assert terminal.children[0].manifest_sha256 and terminal.children[1].state == "skipped"
    assert all(row.generation == 7 for row in rows)
    assert [row.revision for row in rows] == sorted({row.revision for row in rows})
    assert "private-secret-tail" not in events.getvalue() and current.read_text() == "previous sentinel"


def test_broker_cancel_owns_one_whole_supervisor_branch(tmp_path, monkeypatch):
    run = request(tmp_path)
    stopped = []
    class Supervisor:
        def start(self, argv, **kwargs):
            self.done = kwargs["on_done"]
            return True
        def request_cancel(self):
            stopped.append(True)
            self.done(130, "private tail")
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    events = io.StringIO()
    assert fleet.serve(run, control=io.StringIO("cancel\n"), events=events) == 0
    terminal = parse_run_message(json.loads(events.getvalue().splitlines()[-1]))
    assert stopped == [True] and terminal.fleet_outcome == "cancelled"
    assert terminal.artifact_readiness == "unavailable" and terminal.state == "cancelled"


def test_parent_publication_failure_with_complete_children_is_failed_not_partial(tmp_path, monkeypatch):
    from attackmap.artifact_publisher import generation_dir
    run = request(tmp_path)
    folder = generation_dir(Path(run.output_path), run.run_id)
    child_generations(run, folder)
    class Supervisor:
        def start(self, argv, **kwargs):
            kwargs["on_done"](1, "")
            return True
        def request_cancel(self):
            pytest.fail("Unexpected cancellation")
    monkeypatch.setattr("attackmap.execution.ProcessSupervisor", Supervisor)
    events = io.StringIO()
    assert fleet.serve(run, control=io.StringIO(""), events=events) == 0
    terminal = parse_run_message(json.loads(events.getvalue().splitlines()[-1]))
    assert terminal.fleet_outcome == "failed" and all(row.state == "completed" for row in terminal.children)
