"""AM049 / C35: finite default budgets with honest breach reporting.

Covers the deterministic elapsed-time budget (pipeline), the graph edge budget,
the stress-fixture generator's declarations, and cancellation-under-load: a
breached run must end COMPLETED with explicit partial coverage, never a hang
and never a truncated result presented as complete.
"""

import importlib.util
import json
import os
import time
from pathlib import Path

import pytest

from attackmap import pipeline
from attackmap.analyzers import BuiltinPythonWebAnalyzer
from attackmap.application_errors import AnalysisConfigurationError
from attackmap.artifact_publisher import current_generation
from attackmap.graph import build_graph, resolve_max_graph_edges
from attackmap.models import ExternalCall, ScanResult
from attackmap.pipeline import (
    DEFAULT_TIME_BUDGET_SECONDS,
    TIME_BUDGET_ENV,
    AnalyzeOptions,
    TimeBudget,
    resolve_time_budget_seconds,
    run_scan,
)

_spec = importlib.util.spec_from_file_location(
    "gen_stress_repo", Path(__file__).parents[1] / "tools" / "gen_stress_repo.py"
)
gen_stress_repo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen_stress_repo)


def _flask_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from flask import Flask, request\n"
        "import subprocess, os\n"
        "app = Flask(__name__)\n"
        "@app.route('/exec', methods=['POST'])\n"
        "def run_cmd():\n"
        "    cmd = request.args.get('cmd')\n"
        "    subprocess.call(cmd, shell=True)\n"
        "    return os.environ.get('ADMIN_TOKEN')\n",
        encoding="utf-8",
    )
    return repo


def _run(repo: Path, output: Path, **kwargs) -> tuple[pipeline.RunState, dict]:
    state = run_scan(AnalyzeOptions(
        repo_path=repo, output=output, atomic_output=False, no_progress=True,
        analyzers=[BuiltinPythonWebAnalyzer()], echo=lambda *a, **k: None, **kwargs,
    ))
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    return state, manifest


class _ExpiredBudget(TimeBudget):
    """A budget whose deadline is already in the past at every check."""

    def __post_init__(self) -> None:
        super().__post_init__()
        self._deadline = float("-inf")


class _BreachOnNthCheckBudget(TimeBudget):
    """Passes the first ``pass_count`` checks, breaches every later one."""

    pass_count: int = 1

    def __post_init__(self) -> None:
        super().__post_init__()
        self._seen = 0

    def check(self, skipped_stage: str) -> bool:
        self._seen += 1
        if self._seen > self.pass_count:
            self.exceeded_stage = skipped_stage
            return True
        return super().check(skipped_stage)


def test_time_budget_defaults_to_600_seconds_with_env_and_explicit_overrides(monkeypatch):
    monkeypatch.delenv(TIME_BUDGET_ENV, raising=False)
    assert resolve_time_budget_seconds() == DEFAULT_TIME_BUDGET_SECONDS == 600
    monkeypatch.setenv(TIME_BUDGET_ENV, "2")
    assert resolve_time_budget_seconds() == 2
    assert resolve_time_budget_seconds(30) == 30  # explicit beats env
    monkeypatch.setenv(TIME_BUDGET_ENV, "bogus")
    with pytest.raises(AnalysisConfigurationError):
        resolve_time_budget_seconds()
    with pytest.raises(AnalysisConfigurationError):
        resolve_time_budget_seconds(0)


def test_time_budget_check_overhead_is_negligible():
    budget = TimeBudget(seconds=60)
    started = time.perf_counter()
    for _ in range(100_000):
        budget.check("probe")
    per_check_ns = (time.perf_counter() - started) / 100_000 * 1e9
    # A run makes ~10 checks; even at 1 microsecond each that is 10 microseconds
    # of total overhead. The bound is 3 orders of magnitude above the ~240 ns
    # measured on the reference host, so it cannot mask a real regression.
    assert per_check_ns < 1_000, per_check_ns


def test_expired_budget_before_scan_ends_completed_with_partial_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "TimeBudget", _ExpiredBudget)
    repo = _flask_repo(tmp_path)
    state, manifest = _run(repo, tmp_path / "out")
    assert state.exit_code == 0
    assert manifest["scan_timing"]["outcome"] == "completed"
    assert manifest["time_budget"] == {
        "seconds": 600, "exceeded": True, "exceeded_before": "scan_and_merge",
    }
    # The scan itself was skipped: zero files, no scan stage, explicit markers.
    assert manifest["files_scanned"] == 0
    assert "scan_and_merge" not in {s["name"] for s in manifest["stages"]}
    assert manifest["analyzer_errors"][0]["error_type"] == "time_budget_exceeded"
    assert manifest["diagnostic_context"]["coverage"]["status"] == "partial"
    report = json.loads((tmp_path / "out" / "attackmap-report.json").read_text(encoding="utf-8"))
    assert any("ANALYSIS IS PARTIAL" in item for item in report["scan"]["limitations"])


def test_expired_budget_mid_run_keeps_scanned_evidence_and_skips_later_stages(tmp_path, monkeypatch):
    # The first check (pre-scan) passes, the next (suppress boundary) breaches:
    # the real scan evidence survives, suppress and later optional stages skip.
    monkeypatch.setattr(pipeline, "TimeBudget", _BreachOnNthCheckBudget)
    repo = _flask_repo(tmp_path)
    state, manifest = _run(repo, tmp_path / "out")
    assert state.exit_code == 0
    assert manifest["files_scanned"] == 1  # the scan genuinely ran
    assert manifest["time_budget"]["exceeded"] is True
    assert manifest["time_budget"]["exceeded_before"] == "suppress"
    stage_names = {s["name"] for s in manifest["stages"]}
    assert "scan_and_merge" in stage_names and "suppress" not in stage_names
    assert manifest["diagnostic_context"]["coverage"]["status"] == "partial"
    assert any(e["error_type"] == "time_budget_exceeded" for e in manifest["analyzer_errors"])


def test_manifest_declares_unbreached_budget_on_normal_run(tmp_path):
    repo = _flask_repo(tmp_path)
    state, manifest = _run(repo, tmp_path / "out", time_budget_seconds=600)
    assert state.exit_code == 0
    assert manifest["time_budget"] == {"seconds": 600, "exceeded": False}


def test_graph_edge_budget_default_env_and_explicit(monkeypatch):
    monkeypatch.delenv("ATTACKMAP_MAX_GRAPH_EDGES", raising=False)
    assert resolve_max_graph_edges() == 1_000_000
    monkeypatch.setenv("ATTACKMAP_MAX_GRAPH_EDGES", "5")
    assert resolve_max_graph_edges() == 5
    assert resolve_max_graph_edges(7) == 7
    monkeypatch.setenv("ATTACKMAP_MAX_GRAPH_EDGES", "bogus")
    with pytest.raises(AnalysisConfigurationError):
        resolve_max_graph_edges()
    with pytest.raises(AnalysisConfigurationError):
        resolve_max_graph_edges(0)


def test_graph_edge_budget_breach_keeps_partial_subgraph_usable():
    from attackmap.models import DatabaseHint, Route

    scan = ScanResult(
        root=".",
        routes=[Route(path="/users", method="GET", file="api.py")],
        databases=[DatabaseHint(kind=f"db{i}", file="a.py") for i in range(4)],
        external_calls=[ExternalCall(target=f"api_{i}.example.com", file="a.py") for i in range(4)],
    )
    graph = build_graph(scan, max_edges=3)
    assert graph.number_of_edges() == 3  # hard ceiling held
    assert graph.graph["edge_budget"] == 3
    assert graph.graph["edge_budget_exceeded"] is True
    assert "PARTIAL subgraph" in graph.graph["edge_budget_note"]
    assert any("graph edge budget (3) reached" in item for item in scan.limitations)
    # The already-built subgraph stays usable and nodes remain labelled.
    assert graph.has_edge("repo", "web")
    assert "db0" in graph.nodes and graph.nodes["db0"]["kind"] == "database"


def test_graph_without_breach_declares_budget_and_no_truncation():
    from attackmap.models import Route

    scan = ScanResult(root=".", routes=[Route(path="/users", method="GET", file="api.py")])
    graph = build_graph(scan)  # default 1,000,000
    assert graph.number_of_edges() >= 1
    assert graph.graph["edge_budget"] == 1_000_000
    assert "edge_budget_exceeded" not in graph.graph
    assert scan.limitations == []


def test_stress_generator_declares_exact_bytes_and_is_deterministic(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    declared_a = gen_stress_repo.generate_fixture(first, 40)
    declared_b = gen_stress_repo.generate_fixture(second, 40)
    assert declared_a["files"] == declared_b["files"] == 40
    assert declared_a["bytes"] == declared_b["bytes"]
    actual = sum(p.stat().st_size for p in first.rglob("*.py"))
    assert declared_a["bytes"] == actual  # declaration matches disk, not a guess
    names_a = sorted(p.relative_to(first).as_posix() for p in first.rglob("*.py"))
    names_b = sorted(p.relative_to(second).as_posix() for p in second.rglob("*.py"))
    assert names_a == names_b
    assert all(p.read_text(encoding="utf-8") == (second / n).read_text(encoding="utf-8")
               for p, n in zip(sorted(first.rglob("*.py")), names_b))
    sample = first / names_a[0]
    compile(sample.read_text(encoding="utf-8"), str(sample), "exec")  # valid Python
    assert declared_a["bytes"] / declared_a["files"] > 300  # analyzable, not empty stubs


@pytest.mark.skipif(
    os.environ.get("ATTACKMAP_STRESS_TESTS") != "1",
    reason="cancellation-under-load proof: a ~5000-file fixture needs ~2 minutes; "
           "run with ATTACKMAP_STRESS_TESTS=1",
)
def test_cancellation_under_load_terminates_promptly_with_partial_coverage(tmp_path):
    """A 1-second budget on a real 5,000-file load must not hang (C35).

    The breach is detected at the first stage boundary after the deadline; the
    in-flight scan stage runs to completion by design, so the whole run stays
    bounded by one stage's duration plus publication.
    """
    repo = tmp_path / "stress-repo"
    gen_stress_repo.generate_fixture(repo, 5_000)
    started = time.perf_counter()
    state, manifest = _run(repo, tmp_path / "out", time_budget_seconds=1)
    wall_seconds = time.perf_counter() - started
    # Prompt termination: bounded by fixture size on this host (measured
    # ~2-3 minutes), far from a hang. 10 minutes is the pipeline default this
    # test proves we do NOT wait for.
    assert wall_seconds < 600, wall_seconds
    assert state.exit_code == 0
    assert manifest["scan_timing"]["outcome"] == "completed"
    assert manifest["time_budget"]["exceeded"] is True
    assert manifest["time_budget"]["seconds"] == 1
    assert manifest["diagnostic_context"]["coverage"]["status"] == "partial"
    assert any(e["error_type"] == "time_budget_exceeded" for e in manifest["analyzer_errors"])
    stage_names = {s["name"] for s in manifest["stages"]}
    assert "scan_and_merge" in stage_names  # evidence was produced under load
    assert "suppress" not in stage_names  # later optional stages were skipped
    report = json.loads((tmp_path / "out" / "attackmap-report.json").read_text(encoding="utf-8"))
    assert report["scan"]["limitations"]  # the report itself carries the partial marker
