"""Isolated analyzer host (AM050 / criterion C36).

Controlled malicious-behavior fixtures under tests/fixtures/analyzer_host/
prove that a crashing, hanging, stdout-flooding, malformed-output,
filesystem-writing or namespace-forging analyzer cannot crash core or
corrupt another analyzer's output, and that every breach yields a NAMED
partial-coverage result. The filesystem-write fixture deliberately proves
what the host does NOT prevent (it is fault containment, not a sandbox).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

from attackmap.analyzer_contracts import (
    EXTRACTION_PROTOCOL_VERSION,
    check_extraction_compatibility,
    describe_extraction_protocol,
)
from attackmap.analyzer_host import (
    HOST_CRASH,
    HOST_INVALID_OUTPUT,
    HOST_MEMORY_LIMIT,
    HOST_OUTPUT_LIMIT,
    HOST_TIMEOUT,
    HostLimits,
    run_isolated_analyzer,
)
from attackmap.analyzers import BuiltinPythonWebAnalyzer, analyze_repository, get_registered_analyzers

FIXTURES = Path(__file__).parent / "fixtures" / "analyzer_host"
APP = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ok')\ndef ok():\n    return 'ok'\n"


def _fixture_analyzer(file_name: str, class_name: str):
    module_name = f"am050_{Path(file_name).stem}"
    spec = importlib.util.spec_from_file_location(module_name, FIXTURES / file_name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module  # standard pattern; also lets the host locate the file
    spec.loader.exec_module(module)
    return getattr(module, class_name)()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP, encoding="utf-8")
    return repo


def _limits(**overrides) -> HostLimits:
    values = dict(timeout_seconds=30, stream_bytes=8 * 1024 * 1024, result_bytes=64 * 1024 * 1024, memory_bytes=0)
    values.update(overrides)
    return HostLimits(**values)


# ---------------------------------------------------------------------------
# Versioned extraction protocol
# ---------------------------------------------------------------------------


def test_extraction_protocol_version_is_pinned() -> None:
    assert EXTRACTION_PROTOCOL_VERSION == "1.0"
    described = describe_extraction_protocol()
    assert described["version"] == EXTRACTION_PROTOCOL_VERSION
    for key in ("input", "output", "metadata", "isolation"):
        assert key in described


def test_registered_analyzers_are_protocol_compatible() -> None:
    """Every built-in (and any installed plugin) analyzer satisfies
    extraction protocol 1.0 — backwards compatible with the current
    official analyzers."""
    analyzers = get_registered_analyzers()
    assert analyzers, "expected at least the built-in analyzers"
    for analyzer in analyzers:
        report = check_extraction_compatibility(analyzer)
        assert report.compatible, f"{analyzer.name}: {report.issues}"


def test_fixture_analyzers_are_protocol_compatible() -> None:
    for file_name, class_name in (
        ("good_plugin.py", "GoodPluginAnalyzer"),
        ("evil_crash.py", "EvilCrashAnalyzer"),
        ("evil_namespace.py", "EvilNamespaceAnalyzer"),
    ):
        report = check_extraction_compatibility(_fixture_analyzer(file_name, class_name))
        assert report.compatible, f"{file_name}: {report.issues}"


def test_incompatible_object_is_reported_not_raised() -> None:
    report = check_extraction_compatibility(object())
    assert not report.compatible
    assert report.issues


# ---------------------------------------------------------------------------
# Host: well-behaved round trip
# ---------------------------------------------------------------------------


def test_good_analyzer_round_trips_through_host(tmp_path: Path) -> None:
    outcome = run_isolated_analyzer(_fixture_analyzer("good_plugin.py", "GoodPluginAnalyzer"), _repo(tmp_path), _limits())
    assert outcome.ok, (outcome.error_type, outcome.message)
    assert [r.path for r in outcome.result.routes] == ["/good"]
    assert outcome.result.root  # result carries the repo root


def test_good_analyzer_merges_alongside_in_process_sibling(tmp_path: Path) -> None:
    scan = analyze_repository(
        _repo(tmp_path),
        analyzers=[BuiltinPythonWebAnalyzer(), _fixture_analyzer("good_plugin.py", "GoodPluginAnalyzer")],
        isolated_analyzers=True,
        isolated_limits=_limits(),
    )
    assert sorted(r.path for r in scan.routes) == ["/good", "/ok"]
    by_path = {r.path: r.source_analyzer for r in scan.routes}
    assert by_path == {"/ok": "python-web", "/good": "good-plugin"}
    assert scan.analyzer_errors == []


# ---------------------------------------------------------------------------
# Host: malicious behaviors produce named partial coverage
# ---------------------------------------------------------------------------


def test_crashing_analyzer_yields_named_partial_coverage(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    evil = _fixture_analyzer("evil_crash.py", "EvilCrashAnalyzer")
    outcome = run_isolated_analyzer(evil, repo, _limits())
    assert outcome.error_type == HOST_CRASH
    assert "RuntimeError" in outcome.message
    assert outcome.limitation and "partial coverage" in outcome.limitation


def test_crashing_analyzer_does_not_take_down_siblings(tmp_path: Path) -> None:
    scan = analyze_repository(
        _repo(tmp_path),
        analyzers=[BuiltinPythonWebAnalyzer(), _fixture_analyzer("evil_crash.py", "EvilCrashAnalyzer")],
        isolated_analyzers=True,
        isolated_limits=_limits(),
    )
    assert [r.path for r in scan.routes] == ["/ok"]  # sibling output intact
    assert [(e.analyzer, e.error_type) for e in scan.analyzer_errors] == [("evil-crash", HOST_CRASH)]
    assert any("evil-crash" in note and "partial coverage" in note for note in scan.limitations)


def test_default_stays_in_process_for_exceptions(tmp_path: Path) -> None:
    """Without the flag the historic #220 behavior is unchanged: the
    analyzer's own exception type is recorded, not a host event."""
    scan = analyze_repository(
        _repo(tmp_path),
        analyzers=[_fixture_analyzer("evil_crash.py", "EvilCrashAnalyzer")],
    )
    assert [(e.analyzer, e.error_type) for e in scan.analyzer_errors] == [("evil-crash", "RuntimeError")]


def test_hanging_analyzer_is_force_killed(tmp_path: Path) -> None:
    """evil_hang ignores SIGBREAK/SIGTERM, so only the supervisor's verified
    forced tree kill can end it — proven by the run returning at all,
    well inside the fixture's own 120 s sleep."""
    started = time.monotonic()
    outcome = run_isolated_analyzer(
        _fixture_analyzer("evil_hang.py", "EvilHangAnalyzer"), _repo(tmp_path),
        _limits(timeout_seconds=3),
    )
    elapsed = time.monotonic() - started
    assert outcome.error_type == HOST_TIMEOUT
    assert elapsed < 30, f"forced kill took {elapsed:.1f}s"


def test_stdout_flood_terminates_at_byte_cap(tmp_path: Path) -> None:
    outcome = run_isolated_analyzer(
        _fixture_analyzer("evil_flood.py", "EvilFloodAnalyzer"), _repo(tmp_path),
        _limits(stream_bytes=256 * 1024, timeout_seconds=20),
    )
    assert outcome.error_type == HOST_OUTPUT_LIMIT
    assert outcome.limitation and "stdout/stderr byte cap" in outcome.limitation


def test_malformed_output_is_rejected_not_merged(tmp_path: Path) -> None:
    outcome = run_isolated_analyzer(
        _fixture_analyzer("evil_malformed.py", "EvilMalformedAnalyzer"), _repo(tmp_path), _limits()
    )
    assert outcome.error_type == HOST_INVALID_OUTPUT
    assert "ScanResult" in outcome.message or "Validation" in outcome.message


@pytest.mark.skipif(os.name != "nt", reason="job-object memory cap is Windows-only (documented)")
def test_memory_hog_terminated_by_job_commit_cap(tmp_path: Path) -> None:
    outcome = run_isolated_analyzer(
        _fixture_analyzer("evil_memory.py", "EvilMemoryAnalyzer"), _repo(tmp_path),
        _limits(timeout_seconds=60, memory_bytes=256 * 1024 * 1024),
    )
    assert outcome.error_type == HOST_MEMORY_LIMIT, (outcome.error_type, outcome.message)


def test_write_outside_working_dir_is_not_prevented_and_scan_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Documents honestly what the host does NOT prevent: the worker keeps
    the user's full filesystem access. The sentinel is written; core and
    the sibling analyzer are unaffected."""
    outside = tmp_path / "outside-repo"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    monkeypatch.setenv("ATTACKMAP_FIXTURE_ESCAPE_TARGET", str(sentinel))

    scan = analyze_repository(
        _repo(tmp_path),
        analyzers=[BuiltinPythonWebAnalyzer(), _fixture_analyzer("evil_escape.py", "EvilEscapeAnalyzer")],
        isolated_analyzers=True,
        isolated_limits=_limits(),
    )
    assert sentinel.exists(), "fixture premise: the host does not restrict filesystem writes"
    assert sentinel.read_text(encoding="utf-8").startswith("the isolated analyzer host did NOT prevent")
    assert sorted(r.path for r in scan.routes) == ["/escape", "/ok"]  # sibling intact
    assert scan.analyzer_errors == []


def test_forged_namespace_cannot_corrupt_sibling_output(tmp_path: Path) -> None:
    """evil-namespace forges a sibling's provenance and injects
    analyzer_errors framing python-web. Core owns the merge: the duplicate
    route loses to the sibling's first-seen signal and the forged error
    entries never reach the merged result."""
    scan = analyze_repository(
        _repo(tmp_path),
        analyzers=[BuiltinPythonWebAnalyzer(), _fixture_analyzer("evil_namespace.py", "EvilNamespaceAnalyzer")],
        isolated_analyzers=True,
        isolated_limits=_limits(),
    )
    assert [r.path for r in scan.routes] == ["/ok"]
    forged_errors = [e for e in scan.analyzer_errors if e.analyzer == "python-web"]
    assert forged_errors == [], "forged analyzer_errors must not survive the merge"
    # The builtin remains the first-seen typed representative. The isolated
    # duplicate is attributed to its selected emitter in the normalized view.
    assert scan.routes[0].source_analyzer == "python-web"
    origins = [origin for signal in scan.all_signals() for origin in signal.origins]
    assert any(origin.analyzer == "evil-namespace" and
               origin.properties.get("untrusted_claimed_producer") == "python-web"
               for origin in origins)


def test_isolated_failure_with_strict_raises(tmp_path: Path) -> None:
    from attackmap.analyzer_host import AnalyzerHostError

    with pytest.raises(AnalyzerHostError, match=HOST_CRASH):
        analyze_repository(
            _repo(tmp_path),
            analyzers=[_fixture_analyzer("evil_crash.py", "EvilCrashAnalyzer")],
            isolated_analyzers=True,
            isolated_limits=_limits(),
            strict=True,
        )


def test_redacted_secret_in_host_tail(tmp_path: Path) -> None:
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    crash_file = tmp_path / "leaky_crash.py"
    crash_file.write_text(
        "from types import SimpleNamespace\n"
        "METADATA = SimpleNamespace(name='leaky-crash', display_name='leaky', version='0.1.0',\n"
        "    description='d', scope='s', targets=[], languages=[], priority=500,\n"
        "    experimental=True, enabled_by_default=True)\n"
        "class LeakyCrashAnalyzer:\n"
        "    metadata = METADATA\n"
        "    @property\n"
        "    def name(self): return self.metadata.name\n"
        "    def detect(self, root): return True\n"
        "    def analyze(self, root):\n"
        f"        raise RuntimeError('token={secret}')\n",
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location("am050_leaky_crash", crash_file)
    module = importlib.util.module_from_spec(spec)
    sys.modules["am050_leaky_crash"] = module
    spec.loader.exec_module(module)
    outcome = run_isolated_analyzer(module.LeakyCrashAnalyzer(), _repo(tmp_path), _limits())
    assert outcome.error_type == HOST_CRASH
    assert secret not in outcome.message
