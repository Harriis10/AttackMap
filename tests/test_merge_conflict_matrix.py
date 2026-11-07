"""C11 conflict matrix: multi-analyzer contradictions survive merge losslessly.

Parametrized over JSON fixtures in ``tests/fixtures/signal_conflicts/``. Every
scenario pins the C11 contract end to end:

- contradictory property values from two analyzers both survive as
  ``SignalConflict`` with corroborating origins (analyzer names preserved);
- the normalized Signal view is permutation-invariant — any input ordering
  yields byte-identical merged observations and observation IDs;
- merging never mutates analyzer-owned input objects (deep-copy proof:
  full JSON snapshots before/after, plus output mutation cannot leak back);
- identical observations corroborate without double-counting files
  (``scanned_files`` stays a unique union).

These extend ``test_merge_signal_provenance.py`` (which covers the route auth
pair inline) with a fixture-driven matrix across signal kinds and properties.
"""

from __future__ import annotations

import json
from itertools import permutations
from pathlib import Path

import pytest

from attackmap.analyzers import merge_analyzer_results
from attackmap.models import ScanResult

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "signal_conflicts"
SCENARIOS = sorted(path.stem for path in FIXTURE_DIR.glob("*.json"))


def _load(name: str) -> tuple[list[ScanResult], dict]:
    payload = json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))
    return [ScanResult.model_validate(item) for item in payload["inputs"]], payload["expected"]


@pytest.mark.parametrize("name", SCENARIOS)
def test_contradictions_and_corroboration_survive_merge(name: str) -> None:
    inputs, expected = _load(name)
    merged = merge_analyzer_results(inputs)
    signals = merged.all_signals()
    assert signals, "expected at least one normalized observation"

    if "conflict_field" in expected:
        conflicts = {
            conflict.field: sorted(conflict.values)
            for signal in signals
            for conflict in signal.conflicts
        }
        assert conflicts.get(expected["conflict_field"]) == expected["conflict_values"]
    else:
        assert all(not signal.conflicts for signal in signals)

    analyzers = {
        origin.analyzer for signal in signals for origin in signal.origins if origin.analyzer
    }
    assert analyzers == set(expected["origin_analyzers"])

    # Corroboration must not duplicate the observation itself.
    assert len({signal.observation_id for signal in signals}) == len(signals)
    if "merged_routes" in expected:
        assert len(merged.routes) == expected["merged_routes"]
    if "merged_taint_chains" in expected:
        assert len(merged.taint_chains) == expected["merged_taint_chains"]
    if "typed_auth_after_upgrade" in expected:
        assert merged.routes[0].auth == expected["typed_auth_after_upgrade"]


@pytest.mark.parametrize("name", SCENARIOS)
def test_merged_observations_are_permutation_invariant(name: str) -> None:
    # Fresh objects per permutation (analyzer results are reusable, but the
    # invariance claim must not depend on shared mutable state).
    reference, _ = _load(name)
    outputs = []
    all_ids = []
    for order in permutations(range(len(reference))):
        inputs, _ = _load(name)
        merged = merge_analyzer_results([inputs[i] for i in order]).all_signals()
        outputs.append([signal.model_dump() for signal in merged])
        all_ids.append([signal.observation_id for signal in merged])
    assert all(output == outputs[0] for output in outputs), "input order changed merged observations"
    assert all(row == all_ids[0] for row in all_ids), "input order changed observation IDs"


@pytest.mark.parametrize("name", SCENARIOS)
def test_merge_never_mutates_analyzer_inputs(name: str) -> None:
    inputs, _ = _load(name)
    snapshots = [item.model_dump_json() for item in inputs]
    merged = merge_analyzer_results(inputs)
    # Merging the output again, then mutating the *output* deeply, must not
    # reach back into analyzer-owned input objects.
    remerged = merge_analyzer_results([merged, merged])
    for signal in remerged.all_signals():
        signal.conflicts.clear()
        for origin in signal.origins:
            origin.analyzer = "tampered"
    for route in remerged.routes:
        route.auth = "tampered"
    assert [item.model_dump_json() for item in inputs] == snapshots, "merge mutated analyzer inputs"


@pytest.mark.parametrize("name", SCENARIOS)
def test_overlapping_coverage_is_counted_once(name: str) -> None:
    inputs, expected = _load(name)
    merged = merge_analyzer_results(inputs)
    # Every fixture enumerates scanned_files, so unique-file coverage must hold.
    assert merged.scanned_files == sorted(set(merged.scanned_files))
    assert merged.files_scanned == len(merged.scanned_files)
    if "unique_scanned_files" in expected:
        assert merged.scanned_files == expected["unique_scanned_files"]


def test_fixture_expectations_are_self_consistent() -> None:
    # Guard: every fixture declares which contract dimension it exercises.
    for name in SCENARIOS:
        _, expected = _load(name)
        assert "origin_analyzers" in expected, name
        assert ("conflict_field" in expected) == bool(expected.get("conflict_values"), ), name
