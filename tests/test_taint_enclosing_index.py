"""Differential coverage for the Python enclosing-function interval index."""
from __future__ import annotations

import ast
import bisect
import random
from pathlib import Path

import pytest

from attackmap import taint_flow
from attackmap.scanner import scan_repo


def _linear(funcs, line):
    best = None
    best_start = -1
    for start, end, node in funcs:
        if start <= line <= end and start > best_start:
            best, best_start = node, start
    return best


def _assert_lookup_equivalent(funcs, lines):
    starts, winners = taint_flow._enclosing_segments(funcs)
    for line in lines:
        position = bisect.bisect_right(starts, line) - 1
        actual = winners[position] if position >= 0 else None
        assert actual is _linear(funcs, line), (line, funcs)


def test_empty_inclusive_endpoints_ties_and_overlaps():
    _assert_lookup_equivalent([], range(-5, 110))
    a, b, c, d = [ast.Pass() for _ in range(4)]
    _assert_lookup_equivalent(
        [(2, 4, a), (2, 10, b), (3, 7, c), (6, 8, d),
         (-1, 99, ast.Pass()), (30, 29, ast.Pass()), (40, 40, a)],
        range(-5, 110),
    )


def test_deterministic_random_overlapping_intervals():
    rng = random.Random(3533)
    for _ in range(250):
        funcs = []
        for _ in range(rng.randrange(65)):
            start = rng.randrange(-3, 80)
            funcs.append((start, start + rng.randrange(-2, 40), ast.Pass()))
        rng.shuffle(funcs)
        _assert_lookup_equivalent(funcs, range(-5, 125))


def test_async_decorators_nested_functions_and_sibling_boundaries():
    flow = taint_flow._PyFlow('''@decorate
async def outer():
    @decorate
    def inner():
        return 1
    return inner()

class Container:
    @decorate
    async def sibling(self):
        return 2
''')
    for line in range(-3, 20):
        assert flow._enclosing(line) is _linear(flow.funcs, line)
    assert flow._enclosing(1).name == 'outer'
    assert flow._enclosing(3).name == 'inner'
    assert flow._enclosing(9).name == 'sibling'


@pytest.mark.parametrize('fixture', sorted(
    (Path(__file__).parent / 'fixtures' / 'taint_flow' / 'py').glob('*.py')
), ids=lambda path: path.name)
def test_python_flow_fixture_full_scan_matches_linear_lookup(fixture, tmp_path, monkeypatch):
    (tmp_path / fixture.name).write_bytes(fixture.read_bytes())
    indexed = scan_repo(tmp_path).model_dump(mode='json')
    monkeypatch.setattr(taint_flow._PyFlow, '_enclosing', lambda self, line: _linear(self.funcs, line))
    reference = scan_repo(tmp_path).model_dump(mode='json')
    assert indexed == reference
