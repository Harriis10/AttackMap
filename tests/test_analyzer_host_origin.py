"""Worker reconstruction must preserve the selected entry point's origin."""
from argparse import Namespace
from types import SimpleNamespace

import pytest

from attackmap import analyzer_host as host


def point(package="selected-plugin", value="selected:Analyzer", version="1.0"):
    return SimpleNamespace(name="python", value=value,
        dist=SimpleNamespace(name=package, version=version), load=lambda: value)


def args(**updates):
    values = dict(entry_point="python", entry_point_value="selected:Analyzer",
        distribution="selected-plugin", distribution_version="1.0",
        analyzer_module=None, analyzer_file=None, analyzer_attr=None)
    return Namespace(**(values | updates))


def test_load_spec_preserves_discovered_origin():
    analyzer = SimpleNamespace(_attackmap_entry_point_name="python", _attackmap_entry_point=point())
    spec = host._analyzer_load_spec(analyzer)
    assert spec["distribution"] == "selected-plugin"
    assert spec["distribution_version"] == "1.0"
    assert spec["entry_point_value"] == "selected:Analyzer"


def test_worker_loads_selected_origin_even_when_colliding_name_is_first(monkeypatch):
    monkeypatch.setattr(host, "entry_points", lambda **_: [point("other-plugin", "other:Analyzer"), point()])
    assert host._load_analyzer(args()) == "selected:Analyzer"


@pytest.mark.parametrize("points", [
    [point("other-plugin")], [point(value="changed:Analyzer")],
    [point(version="2.0")], [point(), point()], [],
])
def test_missing_changed_or_ambiguous_origin_never_executes_other_plugin(monkeypatch, points):
    loaded = []
    for item in points:
        item.load = lambda: loaded.append(True)
    monkeypatch.setattr(host, "entry_points", lambda **_: points)
    with pytest.raises(RuntimeError, match="could not load analyzer"):
        host._load_analyzer(args())
    assert loaded == []


def test_distribution_identity_accepts_standard_name_normalization(monkeypatch):
    monkeypatch.setattr(host, "entry_points", lambda **_: [point("Selected_Plugin")])
    assert host._load_analyzer(args()) == "selected:Analyzer"


def test_recorded_origin_failure_does_not_fall_back_to_other_module(monkeypatch):
    monkeypatch.setattr(host, "entry_points", lambda **_: [])
    monkeypatch.setattr(host.importlib, "import_module", lambda _: pytest.fail("Unexpected fallback load"))
    with pytest.raises(RuntimeError, match="could not load analyzer"):
        host._load_analyzer(args(analyzer_module="other", analyzer_attr="Analyzer"))


def test_legacy_unique_name_works_and_ambiguous_name_fails(monkeypatch):
    legacy = args(entry_point_value=None, distribution=None, distribution_version=None)
    monkeypatch.setattr(host, "entry_points", lambda **_: [point()])
    assert host._load_analyzer(legacy) == "selected:Analyzer"
    monkeypatch.setattr(host, "entry_points", lambda **_: [point(), point("other")])
    with pytest.raises(RuntimeError):
        host._load_analyzer(legacy)
