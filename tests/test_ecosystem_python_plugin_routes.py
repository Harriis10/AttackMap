"""Pinned Python plugin Django route normalization and coexistence controls."""
from pathlib import Path
from types import SimpleNamespace

from attackmap.analyzers import BuiltinPythonServiceAnalyzer, analyze_repository
from attackmap.sdk import AnalyzerMetadata, AnalyzerResult, Route
from attackmap.models import Signal
from attackmap.python_django_routes import normalize_pinned_python_plugin_routes


URLS = """from django.urls import path, re_path, include
urlpatterns = [
    path('health/', health),
    # path('commented/', health),
    path('api/', include('app.urls')),
    re_path(r'^literal/$', health),
    re_path(r'^items/\\d+/$', health),
]
Route('/starlette', endpoint=health)
"""

PINNED_ROUTES = [
    ("/health/", "ANY", "project/urls.py", 3),
    ("/commented/", "ANY", "project/urls.py", 4),
    ("/api/", "ANY", "project/urls.py", 5),
    ("^literal/$", "ANY", "project/urls.py", 6),
    (r"^items/\d+/$", "ANY", "project/urls.py", 7),
    ("/starlette", "ANY", "project/urls.py", 9),
]


class FakePythonPlugin:
    metadata = AnalyzerMetadata(
        name="python",
        version="0.1.0",
        description="Pinned-plugin route projection for extraction regression tests.",
        priority=10,
    )

    def __init__(self, distribution="attackmap-analyzer-python"):
        self._attackmap_entry_point = SimpleNamespace(dist=SimpleNamespace(name=distribution))

    @property
    def name(self):
        return self.metadata.name

    def detect(self, root):
        return True

    def analyze(self, root):
        return AnalyzerResult(
            root=str(root),
            routes=[Route(path=path, method=method, file=file, line=line)
                    for path, method, file, line in PINNED_ROUTES],
        )


def write_urls(root: Path):
    (root / "project").mkdir()
    (root / "project" / "urls.py").write_text(URLS, encoding="utf-8")


def test_pinned_plugin_django_routes_are_validated_and_deduplicated(tmp_path):
    write_urls(tmp_path)

    result = analyze_repository(
        tmp_path,
        analyzers=[FakePythonPlugin(), BuiltinPythonServiceAnalyzer()],
    )

    assert [(route.path, route.method, route.file) for route in result.routes] == [
        ("/health/", "ANY", "project/urls.py"),
        ("/literal/", "ANY", "project/urls.py"),
        ("/starlette", "ANY", "project/urls.py"),
    ]


def test_route_normalization_is_scoped_to_the_official_python_distribution(tmp_path):
    write_urls(tmp_path)

    result = analyze_repository(
        tmp_path,
        analyzers=[FakePythonPlugin(distribution="third-party-python")],
    )

    assert [(route.path, route.file) for route in result.routes] == [
        (path, file) for path, _method, file, _line in PINNED_ROUTES
    ]


def test_materialized_route_observations_match_normalization_before_transport(tmp_path):
    expected = FakePythonPlugin().analyze(tmp_path)
    transported = expected.model_copy(deep=True)
    transported.signals = transported.all_signals()
    files = {"project/urls.py": URLS}
    normalize_pinned_python_plugin_routes(expected, files)
    normalize_pinned_python_plugin_routes(transported, files)
    assert transported.routes == expected.routes
    assert transported.all_signals() == expected.all_signals()
    literal = next(signal for signal in transported.all_signals() if signal.label == "ANY /literal/")
    assert literal.properties["path"] == "/literal/"
    assert all(origin.properties["path"] == "/literal/" for origin in literal.origins)
    assert literal.observation_id == next(signal.observation_id for signal in expected.all_signals()
        if signal.label == "ANY /literal/")


def test_route_observation_reconciliation_preserves_independent_producers_and_locations(tmp_path):
    result = FakePythonPlugin().analyze(tmp_path)
    result.signals = result.all_signals()
    rejected = next(signal for signal in result.signals if signal.label == "ANY /commented/")
    rejected.origins[0].analyzer = "python"
    foreign = rejected.origins[0].model_copy(deep=True)
    foreign.analyzer = "other-producer"
    rejected.origins.append(foreign)
    original_foreign = foreign.model_copy(deep=True)
    unrelated = [
        Signal(kind="route", label="ANY /commented/", file="another.py", line=4,
            properties={"method": "ANY", "path": "/commented/"}),
        Signal(kind="route", label="POST /commented/", file="project/urls.py", line=4,
            properties={"method": "POST", "path": "/commented/"}),
        Signal(kind="route", label="ANY /commented/", file="project/urls.py", line=99,
            properties={"method": "ANY", "path": "/commented/"}),
        Signal(kind="auth", label="ANY /commented/", file="project/urls.py", line=4,
            properties={"method": "ANY", "path": "/commented/"}),
    ]
    originals = [signal.model_copy(deep=True) for signal in unrelated]
    result.signals.extend(unrelated)
    normalize_pinned_python_plugin_routes(result, {"project/urls.py": URLS})
    preserved = next(signal for signal in result.signals if signal.kind == "route"
        and signal.label == "ANY /commented/" and signal.file == "project/urls.py" and signal.line == 4)
    assert preserved.origins == [original_foreign]
    assert all(signal in result.signals for signal in originals)


def test_renamed_route_preserves_foreign_origin_as_separate_observation(tmp_path):
    result = FakePythonPlugin().analyze(tmp_path)
    result.signals = result.all_signals()
    literal = next(signal for signal in result.signals if signal.label == "ANY ^literal/$")
    foreign = literal.origins[0].model_copy(deep=True)
    foreign.analyzer = "other-producer"
    foreign.line = 99
    foreign.evidence_text = "Independent producer evidence"
    foreign.properties["auth"] = "required"
    literal.origins.append(foreign)
    original_foreign = foreign.model_copy(deep=True)
    normalize_pinned_python_plugin_routes(result, {"project/urls.py": URLS})
    old = next(signal for signal in result.signals if signal.label == "ANY ^literal/$")
    new = next(signal for signal in result.signals if signal.label == "ANY /literal/")
    assert old.origins == [original_foreign]
    assert (old.file, old.line, old.evidence_text) == (foreign.file, 99, foreign.evidence_text)
    assert old.properties == foreign.properties
    assert not old.conflicts
    assert len(new.origins) == 1 and new.origins[0].properties["path"] == "/literal/"


def test_reconciliation_matches_individual_origin_not_representative_line(tmp_path):
    result = FakePythonPlugin().analyze(tmp_path)
    result.signals = result.all_signals()
    literal = next(signal for signal in result.signals if signal.label == "ANY ^literal/$")
    independent = literal.origins[0].model_copy(deep=True)
    independent.line = 99
    literal.origins.append(independent)
    literal.line = 99
    normalize_pinned_python_plugin_routes(result, {"project/urls.py": URLS})
    old = next(signal for signal in result.signals if signal.label == "ANY ^literal/$")
    new = next(signal for signal in result.signals if signal.label == "ANY /literal/")
    assert old.origins == [independent]
    assert len(new.origins) == 1 and new.origins[0].line == 6
    assert (new.file, new.line, new.evidence_text) == (new.origins[0].file, 6, new.origins[0].evidence_text)
    assert new.properties == new.origins[0].properties


def test_untrusted_claimed_producer_cannot_bypass_rejected_route_policy(tmp_path):
    result = FakePythonPlugin().analyze(tmp_path)
    result.signals = result.all_signals()
    rejected = next(signal for signal in result.signals if signal.label == "ANY /commented/")
    rejected.origins[0].analyzer = "python"
    rejected.origins[0].properties["untrusted_claimed_producer"] = "other-producer"
    normalize_pinned_python_plugin_routes(result, {"project/urls.py": URLS})
    assert not any(signal.label == "ANY /commented/" for signal in result.signals)
