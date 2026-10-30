"""Pinned Python plugin Django route normalization and coexistence controls."""
from pathlib import Path
from types import SimpleNamespace

from attackmap.analyzers import BuiltinPythonServiceAnalyzer, analyze_repository
from attackmap.sdk import AnalyzerMetadata, AnalyzerResult, Route


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
