"""Real installed-distribution checks; run via verify_wp039_installed_python.py."""
import importlib
import json
import os
from pathlib import Path

import pytest

from attackmap.analyzer_host import HostLimits
from attackmap.analyzers import (BuiltinPythonServiceAnalyzer, analyze_repository,
    discover_installed_analyzers, get_builtin_repository_analyzers, resolve_analyzer_run)
from attackmap.merge import MERGE_SCHEMA

pytestmark = pytest.mark.skipif(not os.environ.get("WP039_PINNED_TARGET"),
    reason="Requires task-owned offline pinned installation; use tools/verify_wp039_installed_python.py")

URLS = """from django.urls import path, re_path, include
urlpatterns = [
    path('health/', health),
    # path('commented/', health),
    path('api/', include('missing.urls')),
    re_path(r'^literal/$', health),
    re_path(r'^items/\\d+/$', health),
]
"""


def installed(package):
    matches = [a for a in discover_installed_analyzers()
        if a._attackmap_entry_point.dist.name == package]
    assert len(matches) == 1
    module_path = Path(importlib.import_module(type(matches[0]).__module__).__file__).resolve()
    assert module_path.is_relative_to(Path(os.environ["WP039_PINNED_TARGET"]).resolve())
    return matches[0]


def evidence(name, data):
    output = os.environ.get("WP039_EVIDENCE")
    if output:
        (Path(output) / name).write_text(json.dumps(data, indent=2), encoding="utf-8")


def execute(root, analyzers, isolated):
    plan = resolve_analyzer_run(root, analyzers=analyzers)
    result = analyze_repository(root, run_plan=plan, strict=True,
        isolated_analyzers=isolated, isolated_limits=HostLimits(timeout_seconds=45))
    assert not result.analyzer_errors
    assert all(row.execution == "succeeded" for row in plan.ledger.entries)
    return result, plan.ledger.model_dump(mode="json")


@pytest.mark.parametrize("isolated", [False, True], ids=["in-process", "isolated"])
def test_actual_pinned_plugin_route_normalization_and_ledger(tmp_path, isolated):
    (tmp_path / "project").mkdir()
    (tmp_path / "project/urls.py").write_text(URLS, encoding="utf-8")
    (tmp_path / "project/foreign.py").write_text("def path(*args): pass\nurlpatterns = [path('foreign/', handler)]\n", encoding="utf-8")
    plugin = installed("attackmap-analyzer-python")
    # The actual pinned extractor reproduces the historical false surfaces.
    raw = plugin.analyze(tmp_path)
    assert {"/commented/", "/api/", "^literal/$"} <= {route.path for route in raw.routes}
    result, ledger = execute(tmp_path, [plugin, BuiltinPythonServiceAnalyzer()], isolated)
    routes = [(r.path, r.method, r.file, r.source_analyzer) for r in result.routes]
    assert routes == [("/health/", "ANY", "project/urls.py", "python"),
        ("/literal/", "ANY", "project/urls.py", "python")]
    row = next(row for row in ledger["entries"] if row["name"] == "python")
    assert row["origin"] == "plugin"
    assert row["package"]["name"] == "attackmap-analyzer-python"
    assert row["entry_point"]["value"] == "attackmap_analyzer_python:PythonAnalyzer"
    assert row["signal_counts"]["routes"] == 2
    assert row["execution_mode"] == ("isolated" if isolated else "in_process")
    if isolated:
        reference, _ = execute(tmp_path, [plugin, BuiltinPythonServiceAnalyzer()], False)
        assert result.all_signals() == reference.all_signals()
    signals = [signal.model_dump(mode="json") for signal in result.all_signals()]
    assert not any(signal["kind"] == "route" and signal["properties"]["path"]
        in {"/commented/", "/api/", "^literal/$", r"^items/\d+/$", "/foreign/"} for signal in signals)
    evidence(f"pinned-{'isolated' if isolated else 'in-process'}.json", dict(routes=routes, ledger=ledger,
        normalized_signals=signals, in_process_isolated_normalized_signal_parity=isolated))


@pytest.mark.parametrize("isolated", [False, True], ids=["in-process", "isolated"])
def test_actual_pin_regex_mount_class_auth_has_no_unmounted_or_raw_regex_surface(tmp_path, isolated):
    files = {
        "settings.py": "ROOT_URLCONF='project.urls'\n",
        "project/urls.py": "from django.urls import re_path, include\nurlpatterns=[re_path(r'^api/', include('app.urls'))]\n",
        "app/urls.py": "from django.urls import re_path\nfrom .views import Detail\nurlpatterns=[re_path(r'^items/(?P<pk>[0-9]+)/$', Detail.as_view())]\n",
        "app/views.py": "from django.views import View\nfrom django.contrib.auth.mixins import LoginRequiredMixin\nclass Detail(LoginRequiredMixin, View):\n def get(self, request): return None\n",
    }
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    plugin = installed("attackmap-analyzer-python")
    assert {r.path for r in plugin.analyze(tmp_path).routes} == {"^api/", "^items/(?P<pk>[0-9]+)/$"}
    result, ledger = execute(tmp_path, [plugin, BuiltinPythonServiceAnalyzer()], isolated)
    assert [(r.path, r.auth, r.file, r.line) for r in result.routes] == [
        ("/api/items/{pk}/", "required", "app/urls.py", 3)]
    assert "app/views.py:3" in result.routes[0].guard_evidence
    route_signals = [s for s in result.all_signals() if s.kind == "route"]
    assert {s.properties["path"] for s in route_signals} == {"/api/items/{pk}/"}
    evidence(f"class-routes-{'isolated' if isolated else 'in-process'}.json", dict(
        routes=[r.model_dump(mode="json") for r in result.routes], ledger=ledger,
        route_signals=[s.model_dump(mode="json") for s in route_signals]))


def test_real_colliding_entrypoints_preserve_explicit_selected_implementation(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    from importlib.metadata import entry_points
    points = [p for p in entry_points(group="attackmap.analyzers") if p.name == "python"]
    assert len(points) == 2
    # Select the last real installed entrypoint: old name-only worker loads first.
    selected = next(a for a in discover_installed_analyzers() if
        a._attackmap_entry_point.dist.name == points[-1].dist.name)
    direct, direct_ledger = execute(tmp_path, [selected], False)
    isolated, isolated_ledger = execute(tmp_path, [selected], True)
    assert isolated.routes == direct.routes
    assert isolated_ledger["entries"][0]["package"] == direct_ledger["entries"][0]["package"]
    evidence("installed-collision.json", dict(entrypoints=[dict(name=p.name, value=p.value, package=p.dist.name) for p in points],
        selected=direct_ledger["entries"][0]["package"], routes=[r.model_dump() for r in isolated.routes], ledger=isolated_ledger))


@pytest.mark.parametrize("isolated", [False, True], ids=["in-process", "isolated"])
def test_actual_pin_mounted_function_auth_reexport_keeps_unknown_sibling(tmp_path, isolated):
    files = {
        "settings.py": "ROOT_URLCONF='project.urls'\n",
        "project/urls.py": "from django.urls import path, include\nurlpatterns=[path('api/', include('app.urls'))]\n",
        "app/__init__.py": "from . import fake as auth\n",
        "app/urls.py": "from django.urls import re_path\nfrom .views import private, unresolved\nurlpatterns=[re_path(r'^private/(?P<pk>[0-9]+)/$', private), re_path(r'^unresolved/(?P<pk>[0-9]+)/$', unresolved)]\n",
        "app/auth.py": "from django.contrib.auth.decorators import login_required as gate\n",
        "app/fake.py": "def gate(view): return view\n",
        "app/views.py": "from .auth import gate\nfrom foreign import login_required\n@gate\ndef private(request): return None\n@login_required\ndef unresolved(request): return None\n",
    }
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    plugin = installed("attackmap-analyzer-python")
    raw = plugin.analyze(tmp_path)
    assert "^private/(?P<pk>[0-9]+)/$" in {r.path for r in raw.routes}
    result, ledger = execute(tmp_path, [plugin, BuiltinPythonServiceAnalyzer()], isolated)
    assert [(r.path, r.auth, r.file, r.line) for r in result.routes] == [
        ("/api/private/{pk}/", "required", "app/urls.py", 3),
        ("/api/unresolved/{pk}/", "unknown", "app/urls.py", 3)]
    assert result.routes[0].guards == ["@login_required (app/views.py:3)"]
    assert "app/views.py:4" in result.routes[0].guard_evidence
    assert not result.routes[1].guards
    assert any("function-view authentication unresolved in app/urls.py:3" in item for item in result.limitations)
    route_signals = [s for s in result.all_signals() if s.kind == "route"]
    assert {s.properties["path"] for s in route_signals} == {"/api/private/{pk}/", "/api/unresolved/{pk}/"}
    if isolated:
        reference, _ = execute(tmp_path, [plugin, BuiltinPythonServiceAnalyzer()], False)
        assert result.all_signals() == reference.all_signals()
    evidence(f"decorator-routes-{'isolated' if isolated else 'in-process'}.json", dict(
        raw_routes=[r.model_dump(mode="json") for r in raw.routes],
        routes=[r.model_dump(mode="json") for r in result.routes], ledger=ledger,
        route_signals=[s.model_dump(mode="json") for s in route_signals],
        in_process_isolated_normalized_signal_parity=isolated))


@pytest.mark.parametrize("isolated", [False, True], ids=["in-process", "isolated"])
def test_actual_pin_package_shadow_never_uses_unrelated_auth_sibling(tmp_path, isolated):
    files = {
        "settings.py": "ROOT_URLCONF='project.urls'\n",
        "project/urls.py": "from django.urls import path, include\nurlpatterns=[path('api/', include('app.urls'))]\n",
        "app/__init__.py": "from . import fake as auth\n",
        "app/urls.py": "from django.urls import re_path\nfrom .views import private, forced, ordinary\nurlpatterns=[re_path(r'^private/(?P<pk>[0-9]+)/$', private), re_path(r'^forced/(?P<pk>[0-9]+)/$', forced), re_path(r'^ordinary/(?P<pk>[0-9]+)/$', ordinary)]\n",
        "app/auth.py": "from django.contrib.auth.decorators import login_required as gate\n",
        "app/fake.py": "def gate(view): return view\n",
        "app/unused/__init__.py": "",
        "app/unused/auth.py": "from django.contrib.auth.decorators import login_required as gate\n",
        "app/views.py": "from app import auth\nimport app.auth as checks\n@auth.gate\ndef private(request): return None\n@checks.gate\ndef forced(request): return None\nimport app.unused\n@app.unused.auth.gate\ndef ordinary(request): return None\n",
    }
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    result, ledger = execute(tmp_path, [installed("attackmap-analyzer-python"), BuiltinPythonServiceAnalyzer()], isolated)
    assert [(r.path, r.auth) for r in result.routes] == [
        ("/api/private/{pk}/", "unknown"), ("/api/forced/{pk}/", "required"),
        ("/api/ordinary/{pk}/", "unknown")]
    assert result.routes[0].guards == [] and result.routes[0].guard_evidence is None
    assert result.routes[1].guards == ["@login_required (app/views.py:5)"]
    assert not result.routes[2].guards and result.routes[2].guard_evidence is None
    assert any("function-view authentication unresolved in app/urls.py:3" in item for item in result.limitations)
    if isolated:
        reference, _ = execute(tmp_path, [installed("attackmap-analyzer-python"), BuiltinPythonServiceAnalyzer()], False)
        assert result.all_signals() == reference.all_signals()
    evidence(f"package-shadow-{'isolated' if isolated else 'in-process'}.json", dict(
        routes=[r.model_dump(mode="json") for r in result.routes], ledger=ledger,
        in_process_isolated_normalized_signal_parity=isolated))


@pytest.mark.parametrize("isolated", [False, True], ids=["in-process", "isolated"])
def test_actual_pin_package_view_targets_preserve_explicit_submodule_imports(tmp_path, isolated):
    files = {
        "settings.py": "ROOT_URLCONF='project.urls'\n",
        "project/urls.py": "from django.urls import path, include\nurlpatterns=[path('api/', include('app.urls'))]\n",
        "app/__init__.py": "from . import public_views as views\n",
        "app/urls.py": "from django.urls import re_path\nfrom app import views as package_views\nfrom . import views as relative_views\nimport app.views as forced_views\nfrom app.views import private as forced_symbol\nimport app\nurlpatterns=[re_path(r'^package/(?P<pk>[0-9]+)/$', package_views.private), re_path(r'^relative/(?P<pk>[0-9]+)/$', relative_views.private), re_path(r'^module/(?P<pk>[0-9]+)/$', forced_views.private), re_path(r'^symbol/(?P<pk>[0-9]+)/$', forced_symbol), re_path(r'^ordinary/(?P<pk>[0-9]+)/$', app.unloaded_views.private)]\n",
        "app/auth.py": "from django.contrib.auth.decorators import login_required as gate\n",
        "app/views.py": "from .auth import gate\n@gate\ndef private(request): return None\n",
        "app/unloaded_views.py": "from .auth import gate\n@gate\ndef private(request): return None\n",
        "app/public_views.py": "def private(request): return None\n",
    }
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    result, ledger = execute(tmp_path, [installed("attackmap-analyzer-python"), BuiltinPythonServiceAnalyzer()], isolated)
    assert [(r.path, r.auth) for r in result.routes] == [
        ("/api/package/{pk}/", "unknown"), ("/api/relative/{pk}/", "unknown"),
        ("/api/module/{pk}/", "required"), ("/api/symbol/{pk}/", "required"),
        ("/api/ordinary/{pk}/", "unknown")]
    assert all(not r.guards and r.guard_evidence is None for r in result.routes[:2])
    assert all("app/views.py:3" in r.guard_evidence for r in result.routes[2:4])
    assert not result.routes[4].guards and result.routes[4].guard_evidence is None
    if isolated:
        reference, _ = execute(tmp_path, [installed("attackmap-analyzer-python"), BuiltinPythonServiceAnalyzer()], False)
        assert result.all_signals() == reference.all_signals()
    evidence(f"view-target-bindings-{'isolated' if isolated else 'in-process'}.json", dict(
        routes=[r.model_dump(mode="json") for r in result.routes], ledger=ledger,
        in_process_isolated_normalized_signal_parity=isolated))


def test_installed_python_does_not_claim_node_only_repository(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"node-only","dependencies":{"express":"4.0.0"}}', encoding="utf-8")
    (tmp_path / "app.js").write_text("const express = require('express');\nconst app = express();\napp.get('/health', (req,res) => res.send('ok'));\n", encoding="utf-8")
    plugin = installed("attackmap-analyzer-python")
    assert not plugin.detect(tmp_path)
    plan = resolve_analyzer_run(tmp_path, analyzers=[*get_builtin_repository_analyzers(), plugin])
    result = analyze_repository(tmp_path, run_plan=plan, strict=True)
    row = next(row for row in plan.ledger.entries if row.name == "python")
    assert row.applicability == "unmatched" and row.execution == "skipped"
    assert all("python" not in language.lower() for language in result.languages)
    assert any(route.path == "/health" for route in result.routes)
    evidence("node-only-negative.json", dict(languages=result.languages, python_ledger=row.model_dump(mode="json")))


def test_juice_shop_non_regression_with_actual_pinned_plugin():
    root = Path("C:/tmp/juice-shop")
    assert root.is_dir(), "Required real Juice Shop repository unavailable"
    plugin = installed("attackmap-analyzer-python")
    builtin = get_builtin_repository_analyzers()
    baseline = analyze_repository(root, analyzers=[*builtin, plugin], strict=True)
    candidate = analyze_repository(root, analyzers=[*builtin, plugin], strict=True,
        isolated_analyzers=True, isolated_limits=HostLimits(timeout_seconds=90))
    fields = [rule.attr for rule in MERGE_SCHEMA]
    facts = lambda scan: {field: [item.model_dump(mode="json") for item in getattr(scan, field)] for field in fields}
    assert facts(candidate) == facts(baseline)
    assert candidate.languages == baseline.languages
    assert not candidate.analyzer_errors
    evidence("juice-shop.json", dict(repository=str(root), pinned_applicable=plugin.detect(root),
        comparison="Actual installed pinned plugin plus builtins, in-process versus isolated",
        signal_families_identical=fields, counts={field: len(getattr(candidate, field)) for field in fields},
        languages=candidate.languages, scope="Real repository deterministic extraction; no provider or GUI calls"))
