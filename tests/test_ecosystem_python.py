"""Tests for the Python web-services ecosystem overlay (AM052 / C38).

Deterministic expected-signal assertions against the
``python-service-app`` fixture, silence checks on non-Python-web control
repos, evidence path/line assertions, and analyzer-contract compatibility
for the thin registration class modeled on the analyzers.py patch.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.analyzer_contracts import (
    EXTRACTION_PROTOCOL_VERSION,
    check_extraction_compatibility,
)
from attackmap.analyzers import BuiltinPythonWebAnalyzer, merge_analyzer_results
from attackmap.ecosystem_python import detect_python_service_repo, scan_python_services
from attackmap.models import ScanResult
from attackmap.sdk import AnalyzerMetadata

FIXTURE = Path(__file__).parent / "fixtures" / "python-service-app"


@pytest.fixture(scope="module")
def result() -> ScanResult:
    return scan_python_services(FIXTURE)


# ---------------------------------------------------------------------------
# Applicability detection
# ---------------------------------------------------------------------------


def test_detect_accepts_python_service_fixture() -> None:
    assert detect_python_service_repo(FIXTURE) is True


def test_detect_silent_on_non_python_repo(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {}}', encoding="utf-8")
    (tmp_path / "index.js").write_text("require('http');\n", encoding="utf-8")
    assert detect_python_service_repo(tmp_path) is False


def test_detect_silent_on_plain_python_repo(tmp_path: Path) -> None:
    (tmp_path / "script.py").write_text("import json\nprint(json.dumps({'a': 1}))\n", encoding="utf-8")
    assert detect_python_service_repo(tmp_path) is False


def test_detect_ignores_framework_markers_in_test_scaffolding(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
    )
    assert detect_python_service_repo(tmp_path) is False


def test_scan_silent_on_non_python_repo(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "x"}', encoding="utf-8")
    (tmp_path / "index.js").write_text("require('http');\n", encoding="utf-8")
    result = scan_python_services(tmp_path)
    assert result.routes == []
    assert result.auth_hints == []
    assert result.framework_hints == []
    assert result.files_scanned == 0


# ---------------------------------------------------------------------------
# FastAPI cross-file wiring
# ---------------------------------------------------------------------------


def test_fastapi_include_dependencies_upgrade_route_auth(result: ScanResult) -> None:
    """The include-site `dependencies=[Depends(verify_tenant)]` lives in
    app/main.py — invisible to per-file extraction of routers/items.py."""
    routes = {(r.path, r.method): r for r in result.routes}
    get_item = routes[("/items/{item_id}", "GET")]
    assert get_item.auth == "required"
    assert get_item.line == 12
    assert any("app/main.py:15" in g for g in get_item.guards)
    create_item = routes[("/items", "POST")]
    assert create_item.auth == "required"
    assert create_item.line == 17


def test_fastapi_include_without_dependencies_leaves_route_unknown(result: ScanResult) -> None:
    """webhooks.router is included without auth deps; the overlay must not
    invent a guard (the webhook exposure family owns that claim)."""
    assert all(r.path != "/webhooks/stripe" for r in result.routes)


def test_fastapi_mount_hint_documents_cross_file_prefix(result: ScanResult) -> None:
    hint = next(h for h in result.framework_hints if h.hint == "fastapi_router_mount:/api/items")
    assert (hint.file, hint.line) == ("app/main.py", 15)
    assert "app/routers/items.py" in (hint.evidence_text or "")


def test_fastapi_boundaries_and_hardening(result: ScanResult) -> None:
    framework = {(h.hint, h.file): h.line for h in result.framework_hints}
    assert framework[("asgi_app:fastapi", "app/main.py")] == 11
    assert framework[("hardening_middleware:TrustedHostMiddleware", "app/main.py")] == 13
    entrypoints = {(h.hint, h.file): h.line for h in result.entrypoint_hints}
    assert entrypoints[("asgi_server:uvicorn", "app/main.py")] == 27


def test_fastapi_auth_dependency_definition_hint(result: ScanResult) -> None:
    hint = next(
        h for h in result.auth_hints
        if h.hint == "auth_dependency_definition" and h.file == "app/deps.py"
    )
    assert hint.line == 11  # def get_current_user


# ---------------------------------------------------------------------------
# Flask cross-file wiring
# ---------------------------------------------------------------------------


def test_flask_blueprint_before_request_hook_guards_routes(result: ScanResult) -> None:
    hook = next(h for h in result.auth_hints if h.hint == "blueprint_auth_hook:require_api_key")
    assert (hook.file, hook.line) == ("web/api_views.py", 10)
    routes = {(r.path, r.method): r for r in result.routes}
    for key in ("/v1/health", "GET"), ("/v1/orders", "POST"), ("/v1/orders/<int:order_id>", "DELETE"):
        assert routes[key].auth == "required", key
    assert any("web/auth.py:19" in g for g in routes[("/v1/orders", "POST")].guards)


def test_flask_custom_decorator_validated_at_definition_site(result: ScanResult) -> None:
    """@require_subscription is not a known auth decorator name; the overlay
    validates the wrapper body in web/auth.py before claiming a guard."""
    hint = next(h for h in result.auth_hints if h.hint == "custom_auth_decorator:require_subscription")
    assert (hint.file, hint.line) == ("web/auth.py", 25)
    route = next(r for r in result.routes if r.method == "DELETE" and r.path == "/v1/orders/<int:order_id>")
    assert route.line == 33
    assert any("web/auth.py:25" in g for g in route.guards)


def test_flask_blueprint_mount_hint(result: ScanResult) -> None:
    hint = next(h for h in result.framework_hints if h.hint == "flask_blueprint_mount:/api/v1")
    assert (hint.file, hint.line) == ("web/flask_app.py", 11)
    assert "web/api_views.py" in (hint.evidence_text or "")


def test_flask_orm_scoping_hints(result: ScanResult) -> None:
    scoped = next(
        h for h in result.auth_hints
        if h.hint == "orm_scoped_query" and h.file == "web/api_views.py"
    )
    assert scoped.line == 21
    assert scoped.confidence >= 0.8


# ---------------------------------------------------------------------------
# Django URLconf tree
# ---------------------------------------------------------------------------


def test_django_routes_extracted_with_include_recursion(result: ScanResult) -> None:
    """The per-file pass extracts no Django routes; every one of these is
    net-new surface with exact evidence lines."""
    expected = {
        ("/health/", "ANY", "django_site/urls.py", 12, "unknown"),
        ("/api/notes/", "ANY", "django_site/api/urls.py", 9, "unknown"),
        ("/api/notes/search", "ANY", "django_site/api/urls.py", 10, "unknown"),
        ("/api/notes/{pk}", "ANY", "django_site/api/urls.py", 11, "required"),
    }
    actual = {
        (r.path, r.method, r.file, r.line, r.auth)
        for r in result.routes
        if r.file.endswith("urls.py")
    }
    assert actual == expected


def test_django_view_decorator_auth_resolves_cross_file(result: ScanResult) -> None:
    route = next(r for r in result.routes if r.path == "/api/notes/{pk}")
    assert route.auth == "required"
    assert any("login_required" in g and "django_site/api/views.py:21" in g for g in route.guards)


def test_django_urlconf_and_admin_observations(result: ScanResult) -> None:
    framework = {(h.hint, h.file): h.line for h in result.framework_hints}
    assert framework[("django_admin_surface", "django_site/urls.py")] == 10
    assert framework[("urlconf_include:django_site.api.urls", "django_site/urls.py")] == 11
    assert framework[("django_middleware_chain", "django_site/settings.py")] == 20
    assert framework[("wsgi_boundary:django", "django_site/wsgi.py")] == 10


def test_django_global_auth_middleware_strength_hint(result: ScanResult) -> None:
    hint = next(h for h in result.auth_hints if h.hint == "global_auth_middleware")
    assert (hint.file, hint.line) == ("django_site/settings.py", 20)


def test_django_login_required_middleware_infers_global_auth(tmp_path: Path) -> None:
    (tmp_path / "site").mkdir()
    (tmp_path / "site" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "site" / "settings.py").write_text(
        'MIDDLEWARE = [\n    "django.contrib.auth.middleware.LoginRequiredMiddleware",\n]\n'
        'ROOT_URLCONF = "site.urls"\n',
        encoding="utf-8",
    )
    (tmp_path / "site" / "urls.py").write_text(
        "from django.urls import path\nfrom site import views\n"
        'urlpatterns = [\n    path("notes/", views.list_notes),\n]\n',
        encoding="utf-8",
    )
    (tmp_path / "site" / "views.py").write_text("def list_notes(request):\n    return None\n", encoding="utf-8")
    result = scan_python_services(tmp_path)
    route = next(r for r in result.routes if r.path == "/notes/")
    assert route.auth == "required"
    assert route.guards == ["LoginRequiredMiddleware (settings MIDDLEWARE)"]


def test_django_unresolvable_root_urlconf_records_limitation(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(
        'ROOT_URLCONF = "missing.urls"\nMIDDLEWARE = ["django.middleware.common.CommonMiddleware"]\n',
        encoding="utf-8",
    )
    result = scan_python_services(tmp_path)
    assert any("missing.urls" in note for note in result.limitations)


# ---------------------------------------------------------------------------
# ORM query scoping / raw escapes
# ---------------------------------------------------------------------------


def test_raw_sql_escape_hints(result: ScanResult) -> None:
    databases = {(d.kind, d.file): d for d in result.databases}
    extra = databases[("sql", "django_site/api/views.py")]
    assert extra.line == 17
    assert "extra" in (extra.evidence_text or "")
    text_escape = databases[("sql", "db.py")]
    assert text_escape.line == 20
    assert "text()" in (text_escape.evidence_text or "")


def test_orm_scoping_hints_bola_relevant(result: ScanResult) -> None:
    unscoped = {(h.file): h for h in result.auth_hints if h.hint == "orm_unscoped_lookup"}
    assert unscoped["app/routers/items.py"].line == 14
    assert unscoped["django_site/api/views.py"].line == 24
    assert unscoped["django_site/api/views.py"].confidence <= 0.5  # inferred, stays low
    scoped = {h.file for h in result.auth_hints if h.hint == "orm_scoped_query"}
    assert scoped == {"web/api_views.py", "django_site/api/views.py", "db.py"}


# ---------------------------------------------------------------------------
# Background / service surface, settings, CLI
# ---------------------------------------------------------------------------


def test_celery_service_surface(result: ScanResult) -> None:
    service = next(h for h in result.service_hints if h.hint == "celery_worker")
    assert (service.file, service.line) == ("tasks/celery_app.py", 6)
    broker = next(d for d in result.databases if d.file == "tasks/celery_app.py")
    assert broker.kind == "redis"


def test_celery_dispatch_emits_queue_external_calls(result: ScanResult) -> None:
    calls = {(c.target, c.file): c.line for c in result.external_calls}
    assert calls[("queue://celery/orders", "tasks/jobs.py")] == 18
    assert calls[("queue://celery/default", "tasks/jobs.py")] == 19


def test_celery_task_entrypoint(result: ScanResult) -> None:
    hint = next(h for h in result.entrypoint_hints if h.hint == "celery_task")
    assert (hint.file, hint.line) == ("tasks/jobs.py", 7)


def test_settings_secret_flow(result: ScanResult) -> None:
    secrets = {(s.name, s.file): s for s in result.secret_hints}
    assert secrets[("API_TOKEN", "app/settings.py")].line == 10
    assert secrets[("SESSION_SECRET", "app/settings.py")].line == 11
    assert secrets[("STRIPE_WEBHOOK_SECRET", "app/routers/webhooks.py")].line == 16
    assert secrets[("DJANGO_SECRET_KEY", "django_site/settings.py")].line == 6
    assert secrets[("DB_PASSWORD", "django_site/settings.py")].line == 36
    assert all(s.kind == "env_reference" for s in result.secret_hints)


def test_cli_entrypoint(result: ScanResult) -> None:
    hint = next(h for h in result.entrypoint_hints if h.hint == "cli_entrypoint")
    assert (hint.file, hint.line) == ("cli.py", 7)


def test_oversized_file_records_limitation(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    (tmp_path / "big.py").write_text("# padding\n# " + "x" * 1_100_000 + "\n", encoding="utf-8")
    result = scan_python_services(tmp_path)
    assert any("big.py" in note for note in result.limitations)
    assert result.files_scanned == 1


# ---------------------------------------------------------------------------
# Evidence hygiene
# ---------------------------------------------------------------------------


def test_every_signal_carries_file_and_line(result: ScanResult) -> None:
    for route in result.routes:
        assert route.file and route.line and route.line >= 1
    for family in (
        result.auth_hints, result.service_hints, result.framework_hints,
        result.entrypoint_hints, result.secret_hints, result.databases,
        result.external_calls,
    ):
        for hint in family:
            assert hint.file, hint
            assert hint.line and hint.line >= 1, hint
    assert result.scanned_files  # coverage enumerated, not implied by hint locations


def test_no_finding_like_output(result: ScanResult) -> None:
    """Extraction-only contract: no findings, no scores, no report text."""
    assert result.vulnerabilities == []
    assert result.signals == []


# ---------------------------------------------------------------------------
# Analyzer contract + merge compatibility
# ---------------------------------------------------------------------------


def _registered_python_service_analyzer():
    from attackmap.analyzers import BuiltinPythonServiceAnalyzer

    return BuiltinPythonServiceAnalyzer()


def test_extraction_protocol_compatibility() -> None:
    assert EXTRACTION_PROTOCOL_VERSION == "1.0"
    compatibility = check_extraction_compatibility(_registered_python_service_analyzer())
    assert compatibility.compatible, compatibility.issues


def test_registration_metadata_shape() -> None:
    metadata = _registered_python_service_analyzer().metadata
    assert metadata.name == "python-service"
    assert metadata.priority == 50  # framework layer: after python-web (20), before app overlays
    assert metadata.experimental is True
    assert metadata.enabled_by_default is True


def test_merge_upgrades_python_web_routes_without_duplicates() -> None:
    """First-seen python-web routes win; the overlay's auth resolution fills
    in via the routes merge upgrade (`_upgrade_route_auth`) — no duplicate
    attack surface, no lost Django routes."""
    base = BuiltinPythonWebAnalyzer().analyze(FIXTURE)
    overlay = scan_python_services(FIXTURE)
    merged = merge_analyzer_results([base, overlay], root=FIXTURE)
    base_keys = {(r.path, r.method) for r in base.routes}
    overlay_keys = {(r.path, r.method) for r in overlay.routes}
    merged_keys = {(r.path, r.method) for r in merged.routes}
    assert base_keys | overlay_keys == merged_keys  # nothing duplicated, nothing dropped
    items = next(r for r in merged.routes if r.path == "/items/{item_id}" and r.method == "GET")
    assert items.auth == "required"
    assert any("app/main.py:15" in g for g in items.guards)
