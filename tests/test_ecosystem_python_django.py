"""Static Django declarations/auth evidence; no Django installation or execution."""
from __future__ import annotations

import pytest

import attackmap.python_django_routes as django_routes
from attackmap.python_django_routes import DJANGO_ADMIN_TARGET, DjangoAuthResolver, django_view_auth, extract_django_url_entries


def extract(source):
    return extract_django_url_entries("project/urls.py", source)


def views(source="def public(request):\n    return None\n", urls="from app import views\n"):
    return {"project/urls.py": urls, "app/views.py": source}


def test_import_bound_factories_aliases_and_converter_paths():
    entries, limits = extract("from django.urls import path as route\nfrom app import views\nurlpatterns = [route('items/<int:pk>/', views.public)]\n")
    assert entries == [("items/{pk}/", "views.public", 3)]
    assert limits == []


@pytest.mark.parametrize("imports,factory", [
    ("import django.urls", "django.urls.path"),
    ("import django.urls as routes", "routes.path"),
    ("from django import urls", "urls.path"),
])
def test_qualified_framework_module_factories(imports, factory):
    entries, limits = extract(f"{imports}\nurlpatterns = [{factory}('', health)]\n")
    assert entries == [("", "health", 2)]
    assert not limits


def test_keyword_only_arguments_and_static_augmented_lists():
    entries, limits = extract("from django.urls import path\nurlpatterns = []\nurlpatterns += [path(route='one/', view=first)]\nurlpatterns += (path('two/', second),)\n")
    assert [entry[:2] for entry in entries] == [("one/", "first"), ("two/", "second")]
    assert not limits


@pytest.mark.parametrize("pattern,expected", [("^literal/$", "literal/"), (r"^v1\.0/status/$", "v1.0/status/"), ("^$", "")])
def test_only_exact_literal_anchored_regexes_are_normalized(pattern, expected):
    entries, limits = extract(f"from django.urls import re_path\nurlpatterns = [re_path({pattern!r}, public)]\n")
    assert entries[0][0] == expected
    assert not limits


@pytest.mark.parametrize("pattern", [r"^items/\d+/$", r"^api/(one|two)/$", "^health/?$", "prefix/", "^prefix/", "^prefix.$"])
def test_regex_groups_quantifiers_and_prefix_matches_are_not_guessed(pattern):
    entries, limits = extract(f"from django.urls import re_path\nurlpatterns = [re_path({pattern!r}, public)]\n")
    assert entries == []
    assert any("regex route is unsupported" in limit for limit in limits)


@pytest.mark.parametrize("target,imports", [
    ("include(('app.urls', 'app'), namespace='one')", "from django.urls import include"),
    ("mount(app_urls, namespace='two')", "from django.urls import include as mount\nfrom app import urls as app_urls"),
    ("include('app.urls')", "from django.urls import include"),
])
def test_literal_namespace_and_imported_module_includes_are_canonical(target, imports):
    entries, limits = extract(f"from django.urls import path\n{imports}\nurlpatterns = [path('api/', {target})]\n")
    assert entries[0][:2] == ("api/", "include('app.urls')")
    assert not limits


@pytest.mark.parametrize("target", ["include(resolve_urlconf())", "include('app.urls', namespace=get_namespace())", "include((patterns, 'app'))"])
def test_dynamic_include_is_skipped_with_named_limitation(target):
    entries, limits = extract(f"from django.urls import path, include\nurlpatterns = [path('api/', {target})]\n")
    assert entries == []
    assert any("include" in limit for limit in limits)


@pytest.mark.parametrize("namespace", ["True", "False", "1", "namespace_value"])
def test_boolean_numeric_and_dynamic_namespaces_are_not_strings(namespace):
    entries, limits = extract(f"from django.urls import path, include\nurlpatterns = [path('api/', include('app.urls', namespace={namespace}))]")
    assert entries == [] and limits


def test_duplicate_include_namespace_is_not_canonicalized():
    entries, limits = extract("from django.urls import path, include\nurlpatterns = [path('api/', include('app.urls', namespace='a', namespace='b'))]")
    assert entries == [] and limits


def test_admin_marker_requires_exact_framework_import_binding():
    entries, limits = extract("from django.urls import path\nfrom django.contrib import admin\nurlpatterns = [path('admin/', admin.site.urls)]")
    assert entries[0][1] == DJANGO_ADMIN_TARGET and not limits
    for imports in ("from foreign import admin", "from django.contrib import admin\nadmin = foreign"):
        entries, limits = extract(f"from django.urls import path\n{imports}\nurlpatterns = [path('admin/', admin.site.urls)]")
        assert entries[0][1] != DJANGO_ADMIN_TARGET


def test_plain_function_name_starting_include_is_a_terminal_view():
    entries, limits = extract("from django.urls import path\nfrom app.views import include_view\nurlpatterns = [path('included-name/', include_view)]")
    assert entries[0][1] == "include_view" and not limits


def test_only_registered_ast_calls_are_extracted():
    entries, limits = extract("from django.urls import path\nurlpatterns = []\n# path('comment/', public)\nnote = \"path('string/', public)\"\ndef factory():\n    return path('function/', public)\n")
    assert entries == []
    assert not limits


@pytest.mark.parametrize("source", [
    "from foreign import path\nurlpatterns = [path('foreign/', public)]",
    "from django.urls import path\ndef path(*args): pass\nurlpatterns = [path('shadowed/', public)]",
    "from django.urls import path\nurlpatterns = [path('literal/' + suffix, public)]",
    "from django.urls import path\nurlpatterns = [path(f'{prefix}/', public)]",
    "from django.urls import path\nif flag:\n    urlpatterns = [path('conditional/', public)]",
    "from django.urls import path\nurlpatterns = [path('before/', public)]\nurlpatterns = build_patterns()",
    "from django.urls import path\nurlpatterns = []\nurlpatterns.append(path('method/', public))",
])
def test_foreign_rebound_and_dynamic_urlpatterns_do_not_invent_routes(source):
    entries, limits = extract(source)
    assert entries == []
    assert limits


def test_source_and_syntax_bounds_are_explicit():
    assert extract_django_url_entries("urls.py", "urlpatterns = [")[1]
    assert extract_django_url_entries("urls.py", "# urlpatterns\n" + " " * (1024 * 1024))[1]


@pytest.mark.parametrize("urls,target", [
    ("from app import views", "views.private"),
    ("from app.views import private", "private"),
    ("from app.views import private as protected", "protected"),
    ("import app.views as handlers", "handlers.private"),
    ("import app.views", "app.views.private"),
])
def test_exact_imported_function_and_framework_decorator_prove_auth(urls, target):
    files = views("from django.contrib.auth.decorators import login_required as gate\n@gate\ndef private(request):\n    return None\n", urls)
    auth, guards, evidence, eligible = django_view_auth(files, "project/urls.py", target)
    assert auth == "required"
    assert guards == ["@login_required (app/views.py:2)"]
    assert evidence and "app/views.py:3" in evidence
    assert eligible


def test_relative_view_import_and_bounded_reexport():
    files = {"app/urls.py": "from .views import private as protected", "app/views.py": "from .actual import private", "app/actual.py": "from django.contrib.auth.decorators import login_required\n@login_required\ndef private(request): return None"}
    assert django_view_auth(files, "app/urls.py", "protected")[0] == "required"


@pytest.mark.parametrize("source", [
    "def login_required(fn): return fn\n@login_required\ndef public(request): return None",
    "from foreign import login_required\n@login_required\ndef public(request): return None",
    "from django.contrib.auth.decorators import login_required\nlogin_required = foreign\n@login_required\ndef public(request): return None",
    "from rest_framework.decorators import api_view\n@api_view(['GET'])\ndef public(request): return None",
    "from django.contrib.auth.decorators import login_required\n@unknown\n@login_required\ndef public(request): return None",
    "from django.contrib.auth.decorators import user_passes_test\n@user_passes_test(lambda user: True)\ndef public(request): return None",
])
def test_name_only_foreign_shadowed_and_unknown_decorators_are_not_auth(source):
    assert django_view_auth(views(source), "project/urls.py", "views.public") == ("unknown", [], None, False)


def test_plain_public_function_is_only_middleware_eligible_not_authenticated():
    assert django_view_auth(views(), "project/urls.py", "views.public") == ("unknown", [], None, True)


def test_exact_login_not_required_excludes_middleware_without_claiming_public_access():
    source = "from django.contrib.auth.decorators import login_not_required\n@login_not_required\ndef public(request): return None"
    assert django_view_auth(views(source), "project/urls.py", "views.public") == ("unknown", [], None, False)
    files = views(urls="from app import views\nfrom django.contrib.auth.decorators import login_not_required")
    assert django_view_auth(files, "project/urls.py", "login_not_required(views.public)") == ("unknown", [], None, False)


def test_official_url_wrapper_requires_plain_bound_function_and_accurate_entry_citation():
    files = views(urls="from app import views\nfrom django.contrib.auth.decorators import login_required\nurlpatterns = []")
    auth, guards, evidence, eligible = django_view_auth(files, "project/urls.py", "login_required(views.public)", target_line=3)
    assert auth == "required" and eligible and guards == ["login_required wrapper at URL entry (project/urls.py:3)"]
    assert django_view_auth(files, "project/urls.py", "login_required(views.public)")[1] == ["login_required wrapper at URL entry (project/urls.py)"]


@pytest.mark.parametrize("target", ["DetailView.as_view()", "views.DetailView.as_view()", "views.DetailView.as_view(template_name='detail.html')"])
def test_imported_class_view_requires_exact_mixin_and_plain_as_view(target):
    source = "from django.views import View\nfrom django.contrib.auth.mixins import LoginRequiredMixin\nclass DetailView(LoginRequiredMixin, View):\n    def get(self, request): return None"
    files = views(source, "from app import views\nfrom app.views import DetailView")
    result = django_view_auth(files, "project/urls.py", target)
    assert result[0] == ("unknown" if "template_name" in target else "required")
    if "template_name" not in target:
        assert result[1] == ["LoginRequiredMixin (app/views.py:3)"]
        assert result[3]
    entries, limits = extract(f"from django.urls import path\nfrom app.views import DetailView\nurlpatterns = [path('detail/', {target})]")
    assert entries[0][0] == "detail/" and not limits


def test_foreign_url_wrapper_and_rebound_view_module_are_unknown():
    files = views(urls="from app import views\nfrom foreign import login_required")
    assert django_view_auth(files, "project/urls.py", "login_required(views.public)") == ("unknown", [], None, False)
    files["project/urls.py"] = "from app import views\nviews = foreign_module"
    assert django_view_auth(files, "project/urls.py", "views.public") == ("unknown", [], None, False)


def test_function_alias_collision_does_not_choose_same_named_wrong_definition():
    source = "from django.contrib.auth.decorators import login_required\n@login_required\ndef selected(request): return None\ndef public(request): return None"
    files = views(source, "from app.views import public as selected")
    assert django_view_auth(files, "project/urls.py", "selected") == ("unknown", [], None, True)


def test_reexport_cycle_and_duplicate_definitions_stay_unknown():
    files = {"project/urls.py": "from app.views import public", "app/views.py": "from app.actual import public", "app/actual.py": "from app.views import public"}
    assert django_view_auth(files, "project/urls.py", "public") == ("unknown", [], None, False)
    files["app/views.py"] = "def public(request): pass\ndef public(request): pass"
    assert django_view_auth(files, "project/urls.py", "public") == ("unknown", [], None, False)


def test_project_local_django_namespace_is_not_framework_auth_attestation():
    files = views("from django.contrib.auth.decorators import login_required\n@login_required\ndef public(request): return None")
    files["django/contrib/auth/decorators.py"] = "def login_required(fn): return fn"
    assert django_view_auth(files, "project/urls.py", "views.public") == ("unknown", [], None, False)


def test_per_scan_resolver_parses_only_two_modules_for_one_hundred_routes(monkeypatch):
    files = views("\n".join(f"def view_{index}(request): return None" for index in range(100)))
    parsed = []
    original = django_routes._info

    def count_parse(rel, text):
        parsed.append(rel)
        return original(rel, text)

    monkeypatch.setattr(django_routes, "_info", count_parse)
    resolver = DjangoAuthResolver(files)
    for index in range(100):
        assert resolver.resolve("project/urls.py", f"views.view_{index}") == ("unknown", [], None, True)
    assert parsed == ["project/urls.py", "app/views.py"]
    assert resolver.cached_module_count == 2


def test_resolver_caches_failed_parses_and_keeps_instances_independent(monkeypatch):
    files = views("def broken(")
    parsed = []
    original = django_routes._info

    def count_parse(rel, text):
        parsed.append(rel)
        return original(rel, text)

    monkeypatch.setattr(django_routes, "_info", count_parse)
    resolver = DjangoAuthResolver(files)
    for _ in range(3):
        assert resolver.resolve("project/urls.py", "views.public") == ("unknown", [], None, False)
    assert parsed == ["project/urls.py", "app/views.py"]
    assert resolver.cached_module_count == 2
    assert DjangoAuthResolver(files).resolve("project/urls.py", "views.public") == ("unknown", [], None, False)
    assert parsed == ["project/urls.py", "app/views.py"] * 2


def test_resolver_uses_scan_source_snapshot_and_legacy_wrapper_still_works():
    files = views()
    resolver = DjangoAuthResolver(files)
    files["app/views.py"] = "def broken("
    assert resolver.resolve("project/urls.py", "views.public") == ("unknown", [], None, True)
    assert django_view_auth(files, "project/urls.py", "views.public") == ("unknown", [], None, False)


def test_resolver_evicts_least_recent_module_and_never_exceeds_bound(monkeypatch):
    files = {"project/urls.py": "from app import first, second", "app/first.py": "def public(request): pass", "app/second.py": "def public(request): pass"}
    parsed = []
    original = django_routes._info

    def count_parse(rel, text):
        parsed.append(rel)
        return original(rel, text)

    monkeypatch.setattr(django_routes, "_info", count_parse)
    resolver = DjangoAuthResolver(files, max_modules=2)
    for target in ("first.public", "second.public", "first.public"):
        assert resolver.resolve("project/urls.py", target) == ("unknown", [], None, True)
        assert resolver.cached_module_count == 2
    assert parsed == ["project/urls.py", "app/first.py", "app/second.py", "app/first.py"]


def test_default_resolver_cache_is_bounded_to_thirty_two_modules():
    files = {"project/urls.py": "\n".join(f"from app import view_{index}" for index in range(40))}
    files.update({f"app/view_{index}.py": "def public(request): pass" for index in range(40)})
    resolver = DjangoAuthResolver(files)
    for index in range(40):
        assert resolver.resolve("project/urls.py", f"view_{index}.public") == ("unknown", [], None, True)
        assert resolver.cached_module_count <= 32
    assert resolver.cached_module_count == 32


@pytest.mark.parametrize("bound", [0, 33, -1, True, False, 1.5, "2", None])
def test_resolver_rejects_invalid_cache_bounds(bound):
    with pytest.raises(ValueError, match="max_modules"):
        DjangoAuthResolver({}, max_modules=bound)


@pytest.mark.parametrize("rebinding", [
    "with context() as login_required:\n    pass",
    "try:\n    something()\nexcept Exception as login_required:\n    pass",
    "match something:\n    case login_required:\n        pass",
    "match something:\n    case {'item': _, **login_required}:\n        pass",
    "(login_required := foreign)",
    "other = (login_required := foreign)",
    "def unrelated(default=(login_required := foreign)): pass",
    "other = lambda default=(login_required := foreign): None",
    "class Unrelated((login_required := foreign)): pass",
    "other: (login_required := foreign)",
    "def unrelated(arg: (login_required := foreign)): pass",
])
def test_enclosing_scope_binding_forms_cannot_attest_framework_decorator(rebinding):
    source = f"from django.contrib.auth.decorators import login_required\n{rebinding}\n@login_required\ndef public(request): return None"
    assert django_view_auth(views(source), "project/urls.py", "views.public") == ("unknown", [], None, False)


def test_assignment_inside_unrelated_function_does_not_rebind_module_decorator():
    source = "from django.contrib.auth.decorators import login_required\ndef unrelated():\n    login_required = foreign\n@login_required\ndef public(request): return None"
    assert django_view_auth(views(source), "project/urls.py", "views.public")[0] == "required"


@pytest.mark.parametrize("rebinding", ["with context() as path:\n    pass", "(path := foreign)", "def unrelated(default=(path := foreign)): pass"])
def test_rebound_path_factories_do_not_emit_routes(rebinding):
    entries, limits = extract(f"from django.urls import path\n{rebinding}\nurlpatterns = [path('public/', views.public)]")
    assert entries == []
    assert any("unresolved" in item for item in limits)


@pytest.mark.parametrize("mutation", [
    "mutate(urlpatterns)",
    "alias = urlpatterns\nalias.clear()",
    "urlpatterns[0] = foreign_route",
    "urlpatterns[:] = []",
    "del urlpatterns[0]",
])
def test_dynamic_urlpatterns_references_and_subscript_writes_are_not_certified(mutation):
    entries, limits = extract(f"from django.urls import path\nurlpatterns = [path('private/', views.private)]\n{mutation}")
    assert entries == []
    assert any("unsupported" in item for item in limits)


def test_final_literal_urlpatterns_reassignment_can_restore_known_entries():
    entries, _limits = extract("from django.urls import path\nurlpatterns = [path('old/', views.private)]\nmutate(urlpatterns)\nurlpatterns = [path('new/', views.public)]")
    assert entries == [("new/", "views.public", 4)]
