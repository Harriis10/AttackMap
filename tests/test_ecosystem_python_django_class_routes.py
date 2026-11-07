"""Bounded class-view auth and mounted regex route coverage."""
import pytest

from attackmap.ecosystem_python import scan_python_services
from attackmap.python_django_routes import django_view_auth, extract_django_url_entries


@pytest.mark.parametrize("segment", [r"\d+", "[0-9]+", r"\w+", "[-a-zA-Z0-9_]+", "[^/]+"])
def test_named_regex_segments_have_exact_entry_evidence(segment):
    source = f"from django.urls import re_path\nurlpatterns = [re_path(r'^items/(?P<pk>{segment})/$', view)]"
    entries, limits = extract_django_url_entries("urls.py", source)
    assert entries == [("items/{pk}/", "view", 2)]
    assert not limits


@pytest.mark.parametrize("pattern", [r"^items/(?P<pk>.*)/$", r"^items/(?P<pk>\d*)/$",
    r"^items/(?P<pk>[0-9]+)/(?P<pk>[0-9]+)/$", r"^items/(?P<pk>(a|b))/$",
    r"^items/(?P<pk>[^/]+)?/$", r"^items/(?P<pk>.+)/$", r"^items/(?P<pk>[0-9]+)/"])
def test_ambiguous_optional_and_cross_segment_regexes_stay_explicitly_unsupported(pattern):
    entries, limits = extract_django_url_entries("urls.py", f"from django.urls import re_path\nurlpatterns=[re_path({pattern!r}, view)]")
    assert not entries
    assert any("regex route is unsupported" in item for item in limits)


def test_nested_regex_include_and_repeated_mounts_keep_class_auth_and_locations(tmp_path):
    files = {
        "settings.py": "ROOT_URLCONF='project.urls'\n",
        "project/urls.py": "from django.urls import path, re_path, include\nurlpatterns=[re_path(r'^org/(?P<org>[-a-zA-Z0-9_]+)/', include('app.urls')), path('internal/', include(('app.urls', 'app'), namespace='private'))]\n",
        "app/urls.py": "from django.urls import re_path\nfrom .views import Detail as Page\nurlpatterns=[re_path(r'^items/(?P<pk>[0-9]+)/$', Page.as_view())]\n",
        "app/views.py": "from django.views import View\nfrom django.contrib.auth.mixins import LoginRequiredMixin as Gate\nclass Detail(Gate, View):\n def get(self, request): return None\n",
    }
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    result = scan_python_services(tmp_path)
    assert {r.path for r in result.routes} == {"/org/{org}/items/{pk}/", "/internal/items/{pk}/"}
    assert all(r.auth == "required" and r.file == "app/urls.py" and r.line == 3 for r in result.routes)
    assert all("app/views.py:3" in r.guard_evidence for r in result.routes)


@pytest.mark.parametrize("pattern", ["^api/$", "^api", "api/", "^api/?"])
def test_include_prefix_requires_unambiguous_segment_boundary(pattern):
    entries, limits = extract_django_url_entries("urls.py", f"from django.urls import re_path, include\nurlpatterns=[re_path({pattern!r}, include('app.urls'))]")
    assert not entries and limits


@pytest.mark.parametrize("source,target", [
    ("from foreign import View, LoginRequiredMixin\nclass Page(LoginRequiredMixin, View): pass", "Page.as_view()"),
    ("from django.views import View\nfrom foreign import LoginRequiredMixin\nclass Page(LoginRequiredMixin, View): pass", "Page.as_view()"),
    ("from django.views import View\nfrom django.contrib.auth.mixins import LoginRequiredMixin\nclass Page(View, LoginRequiredMixin): pass", "Page.as_view()"),
    ("from django.views import View\nfrom django.contrib.auth.mixins import LoginRequiredMixin\nclass Page(LoginRequiredMixin, View):\n def dispatch(self, request): pass", "Page.as_view()"),
    ("from django.views import View\nfrom django.contrib.auth.mixins import LoginRequiredMixin\nclass Page(LoginRequiredMixin, View):\n def as_view(self): pass", "Page.as_view()"),
    ("from django.views import View\nfrom django.contrib.auth.mixins import LoginRequiredMixin\n@custom\nclass Page(LoginRequiredMixin, View): pass", "Page.as_view()"),
    ("from django.views import View\nclass Page(View): pass\nPage=foreign", "Page.as_view()"),
    ("from django.views import View\nView=foreign\nclass Page(View): pass", "Page.as_view()"),
    ("from django.views import View\nclass Page(View): pass\nclass Page(View): pass", "Page.as_view()"),
    ("from django.views import View\nclass Base(View): pass\nclass Page(Base): pass", "Page.as_view()"),
    ("from django.views import View\nclass Page(View): pass", "Page.as_view(**options)"),
])
def test_class_names_custom_dispatch_and_dynamic_configuration_never_attest_auth(source, target):
    files = {"app/urls.py": "from .views import Page", "app/views.py": source}
    assert django_view_auth(files, "app/urls.py", target) == ("unknown", [], None, False)


def test_plain_local_class_and_reexport_are_middleware_eligible_and_wrapper_is_cited():
    files = {"app/urls.py": "from .views import Page\nfrom django.contrib.auth.decorators import login_required\n",
        "app/views.py": "from .actual import Page", "app/actual.py": "from django.views import View\nclass Page(View): pass"}
    assert django_view_auth(files, "app/urls.py", "Page.as_view()") == ("unknown", [], None, True)
    auth, guards, _, eligible = django_view_auth(files, "app/urls.py", "login_required(Page.as_view())", target_line=2)
    assert auth == "required" and eligible
    assert guards == ["login_required wrapper at URL entry (app/urls.py:2)"]
    files["app/urls.py"] = "from django.views import View\nclass Page(View): pass"
    assert django_view_auth(files, "app/urls.py", "Page.as_view()") == ("unknown", [], None, True)


def test_login_middleware_applies_only_to_attested_plain_class(tmp_path):
    (tmp_path / "settings.py").write_text("ROOT_URLCONF='urls'\nMIDDLEWARE=['django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.auth.middleware.LoginRequiredMiddleware']\n", encoding="utf-8")
    (tmp_path / "urls.py").write_text("from django.urls import path\nfrom views import Plain, Custom\nurlpatterns=[path('plain/', Plain.as_view()), path('custom/', Custom.as_view())]\n", encoding="utf-8")
    (tmp_path / "views.py").write_text("from django.views.generic import View\nclass Plain(View): pass\nclass Custom(View):\n def dispatch(self, request): pass\n", encoding="utf-8")
    result = scan_python_services(tmp_path)
    routes = {r.path: r for r in result.routes}
    assert routes["/plain/"].auth == "required"
    assert "settings.py:2" in routes["/plain/"].guard_evidence
    assert routes["/custom/"].auth == "unknown"
    assert any("class-view authentication unresolved in urls.py:3" in item for item in result.limitations)
