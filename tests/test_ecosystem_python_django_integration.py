"""Django URLconf traversal and root-scoped authentication observations."""
from pathlib import Path

import pytest

from attackmap.ecosystem_python import scan_python_services


AUTH = "django.contrib.auth.middleware.AuthenticationMiddleware"
LOGIN = "django.contrib.auth.middleware.LoginRequiredMiddleware"


def write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def app(root: Path, middleware: str) -> None:
    write(root, {
        "settings.py": f"ROOT_URLCONF = 'site.urls'\nMIDDLEWARE = {middleware}\n",
        "site/urls.py": "from django.urls import path\nfrom site.views import home\n"
                        "urlpatterns = [path('home/', home)]\n",
        "site/views.py": "def home(request):\n    return None\n",
    })


@pytest.mark.parametrize("middleware", [repr([LOGIN]), repr([LOGIN, AUTH]),
    repr([AUTH, "example.LoginRequiredMiddleware"]),
    repr([AUTH, LOGIN]) + "\nMIDDLEWARE.clear()",
    repr([AUTH, LOGIN]) + "\nif DEBUG:\n    MIDDLEWARE = []",
    repr([AUTH, LOGIN]) + "\nMIDDLEWARE[:] = []",
    repr([AUTH, LOGIN]) + "\ndel MIDDLEWARE",
    repr([AUTH, LOGIN]) + "\nfrom custom import MIDDLEWARE",
    repr([AUTH, LOGIN]) + "\ndef MIDDLEWARE():\n    return None",
    repr([AUTH, LOGIN]) + "\ntry:\n    action()\nexcept Exception as MIDDLEWARE:\n    pass",
    repr([AUTH, LOGIN]) + "\nmatch value:\n    case [*MIDDLEWARE]:\n        pass",
    repr([AUTH, LOGIN]) + "\nmatch value:\n    case {**MIDDLEWARE}:\n        pass",
    repr([AUTH, LOGIN]) + "\nfrom local_settings import *",
])
def test_middleware_requires_unambiguous_ordered_framework_binding(tmp_path, middleware):
    app(tmp_path, middleware)
    result = scan_python_services(tmp_path)
    assert result.routes[0].auth == "unknown"
    assert not result.routes[0].guards


def test_ordered_middleware_has_root_settings_evidence(tmp_path):
    app(tmp_path, repr([AUTH, LOGIN]))
    route = scan_python_services(tmp_path).routes[0]
    assert route.auth == "required"
    assert "settings.py:2" in route.guard_evidence


def test_other_root_and_conflicting_settings_do_not_inherit_login(tmp_path):
    app(tmp_path, repr([AUTH, LOGIN]))
    write(tmp_path, {
        "public/settings.py": "ROOT_URLCONF = 'public.urls'\nMIDDLEWARE = []\n",
        "public/urls.py": "from django.urls import path\nfrom site.views import home\n"
                          "urlpatterns = [path('public/', home)]\n",
    })
    routes = {route.path: route for route in scan_python_services(tmp_path).routes}
    assert routes["/home/"].auth == "required"
    assert routes["/public/"].auth == "unknown"
    write(tmp_path, {"other_settings.py": "ROOT_URLCONF = 'site.urls'\nMIDDLEWARE = []\n"})
    routes = {route.path: route for route in scan_python_services(tmp_path).routes}
    assert routes["/home/"].auth == "unknown"


def test_login_opt_out_and_unknown_wrappers_do_not_gain_global_auth(tmp_path):
    app(tmp_path, repr([AUTH, LOGIN]))
    for decoration in ("@login_not_required", "@foreign_decorator"):
        write(tmp_path, {"site/views.py": "from django.contrib.auth.decorators import login_not_required\n"
               "from foreign import foreign_decorator\n" + decoration + "\ndef home(request):\n    return None\n"})
        assert scan_python_services(tmp_path).routes[0].auth == "unknown"


def test_repeat_include_mounts_and_cycle_are_bounded(tmp_path):
    write(tmp_path, {
        "settings.py": "ROOT_URLCONF = 'site.urls'\n",
        "site/urls.py": "from django.urls import path, include\nurlpatterns = ["
            "path('a/', include('site.child')), path('b/', include(('site.child', 'app'), namespace='second'))]\n",
        "site/child.py": "from django.urls import path, include\nfrom site.views import home\nurlpatterns = ["
            "path('home/', home), path('loop/', include('site.urls'))]\n",
        "site/views.py": "def home(request):\n    return None\n",
    })
    result = scan_python_services(tmp_path)
    assert {route.path for route in result.routes} == {"/a/home/", "/b/home/"}
    assert any("cycle/depth" in limitation for limitation in result.limitations)


def test_inferred_root_does_not_inherit_unresolved_settings_middleware(tmp_path):
    app(tmp_path, repr([AUTH, LOGIN]))
    write(tmp_path, {"settings.py": f"ROOT_URLCONF = 'missing.urls'\nMIDDLEWARE = {[AUTH, LOGIN]!r}\n"})
    result = scan_python_services(tmp_path)
    assert result.routes[0].auth == "unknown"
    assert any("missing.urls" in limitation for limitation in result.limitations)


def test_deleted_root_urlconf_cannot_apply_settings_auth(tmp_path):
    app(tmp_path, repr([AUTH, LOGIN]))
    with (tmp_path / "settings.py").open("a", encoding="utf-8") as stream:
        stream.write("del ROOT_URLCONF\n")
    result = scan_python_services(tmp_path)
    assert result.routes[0].auth == "unknown"
    assert any("ambiguous Django ROOT_URLCONF" in note for note in result.limitations)
