"""Bounded import-only Django auth-decorator resolution; never execute views."""
import pytest

from attackmap.ecosystem_python import scan_python_services
from attackmap.python_django_routes import django_view_auth


def sources(auth="from django.contrib.auth.decorators import login_required as gate\n", decorator="@gate"):
    return {
        "settings.py": "ROOT_URLCONF='project.urls'\n",
        "project/urls.py": "from django.urls import path, re_path, include\nurlpatterns=[path('api/', include('app.urls')), re_path(r'^internal/', include('app.urls'))]\n",
        "app/urls.py": "from django.urls import path\nfrom .views import private\nurlpatterns=[path('private/', private)]\n",
        "app/auth.py": auth,
        "app/views.py": f"from .auth import gate\n{decorator}\ndef private(request): return None\n",
    }


def write_sources(root, files):
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


@pytest.mark.parametrize("binding", [
    "from .auth import gate\n@gate",
    "from app.auth import gate as protected\n@protected",
    "from app import auth\n@auth.gate",
    "import app.auth as checks\n@checks.gate",
])
def test_import_only_auth_reexports_resolve_to_exact_django_decorator(binding):
    files = sources()
    files["app/views.py"] = binding + "\ndef private(request): return None\n"
    auth, guards, evidence, eligible = django_view_auth(files, "app/urls.py", "private")
    assert auth == "required" and eligible
    assert guards == ["@login_required (app/views.py:2)"]
    assert "app/views.py:3" in evidence


def test_package_and_relative_reexports_keep_mounted_routes_and_guard_sites(tmp_path):
    files = sources("from .security import gate\n")
    files["app/security/__init__.py"] = "from .decorators import gate\n"
    files["app/security/decorators.py"] = "from django.contrib.auth.decorators import login_required as gate\n"
    write_sources(tmp_path, files)
    result = scan_python_services(tmp_path)
    assert [(r.path, r.auth, r.file, r.line) for r in result.routes] == [
        ("/api/private/", "required", "app/urls.py", 3),
        ("/internal/private/", "required", "app/urls.py", 3),
    ]
    assert all(r.guards == ["@login_required (app/views.py:2)"] for r in result.routes)
    assert all("app/views.py:3" in r.guard_evidence for r in result.routes)


@pytest.mark.parametrize("package", [
    "from . import fake as auth\n",
    "import app.fake as auth\n",
    "from .fake import auth\n",
    "auth = fake\n",
    "def auth(): pass\n",
    "class auth: pass\n",
    "if enabled:\n from . import auth\n",
    "from .fake import *\n",
    "def __getattr__(name): return fake\n",
])
def test_package_binding_cannot_promote_unrelated_sibling_module_to_framework_auth(package):
    files = sources()
    files["app/views.py"] = "from app import auth\n@auth.gate\ndef private(request): return None\n"
    files["app/__init__.py"] = package
    files["app/fake.py"] = "def gate(view): return view\n"
    assert django_view_auth(files, "app/urls.py", "private") == ("unknown", [], None, False)


@pytest.mark.parametrize("package", ["", "from . import auth\n", "from .auth import gate\n"])
def test_unambiguous_package_module_and_symbol_reexports_remain_supported(package):
    files = sources()
    files["app/views.py"] = "from app import auth\n@auth.gate\ndef private(request): return None\n"
    files["app/__init__.py"] = package
    assert django_view_auth(files, "app/urls.py", "private")[0] == "required"


def test_nested_package_binding_and_module_package_parent_collision_stay_unknown():
    files = sources()
    files["app/views.py"] = "from app.security import decorators\n@decorators.gate\ndef private(request): return None\n"
    files["app/security/__init__.py"] = "from . import fake as decorators\n"
    files["app/security/decorators.py"] = "from django.contrib.auth.decorators import login_required as gate\n"
    files["app/security/fake.py"] = "def gate(view): return view\n"
    assert django_view_auth(files, "app/urls.py", "private") == ("unknown", [], None, False)
    files = sources()
    files["app.py"] = "auth = fake\n"
    assert django_view_auth(files, "app/urls.py", "private") == ("unknown", [], None, False)


@pytest.mark.parametrize("binding,decorator,package_path,package_source", [
    ("from app.auth import gate", "gate", "app/__init__.py", "from . import fake as auth\n"),
    ("from app.security.decorators import gate", "gate", "app/security/__init__.py", "from . import fake as decorators\n"),
    ("import app.auth as checks", "checks.gate", "app/__init__.py", "from . import fake as auth\n"),
    ("import app.auth", "app.auth.gate", "app/__init__.py", "from . import fake as auth\n"),
    ("import app.security.decorators as checks", "checks.gate", "app/security/__init__.py", "from . import fake as decorators\n"),
])
def test_explicit_submodule_symbol_import_is_not_replaced_by_package_attribute(binding, decorator, package_path, package_source):
    files = sources()
    files["app/views.py"] = binding + f"\n@{decorator}\ndef private(request): return None\n"
    files[package_path] = package_source
    files["app/security/decorators.py"] = "from django.contrib.auth.decorators import login_required as gate\n"
    files["app/fake.py"] = files["app/security/fake.py"] = "def gate(view): return view\n"
    assert django_view_auth(files, "app/urls.py", "private")[0] == "required"


def test_relative_from_package_auth_attribute_keeps_shadow_unknown():
    files = sources()
    files["app/views.py"] = "from . import auth\n@auth.gate\ndef private(request): return None\n"
    files["app/__init__.py"] = "from . import fake as auth\n"
    files["app/fake.py"] = "def gate(view): return view\n"
    assert django_view_auth(files, "app/urls.py", "private") == ("unknown", [], None, False)


@pytest.mark.parametrize("binding,target,expected", [
    ("from app import views", "views.private", "unknown"),
    ("from . import views", "views.private", "unknown"),
    ("from app.views import private", "private", "required"),
    ("from .views import private", "private", "required"),
    ("import app.views as handlers", "handlers.private", "required"),
    ("import app.views", "app.views.private", "required"),
])
def test_view_target_package_binding_never_selects_unrelated_guarded_sibling(binding, target, expected):
    files = sources()
    files["app/urls.py"] = binding + "\n"
    files["app/__init__.py"] = "from . import public_views as views\n"
    files["app/public_views.py"] = "def private(request): return None\n"
    result = django_view_auth(files, "app/urls.py", target)
    assert result[0] == expected
    if expected == "unknown":
        assert result == ("unknown", [], None, False)


@pytest.mark.parametrize("binding,target,expected", [
    ("from app import views", "views.Detail.as_view()", "unknown"),
    ("import app.views as handlers", "handlers.Detail.as_view()", "required"),
])
def test_class_view_target_uses_same_package_binding_rules(binding, target, expected):
    files = sources()
    files["app/urls.py"] = binding + "\n"
    files["app/__init__.py"] = "from . import public_views as views\n"
    files["app/public_views.py"] = "from django.views import View\nclass Detail(View): pass\n"
    files["app/views.py"] = "from django.views import View\nfrom django.contrib.auth.mixins import LoginRequiredMixin\nclass Detail(LoginRequiredMixin, View): pass\n"
    assert django_view_auth(files, "app/urls.py", target)[0] == expected


def test_same_qualified_binding_with_conflicting_import_semantics_stays_unknown():
    files = sources()
    files["app/views.py"] = "import app.auth as checks\nfrom app import auth as checks\n@checks.gate\ndef private(request): return None\n"
    assert django_view_auth(files, "app/urls.py", "private") == ("unknown", [], None, False)


@pytest.mark.parametrize("scope", ["decorator", "view"])
def test_ordinary_package_attribute_does_not_implicitly_import_sibling(scope):
    files = sources()
    files["app/__init__.py"] = ""
    if scope == "decorator":
        files["app/views.py"] = "import app\n@app.auth.gate\ndef private(request): return None\n"
        target = "private"
    else:
        files["app/urls.py"] = "import app\n"
        target = "app.views.private"
    assert django_view_auth(files, "app/urls.py", target) == ("unknown", [], None, False)


@pytest.mark.parametrize("package", ["from . import auth\n", "from .auth import gate\n", "import app.auth\n"])
def test_ordinary_package_attribute_is_supported_when_init_imports_that_child(package):
    files = sources()
    files["app/__init__.py"] = package
    files["app/views.py"] = "import app\n@app.auth.gate\ndef private(request): return None\n"
    assert django_view_auth(files, "app/urls.py", "private")[0] == "required"


def test_from_explicit_package_preserves_force_prefix_and_only_final_child_fallback():
    files = sources()
    files["app/__init__.py"] = "from . import fake as security\n"
    files["app/fake.py"] = "def gate(view): return view\n"
    files["app/security/__init__.py"] = ""
    files["app/security/decorators.py"] = "from django.contrib.auth.decorators import login_required as gate\n"
    files["app/views.py"] = "from app.security import decorators\n@decorators.gate\ndef private(request): return None\n"
    assert django_view_auth(files, "app/urls.py", "private")[0] == "required"


@pytest.mark.parametrize("auth", [
    "from foreign import login_required as gate\n",
    "def gate(view): return view\n",
    "from django.contrib.auth.decorators import login_required as gate\ngate = foreign\n",
    "from django.contrib.auth.decorators import login_required as gate\nfrom foreign import gate\n",
    "from django.contrib.auth.decorators import login_required as gate\ndef gate(view): return view\n",
    "from django.contrib.auth.decorators import *\nfrom django.contrib.auth.decorators import login_required as gate\n",
    "if enabled:\n from django.contrib.auth.decorators import login_required as gate\n",
    "from django.contrib.auth.decorators import login_required\ngate = login_required\n",
    "from django.contrib.auth.decorators import login_required\ndef gate(view): return login_required(view)\n",
    "from django.contrib.auth.decorators import login_required as gate\nwith context() as gate: pass\n",
])
def test_foreign_custom_rebound_conditional_and_star_decorator_exports_stay_unknown(auth):
    assert django_view_auth(sources(auth), "app/urls.py", "private") == ("unknown", [], None, False)


@pytest.mark.parametrize("extra", [
    {"app/auth/__init__.py": "from django.contrib.auth.decorators import login_required as gate\n"},
    {"django.py": ""},
    {"app/auth.py": "from .other import gate\n", "app/other.py": "from .auth import gate\n"},
    {"app/auth.py": "from .other import gate\n", "app/other.py": "def broken("},
])
def test_ambiguous_modules_local_django_cycles_and_failed_parses_do_not_attest_auth(extra):
    assert django_view_auth({**sources(), **extra}, "app/urls.py", "private") == ("unknown", [], None, False)


@pytest.mark.parametrize("decorator", [
    "@gate(resolve_url())",
    "@gate(login_url=resolve_url())",
    "@gate(**configuration)",
    "@foreign\n@gate",
    "@gate\n@foreign",
])
def test_dynamic_configuration_and_unknown_decorator_stacks_keep_auth_unknown(decorator):
    assert django_view_auth(sources(decorator=decorator), "app/urls.py", "private") == ("unknown", [], None, False)


@pytest.mark.parametrize("decorator", ["@gate()", "@gate(login_url='/accounts/login/', redirect_field_name=None)"])
def test_literal_decorator_factory_configuration_is_bounded(decorator):
    assert django_view_auth(sources(decorator=decorator), "app/urls.py", "private")[0] == "required"


@pytest.mark.parametrize("configuration", ["login_url=resolve_url()", "login_url='/a/', login_url='/b/'"])
def test_direct_framework_factory_also_rejects_dynamic_or_duplicate_configuration(configuration):
    files = sources()
    files["app/views.py"] = (
        "from django.contrib.auth.decorators import login_required\n"
        f"@login_required({configuration})\ndef private(request): return None\n"
    )
    assert django_view_auth(files, "app/urls.py", "private") == ("unknown", [], None, False)


def test_reexported_login_not_required_excludes_global_middleware(tmp_path):
    files = sources("from django.contrib.auth.decorators import login_not_required as gate\n")
    files["settings.py"] += "MIDDLEWARE=['django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
    write_sources(tmp_path, files)
    result = scan_python_services(tmp_path)
    assert {r.path for r in result.routes} == {"/api/private/", "/internal/private/"}
    assert all(r.auth == "unknown" and not r.guards for r in result.routes)


def test_unknown_function_decorator_has_explicit_mounted_url_entry_limitation(tmp_path):
    write_sources(tmp_path, sources("from foreign import login_required as gate\n"))
    result = scan_python_services(tmp_path)
    assert all(r.auth == "unknown" and not r.guards for r in result.routes)
    assert any("function-view authentication unresolved in app/urls.py:3" in item for item in result.limitations)


def test_decorator_reexport_depth_is_bounded():
    files = sources("from .auth0 import gate\n")
    files.update({f"app/auth{i}.py": f"from .auth{i + 1} import gate\n" for i in range(8)})
    files["app/auth8.py"] = "from django.contrib.auth.decorators import login_required as gate\n"
    assert django_view_auth(files, "app/urls.py", "private") == ("unknown", [], None, False)
