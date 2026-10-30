"""Same-input extraction oracle; inert fixture source, no Django/provider execution."""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from pathlib import Path
import sys


VIEWS = """from django.contrib.auth.decorators import login_required
from django.views import View

@login_required
def private(request):
    return None

def public(request):
    return None

class DetailView(View):
    def get(self, request):
        return None
"""


def cases():
    common = {
        "pyproject.toml": '[project]\nname = "django-oracle"\ndependencies = ["django"]\n',
        "project/__init__.py": "",
        "project/settings.py": "ROOT_URLCONF = 'project.urls'\nMIDDLEWARE = []\n",
        "app/__init__.py": "",
        "app/views.py": VIEWS,
    }
    specs = [
        ("module-function-control", "from django.urls import path\nfrom app import views\nurlpatterns = [path('private/', views.private)]\n", {"/private/": "required"}, []),
        ("direct-function-import", "from django.urls import path\nfrom app.views import private\nurlpatterns = [path('private/', private)]\n", {"/private/": "required"}, []),
        ("imported-class-view", "from django.urls import path\nfrom app.views import DetailView\nurlpatterns = [path('detail/', DetailView.as_view())]\n", {"/detail/": "unknown"}, []),
        ("literal-re-path", "from django.urls import re_path\nfrom app import views\nurlpatterns = [re_path(r'^literal/$', views.public)]\n", {"/literal/": "unknown"}, []),
        ("unsupported-regex", "from django.urls import re_path\nfrom app import views\nurlpatterns = [re_path(r'^items/(?P<pk>[0-9]+)/$', views.public)]\n", {}, ["/items/{pk}/"]),
        ("dynamic-path-concatenation", "from django.urls import path\nfrom app import views\nsuffix = resolve_suffix()\nurlpatterns = [path('admin/' + suffix, views.public)]\n", {}, ["/admin/"]),
        ("commented-path", "from django.urls import path\nfrom app import views\nurlpatterns = []\n# path('not-registered/', views.private)\n", {}, ["/not-registered/"]),
        ("foreign-path-function", "from local_router import path\nfrom app import views\nurlpatterns = [path('not-django/', views.private)]\n", {}, ["/not-django/"]),
        ("shadowed-auth-decorator", "from django.urls import path\nfrom app import views\nurlpatterns = [path('public/', views.public)]\n", {"/public/": "unknown"}, []),
        ("spoof-middleware-name", "from django.urls import path\nfrom app import views\nurlpatterns = [path('public/', views.public)]\n", {"/public/": "unknown"}, []),
        ("include-two-mounts", "from django.urls import path, include\nurlpatterns = [path('v1/', include('app.urls', namespace='one')), path('v2/', include('app.urls', namespace='two'))]\n", {"/v1/item/": "unknown", "/v2/item/": "unknown"}, []),
        ("include-literal-tuple", "from django.urls import path, include\nurlpatterns = [path('api/', include(('app.urls', 'app'), namespace='one'))]\n", {"/api/item/": "unknown"}, []),
        ("include-import-alias", "from django.urls import path as route, include as mount\nfrom app import urls as app_urls\nurlpatterns = [route('api/', mount(app_urls, namespace='one'))]\n", {"/api/item/": "unknown"}, []),
        ("dynamic-include-expression", "from django.urls import path, include\nurlpatterns = [path('api/', include(resolve_urlconf()))]\n", {}, ["/api/item/"]),
        ("foreign-auth-wrapper", "from django.urls import path\nfrom local_wrappers import login_required\nfrom app import views\nurlpatterns = [path('public/', login_required(views.public))]\n", {"/public/": "unknown"}, []),
        ("fake-public-wrapper", "from django.urls import path\nfrom app import views\ndef login_not_required(view):\n    return view\nurlpatterns = [path('public/', login_not_required(views.public))]\n", {"/public/": "unknown"}, []),
        ("canonical-public-wrapper", "from django.urls import path\nfrom django.contrib.auth.decorators import login_not_required\nfrom app import views\nurlpatterns = [path('public/', login_not_required(views.public))]\n", {"/public/": "unknown"}, []),
    ]
    output = []
    for name, urls, expected, forbidden in specs:
        files = {**common, "project/urls.py": urls}
        if name.startswith("include-"):
            files["app/urls.py"] = "from django.urls import path\nfrom app import views\napp_name = 'app'\nurlpatterns = [path('item/', views.public)]\n"
        if name == "shadowed-auth-decorator":
            files["app/views.py"] = "def login_required(fn):\n    return fn\n\n@login_required\ndef public(request):\n    return None\n"
        if name == "spoof-middleware-name":
            files["project/settings.py"] = "ROOT_URLCONF = 'project.urls'\nMIDDLEWARE = ['vendor.LoginRequiredMiddlewareSpoof']\n"
        output.append({"name": name, "files": files, "expected_overlay_auth": expected, "forbidden_overlay_paths": forbidden})
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--core-src", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    definitions = cases()
    for case in definitions:
        directory = args.fixtures / case["name"]
        for rel, source in case["files"].items():
            target = directory / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_text(encoding="utf-8") != source:
                raise RuntimeError(f"Refusing to replace different fixture: {target}")
            if not target.exists():
                if not args.prepare_only:
                    raise RuntimeError(f"Prepare the immutable fixture first: {target}")
                target.write_text(source, encoding="utf-8")
    manifest = [{"name": case["name"], "expected_overlay_auth": case["expected_overlay_auth"], "forbidden_overlay_paths": case["forbidden_overlay_paths"], "files": {rel: hashlib.sha256((args.fixtures / case["name"] / rel).read_bytes()).hexdigest() for rel in case["files"]}} for case in definitions]
    manifest_path = args.fixtures / "oracle-manifest.json"
    manifest_text = json.dumps(manifest, indent=2) + "\n"
    if not manifest_path.exists() or manifest_path.read_text(encoding="utf-8") != manifest_text:
        if not args.prepare_only:
            raise RuntimeError("Prepared fixture manifest does not match current fixture bytes")
        manifest_path.write_text(manifest_text, encoding="utf-8")
    if args.prepare_only:
        print(json.dumps({"fixtures": str(args.fixtures), "cases": len(definitions)}))
        return
    if args.core_src:
        sys.path.insert(0, str(args.core_src.resolve()))
    from attackmap.analyzers import analyze_repository, get_builtin_repository_analyzers
    from attackmap.analyzer_profiles import resolve_analyzer_profile
    from attackmap.ecosystem_python import scan_python_services
    from attackmap_analyzer_python import PythonAnalyzer

    plugin = PythonAnalyzer()
    available = {analyzer.name: analyzer for analyzer in [*get_builtin_repository_analyzers(), plugin]}
    selection = resolve_analyzer_profile("python@1.0", [item.metadata for item in available.values()])
    profile = [available[name] for name in selection.module_names]
    results = []
    for case in definitions:
        directory = args.fixtures / case["name"]
        lanes = {
            "builtin_overlay": scan_python_services(directory),
            "official_plugin": plugin.analyze(directory),
            "python_profile": analyze_repository(directory, analyzers=profile),
        }
        serialized = {name: {"routes": [route.model_dump(mode="json") for route in result.routes], "limitations": result.limitations} for name, result in lanes.items()}
        actual = {route.path: route.auth for route in lanes["builtin_overlay"].routes}
        mismatches = [f"{path}: expected {auth}, got {actual.get(path, 'MISSING')}" for path, auth in case["expected_overlay_auth"].items() if actual.get(path) != auth]
        mismatches += [f"forbidden route emitted: {path}" for path in case["forbidden_overlay_paths"] if path in actual]
        results.append({"name": case["name"], "expected_overlay_auth": case["expected_overlay_auth"], "forbidden_overlay_paths": case["forbidden_overlay_paths"], "overlay_mismatches": mismatches, "lanes": serialized})
    source = Path(inspect.getsourcefile(scan_python_services))
    plugin_source = Path(inspect.getsourcefile(PythonAnalyzer))
    output = {"scope": "Deterministic extraction only on identical inert fixtures. No Django server/framework execution, provider, installation or release acceptance.", "interpreter": sys.executable, "overlay_source": str(source), "overlay_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "plugin_source": str(plugin_source), "plugin_source_sha256": hashlib.sha256(plugin_source.read_bytes()).hexdigest(), "plugin_pin_verification": "See upstream qualification evidence; installed wheel metadata alone is not a Git attestation.", "profile": selection.as_dict(), "profile_impl": [{"name": analyzer.name, "module": type(analyzer).__module__, "class": type(analyzer).__qualname__} for analyzer in profile], "case_count": len(results), "overlay_oracle_pass_count": sum(not row["overlay_mismatches"] for row in results), "cases": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "cases": len(results), "overlay_oracle_pass_count": output["overlay_oracle_pass_count"], "mismatches": {row["name"]: row["overlay_mismatches"] for row in results if row["overlay_mismatches"]}}, indent=2))


if __name__ == "__main__":
    main()
