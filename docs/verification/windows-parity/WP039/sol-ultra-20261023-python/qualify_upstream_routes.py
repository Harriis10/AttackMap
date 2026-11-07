"""Paired extraction from installed pin and immutable upstream source overlays."""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
WORK = ROOT / ".tmp/wp039-sol-ultra-20261023-python/upstream-qualification"
CORE = ROOT / ".tmp/wp042-sol-ultra-20261023-batch2/engine-final/source/src"
PYTHON = ROOT / ".tools/wp024-freeze-venv/Scripts/python.exe"


def save(path, payload):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def fixtures():
    fastapi_routes = "from fastapi import APIRouter\nrouter = APIRouter(prefix='/v1')\n@router.get('/users')\ndef users():\n    return {}\n"
    flask_routes = "from flask import Blueprint\nbp = Blueprint('users', __name__, url_prefix='/v1')\n@bp.route('/users', methods=['GET'])\ndef users():\n    return {}\n"
    cases = {}
    def add(name, files, expected, forbidden=()):
        cases[name] = {"files": {"pyproject.toml": '[project]\nname="qualification"\nversion="0.0.0"\n', **files},
                       "expected_mounted_paths": expected, "forbidden_mounted_paths": list(forbidden)}
    for label, includes, expected in (
        ("fastapi-import-alias", "app.include_router(api_router, prefix='/api')\n", ["/api/v1/users"]),
        ("fastapi-multi-mount", "app.include_router(api_router, prefix='/internal')\napp.include_router(api_router, prefix='/public')\n", ["/internal/v1/users", "/public/v1/users"]),
        ("fastapi-dynamic-prefix", "prefix = get_prefix()\napp.include_router(api_router, prefix=prefix)\n", []),
    ):
        add(label, {"routes.py": fastapi_routes, "main.py": "from fastapi import FastAPI\nfrom routes import router as api_router\napp=FastAPI()\n" + includes}, expected,
            ["/api/v1/users"] if label.endswith("dynamic-prefix") else [])
    add("fastapi-wrong-import", {"routes.py": fastapi_routes,
        "other.py": "from fastapi import APIRouter\nrouter=APIRouter(prefix='/v2')\n@router.get('/status')\ndef status(): return {}\n",
        "main.py": "from fastapi import FastAPI\nfrom other import router as api_router\napp=FastAPI()\napp.include_router(api_router,prefix='/api')\n"}, ["/api/v2/status"], ["/api/v1/users"])
    for label, registrations, expected in (
        ("flask-registration-override", "app.register_blueprint(api_bp,url_prefix='/api')\n", ["/api/users"]),
        ("flask-constructor-prefix", "app.register_blueprint(api_bp)\n", ["/v1/users"]),
        ("flask-multi-mount", "app.register_blueprint(api_bp,url_prefix='/internal',name='internal')\napp.register_blueprint(api_bp,url_prefix='/public',name='public')\n", ["/internal/users", "/public/users"]),
        ("flask-dynamic-prefix", "prefix=get_prefix()\napp.register_blueprint(api_bp,url_prefix=prefix)\n", []),
    ):
        add(label, {"views.py": flask_routes, "main.py": "from flask import Flask\nfrom views import bp as api_bp\napp=Flask(__name__)\n" + registrations}, expected,
            ["/api/v1/users"] if label == "flask-registration-override" else [])
    common = {"manage.py": "# Django project marker\n", "project/__init__.py": "", "shop/__init__.py": "",
        "project/settings.py": "ROOT_URLCONF='project.urls'\nINSTALLED_APPS=['shop']\n",
        "shop/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns=[path('items/',views.items)]\n",
        "shop/views.py": "def items(request): return None\n"}
    add("django-include-positive", {**common, "project/urls.py": "from django.urls import path,include\nurlpatterns=[path('api/',include('shop.urls'))]\n"}, ["/api/items/"])
    add("django-include-wrong-target", {**common, "other/__init__.py": "", "other/views.py": "def status(request): return None\n",
        "other/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns=[path('status/',views.status)]\n",
        "project/urls.py": "from django.urls import path,include\nurlpatterns=[path('api/',include('other.urls'))]\n"}, ["/api/status/"], ["/api/items/"])
    return cases


def worker(label, output, fixture_manifest):
    import attackmap
    from attackmap.analyzers import (BuiltinPythonWebAnalyzer, BuiltinPythonServiceAnalyzer,
                                    BuiltinConfigAnalyzer, DefaultAnalyzer, analyze_repository)
    from attackmap.index import clear_pinned_index
    from attackmap_analyzer_python import PythonAnalyzer
    assert Path(attackmap.__file__).resolve().is_relative_to(CORE.resolve())
    origins = {"core": attackmap.__file__, "plugin": inspect.getfile(PythonAnalyzer),
               "builtin_service": inspect.getfile(BuiltinPythonServiceAnalyzer)}
    result = {"label": label, "origins": origins, "fixtures": {}}
    for name, fixture in fixture_manifest.items():
        root = Path(fixture["root"])
        roles = {}
        for role, analyzer in (("plugin_only", PythonAnalyzer()), ("builtin_web", BuiltinPythonWebAnalyzer()),
                               ("builtin_service", BuiltinPythonServiceAnalyzer())):
            clear_pinned_index()
            scan = analyzer.analyze(root)
            roles[role] = scan.model_dump(mode="json")
        clear_pinned_index()
        selected = [PythonAnalyzer(), BuiltinPythonWebAnalyzer(), BuiltinConfigAnalyzer(), BuiltinPythonServiceAnalyzer(), DefaultAnalyzer()]
        scan = analyze_repository(root, analyzers=selected, incremental=False)
        roles["effective_python_profile"] = scan.model_dump(mode="json")
        clear_pinned_index()
        result["fixtures"][name] = {"expected_mounted_paths": fixture["expected_mounted_paths"],
            "forbidden_mounted_paths": fixture["forbidden_mounted_paths"], "roles": roles,
            "route_projection": {role: [{key: row.get(key) for key in ("path", "method", "file", "line", "auth", "guards")}
                                        for row in scan["routes"]] for role, scan in roles.items()}}
    save(output, result)


def run():
    definitions = fixtures()
    fixture_manifest = {}
    for name, definition in definitions.items():
        folder = WORK / "routing-fixtures" / name
        folder.mkdir(parents=True, exist_ok=False)
        hashes = {}
        for relative, text in definition["files"].items():
            path = folder / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        fixture_manifest[name] = {"root": str(folder), "files": definition["files"], "sha256": hashes,
            "expected_mounted_paths": definition["expected_mounted_paths"], "forbidden_mounted_paths": definition["forbidden_mounted_paths"]}
    save(OUT / "upstream-route-fixtures.json", fixture_manifest)
    fetched = json.loads((OUT / "upstream-fetch.json").read_text(encoding="utf-8"))
    variants = {"installed": None, **{key: Path(row["source_root"]) / "src" for key, row in fetched["archives"].items()}}
    outcomes = {}
    for label, plugin_source in variants.items():
        output = OUT / f"upstream-routes-{label}.json"
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(str(path) for path in (plugin_source, CORE) if path is not None), PYTHONDONTWRITEBYTECODE="1")
        command = [str(PYTHON), "-B", str(Path(__file__).resolve()), "--worker", label, "--output", str(output)]
        completed = subprocess.run(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        (OUT / f"upstream-routes-{label}.stdout.log").write_bytes(completed.stdout)
        (OUT / f"upstream-routes-{label}.stderr.log").write_bytes(completed.stderr)
        assert completed.returncode == 0, (label, completed.stderr.decode("utf-8", errors="replace"))
        actual = json.loads(output.read_text(encoding="utf-8"))
        expected_origin = ROOT / ".tools/wp024-freeze-venv/Lib/site-packages" if plugin_source is None else plugin_source
        assert Path(actual["origins"]["plugin"]).resolve().is_relative_to(expected_origin.resolve())
        outcomes[label] = {"command": command, "exit_code": completed.returncode, "output": str(output), "origins": actual["origins"],
            "fixtures": {name: {role: {"paths": sorted({row["path"] for row in rows}),
                "expected_mounted_present": sorted(set(item["expected_mounted_paths"]) & {row["path"] for row in rows}),
                "expected_mounted_missing": sorted(set(item["expected_mounted_paths"]) - {row["path"] for row in rows}),
                "forbidden_mounted_present": sorted(set(item["forbidden_mounted_paths"]) & {row["path"] for row in rows})}
                for role, rows in item["route_projection"].items()} for name, item in actual["fixtures"].items()}}
    installed = json.loads((OUT / "upstream-routes-installed.json").read_text(encoding="utf-8"))
    pinned = json.loads((OUT / "upstream-routes-pinned.json").read_text(encoding="utf-8"))
    assert {name: row["route_projection"] for name, row in installed["fixtures"].items()} == {name: row["route_projection"] for name, row in pinned["fixtures"].items()}
    save(OUT / "upstream-route-comparison.json", {"scope": "Identical paired fixtures, isolated plugin source overlays, immutable captured baseline core; no installed pin changes",
        "fixture_count": len(definitions), "variant_count": len(variants), "installed_pinned_route_projections_identical": True, "variants": outcomes})
    print(json.dumps({"fixtures": len(definitions), "variants": len(variants), "installed_pinned_route_projections_identical": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.output, json.loads((OUT / "upstream-route-fixtures.json").read_text(encoding="utf-8")))
    else:
        run()
