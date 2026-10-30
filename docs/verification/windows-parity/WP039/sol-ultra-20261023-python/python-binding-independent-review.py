"""Read-only adversarial guard and prefix probes; source is never executed."""
from __future__ import annotations
import argparse, ast, hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "src"))
from attackmap.python_route_binding import BindingIndex
from attackmap.scanner import _python_route_prefixes

CASES = {
    "missing-token-control": ("if token is None:\n    raise HTTPException(status_code=401)\n", True),
    "present-token-not-equal-none": ("if token != None:\n    raise HTTPException(status_code=401)\n", False),
    "present-token-negated-missing": ("if not (token is None):\n    raise HTTPException(status_code=401)\n", False),
    "positive-authenticated-not-equal-false": ("if user.is_authenticated != False:\n    raise HTTPException(status_code=401)\n", False),
    "jwt-decode-dead-branch": ("try:\n    if False:\n        jwt.decode(token)\nexcept Exception:\n    raise HTTPException(status_code=401)\n", False),
    "jwt-decode-optional-branch": ("try:\n    if enable_auth:\n        jwt.decode(token)\nexcept Exception:\n    raise HTTPException(status_code=401)\n", False),
    "early-return-control": ("return None\nif not token:\n    raise HTTPException(status_code=401)\n", False),
    "conditional-failure-control": ("if not token:\n    if enable_auth:\n        raise HTTPException(status_code=401)\n", False),
    "jwt-exception-swallowed-before-reject": ("try:\n    jwt.decode(token)\nexcept jwt.DecodeError:\n    pass\nexcept Exception:\n    raise HTTPException(status_code=401)\n", False),
    "truthy-credential-default": ("if not request.headers.get('Authorization', 'public'):\n    raise HTTPException(status_code=401)\n", False),
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="after")
    args = parser.parse_args()
    results = {}
    for name, (body, expected) in CASES.items():
        source = "def verify(token=None):\n" + "".join("    " + line + "\n" for line in body.splitlines())
        index = BindingIndex({"main.py": "from fastapi import FastAPI, APIRouter, Depends, HTTPException\nimport jwt\n" + source + "\napp=FastAPI()\nrouter=APIRouter()\napp.include_router(router,dependencies=[Depends(verify)])\n"})
        bound = [d.blocking_guard for mount in index.mounts for d in mount.dependencies]
        actual = bound == [True]
        results[name] = {"source": source, "expected": expected, "actual": actual,
                         "bound_dependency_guard": bound}
    graph_cases = {
        "conflicting-mounts": "router=APIRouter(prefix='/v1')\napp.include_router(router,prefix='/one')\napp.include_router(router,prefix='/two')\n",
        "two-node-cycle": "a=APIRouter(prefix='/a')\nb=APIRouter(prefix='/b')\na.include_router(b,prefix='/x')\nb.include_router(a,prefix='/y')\n",
        "self-cycle": "a=APIRouter(prefix='/a')\na.include_router(a,prefix='/x')\n",
    }
    for name, source in graph_cases.items():
        results[name] = {"source": source, "prefixes": _python_route_prefixes(source)}
    from attackmap import ecosystem_python as overlay
    from attackmap.models import ScanResult
    decorator_cases = {
        "shadowed-known-route-decorator": {"views.py": "from flask import Blueprint\nbp=Blueprint('public',__name__)\ndef login_required(fn):\n    return fn\n@bp.route('/public')\n@login_required\ndef public():\n    return {}\n"},
        "foreign-custom-decorator-collision": {
            "views.py": "from flask import Blueprint\nfrom local_wrappers import custom_auth\nbp=Blueprint('public',__name__)\n@bp.route('/public')\n@custom_auth\ndef public():\n    return {}\n",
            "local_wrappers.py": "def custom_auth(fn):\n    return fn\n",
            "unrelated.py": "from flask import request,abort\ndef custom_auth(fn):\n    def guarded(*args):\n        if not request.headers.get('Authorization'):\n            abort(401)\n        return fn(*args)\n    return guarded\n"},
    }
    for name, files in decorator_cases.items():
        state = overlay._PyState(files=files)
        for file, source in files.items():
            overlay._collect_defs(file, source, state)
            state.symbol_imports[file] = overlay._import_symbols(source)
            overlay._extract_fastapi(file, source, state)
            overlay._extract_flask(file, source, state)
            overlay._extract_routes(file, source, state)
        for route in state.routes:
            state.custom_auth_candidates.update(name for name in route.decorators if overlay._AUTHISH_NAME_RE.search(name))
        scan = ScanResult(root="inert-independent-review")
        overlay._emit(state, scan)
        results[name] = {"files": files, "expected_auth": "unknown", "routes": [row.model_dump(mode="json") for row in scan.routes]}
    output = {"source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
        "src/attackmap/python_route_binding.py", "src/attackmap/ecosystem_python.py", "src/attackmap/scanner.py")}, "probes": results}
    (Path(__file__).parent / ("python-binding-independent-review-" + args.label + ".json")).write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({name: {k: row[k] for k in ("expected", "actual", "bound_dependency_guard") if k in row} for name, row in results.items()}, indent=2))

if __name__ == "__main__":
    main()
