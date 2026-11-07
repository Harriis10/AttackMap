"""Retained paired mount probes; fixture bytes are created once, then checked."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
WORK = ROOT / '.tmp/wp039-python-20261023/python-mounts-fixtures'
CASES = {
    'fastapi-siblings': {
        'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, prefix="/api", dependencies=[Depends(verify_token)])
''',
        'routers.py': '''from fastapi import APIRouter
private = APIRouter(prefix="/private")
public = APIRouter(prefix="/public")
@private.get("/item")
def private_item(): return {}
@public.get("/item")
def public_item(): return {}
''',
        'guards.py': '''from fastapi import HTTPException
def verify_token(token: str):
    if not token:
        raise HTTPException(status_code=401)
    return token
''',
    },
    'flask-siblings': {
        'main.py': '''from flask import Flask
from views import private
app = Flask(__name__)
app.register_blueprint(private, url_prefix="/api")
''',
        'views.py': '''from flask import Blueprint, abort, request
private = Blueprint("private", __name__, url_prefix="/v1")
public = Blueprint("public", __name__, url_prefix="/public")
def verify_token():
    if not request.headers.get("Authorization"):
        abort(401)
private.before_request(verify_token)
@private.route("/item")
def private_item(): return {}
@public.route("/item")
def public_item(): return {}
''',
    },
    'fastapi-mixed-mounts': {
        'main.py': '''from fastapi import FastAPI, Depends
from routers import router
from guards import verify_token
app = FastAPI()
app.include_router(router, prefix="/private", dependencies=[Depends(verify_token)])
app.include_router(router, prefix="/public")
''',
        'routers.py': '''from fastapi import APIRouter
router = APIRouter(prefix="/items")
@router.get("/item")
def item(): return {}
''',
        'guards.py': '''from fastapi import HTTPException
def verify_token(token: str):
    if not token:
        raise HTTPException(status_code=401)
    return token
''',
    },
    'unbound-child': {
        'main.py': '''from fastapi import FastAPI, Depends
from guards import verify_token
app = FastAPI()
app.include_router(router, prefix="/unproven", dependencies=[Depends(verify_token)])
''',
        'routers.py': '''from fastapi import APIRouter
router = APIRouter(prefix="/items")
@router.get("/item")
def item(): return {}
''',
        'guards.py': '''from fastapi import HTTPException
def verify_token(token: str):
    if not token:
        raise HTTPException(status_code=401)
    return token
''',
    },
}


def main():
    mode = sys.argv[1]
    if mode == 'create':
        for case, sources in CASES.items():
            folder = WORK / case
            folder.mkdir(parents=True, exist_ok=False)
            for name, text in sources.items():
                (folder / name).write_bytes(text.encode('utf-8'))
        return
    import faulthandler
    faulthandler.dump_traceback_later(20, exit=True)
    import attackmap.ecosystem_python as builtin_module
    from attackmap.ecosystem_python import scan_python_services
    from attackmap_analyzer_python.analyzer import PythonAnalyzer
    evidence = {'mode': mode, 'python': sys.executable, 'cases': {}}
    for case, sources in CASES.items():
        if len(sys.argv) > 2 and case != sys.argv[2]:
            continue
        if len(sys.argv) == 2 and case == 'fastapi-mixed-mounts':
            continue  # retained baseline hang; run explicitly under the timer
        print(case, flush=True)
        folder = WORK / case
        hashes = {}
        for name, text in sources.items():
            raw = (folder / name).read_bytes()
            assert raw == text.encode('utf-8'), (case, name, 'fixture changed')
            hashes[name] = hashlib.sha256(raw).hexdigest()
        results = {}
        for label, result in [('builtin_python_service', scan_python_services(folder)),
                              ('installed_python_plugin', PythonAnalyzer().analyze(folder))]:
            results[label] = {key: [item.model_dump(mode='json') for item in getattr(result, key)]
                              for key in ['routes', 'framework_hints', 'auth_hints', 'limitations']
                              if key != 'limitations'}
            results[label]['limitations'] = result.limitations
        evidence['cases'][case] = {'fixture': str(folder), 'sha256': hashes, 'results': results}
    evidence['source_file'] = builtin_module.__file__
    evidence['source_sha256'] = hashlib.sha256(Path(builtin_module.__file__).read_bytes()).hexdigest()
    suffix = '-' + sys.argv[2] if len(sys.argv) > 2 else ''
    path = OUT / f'python-mounts-{mode}{suffix}.json'
    assert not path.exists(), path
    path.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    faulthandler.cancel_dump_traceback_later()
    print(path)


if __name__ == '__main__':
    main()
