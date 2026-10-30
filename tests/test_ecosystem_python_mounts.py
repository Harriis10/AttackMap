"""Bound mount controls must not certify public sibling objects."""
from pathlib import Path

import pytest

from attackmap.ecosystem_python import scan_python_services


def write_repo(root: Path, sources: dict[str, str]):
    for name, source in sources.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding='utf-8')


GUARD = '''from fastapi import HTTPException
def verify_token(token: str):
    if not token:
        raise HTTPException(status_code=401)
    return token
'''
ROUTERS = '''from fastapi import APIRouter
private = APIRouter(prefix="/private")
public = APIRouter(prefix="/public")
@private.get("/item")
def one(): return {}
@public.get("/item")
def two(): return {}
'''


def test_fastapi_guard_attaches_only_exact_router(tmp_path):
    write_repo(tmp_path, {'routers.py': ROUTERS, 'guards.py': GUARD, 'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, prefix="/api", dependencies=[Depends(verify_token)])
'''})
    result = scan_python_services(tmp_path)
    assert [(r.path, r.auth) for r in result.routes] == [('/private/item', 'required')]
    assert any(h.hint == 'fastapi_router_mount:/api/private' for h in result.framework_hints)


@pytest.mark.parametrize('second', ['', ', dependencies=[Depends(verify_token)]'])
def test_fastapi_all_mounts_must_have_validated_guard(tmp_path, second):
    write_repo(tmp_path, {'routers.py': ROUTERS, 'guards.py': GUARD, 'main.py': f'''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, prefix="/first", dependencies=[Depends(verify_token)])
app.include_router(private, prefix="/second"{second})
'''})
    result = scan_python_services(tmp_path)
    assert bool(result.routes) == bool(second)
    assert {h.hint for h in result.framework_hints if h.hint.startswith('fastapi_router_mount:')} == {
        'fastapi_router_mount:/first/private', 'fastapi_router_mount:/second/private'}


def test_auth_dependency_name_alone_does_not_certify(tmp_path):
    write_repo(tmp_path, {'routers.py': ROUTERS, 'guards.py': 'def verify_token():\n    return None\n',
                         'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, dependencies=[Depends(verify_token)])
'''})
    assert scan_python_services(tmp_path).routes == []


def test_flask_hook_and_prefix_bind_exact_blueprint(tmp_path):
    write_repo(tmp_path, {'main.py': '''from flask import Flask
from views import private
app = Flask(__name__)
app.register_blueprint(private, url_prefix="/api")
''', 'views.py': '''from flask import Blueprint, abort, request
private = Blueprint("private", __name__, url_prefix="/v1")
public = Blueprint("public", __name__, url_prefix="/public")
def verify_token():
    if not request.headers.get("Authorization"):
        abort(401)
private.before_request(verify_token)
@private.route("/item")
def one(): return {}
@public.route("/item")
def two(): return {}
'''})
    result = scan_python_services(tmp_path)
    assert [(r.path, r.auth) for r in result.routes] == [('/v1/item', 'required')]
    assert any(h.hint == 'flask_blueprint_mount:/api' for h in result.framework_hints)
    assert all('/api/v1' not in h.hint for h in result.framework_hints)


def test_same_name_guard_in_unrelated_module_does_not_certify(tmp_path):
    write_repo(tmp_path, {'unrelated.py': GUARD, 'guards.py': 'def verify_token():\n    return None\n',
                         'views.py': '''from flask import Blueprint
from guards import verify_token
bp = Blueprint("api", __name__)
bp.before_request(verify_token)
@bp.route("/item")
def item(): return {}
'''})
    result = scan_python_services(tmp_path)
    assert result.routes == []
    assert not any(h.hint.startswith('blueprint_auth_hook:') for h in result.auth_hints)


@pytest.mark.parametrize('guard', [
    'def verify_token():\n    """request.headers abort(401)"""\n    return None\n',
    'def verify_token():\n    # request.headers abort(401)\n    return None\n',
    'def verify_token(token):\n    return None\n    if not token:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token):\n    if False:\n        raise HTTPException(status_code=401)\n    return token\n',
    'def verify_token(token, optional=False):\n    if optional:\n        return None\n    if not token:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token=None):\n    if token is None:\n        return None\n    else:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token=None):\n    if token is not None:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token=None):\n    try:\n        return None\n        jwt.decode(token)\n    except ValueError:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token=None):\n    if token != None:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token=None):\n    if not (token is None):\n        raise HTTPException(status_code=401)\n',
    'def verify_token(user):\n    if user.is_authenticated != False:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token):\n    try:\n        if False:\n            jwt.decode(token)\n    except ValueError:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token, enable_auth=False):\n    try:\n        if enable_auth:\n            jwt.decode(token)\n    except ValueError:\n        raise HTTPException(status_code=401)\n',
    'def verify_token():\n    token = "public"\n    if not token:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token):\n    token = "public"\n    if not token:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token="public"):\n    if not token:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token="public"):\n    if token is None:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token):\n    try:\n        jwt.decode(token, options={"verify_signature": False})\n    except ValueError:\n        raise HTTPException(status_code=401)\n',
    'def verify_token(token):\n    try:\n        jwt.decode(token)\n    except ValueError:\n        pass\n    except Exception:\n        raise HTTPException(status_code=401)\n',
])
def test_auth_body_string_or_comment_is_not_guard_proof(tmp_path, guard):
    write_repo(tmp_path, {'routers.py': ROUTERS, 'guards.py': guard,
                         'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, dependencies=[Depends(verify_token)])
'''})
    assert scan_python_services(tmp_path).routes == []


def test_unresolved_second_mount_blocks_auth_upgrade(tmp_path):
    write_repo(tmp_path, {'routers.py': ROUTERS, 'guards.py': GUARD, 'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, dependencies=[Depends(verify_token)])
app.include_router(private, prefix=runtime_prefix)
'''})
    result = scan_python_services(tmp_path)
    assert result.routes == []
    assert result.limitations


def test_conditional_app_binding_blocks_mixed_mount_auth(tmp_path):
    write_repo(tmp_path, {'routers.py': ROUTERS, 'guards.py': GUARD, 'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, dependencies=[Depends(verify_token)])
if configured:
    other = FastAPI()
other.include_router(private)
'''})
    result = scan_python_services(tmp_path)
    assert result.routes == []
    assert result.limitations


def test_distinct_routers_with_same_local_merge_key_remain_unknown(tmp_path):
    write_repo(tmp_path, {'routers.py': ROUTERS.replace('prefix="/private"', 'prefix="/same"').replace('prefix="/public"', 'prefix="/same"'),
                         'guards.py': GUARD, 'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, dependencies=[Depends(verify_token)])
'''})
    assert scan_python_services(tmp_path).routes == []


def test_custom_exception_name_does_not_certify_rejection(tmp_path):
    write_repo(tmp_path, {'routers.py': ROUTERS, 'guards.py': '''def HTTPException(status_code):
    return None
def verify_token(token):
    if not token:
        raise HTTPException(status_code=401)
''', 'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, dependencies=[Depends(verify_token)])
'''})
    assert scan_python_services(tmp_path).routes == []


@pytest.mark.parametrize('binding', [
    'from flask import request\ndef verify_token():\n    if not request.headers.get("Authorization", "public"):\n        raise HTTPException(status_code=401)\n',
    'from flask import request\ndef verify_token():\n    token = request.headers.get("Authorization", "public")\n    if not token:\n        raise HTTPException(status_code=401)\n',
])
def test_truthy_header_default_is_not_auth_proof(tmp_path, binding):
    write_repo(tmp_path, {'routers.py': ROUTERS, 'guards.py': 'from fastapi import HTTPException\n' + binding,
                         'main.py': '''from fastapi import FastAPI, Depends
from routers import private
from guards import verify_token
app = FastAPI()
app.include_router(private, dependencies=[Depends(verify_token)])
'''})
    assert scan_python_services(tmp_path).routes == []


@pytest.mark.parametrize('name', ['APIRouter', 'HTTPException'])
def test_default_expression_rebinding_cannot_certify(tmp_path, name):
    write_repo(tmp_path, {'main.py': f'''from fastapi import FastAPI, APIRouter, Depends, HTTPException
def fake(*args, **kwargs): return None
def change_binding(value=({name} := fake)): pass
def verify_token(token):
    if not token:
        raise HTTPException(status_code=401)
app = FastAPI()
router = APIRouter()
app.include_router(router, dependencies=[Depends(verify_token)])
@router.get("/item")
def item(): return {{}}
'''})
    assert scan_python_services(tmp_path).routes == []


@pytest.mark.parametrize('name', ['login_required', 'custom_auth'])
def test_unrelated_same_name_wrapper_cannot_certify_decorator(tmp_path, name):
    write_repo(tmp_path, {'wrappers.py': f'def {name}(handler):\n    return handler\n',
                         'unrelated.py': f'''from functools import wraps
from flask import request, abort
def {name}(handler):
    @wraps(handler)
    def wrapper(*args, **kwargs):
        if not request.headers.get("Authorization"):
            abort(401)
        return handler(*args, **kwargs)
    return wrapper
''', 'main.py': f'''from flask import Flask
from wrappers import {name}
app = Flask(__name__)
@app.route("/public")
@{name}
def item(): return {{}}
'''})
    assert scan_python_services(tmp_path).routes == []
