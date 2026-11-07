"""Imported identities and fail-closed mount observations, without execution."""
import pytest

from attackmap.python_route_binding import BindingIndex


ROUTER = '''from fastapi import APIRouter
router = APIRouter(prefix="/items")
@router.get("/item")
def item(): return {}
'''


@pytest.mark.parametrize('import_line,token', [
    ('from routers import router', 'router'),
    ('from routers import router as selected', 'selected'),
    ('import routers as selected', 'selected.router'),
    ('import routers', 'routers.router'),
])
def test_canonical_import_binding(import_line, token):
    index = BindingIndex({'main.py': f'''from fastapi import FastAPI
{import_line}
app = FastAPI()
app.include_router({token}, prefix="/api")
''', 'routers.py': ROUTER})
    mount, = index.mounts
    assert mount.supported
    assert (mount.child.file, mount.child.name, mount.child.prefix) == ('routers.py', 'router', '/items')
    assert index.route_object('routers.py', 3) == mount.child


def test_relative_import_and_reexport():
    index = BindingIndex({'pkg/main.py': '''from fastapi import FastAPI
from .exports import router as selected
app = FastAPI()
app.include_router(selected, prefix="/api")
''', 'pkg/exports.py': 'from .routers import router\n', 'pkg/routers.py': ROUTER})
    assert index.mounts[0].child.file == 'pkg/routers.py'
    assert index.mounts[0].supported


@pytest.mark.parametrize('wiring', [
    'app.include_router(router, prefix="/api")',  # unique repo name is not a binding
    'from unrelated import router\napp.include_router(router, prefix="/api")',
    'from routers import router\nrouter = object()\napp.include_router(router)',
    'from routers import *\napp.include_router(router)',
    'if enabled:\n    from routers import router\napp.include_router(router)',
    'from routers import router\nif enabled:\n    app.include_router(router)',
    'from routers import router\napp.include_router(router, prefix=runtime_prefix)',
    'from routers import router\napp.include_router(router, **options)',
    'from routers import router\napp = factory()\napp.include_router(router)',
])
def test_unproven_mount_is_explicit(wiring):
    index = BindingIndex({'main.py': 'from fastapi import FastAPI\napp = FastAPI()\n' + wiring,
                          'routers.py': ROUTER})
    assert not any(m.supported for m in index.mounts)
    assert index.issues


def test_ambiguous_module_package_does_not_pick_first():
    index = BindingIndex({'main.py': '''from fastapi import FastAPI
from routers import router
app = FastAPI()
app.include_router(router)
''', 'routers.py': ROUTER, 'routers/__init__.py': ROUTER})
    assert index.mounts[0].child is None


@pytest.mark.parametrize('prefix,expected', [('', '/v1'), (', url_prefix=None', '/v1'),
                                           (', url_prefix=""', ''), (', url_prefix="/api"', '/api')])
def test_flask_factory_registration_option_overrides_default(prefix, expected):
    index = BindingIndex({'main.py': f'''from flask import Flask
from views import bp
def create_app():
    app = Flask(__name__)
    app.register_blueprint(bp{prefix})
    return app
''', 'views.py': 'from flask import Blueprint\nbp = Blueprint("api", __name__, url_prefix="/v1")'})
    assert index.mounts[0].supported
    assert index.mounts[0].prefix == expected


def test_scoped_names_and_exact_hook_import():
    index = BindingIndex({'views.py': '''from flask import Blueprint
from guards import verify as actual_guard
private = Blueprint("private", __name__)
public = Blueprint("public", __name__)
private.before_request(actual_guard)
@private.route("/private")
def one(): pass
@public.route("/public")
def two(): pass
''', 'guards.py': 'def verify():\n    return None\n'})
    file, line, receiver, definition = index.hooks[0]
    assert (file, line, definition.file, definition.name) == ('views.py', 5, 'guards.py', 'verify')
    assert receiver == index.route_object('views.py', 6)
    assert receiver != index.route_object('views.py', 8)


def test_strings_comments_and_unrelated_class_do_not_wire():
    index = BindingIndex({'main.py': '''from custom import FastAPI, APIRouter
app = FastAPI()
router = APIRouter()
# app.include_router(router)
note = "app.include_router(router)"
app.include_router(router)
'''})
    assert len(index.mounts) == 1
    assert not index.mounts[0].supported


def test_function_parameter_shadows_global_router():
    index = BindingIndex({'main.py': '''from fastapi import FastAPI, APIRouter
app = FastAPI()
router = APIRouter()
def configure(router):
    app.include_router(router)
'''})
    assert index.mounts[0].child is None


def test_syntax_error_is_explicit():
    index = BindingIndex({'main.py': 'from fastapi import FastAPI\napp = ('})
    assert index.issues


def test_forward_import_does_not_supply_an_earlier_binding():
    index = BindingIndex({'main.py': '''from fastapi import FastAPI
app = FastAPI()
app.include_router(router)
from routers import router
''', 'routers.py': ROUTER})
    assert index.mounts[0].child is None


@pytest.mark.parametrize('binding', [
    'try:\n    raise ValueError()\nexcept ValueError as router:\n    pass',
    'match value:\n    case router:\n        pass',
])
def test_opaque_rebinding_targets_invalidate_object(binding):
    index = BindingIndex({'main.py': '''from fastapi import FastAPI, APIRouter
app = FastAPI()
router = APIRouter()
''' + binding + '\napp.include_router(router)\n'})
    assert index.mounts[0].child is None


def test_nested_mount_records_explicit_unsupported_parent():
    index = BindingIndex({'main.py': '''from fastapi import APIRouter
outer = APIRouter(prefix="/outer")
inner = APIRouter(prefix="/inner")
outer.include_router(inner, prefix="/nested")
'''})
    assert index.mounts[0].child.name == 'inner'
    assert not index.mounts[0].supported
    assert index.issues
