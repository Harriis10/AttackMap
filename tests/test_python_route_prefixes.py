"""Bounded per-file prefix resolution; multiple mounts need richer identity."""
from attackmap.scanner import _python_route_prefixes


def test_repeated_include_retains_local_prefix():
    text = '''router = APIRouter(prefix="/items")
app.include_router(router, prefix="/private")
app.include_router(router, prefix="/public")
'''
    assert _python_route_prefixes(text)['router'] == '/items'


def test_self_cycle_retains_local_prefix():
    text = 'router = APIRouter(prefix="/items")\nrouter.include_router(router, prefix="/loop")'
    assert _python_route_prefixes(text)['router'] == '/items'


def test_mutual_cycle_and_descendant_retain_local_prefixes():
    text = '''a = APIRouter(prefix="/a")
b = APIRouter(prefix="/b")
c = APIRouter(prefix="/c")
a.include_router(b, prefix="/one")
b.include_router(a, prefix="/two")
b.include_router(c, prefix="/three")
'''
    assert _python_route_prefixes(text) == {'a': '/a', 'b': '/b', 'c': '/c'}


def test_ambiguous_parent_blocks_descendant_composition():
    text = '''a = APIRouter(prefix="/a")
b = APIRouter(prefix="/b")
app.include_router(a, prefix="/one")
app.include_router(a, prefix="/two")
a.include_router(b, prefix="/child")
'''
    assert _python_route_prefixes(text) == {'a': '/a', 'b': '/b'}


def test_unambiguous_long_chain_is_order_independent():
    definitions = '\n'.join(f'r{i} = APIRouter(prefix="/r{i}")' for i in range(300))
    edges = ['app.include_router(r0, prefix="/api")']
    edges += [f'r{i-1}.include_router(r{i})' for i in range(1, 300)]
    expected = '/api/' + '/'.join(f'r{i}' for i in range(300))
    for ordered in (edges, list(reversed(edges))):
        assert _python_route_prefixes(definitions + '\n' + '\n'.join(ordered))['r299'] == expected


def test_flask_registration_override_default_and_empty():
    for options, expected in [(', url_prefix="/api"', '/api'), ('', '/v1'),
                              (', url_prefix=""', '/')]:
        text = f'''bp = Blueprint("bp", __name__, url_prefix="/v1")
app.register_blueprint(bp{options})
'''
        assert _python_route_prefixes(text)['bp'] == expected


def test_nested_flask_override_composes_parent_once():
    text = '''parent = Blueprint("parent", __name__, url_prefix="/parent")
child = Blueprint("child", __name__, url_prefix="/default")
parent.register_blueprint(child, url_prefix="/overridden")
app.register_blueprint(parent, url_prefix="/outer")
'''
    assert _python_route_prefixes(text)['child'] == '/outer/overridden'


def test_prefix_output_budget_falls_back_and_propagates():
    text = '''a = APIRouter(prefix="/a")
b = APIRouter(prefix="/b")
app.include_router(a, prefix="/''' + 'x' * 17000 + '''")
a.include_router(b, prefix="/child")
'''
    assert _python_route_prefixes(text) == {'a': '/a', 'b': '/b'}
