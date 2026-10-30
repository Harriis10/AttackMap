"""Conservative static identities for Python router wiring, without imports.

Only direct statements in modules and functions are supported. Reassignments,
conditional bindings, wildcard imports and dynamic expressions stay unresolved.
This records declared wiring; it does not prove that an app factory is called.
"""
from __future__ import annotations

import ast
import io
import tokenize
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RouteObject:
    file: str
    name: str
    kind: str
    line: int
    prefix: str | None


@dataclass
class Definition:
    file: str
    name: str
    line: int
    text: str
    blocking_guard: bool
    wrapper_guard: bool = False


@dataclass
class Mount:
    file: str
    line: int
    framework: str
    parent: RouteObject | None
    child: RouteObject | None
    prefix: str | None
    dependencies: list[Definition] = field(default_factory=list)
    supported: bool = True


@dataclass
class _Scope:
    file: str
    parent: _Scope | None = None
    names: dict[str, list[object]] = field(default_factory=lambda: defaultdict(list))
    positions: dict[str, int] = field(default_factory=dict)
    wildcard: bool = False


_CONSTRUCTORS = {
    'fastapi.FastAPI': 'fastapi-app', 'fastapi.APIRouter': 'fastapi-router',
    'fastapi.routing.APIRouter': 'fastapi-router',
    'flask.Flask': 'flask-app', 'flask.Blueprint': 'flask-blueprint',
}
_MOUNT_METHODS = {'include_router': 'fastapi', 'register_blueprint': 'flask'}
_ROUTE_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'api_route', 'route'}


def _credential_reference(node: ast.AST, inputs: set[str], resolve) -> bool:
    return any(
        isinstance(part, ast.Name) and (part.id in inputs or resolve(part) in {'flask.request', 'flask.session'})
        for part in ast.walk(node)
    )


def _auth_rejection(node: ast.AST, resolve) -> bool:
    value = node.exc if isinstance(node, ast.Raise) else node.value if isinstance(node, ast.Expr) else None
    if not isinstance(value, ast.Call):
        return False
    if any(isinstance(arg, ast.Starred) for arg in value.args) or any(kw.arg is None for kw in value.keywords):
        return False
    name = value.func.id if isinstance(value.func, ast.Name) else value.func.attr if isinstance(value.func, ast.Attribute) else ''
    canonical = resolve(value.func)
    if isinstance(node, ast.Raise) and name in {'Unauthorized', 'Forbidden', 'PermissionDenied'}:
        return canonical in {'werkzeug.exceptions.Unauthorized', 'werkzeug.exceptions.Forbidden', 'django.core.exceptions.PermissionDenied'}
    if name not in {'abort', 'HTTPException'} or (name == 'HTTPException' and not isinstance(node, ast.Raise)):
        return False
    if canonical not in {'flask.abort', 'werkzeug.exceptions.abort', 'fastapi.HTTPException', 'starlette.exceptions.HTTPException'}:
        return False
    statuses = value.args[:1] + [kw.value for kw in value.keywords if kw.arg in {'code', 'status_code'}]
    return len(statuses) == 1 and any(isinstance(status, ast.Constant) and status.value in {401, 403}
               or isinstance(status, ast.Attribute) and status.attr.startswith(('HTTP_401_', 'HTTP_403_'))
               and (resolve(status) or '').startswith(('fastapi.status.', 'starlette.status.'))
               for status in statuses)


def _rejecting_block(statements: list[ast.stmt], resolve) -> bool:
    for statement in statements:
        if _auth_rejection(statement, resolve):
            return True
        # Do not reason through branches, loops, early exits or nested helpers.
        if not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Pass)):
            return False
    return False


def _default_rejects(value: ast.AST, origins: dict[str, ast.AST | None], *, expected=None, operation=None) -> bool:
    if isinstance(value, ast.Name):
        origin = origins.get(value.id)
        return origin is None or _default_rejects(origin, {}, expected=expected, operation=operation)
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        if value.func.attr == 'get':
            if value.keywords or not 1 <= len(value.args) <= 2:
                return False
            default = value.args[1] if len(value.args) == 2 else ast.Constant(None)
            return _default_rejects(default, {}, expected=expected, operation=operation)
        if value.func.attr in {'startswith', 'endswith'}:
            if value.keywords or len(value.args) != 1 or not isinstance(value.args[0], ast.Constant) or not isinstance(value.args[0].value, str) or not value.args[0].value:
                return False
            return _default_rejects(value.func.value, origins, expected=value.args[0].value, operation=value.func.attr)
    if isinstance(value, ast.Constant):
        if operation == 'is-none':
            return value.value is None
        if operation in {'startswith', 'endswith'}:
            return isinstance(value.value, str) and not getattr(value.value, operation)(expected)
        return value.value != expected if expected is not None else not value.value
    # A runtime value from a proven input has no statically permissive default.
    return isinstance(value, ast.Attribute)


def _missing_credential(node: ast.AST, inputs: set[str], origins, resolve) -> bool:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = node.operand
        supported = isinstance(value, (ast.Name, ast.Attribute)) or (
            isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
            and value.func.attr in {'get', 'startswith', 'endswith'})
        return supported and _credential_reference(value, inputs, resolve) and _default_rejects(value, origins)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return any(_missing_credential(value, inputs, origins, resolve) for value in node.values)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and _credential_reference(node, inputs, resolve):
        values = [node.left, *node.comparators]
        if isinstance(node.ops[0], ast.NotEq):
            literals = [value.value for value in values if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value]
            operands = [value for value in values if isinstance(value, (ast.Name, ast.Attribute))]
            return bool(literals and operands and _default_rejects(operands[0], origins, expected=literals[0]))
        if isinstance(node.ops[0], ast.NotIn):
            return isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
        operands = [value for value in values if isinstance(value, (ast.Name, ast.Attribute))]
        return isinstance(node.ops[0], (ast.Is, ast.Eq)) and any(
            isinstance(value, ast.Constant) and value.value is None for value in values
        ) and bool(operands and _default_rejects(operands[0], origins, operation='is-none'))
    return False


def _blocking_guard(node: ast.AST, resolve, dependency_input=lambda expr: False) -> bool:
    """Small accepted subset: caller-dependent rejection before early exits."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    inputs = {arg.arg for arg in args if any(word in arg.arg.lower() for word in ('token', 'api_key', 'apikey', 'user', 'session', 'authorization', 'credential'))}
    origins = {name: None for name in inputs}
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = list(zip(positional[len(positional) - len(node.args.defaults):], node.args.defaults))
    defaults += list(zip(node.args.kwonlyargs, node.args.kw_defaults))
    for arg, default in defaults:
        if arg.arg in inputs and default is not None:
            if isinstance(default, ast.Call) and resolve(default.func) in {'fastapi.Depends', 'fastapi.Security'}:
                if len(default.args) != 1 or default.keywords or not dependency_input(default.args[0]):
                    inputs.discard(arg.arg)
            else:
                origins[arg.arg] = default
    writes = defaultdict(int)
    for part in ast.walk(node):
        if isinstance(part, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
            targets = part.targets if isinstance(part, ast.Assign) else [part.target]
            for target in targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name):
                        writes[name.id] += 1
    if inputs.intersection(writes):
        return False
    for statement in node.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                if isinstance(target, ast.Name) and isinstance(statement.value, (ast.Call, ast.Attribute)) and writes[target.id] == 1 and _credential_reference(statement.value, inputs, resolve):
                    inputs.add(target.id)
                    origins[target.id] = statement.value
    for statement in node.body:
        if isinstance(statement, ast.If):
            if _missing_credential(statement.test, inputs, origins, resolve):
                if _rejecting_block(statement.body, resolve):
                    return True
        elif isinstance(statement, ast.Try):
            exits = (ast.Return, ast.Raise, ast.Yield, ast.YieldFrom)
            validation = False
            for item in statement.body:
                if not isinstance(item, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Pass)):
                    break
                value = getattr(item, 'value', None)
                if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name) and value.func.value.id == 'jwt' and value.func.attr == 'decode':
                    validation = resolve(value.func) in {'jwt.decode', 'jose.jwt.decode'} and any(_credential_reference(arg, inputs, resolve) for arg in value.args) and not any(kw.arg not in {'algorithms', 'audience', 'issuer', 'leeway'} for kw in value.keywords)
                    break
            if validation and not any(isinstance(part, exits) for item in [*statement.body, *statement.finalbody] for part in ast.walk(item)):
                if statement.handlers and all(_rejecting_block(handler.body, resolve) for handler in statement.handlers):
                    return True
        if any(isinstance(part, (ast.Return, ast.Raise, ast.Yield, ast.YieldFrom)) for part in ast.walk(statement)):
            return False
    return False


class BindingIndex:
    """Resolve only unique local/imported names from captured source files."""

    def __init__(self, files: dict[str, str]):
        self.files = files
        self.lines = {file: text.splitlines(keepends=True) for file, text in files.items()}
        self.modules: dict[str, list[str]] = defaultdict(list)
        self.scopes: dict[str, _Scope] = {}
        self.invalid_files: set[str] = set()
        self.definitions: list[tuple[Definition, ast.AST, _Scope]] = []
        self.calls: list[tuple[ast.Call, _Scope, bool]] = []
        self.route_receivers: dict[tuple[str, int], tuple[ast.expr, _Scope]] = {}
        self.decorators: dict[tuple[str, int, str], tuple[ast.expr, _Scope]] = {}
        self.mounts: list[Mount] = []
        self.hooks: list[tuple[str, int, RouteObject, Definition]] = []
        self.issues: list[str] = []
        for file in files:
            module = file.removesuffix('.py').replace('/', '.')
            if module.endswith('.__init__'):
                module = module[:-9]
            self.modules[module].append(file)
        for file, text in files.items():
            scope = self.scopes[file] = _Scope(file)
            try:
                tree = ast.parse(text)
                count = 0
                for _ in ast.walk(tree):
                    count += 1
                    if count > 100_000:
                        raise ValueError('AST node budget')
                self._collect(tree, scope, True, 0)
            except (SyntaxError, ValueError, RecursionError, MemoryError, tokenize.TokenError):
                scope.wildcard = True
                self.invalid_files.add(file)
                self.issues.append(f'{file}: static Python route binding unavailable (syntax or resource bound)')
        # Bounded propagation supports dependency helpers without importing code.
        for _ in range(8):
            changed = False
            for definition, node, scope in self.definitions:
                guard = _blocking_guard(node, lambda expr: self._external(expr, scope),
                                        lambda expr: self._dependency_input(expr, scope))
                changed |= guard != definition.blocking_guard
                definition.blocking_guard = guard
            if not changed:
                break
        for definition, node, scope in self.definitions:
            statements = [item for item in node.body if not (isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant))]
            if len(statements) == 2 and isinstance(statements[0], (ast.FunctionDef, ast.AsyncFunctionDef)) and isinstance(statements[1], ast.Return) and isinstance(statements[1].value, ast.Name) and statements[1].value.id == statements[0].name:
                wrapper = statements[0]
                if all(isinstance(decorator, ast.Call) and self._external(decorator.func, scope) == 'functools.wraps'
                       for decorator in wrapper.decorator_list):
                    definition.wrapper_guard = _blocking_guard(wrapper, lambda expr: self._external(expr, scope))
        for call, scope, direct in self.calls:
            method = call.func.attr
            if method in _MOUNT_METHODS:
                self._mount(call, scope, direct)
            elif method == 'before_request':
                obj = self.object(call.func.value, scope)
                target = self.definition(call.args[0], scope) if len(call.args) == 1 else None
                if direct and obj and obj.kind == 'flask-blueprint' and target and not call.keywords:
                    self.hooks.append((scope.file, call.lineno, obj, target))
                else:
                    self.issues.append(f'{scope.file}:{call.lineno}: before_request binding unresolved')

    def _collect(self, node: ast.AST, scope: _Scope, direct: bool, depth: int):
        if depth > 100:
            raise ValueError('AST depth budget')
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            segment = ''.join(self.lines[scope.file][node.lineno - 1:node.end_lineno])
            # Definition evidence ignores comments/docstrings/string decoys.
            tokens = tokenize.generate_tokens(io.StringIO(segment).readline)
            code = tokenize.untokenize(token for token in tokens
                                      if token.type not in {tokenize.COMMENT, tokenize.STRING})
            value = Definition(scope.file, node.name, node.lineno, code, False)
            scope.names[node.name].append(value if direct and not node.decorator_list and not isinstance(node, ast.ClassDef) else None)
            scope.positions.setdefault(node.name, node.lineno)
            defaults = [*getattr(getattr(node, 'args', None), 'defaults', []),
                        *getattr(getattr(node, 'args', None), 'kw_defaults', [])]
            for expression in [*node.decorator_list, *defaults]:
                if expression is not None:
                    self._collect(expression, scope, direct, depth + 1)
            route_lines = []
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr in _ROUTE_METHODS and direct:
                        self.route_receivers[(scope.file, decorator.lineno)] = (decorator.func.value, scope)
                        route_lines.append(decorator.lineno)
            for line in route_lines:
                for decorator in node.decorator_list:
                    if isinstance(decorator, (ast.Name, ast.Attribute)):
                        name = decorator.id if isinstance(decorator, ast.Name) else decorator.attr
                        self.decorators[(scope.file, line, name)] = (decorator, scope)
            child = _Scope(scope.file, scope)
            child.wildcard = not direct or isinstance(node, ast.ClassDef)
            self.definitions.append((value, node, child))
            args = getattr(node, 'args', None)
            if args:
                for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                    if arg:
                        child.names[arg.arg].append(None)
                        child.positions[arg.arg] = node.lineno
            for statement in node.body:
                self._collect(statement, child, not isinstance(node, ast.ClassDef), depth + 1)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    scope.positions.setdefault(alias.asname or alias.name.split('.')[0], node.lineno)
                    scope.names[alias.asname or alias.name.split('.')[0]].append(
                        (alias.name if alias.asname else alias.name.split('.')[0]) if direct else None)
            else:
                module = node.module or ''
                if node.level:
                    package = scope.file.split('/')[:-1]
                    if node.level > len(package):
                        module = ''
                    else:
                        module = '.'.join(package[:len(package) - node.level + 1] + ([module] if module else []))
                for alias in node.names:
                    if alias.name == '*':
                        scope.wildcard = True
                    else:
                        scope.positions.setdefault(alias.asname or alias.name, node.lineno)
                        scope.names[alias.asname or alias.name].append(
                            f'{module}.{alias.name}' if module and direct else None)
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for item in ast.walk(target):
                    if isinstance(item, ast.Name):
                        scope.positions.setdefault(item.id, node.lineno)
                        value = node.value if direct and isinstance(target, ast.Name) and not isinstance(node, ast.AugAssign) else None
                        scope.names[item.id].append((value, scope, node.lineno))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            # Loop/with/exception targets and deletion cannot supply a static binding.
            scope.names[node.id].append(None)
            scope.positions.setdefault(node.id, node.lineno)
            return
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            scope.names[node.name].append(None)
            scope.positions.setdefault(node.name, node.lineno)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            scope.wildcard = True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {*_MOUNT_METHODS, 'before_request'}:
                self.calls.append((node, scope, direct))
        # Direct expression/assignment children preserve their lexical scope;
        # control flow and comprehensions make their contained wiring unsupported.
        transparent = isinstance(node, (ast.Module, ast.Expr, ast.Assign, ast.AnnAssign))
        for child in ast.iter_child_nodes(node):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and child in targets:
                continue
            self._collect(child, scope, direct if transparent or isinstance(node, ast.Call) else False, depth + 1)

    def _name(self, name: str, scope: _Scope, line: int | None = None):
        while scope:
            if scope.wildcard:
                return None
            values = scope.names.get(name)
            if values is not None:
                return values[0] if len(values) == 1 and (line is None or scope.positions.get(name, 0) <= line) else None
            scope = scope.parent
        return None

    def _symbol(self, node: ast.expr, scope: _Scope):
        if isinstance(node, ast.Name):
            return self._name(node.id, scope, node.lineno)
        if isinstance(node, ast.Attribute):
            base = self._symbol(node.value, scope)
            if isinstance(base, str):
                return base + '.' + node.attr
        return None

    def _imported(self, value, seen: set[str]):
        if not isinstance(value, str) or value in seen:
            return None
        seen = seen | {value}
        module, _, symbol = value.rpartition('.')
        candidates = self.modules.get(module, [])
        if len(candidates) != 1:
            return None
        bound = self._name(symbol, self.scopes[candidates[0]])
        return self._imported(bound, seen) if isinstance(bound, str) else bound

    def _external(self, node: ast.expr, scope: _Scope) -> str | None:
        symbol = self._symbol(node, scope)
        if isinstance(symbol, str) and not self.modules.get(symbol.split('.')[0]):
            return symbol
        return None

    def object(self, node: ast.expr, scope: _Scope) -> RouteObject | None:
        if scope.file in self.invalid_files:
            return None
        value = self._symbol(node, scope)
        value = self._imported(value, set()) if isinstance(value, str) else value
        if not isinstance(value, tuple):
            return None
        expression, owner, line = value
        if not isinstance(expression, ast.Call):
            return None
        kind = _CONSTRUCTORS.get(self._external(expression.func, owner))
        if not kind:
            return None
        keyword = 'url_prefix' if kind.startswith('flask') else 'prefix'
        prefix = self._prefix(expression, keyword, none_default=kind.startswith('flask'))
        name = next((name for name, values in owner.names.items() if len(values) == 1 and values[0] is value), '?')
        return RouteObject(owner.file, name, kind, line, prefix)

    def definition(self, node: ast.expr, scope: _Scope) -> Definition | None:
        if scope.file in self.invalid_files:
            return None
        value = self._symbol(node, scope)
        value = self._imported(value, set()) if isinstance(value, str) else value
        return value if isinstance(value, Definition) else None

    def _dependency_input(self, node: ast.expr, scope: _Scope) -> bool:
        target = self.definition(node, scope)
        if target is not None:
            return target.blocking_guard
        value = self._symbol(node, scope)
        value = self._imported(value, set()) if isinstance(value, str) else value
        if isinstance(value, tuple):
            expression, owner, _ = value
            if isinstance(expression, ast.Call) and not any(kw.arg is None for kw in expression.keywords):
                return self._external(expression.func, owner) in {
                    'fastapi.security.OAuth2PasswordBearer', 'fastapi.security.OAuth2AuthorizationCodeBearer',
                    'fastapi.security.HTTPBearer', 'fastapi.security.HTTPBasic',
                    'fastapi.security.APIKeyHeader', 'fastapi.security.APIKeyCookie', 'fastapi.security.APIKeyQuery',
                }
        return False

    @staticmethod
    def _prefix(call: ast.Call, name: str, *, none_default: bool = False) -> str | None:
        if any(keyword.arg is None for keyword in call.keywords):
            return None
        values = [keyword.value for keyword in call.keywords if keyword.arg == name]
        if not values:
            return ''
        if len(values) == 1 and isinstance(values[0], ast.Constant):
            if isinstance(values[0].value, str):
                return values[0].value
            if none_default and values[0].value is None:
                return ''
        return None

    def _mount(self, call: ast.Call, scope: _Scope, direct: bool):
        framework = _MOUNT_METHODS[call.func.attr]
        parent = self.object(call.func.value, scope)
        child = self.object(call.args[0], scope) if len(call.args) == 1 else None
        expected = 'fastapi-router' if framework == 'fastapi' else 'flask-blueprint'
        prefix = self._prefix(call, 'prefix' if framework == 'fastapi' else 'url_prefix')
        # Flask None and absence select the blueprint default; explicit '' overrides it.
        if framework == 'flask':
            options = [kw.value for kw in call.keywords if kw.arg == 'url_prefix']
            if not options or (len(options) == 1 and isinstance(options[0], ast.Constant) and options[0].value is None):
                prefix = child.prefix if child else None
        supported = bool(direct and parent and parent.kind == framework + '-app'
                         and child and child.kind == expected and prefix is not None
                         and child.prefix is not None and not any(kw.arg is None for kw in call.keywords))
        mount = Mount(scope.file, call.lineno, framework, parent, child, prefix, supported=supported)
        self.mounts.append(mount)
        if not supported:
            self.issues.append(f'{scope.file}:{call.lineno}: {call.func.attr} binding/prefix unresolved or nested; no mount/auth certification')
            return
        if framework == 'fastapi':
            values = [kw.value for kw in call.keywords if kw.arg == 'dependencies']
            if len(values) == 1 and isinstance(values[0], (ast.List, ast.Tuple)):
                for dependency in values[0].elts:
                    if isinstance(dependency, ast.Call) and self._external(dependency.func, scope) in {'fastapi.Depends', 'fastapi.Security'} and len(dependency.args) == 1 and not dependency.keywords:
                        target = self.definition(dependency.args[0], scope)
                        if target:
                            mount.dependencies.append(target)

    def route_object(self, file: str, line: int) -> RouteObject | None:
        binding = self.route_receivers.get((file, line))
        return self.object(*binding) if binding else None

    def route_decorator(self, file: str, line: int, name: str) -> Definition | None:
        binding = self.decorators.get((file, line, name))
        return self.definition(*binding) if binding else None
