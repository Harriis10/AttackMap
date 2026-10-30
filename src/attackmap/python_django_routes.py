"""Bounded Django URL declarations and import-backed function auth evidence.

This module parses source only. It never imports a target project or executes
Django configuration, decorators, factories, regexes or class-based views.
"""
from __future__ import annotations

import ast
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import re


_MAX_BYTES = 1024 * 1024
_MAX_NODES = 20000
_MAX_ENTRIES = 2048
_PARAMETER = re.compile(r"<(?:(\w+):)?(\w+)>")
_MODULE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\Z")
_LOGIN = "django.contrib.auth.decorators.login_required"
_PUBLIC = "django.contrib.auth.decorators.login_not_required"
DJANGO_ADMIN_TARGET = "__attackmap_django_admin_site_urls__"


def _module_name(rel: str) -> str:
    module = rel.removesuffix(".py").replace("/", ".").replace("\\", ".")
    return module.removesuffix(".__init__")


def _import_base(rel: str, node: ast.ImportFrom) -> str | None:
    if not node.level:
        return node.module or ""
    parts = _module_name(rel).split(".")
    if not rel.replace("\\", "/").endswith("/__init__.py"):
        parts = parts[:-1]
    if node.level > len(parts):
        return None
    prefix = parts[:len(parts) - node.level + 1]
    return ".".join([*prefix, *([node.module] if node.module else [])])


def _assigned_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # Defaults/decorators execute in the enclosing scope; function bodies do not.
        expressions = [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults, node.returns]
        expressions.extend(item.annotation for item in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs])
        expressions.extend(item.annotation for item in (node.args.vararg, node.args.kwarg) if item is not None)
        return {node.name} | {name for expression in expressions if expression is not None for name in _assigned_names(expression)}
    if isinstance(node, ast.ClassDef):
        expressions = [*node.decorator_list, *node.bases, *(item.value for item in node.keywords)]
        return {node.name} | {name for expression in expressions for name in _assigned_names(expression)}
    if isinstance(node, ast.Lambda):
        return {name for expression in [*node.args.defaults, *node.args.kw_defaults] if expression is not None for name in _assigned_names(expression)}
    if isinstance(node, ast.Import):
        return {item.asname or item.name.split(".")[0] for item in node.names}
    if isinstance(node, ast.ImportFrom):
        return {item.asname or item.name for item in node.names}
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = {item.id for target in targets for item in ast.walk(target) if isinstance(item, ast.Name)}
        expressions = [node.value, node.annotation] if isinstance(node, ast.AnnAssign) else [node.value]
        return names | {name for expression in expressions if expression is not None for name in _assigned_names(expression)}
    if isinstance(node, ast.Delete):
        return {item.id for target in node.targets for item in ast.walk(target) if isinstance(item, ast.Name)}
    names = {node.id} if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) else set()
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
        names.add(node.name)
    if isinstance(node, ast.MatchMapping) and node.rest:
        names.add(node.rest)
    for child in ast.iter_child_nodes(node):
        names.update(_assigned_names(child))
    return names


@dataclass
class _ModuleInfo:
    rel: str
    tree: ast.Module
    imports: dict[str, str | None] = field(default_factory=dict)
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = field(default_factory=dict)
    blocked: set[str] = field(default_factory=set)
    star_import: bool = False


def _info(rel: str, text: str) -> _ModuleInfo:
    if len(text.encode("utf-8")) > _MAX_BYTES:
        raise ValueError("source limit")
    tree = ast.parse(text)
    if sum(1 for _ in ast.walk(tree)) > _MAX_NODES:
        raise ValueError("AST limit")
    info = _ModuleInfo(rel, tree)
    for node in tree.body:
        imported: list[tuple[str, str]] = []
        if isinstance(node, ast.Import):
            imported = [(item.asname or item.name.split(".")[0], item.name if item.asname else item.name.split(".")[0]) for item in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = _import_base(rel, node)
            if any(item.name == "*" for item in node.names):
                info.star_import = True
            if base:
                imported = [(item.asname or item.name, base + "." + item.name) for item in node.names if item.name != "*"]
        if imported:
            for name, qualified in imported:
                if name in info.imports and info.imports[name] != qualified:
                    info.blocked.add(name)
                info.imports[name] = qualified
                if name in info.functions:
                    info.blocked.add(name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info.blocked.update(_assigned_names(node) - {node.name})
            if node.name in info.functions or node.name in info.imports:
                info.blocked.add(node.name)
            info.functions[node.name] = node
        else:
            info.blocked.update(_assigned_names(node))
    return info


def _symbol(node: ast.AST, info: _ModuleInfo, *, local_function: bool = False) -> str | None:
    if isinstance(node, ast.Name):
        if info.star_import or node.id in info.blocked:
            return None
        if node.id in info.imports:
            return info.imports[node.id]
        if local_function and node.id in info.functions:
            return _module_name(info.rel) + "." + node.id
    elif isinstance(node, ast.Attribute):
        prefix = _symbol(node.value, info)
        if prefix:
            return prefix + "." + node.attr
    return None


def _literal(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _literal_regex(value: str) -> str | None:
    if not value.startswith("^") or not value.endswith("$"):
        return None
    body, output, index = value[1:-1], [], 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            index += 1
            if index >= len(body) or body[index] not in r".\+*?^$()[]{}|-":
                return None
            output.append(body[index])
        elif char in ".+*?^$()[]{}|" or ord(char) < 32:
            return None
        else:
            output.append(char)
        index += 1
    return "".join(output)


def _include(node: ast.AST, info: _ModuleInfo) -> str | None:
    if not isinstance(node, ast.Call) or _symbol(node.func, info) != "django.urls.include" or len(node.args) != 1:
        return None
    if len(node.keywords) > 1 or any(keyword.arg != "namespace" or not (isinstance(keyword.value, ast.Constant) and (keyword.value.value is None or isinstance(keyword.value.value, str))) for keyword in node.keywords):
        return None
    argument = node.args[0]
    if isinstance(argument, ast.Tuple):
        if len(argument.elts) != 2 or _literal(argument.elts[1]) is None:
            return None
        argument = argument.elts[0]
    module = _literal(argument) or _symbol(argument, info)
    if module is None or _MODULE.fullmatch(module) is None:
        return None
    return f"include({module!r})"


def extract_django_url_entries(rel: str, text: str) -> tuple[list[tuple[str, str, int]], list[str]]:
    """Read statically assigned URLpattern lists and exact anchored literals.

    The target-string shape remains compatible with the existing URLconf walk.
    Unsupported expressions are named limitations, never guessed regex paths.
    """
    if "urlpatterns" not in text:
        return [], []
    limitations: list[str] = []
    try:
        info = _info(rel, text)
    except (SyntaxError, ValueError, RecursionError):
        return [], [f"ecosystem_python: unsupported Django URLconf syntax or bounds in {rel}"]
    entries: list[tuple[str, str, int]] | None = None

    def limit(node: ast.AST, reason: str) -> None:
        limitations.append(f"ecosystem_python: Django {reason} in {rel}:{getattr(node, 'lineno', 1)}")

    def read_list(value: ast.AST) -> list[tuple[str, str, int]] | None:
        if not isinstance(value, (ast.List, ast.Tuple)):
            limit(value, "dynamic urlpatterns are unsupported")
            return None
        result = []
        for call in value.elts:
            if len(result) >= _MAX_ENTRIES:
                limit(call, "URL entry limit reached")
                break
            if not isinstance(call, ast.Call):
                limit(call, "dynamic URL entry is unsupported")
                continue
            factory = _symbol(call.func, info)
            if factory not in {"django.urls.path", "django.urls.re_path"}:
                limit(call, "unresolved or non-Django path factory")
                continue
            keywords = {item.arg: item.value for item in call.keywords}
            if None in keywords or any(isinstance(item, ast.Starred) for item in call.args) or len(call.args) > 4 or len(keywords) != len(call.keywords) or set(keywords) - {"route", "view", "kwargs", "name"}:
                limit(call, "dynamic URL call arguments are unsupported")
                continue
            if (call.args and "route" in keywords) or (len(call.args) > 1 and "view" in keywords):
                limit(call, "duplicate URL call arguments are unsupported")
                continue
            path_node = call.args[0] if call.args else keywords.get("route")
            target = call.args[1] if len(call.args) > 1 else keywords.get("view")
            raw = _literal(path_node) if path_node is not None else None
            if raw is None or target is None or len(raw) > 2048 or any(ord(char) < 32 for char in raw):
                limit(call, "non-literal URL path is unsupported")
                continue
            if factory.endswith(".re_path"):
                normalized = _literal_regex(raw)
                if normalized is None:
                    limit(call, "regex route is unsupported beyond exact anchored literals")
                    continue
            else:
                normalized = _PARAMETER.sub(lambda match: "{" + match.group(2) + "}", raw)
            try:
                if _symbol(target, info) == "django.contrib.admin.site.urls":
                    rendered = DJANGO_ADMIN_TARGET
                elif isinstance(target, ast.Call) and _symbol(target.func, info) == "django.urls.include":
                    rendered = _include(target, info)
                    if rendered is None:
                        limit(target, "dynamic include or namespace is unsupported")
                        continue
                else:
                    rendered = ast.unparse(target)
                    # An unresolved include alias must not become a terminal view.
                    if isinstance(target, ast.Call) and isinstance(target.func, ast.Name) and target.func.id == "include":
                        limit(target, "unresolved include factory")
                        continue
                if len(rendered) > 2048:
                    limit(target, "view target bound exceeded")
                    continue
            except RecursionError:
                limit(target, "view target bound exceeded")
                continue
            result.append((normalized, rendered, call.lineno))
        return result

    for statement in info.tree.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(isinstance(target, ast.Name) and target.id == "urlpatterns" for target in targets):
                entries = read_list(statement.value) if statement.value is not None else None
            elif "urlpatterns" in _assigned_names(statement):
                entries = None
                limit(statement, "indirect urlpatterns mutation is unsupported")
        elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name) and statement.target.id == "urlpatterns":
            addition = read_list(statement.value)
            if not isinstance(statement.op, ast.Add) or entries is None or addition is None:
                entries = None
                limit(statement, "dynamic urlpatterns mutation is unsupported")
            else:
                entries.extend(addition)
        elif "urlpatterns" in _assigned_names(statement):
            entries = None
            limit(statement, "conditional urlpatterns assignment is unsupported")
        elif isinstance(statement, ast.Expr) and any(isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name) and item.value.id == "urlpatterns" for item in ast.walk(statement)):
            entries = None
            limit(statement, "urlpatterns method mutation is unsupported")
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load) and item.id == "urlpatterns"
            for item in ast.walk(statement)
        ):
            entries = None
            limit(statement, "dynamic urlpatterns reference is unsupported")
    if entries is not None and len(entries) > _MAX_ENTRIES:
        limitations.append(f"ecosystem_python: Django URL entry limit reached in {rel}")
        entries = entries[:_MAX_ENTRIES]
    return entries or [], list(dict.fromkeys(limitations))


def normalize_pinned_python_plugin_routes(result, files: Mapping[str, str]) -> None:
    """Align the pinned plugin's literal Django routes with validated URL entries.

    Only ANY routes whose evidence line contains a path/re_path call are in
    scope. Unparseable files and every other plugin route family retain their
    original output. Unsupported, foreign, commented and include-only surfaces
    have no validated terminal entry and are omitted.
    """
    factory = re.compile(r"\b(?:path|re_path)\s*\(")
    candidates: dict[str, list] = {}
    source_lines: dict[str, list[str]] = {}
    for route in result.routes:
        if route.method != "ANY" or not isinstance(route.line, int):
            continue
        text = files.get(route.file)
        if text is None:
            continue
        lines = source_lines.setdefault(route.file, text.splitlines())
        if not 1 <= route.line <= len(lines) or not factory.search(lines[route.line - 1]):
            continue
        candidates.setdefault(route.file, []).append(route)

    replacements: dict[int, str | None] = {}
    for rel, routes in candidates.items():
        entries, limitations = extract_django_url_entries(rel, files[rel])
        if any("syntax or bounds" in limitation for limitation in limitations):
            continue
        terminal = {
            (line, "/" + raw.lstrip("/"))
            for raw, target, line in entries
            if not target.startswith("include(")
        }
        for route in routes:
            normalized = "/" + _PARAMETER.sub(
                lambda match: "{" + match.group(2) + "}", route.path
            ).lstrip("/")
            possible = {normalized}
            literal = _literal_regex(route.path)
            if literal is not None:
                possible.add("/" + literal.lstrip("/"))
            match = next((path for line, path in terminal if line == route.line and path in possible), None)
            replacements[id(route)] = match

    if not replacements:
        return
    kept = []
    seen = set()
    for route in result.routes:
        key = (route.path, route.method, route.file)
        if id(route) not in replacements:
            kept.append(route)
            seen.add(key)
            continue
        normalized = replacements[id(route)]
        if normalized is None:
            continue
        key = (normalized, route.method, route.file)
        if key in seen:
            continue
        route.path = normalized
        kept.append(route)
        seen.add(key)
    result.routes[:] = kept


def _function(files: Mapping[str, str], qualified: str, load: Callable[[str], _ModuleInfo | None], seen: frozenset[str] = frozenset()) -> tuple[_ModuleInfo, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    if qualified in seen or len(seen) >= 8:
        return None
    module, separator, name = qualified.rpartition(".")
    if not separator:
        return None
    base = module.replace(".", "/")
    candidates = [path for path in (base + ".py", base + "/__init__.py") if path in files]
    if len(candidates) != 1:
        return None
    info = load(candidates[0])
    if info is None or info.star_import or name in info.blocked:
        return None
    if name in info.functions:
        return info, info.functions[name]
    target = info.imports.get(name)
    return _function(files, target, load, seen | {qualified}) if target else None


def _view_auth(files: Mapping[str, str], load: Callable[[str], _ModuleInfo | None], urls_file: str, target: str, *, target_line: int | None = None) -> tuple[str, list[str], str | None, bool]:
    unknown = ("unknown", [], None, False)
    try:
        if urls_file not in files or len(target) > 2048:
            return unknown
        urls = load(urls_file)
        if urls is None:
            return unknown
        expression = ast.parse(target, mode="eval").body
        wrappers: list[str] = []
        while isinstance(expression, ast.Call):
            wrapper = _symbol(expression.func, urls)
            if wrapper not in {_LOGIN, _PUBLIC} or len(expression.args) != 1 or expression.keywords:
                return unknown
            wrappers.append(wrapper)
            expression = expression.args[0]
        qualified = _symbol(expression, urls, local_function=True)
        resolved = _function(files, qualified, load) if qualified else None
        if resolved is None:
            return unknown
        info, function = resolved
        guards: list[str] = []
        public = False
        for decorator in function.decorator_list:
            expression = decorator.func if isinstance(decorator, ast.Call) else decorator
            canonical = _symbol(expression, info)
            if isinstance(decorator, ast.Call) and (decorator.args or any(item.arg not in {"login_url", "redirect_field_name"} for item in decorator.keywords)):
                return unknown
            if canonical == _LOGIN:
                guards.append(f"@login_required ({info.rel}:{decorator.lineno})")
            elif canonical == _PUBLIC and not isinstance(decorator, ast.Call):
                public = True
            else:
                return unknown
        for wrapper in wrappers:
            if wrapper == _LOGIN:
                site = f"{urls_file}:{target_line}" if isinstance(target_line, int) and 0 < target_line <= len(files[urls_file].splitlines()) else urls_file
                guards.append(f"login_required wrapper at URL entry ({site})")
            else:
                public = True
        if guards:
            return "required", guards, f"validated Django login_required for {info.rel}:{function.lineno}", not public
        return "unknown", [], None, not public
    except (SyntaxError, ValueError, RecursionError):
        return unknown


class DjangoAuthResolver:
    """Resolve one scan's function auth with at most 32 cached module parses.

    The source mapping is snapshotted, failed parses are cached, and least
    recently used entries are evicted. No state survives into another scan.
    Classes, foreign wrappers, rebinding and DRF remain unknown; middleware
    eligibility is separate from observed login-required evidence.
    """

    def __init__(self, files: Mapping[str, str], *, max_modules: int = 32):
        if type(max_modules) is not int or not 1 <= max_modules <= 32:
            raise ValueError("max_modules must be an integer from 1 through 32")
        self._files = dict(files)
        self._max_modules = max_modules
        self._cache: OrderedDict[str, _ModuleInfo | None] = OrderedDict()
        self._local_django = any(path == "django.py" or path.startswith("django/") for path in self._files)

    @property
    def cached_module_count(self) -> int:
        return len(self._cache)

    def _load(self, rel: str) -> _ModuleInfo | None:
        if rel in self._cache:
            self._cache.move_to_end(rel)
            return self._cache[rel]
        try:
            parsed = _info(rel, self._files[rel])
        except (KeyError, SyntaxError, ValueError, RecursionError):
            parsed = None
        self._cache[rel] = parsed
        if len(self._cache) > self._max_modules:
            self._cache.popitem(last=False)
        return parsed

    def resolve(self, urls_file: str, target: str, *, target_line: int | None = None) -> tuple[str, list[str], str | None, bool]:
        """Return auth, guards, evidence and validated middleware eligibility."""
        if self._local_django:
            return "unknown", [], None, False
        return _view_auth(self._files, self._load, urls_file, target, target_line=target_line)


def django_view_auth(files: Mapping[str, str], urls_file: str, target: str, *, target_line: int | None = None) -> tuple[str, list[str], str | None, bool]:
    """Resolve a single route; reuse DjangoAuthResolver for a complete scan."""
    return DjangoAuthResolver(files).resolve(urls_file, target, target_line=target_line)
