"""Bounded BOLA evidence for literal Express imports and Sequelize lookups.

This additive slice resolves one ESM hop to an exact exported function (or a
zero-argument factory returning an Express arrow handler). It deliberately
does not interpret dynamic imports, reexports, arbitrary wrappers, query
operators or ownership policy implementations.
"""
from __future__ import annotations

import posixpath
import re

from .ecosystem_node_atproto import _registration_code, _registration_parts
from .index import PassSources
from .models import BolaCandidate, Route
from .srcpaths import JS_TS_SUFFIXES, is_test_file, is_vendored_file

_IDENT = r"[A-Za-z_$][\w$]*"
_IMPORT = re.compile(r"\bimport\s+(\{[^{}]+\}|\*\s+as\s+\w+)\s+from\s+(['\"])(\.[^'\"]+)\2")
_LIMIT = 24_000


def _excluded(path: str) -> bool:
    return (
        is_test_file(path) or is_vendored_file(path)
        or any(part.lower() in {"examples", "mocks"} for part in path.replace("\\", "/").split("/")[:-1])
    )


def _parts(text: str) -> list[str] | None:
    parsed = _registration_parts(text[:_LIMIT])
    return [text[a:b].strip() for a, b in parsed[0]] if parsed else None


def _parameters_before(code: str, end: int, *, arrow: bool = False) -> str | None:
    """Read a bounded plain callable header; unknown syntax is not transparent."""
    prefix = code[:end].rstrip()
    if prefix.endswith(")"):
        depth = 0
        for pos in range(len(prefix) - 1, max(-1, len(prefix) - _LIMIT - 1), -1):
            if prefix[pos] == ")":
                depth += 1
            elif prefix[pos] == "(":
                depth -= 1
                if depth == 0:
                    params = prefix[pos + 1:-1]
                    # A parenthesized return type is not the input binding list.
                    typed = prefix[:pos].rstrip().endswith(":")
                    return params if "\0" not in params and not typed else None
        return None
    if arrow:
        single = re.search(rf"({_IDENT})$", prefix)
        # A trailing type annotation is not a single-parameter arrow header.
        if single and not prefix[:single.start()].rstrip().endswith(":"):
            return single.group(1)
    return None


def _expression_contains(code: str, start: int, at: int) -> bool:
    """Conservative arrow-expression extent, without guessing ASI boundaries."""
    stack: list[str] = []
    for char in code[start:at]:
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != {")": "(", "]": "[", "}": "{"}[char]:
                return False
        elif char in ",;" and not stack:
            return False
    return True


def _scope_preserves_import(text: str, code: str, local: str, at: int) -> bool:
    """Veto enclosing parameter bindings; this is deliberately not a JS parser.

    Declaration/write vetoes remain file-wide below. Plain function/method,
    catch and arrow headers are supported; ambiguous scope syntax fails closed.
    A name anywhere in a destructuring/default parameter is conservative.
    """
    if "\\" in code:
        return False  # Escaped identifiers cannot establish this literal name.
    name = re.compile(rf"(?<![\w$]){re.escape(local)}(?![\w$])")
    stack: list[tuple[str, int]] = []
    for token in re.finditer(r"\0+|[()\[\]{}]", code[:at]):
        char = token.group()
        if char in {"(", "[", "{"}:
            stack.append((char, token.start()))
            if len(stack) > 64:
                return False
        elif char in {")", "]", "}"}:
            if not stack or stack.pop()[0] != {")": "(", "]": "[", "}": "{"}[char]:
                return False
        elif any(delimiter in text[token.start():token.end()] for delimiter in "()[]{}"):
            return False  # An opaque slash region may hide a scope boundary.
    # Only standalone registrations within plain body/block contexts are
    # supported. In particular, parameter defaults have scope before the body.
    # `at` precedes app.get's own argument list, so its parentheses do not veto.
    if any(char != "{" for char, _ in stack):
        return False
    for _, opening in stack:
        prefix = code[:opening].rstrip()
        if prefix.endswith("=>"):
            params = _parameters_before(code, len(prefix) - 2, arrow=True)
        elif prefix.endswith(")"):
            params = _parameters_before(code, len(prefix))
        elif re.search(r"(?:^|[{;])\s*$|(?:^|[{};])\s*(?:else|try|catch|finally|do)\s*$", prefix) or prefix.endswith(("=", ":", "(", "[", ",")):
            continue  # A plain block or object literal introduces no parameters.
        else:
            return False
        if params is None or name.search(params):
            return False
    # Expression-bodied arrows introduce scope without an enclosing body brace.
    for arrow in re.finditer(r"=>", code[:at]):
        if code[arrow.end():].lstrip().startswith("{"):
            continue
        params = _parameters_before(code, arrow.start(), arrow=True)
        if (params is None or name.search(params)) and _expression_contains(code, arrow.end(), at):
            return False
    return True


def _declared_or_written(code: str, local: str) -> bool:
    """Keep declaration/write rejection conservative across the whole module."""
    escaped = re.escape(local)
    name = re.compile(rf"(?<![\w$]){escaped}(?![\w$])")
    if re.search(rf"\bfunction\b\s*\*?\s*{escaped}(?![\w$])|\b(?:const|let|var|class|enum|namespace|module)\s+{escaped}(?![\w$])|(?<![\w$]){escaped}\s*=(?!=)", code):
        return True
    for declaration in re.finditer(r"\b(?:const|let|var)\b\s*", code):
        pos = declaration.end()
        limit = min(len(code), pos + _LIMIT)
        while pos < limit:
            while pos < limit and code[pos].isspace():
                pos += 1
            if pos >= limit:
                return True
            if code[pos] in "[{":
                parsed = _registration_parts(code[pos:limit])
                if parsed is None:
                    return True
                end = pos + parsed[1] + 1
                if name.search(code[pos:end]):
                    return True
            else:
                binding = re.match(_IDENT, code[pos:limit])
                if binding is None:
                    return True
                if binding.group() == local:
                    return True
                end = pos + binding.end()
            # Initializer commas are not declarator separators. Literals and
            # comments are already blanked; opaque or mismatched syntax vetoes.
            stack: list[str] = []
            pos = end
            while pos < limit:
                char = code[pos]
                if char == "\0":
                    return True
                if char in "([{":
                    stack.append(char)
                    if len(stack) > 64:
                        return True
                elif char in ")]}":
                    if not stack:
                        break
                    if stack.pop() != {")": "(", "]": "[", "}": "{"}[char]:
                        return True
                elif char in ",;" and not stack:
                    break
                pos += 1
            if pos == limit:
                if limit < len(code) or stack:
                    return True
                break
            if code[pos] != ",":
                break
            pos += 1
    return False


def _handler_binding(route: Route, text: str) -> tuple[str, str, bool] | None:
    if route.line is None or _excluded(route.file):
        return None
    start = sum(len(line) for line in text.splitlines(keepends=True)[:route.line - 1])
    tail = text[start:start + _LIMIT]
    match = re.match(rf"\s*{_IDENT}\s*\.\s*{route.method.lower()}\s*(\()", tail)
    if match is None:
        return None
    call = tail[match.start(1):]
    args = _parts(call)
    if not args or len(args) < 2 or args[0] not in {repr(route.path), '"' + route.path + '"'}:
        return None
    expression = args[-1]
    # Only the established asyncHandler shape is transparent, one layer deep.
    wrapper = re.fullmatch(rf"(?:{_IDENT}\.)?asyncHandler\s*\((.*)\)", expression, re.S)
    if wrapper:
        expression = wrapper.group(1).strip()
    target = re.fullmatch(rf"({_IDENT})(?:\.({_IDENT}))?\s*(\(\s*\))?", expression)
    if target is None:
        return None
    local, member, factory = target.groups()
    bindings = []
    code = _registration_code(text)
    for item in _IMPORT.finditer(text):
        if code[item.start():item.start() + 6] != "import":
            continue
        names, _, module = item.groups()
        if names.startswith("*"):
            if member and names.split()[-1] == local:
                bindings.append((module, member, bool(factory)))
        elif member is None:
            for specifier in names[1:-1].split(","):
                namespec = re.fullmatch(rf"\s*({_IDENT})(?:\s+as\s+({_IDENT}))?\s*", specifier)
                if namespec and (namespec.group(2) or namespec.group(1)) == local:
                    bindings.append((module, namespec.group(1), bool(factory)))
    # A duplicate binding or local reassignment cannot establish this target.
    if len(bindings) != 1 or _declared_or_written(code, local):
        return None
    if not _scope_preserves_import(text, code, local, start):
        return None
    return bindings[0]


def _target_text(route: Route, module: str, sources: PassSources) -> tuple[str, str] | None:
    path = posixpath.normpath(posixpath.join(posixpath.dirname(route.file.replace("\\", "/")), module))
    if path.startswith("../") or path == ".." or path.startswith("/"):
        return None
    paths = [path] if posixpath.splitext(path)[1] in JS_TS_SUFFIXES else [path + suffix for suffix in sorted(JS_TS_SUFFIXES)]
    targets = []
    for candidate in paths:
        if _excluded(candidate):
            continue
        content = sources.gated_text(candidate, max_bytes=1_000_000, errors="ignore")
        if content is not None:
            targets.append((candidate, content))
    return targets[0] if len(targets) == 1 else None


def _function_body(text: str, name: str, factory: bool) -> tuple[str, int] | None:
    code = _registration_code(text)
    definitions = list(re.finditer(rf"\bexport\s+(?:async\s+)?function\s+{re.escape(name)}\s*\(([^()]*)\)\s*\{{", code))
    if len(definitions) != 1:
        return None
    match = definitions[0]
    opening = match.end() - 1
    parsed = _registration_parts(text[opening:opening + _LIMIT])
    if parsed is None:
        return None
    body_start, body_end = opening + 1, opening + parsed[1]
    if factory:
        if match.group(1).strip():
            return None
        # No setup statements/custom factory behavior before the returned handler.
        arrow = re.match(r"\s*return\s+(?:async\s+)?\(\s*(?:req|request)\b[^()]*\)\s*=>\s*\{", code[body_start:body_end])
        if arrow is None:
            return None
        opening = body_start + arrow.end() - 1
        parsed = _registration_parts(text[opening:body_end + 1])
        if parsed is None or code[opening + parsed[1] + 1:body_end].strip().strip(";").strip():
            return None
        body_start, body_end = opening + 1, opening + parsed[1]
    elif not re.match(r"\s*(?:req|request)\b", match.group(1)):
        return None
    return code[body_start:body_end], body_start


def bound_lookup_candidate(route: Route, text: str, id_param: str, sources: PassSources) -> BolaCandidate | None:
    """An id-only lookup in an exact imported handler, with source locations.

    Any extra WHERE predicate is conservatively outside this slice, rather
    than being declared safe. Identity reads/logging alone never suppress it.
    """
    binding = _handler_binding(route, text)
    if binding is None:
        return None
    module, name, factory = binding
    target = _target_text(route, module, sources)
    if target is None:
        return None
    file, source = target
    function = _function_body(source, name, factory)
    if function is None:
        return None
    body, offset = function
    lookups = list(re.finditer(rf"\b({_IDENT})\s*\.\s*findOne\s*\(\s*\{{\s*where\s*:\s*\{{([^{{}}]+)\}}", body))
    if len(lookups) != 1:
        return None
    lookup = lookups[0]
    predicate = lookup.group(2).strip().rstrip(",").strip()
    direct = rf"(?:req|request)\.params\.{re.escape(id_param)}"
    addressed = re.fullmatch(rf"{re.escape(id_param)}\s*:\s*{direct}", predicate)
    if not addressed:
        value = re.fullmatch(rf"{re.escape(id_param)}(?:\s*:\s*({_IDENT}))?", predicate)
        if value is None:
            return None
        local = value.group(1) or id_param
        prefix = body[:lookup.start()]
        assignments = list(re.finditer(rf"\b(?:const|let|var)\s+{re.escape(local)}\s*=\s*{direct}\b", prefix))
        if len(assignments) != 1 or re.search(rf"\b{re.escape(local)}\s*=(?!=)", prefix[assignments[0].end():]):
            return None
    # An explicit rejection makes an ownership/authorization path uncertain.
    # Keep such handlers outside this bounded positive claim. A 400 validation
    # or a log statement alone does not establish that control.
    if re.search(r"\bthrow\b|\b(?:res|response)\s*\.\s*(?:sendStatus\s*\(\s*40[13]|status\s*\(\s*40[13])", body):
        return None
    # An explicit policy invocation is an object control, unlike a name/import.
    if re.search(r"\b(?:authorize|canAccess|check_access|verify_owner|assert_owner|ensure_owner|require_permission)\s*\(", body, re.I):
        return None
    # Require a response that exposes the queried object; lookup-only code can
    # validate existence without returning data to the caller.
    assignment = re.search(rf"\b(?:const|let|var)\s+({_IDENT})\s*=\s*(?:await\s+)?$", body[:lookup.start()])
    if assignment is None:
        return None
    result = assignment.group(1)
    if not re.search(rf"\b(?:res|response)\.\s*(?:json|send)\s*\([^;\n]*\b{re.escape(result)}\b", body[lookup.end():]):
        return None
    line = source.count("\n", 0, offset + lookup.start()) + 1
    return BolaCandidate(
        route_path=route.path, route_method=route.method, route_file=file,
        route_line=line,
        id_param=id_param, surface="path_param", reaches_db=True,
        db_evidence=f"{file}:{line} — {lookup.group(1)}.findOne with request-id-only WHERE; imported handler {name} bound at {route.file}:{route.line}",
        has_ownership_check=False, source_analyzer="authz",
    )
