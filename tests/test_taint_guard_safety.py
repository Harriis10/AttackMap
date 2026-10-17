"""C02: protective conditions must prove polarity, dominance and value identity.

The supported proof is an exact value constrained to fixed strings. Broader
validators remain uncertain; their reassuring names never suppress a flow.
"""

from __future__ import annotations

import textwrap

import pytest

from attackmap.taint_flow import FileFlow


def _flow(source: str, suffix: str):
    paren = source.index("sink(") + len("sink")
    flow = FileFlow(source, suffix).sink_flow("ssrf", paren, (0,))
    assert flow is not None
    assert flow.source_kind == "query", source
    return flow


def _python(body: str):
    source = 'def handler():\n    target = request.args["url"]\n'
    source += textwrap.indent(textwrap.dedent(body).strip(), "    ") + "\n"
    return _flow(source, ".py")


@pytest.mark.parametrize(
    "body,safe",
    [
        ('if target == "https://api.example/":\n    sink(target)', True),
        ('if target != "https://api.example/":\n    sink(target)', False),
        ('if not target != "https://api.example/":\n    sink(target)', True),
        ('if not target == "https://api.example/":\n    sink(target)', False),
        ('if target != "https://api.example/":\n    return\nsink(target)', True),
        ('if target == "https://api.example/":\n    return\nsink(target)', False),
        ('if target != "https://api.example/":\n    raise ValueError()\nsink(target)', True),
        ('if target == "https://api.example/":\n    raise ValueError()\nsink(target)', False),
        ('if target != "https://api.example/":\n    pass\nelse:\n    sink(target)', True),
        ('if target == "https://api.example/":\n    pass\nelse:\n    sink(target)', False),
        ('if target != "https://api.example/":\n    if flag:\n        return\nsink(target)', False),
        ('if target != "https://api.example/":\n    if flag:\n        return\n    else:\n        raise ValueError()\nsink(target)', True),
        ('if flag:\n    if target != "https://api.example/":\n        return\nsink(target)', False),
        ('if target == "https://api.example/":\n    if flag:\n        sink(target)', True),
        ('if target != "https://api.example/":\n    if flag:\n        sink(target)', False),
        ('if target != "https://api.example/":\n    return\ntarget = request.args["other"]\nsink(target)', False),
        ('if target != "https://api.example/":\n    return\ntarget += request.args["suffix"]\nsink(target)', False),
        ('other = target\nif other != "https://api.example/":\n    return\nsink(target)', False),
        ('other = target + "/suffix"\nif other != "https://api.example/":\n    return\nsink(target)', False),
        ('if not is_safe_url(target):\n    return\nsink(target)', False),
        ('if is_safe_url(target):\n    return\nsink(target)', False),
        ('if target != "https://api.example/":\n    abort(400)\nsink(target)', False),
        ('assert target == "https://api.example/"\nsink(target)', False),
        ('if target in ("https://a.example/", "https://b.example/"):\n    sink(target)', True),
        ('if target not in ("https://a.example/", "https://b.example/"):\n    sink(target)', False),
        ('if target not in ("https://a.example/", request.args["other"]):\n    return\nsink(target)', False),
        ('if target not in ALLOWED_URLS:\n    return\nsink(target)', False),
        ('if target == "https://a.example/" or target == "https://b.example/":\n    sink(target)', True),
        ('if target == "https://a.example/" or flag:\n    sink(target)', False),
        ('if target == "https://a.example/" and flag:\n    sink(target)', True),
        ('if target != "https://a.example/" and flag:\n    return\nsink(target)', False),
        ('if target != "https://a.example/" or flag:\n    return\nsink(target)', True),
        ('if target != "https://api.example/":\n    return\nsink(target + request.args["suffix"])', False),
        ('try:\n    if target != "https://api.example/":\n        raise ValueError()\nexcept ValueError:\n    pass\nsink(target)', False),
        ('if sink(target) and target == "https://api.example/":\n    pass', False),
        ('if target != "https://api.example/":\n    return\ntry:\n    work()\nexcept Exception as target:\n    sink(target)', False),
        ('if target != "https://api.example/":\n    return\nimport other as target\nsink(target)', False),
        ('if target != "https://api.example/":\n    return\nmatch request.args["other"]:\n    case target:\n        sink(target)', False),
    ],
)
def test_python_guard_matrix(body: str, safe: bool) -> None:
    flow = _python(body)
    assert flow.sanitized is safe
    assert flow.tainted is not safe


FRONTENDS = [
    (".js", "function handler(req) {", "let target = req.query.url;", "===", "!==", "throw Error();"),
    (".ts", "function handler(req: Request) {", "let target = req.query.url;", "===", "!==", "throw Error();"),
    (".go", "func handler(r *http.Request) {", 'target := r.URL.Query().Get("url")', "==", "!=", "return"),
    (".php", "<?php\nfunction handler() {", "$target = $_GET['url'];", "===", "!==", "throw new Exception();"),
    (".java", "void handler(HttpServletRequest request) {", 'String target = request.getParameter("url");', "==", "!=", "throw new Exception();"),
    (".cs", "void Handler() {", 'var target = Request.Query["url"];', "==", "!=", "throw new Exception();"),
]


def _text(frontend, body: str):
    suffix, header, source, eq, ne, throws = frontend
    body = body.replace("EQ", eq).replace("NE", ne).replace("THROW", throws)
    if suffix == ".go":
        body = body.replace("if (", "if ").replace(") {", " {")
    if suffix == ".php":
        for name in ("target", "other", "flag"):
            body = body.replace(name, "$" + name)
    return _flow(f"{header}\n{source}\n{body}\n}}\n", suffix)


@pytest.mark.parametrize("frontend", FRONTENDS, ids=[f[0] for f in FRONTENDS])
@pytest.mark.parametrize(
    "body,safe",
    [
        ('if (target EQ "https://api.example/") { sink(target); }', True),
        ('if (target NE "https://api.example/") { sink(target); }', False),
        ('if (!(target NE "https://api.example/")) { sink(target); }', True),
        ('if (!(target EQ "https://api.example/")) { sink(target); }', False),
        ('if (target NE "https://api.example/") { return; }\nsink(target);', True),
        ('if (target EQ "https://api.example/") { return; }\nsink(target);', False),
        ('if (target NE "https://api.example/") { THROW }\nsink(target);', True),
        ('if (target EQ "https://api.example/") { THROW }\nsink(target);', False),
        ('if (target NE "https://api.example/") { log(); } else { sink(target); }', True),
        ('if (target EQ "https://api.example/") { log(); } else { sink(target); }', False),
        ('if (target NE "https://api.example/") { if (flag) { return; } }\nsink(target);', False),
        ('if (target NE "https://api.example/") { if (flag) return; }\nsink(target);', False),
        ('if (flag) { if (target NE "https://api.example/") { return; } }\nsink(target);', False),
        ('if (target EQ "https://api.example/") { if (flag) { sink(target); } }', True),
        ('if (target NE "https://api.example/") { if (flag) { sink(target); } }', False),
        ('other = target;\nif (target NE "https://api.example/") { return; }\ntarget = other;\nsink(target);', False),
        ('other = target;\nif (other NE "https://api.example/") { return; }\nsink(target);', False),
        ('if (!is_safe_url(target)) { return; }\nsink(target);', False),
        ('if (is_safe_url(target)) { return; }\nsink(target);', False),
        ('if (target NE "https://api.example/") { deny(); }\nsink(target);', False),
        ('if (target EQ "https://a.example/" || target EQ "https://b.example/") { sink(target); }', True),
        ('if (target EQ "https://a.example/" || flag) { sink(target); }', False),
        ('if (target EQ "https://a.example/" && flag) { sink(target); }', True),
        ('if (target NE "https://a.example/" && flag) { return; }\nsink(target);', False),
        ('if (target NE "https://a.example/" || flag) { return; }\nsink(target);', True),
    ],
)
def test_text_guard_matrix(frontend, body: str, safe: bool) -> None:
    flow = _text(frontend, body)
    assert flow.sanitized is safe
    assert flow.tainted is not safe


@pytest.mark.parametrize("negated", [False, True])
def test_original_reversed_private_address_guard_stays_uncertain(negated: bool) -> None:
    condition = "not addr.is_private" if negated else "addr.is_private"
    flow = _python(f"addr = ipaddress.ip_address(target)\nif {condition}:\n    return\nsink(target)")
    assert flow.tainted and not flow.sanitized


@pytest.mark.parametrize(
    "body",
    [
        'for (target of values) { sink(target); }',
        'try { work(); } catch (target) { sink(target); }',
        'target &&= req.query.other; sink(target);',
        'target++; sink(target);',
    ],
)
def test_javascript_rebinding_invalidates_guard(body: str) -> None:
    flow = _text(FRONTENDS[0], 'if (target NE "https://api.example/") { return; }\n' + body)
    assert flow.tainted and not flow.sanitized
