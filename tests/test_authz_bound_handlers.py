"""WP031 authored tuning cases; frozen upstream labels remain separate."""
from pathlib import Path

import pytest

from attackmap.index import RepoIndex
from attackmap.authz import analyze_authz
from attackmap.authz_js_handlers import _handler_binding
from attackmap.bench import Expected, _matches
from attackmap.models import Route
from attackmap.scanner import scan_files, scan_repo
from attackmap.threat_model import generate_findings


def _repo(tmp_path: Path, body: str, *, registration: str = "loadOrder()", imports: str = "import { loadOrder } from './orders'", role: str = "") -> Path:
    repo = tmp_path / "shop"
    repo.mkdir()
    target = repo / role / "orders.ts"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "import { OrderModel } from './model'\n"
        "export function loadOrder () {\n"
        "  return async (req: Request, res: Response) => {\n"
        + body + "\n  }\n}\n", encoding="utf-8")
    (repo / "server.ts").write_text(
        imports + "\nconst app = express()\n"
        f"app.get('/orders/:id', {registration})\n", encoding="utf-8")
    return repo


LOOKUP = "    const id = req.params.id\n    const order = await OrderModel.findOne({ where: { id } })\n"


@pytest.mark.parametrize("noise", [
    "",
    "    const user = req.user\n    audit(user, order)\n",
    "    if (order.ownerId !== req.user.id) { audit('mismatch') }\n",
    "    // requireAuth and owner checks are planned here\n",
])
def test_bound_id_only_lookup_is_bola_despite_identity_or_logging(tmp_path: Path, noise: str) -> None:
    repo = _repo(tmp_path, LOOKUP + noise + "    res.json(order)")
    scan = scan_repo(repo)
    candidates = [c for c in scan.authz_candidates if c.route_path == "/orders/:id"]
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.route_file == "orders.ts" and candidate.route_line == 5
    assert "server.ts:3" in candidate.db_evidence
    assert "OrderModel.findOne" in candidate.db_evidence
    finding = next(f for f in generate_findings(scan) if f.rule_id == "bola-read")
    assert any(loc.file == "orders.ts" and loc.line == 5 for loc in finding.locations)
    assert "GET /orders/:id" in "\n".join(finding.evidence)
    assert "orders.ts:5" in "\n".join(finding.evidence)
    assert _matches(finding.model_dump(), Expected(category="bola", file="orders.ts", line=5), window=0)
    assert not _matches(finding.model_dump(), Expected(category="bola", file="orders.ts", line=4), window=0)


@pytest.mark.parametrize("body", [
    "    const order = await OrderModel.findOne({ where: { id: req.params.id, ownerId: req.user.id } })\n    res.json(order)",
    LOOKUP + "    if (order.ownerId !== req.user.id) { return res.status(403).end() }\n    res.json(order)",
    "    const order = await OrderModel.findOne({ where: { id: 1 } })\n    res.json(order)",
    "    const id = req.params.id\n    res.json({ id })",
])
def test_scoped_denied_constant_or_no_datastore_counterexamples(tmp_path: Path, body: str) -> None:
    assert scan_repo(_repo(tmp_path, body)).authz_candidates == []


@pytest.mark.parametrize(("imports", "registration"), [
    ("import { loadOrder as handler } from './orders'", "handler()"),
    ("import * as orders from './orders'", "orders.loadOrder()"),
    ("import { loadOrder } from './orders'", "utils.asyncHandler(loadOrder())"),
])
def test_literal_alias_namespace_and_async_wrapper_are_bound(tmp_path: Path, imports: str, registration: str) -> None:
    scan = scan_repo(_repo(tmp_path, LOOKUP + "    res.json(order)", imports=imports, registration=registration))
    assert len(scan.authz_candidates) == 1


@pytest.mark.parametrize(("imports", "registration", "role"), [
    ("import { loadOrder } from './examples/orders'", "loadOrder()", "examples"),
    ("import { loadOrder } from './orders'", "unknownWrapper(loadOrder())", ""),
    ("import { loadOrder } from './orders'\nconst loadOrder = other", "loadOrder()", ""),
    ("import { loadOrder } from './orders'", "selectHandler()", ""),
])
def test_unresolved_shadowed_and_source_role_counterexamples(tmp_path: Path, imports: str, registration: str, role: str) -> None:
    scan = scan_repo(_repo(tmp_path, LOOKUP + "    res.json(order)", imports=imports, registration=registration, role=role))
    assert scan.authz_candidates == []


def test_bound_handler_uses_captured_bytes_after_live_safe_edit(tmp_path: Path) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    index = RepoIndex.build(repo)
    (repo / "orders.ts").write_text("export function loadOrder () { return () => {} }", encoding="utf-8")
    scan = scan_files(repo, index=index)
    scan.authz_candidates = analyze_authz(scan, repo, index=index)
    assert len(scan.authz_candidates) == 1


@pytest.mark.parametrize("replacement", [
    "export { loadOrder } from './actual-orders'",
    "export function loadOrder (policy) { return async (req, res) => { BODY } }",
    "export function loadOrder () { installPolicy(); return async (req, res) => { BODY } }",
    "export function loadOrder () { return customFactory(async (req, res) => { BODY }) }",
    "export function other () { return async (req, res) => { BODY } }",
])
def test_reexports_custom_factories_and_unbound_functions_do_not_create_evidence(tmp_path: Path, replacement: str) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    (repo / "orders.ts").write_text(replacement.replace("BODY", LOOKUP + "res.json(order)"), encoding="utf-8")
    assert scan_repo(repo).authz_candidates == []


def test_dynamic_import_does_not_bind_a_handler(tmp_path: Path) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)", imports="const { loadOrder } = await import('./orders')")
    assert scan_repo(repo).authz_candidates == []


def test_safe_sibling_does_not_hide_unscoped_handler(tmp_path: Path) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    with (repo / "orders.ts").open("a", encoding="utf-8") as output:
        output.write("export function safeSibling () { authorize(req.user, order); return order }\n")
    assert len(scan_repo(repo).authz_candidates) == 1


def test_ambiguous_source_extensions_do_not_bind(tmp_path: Path) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    (repo / "orders.js").write_bytes((repo / "orders.ts").read_bytes())
    assert scan_repo(repo).authz_candidates == []


def test_direct_exported_handler_with_request_id_query_is_bound(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "", registration="loadOrder")
    (repo / "orders.ts").write_text(
        "export async function loadOrder (req, res) {\n"
        " const order = await OrderModel.findOne({ where: { id: req.params.id } })\n"
        " res.json(order)\n}\n", encoding="utf-8")
    assert len(scan_repo(repo).authz_candidates) == 1


@pytest.mark.parametrize(("imports", "target", "local"), [
    ("import { loadOrder } from './orders'", "loadOrder()", "loadOrder"),
    ("import { loadOrder as handler } from './orders'", "handler()", "handler"),
    ("import * as orders from './orders'", "orders.loadOrder()", "orders"),
])
@pytest.mark.parametrize("scope", [
    "function mount(LOCAL) {\nREGISTER\n}",
    "function mount(LOCAL = other) {\nREGISTER\n}",
    "function mount({ value: LOCAL }) {\nREGISTER\n}",
    "function mount([LOCAL]) {\nREGISTER\n}",
    "function mount(...LOCAL) {\nREGISTER\n}",
    "function mount(LOCAL) {\nfunction nested() {\nREGISTER\n}\n}",
    "const mount = (LOCAL) => {\nREGISTER\n}",
    "const mount = LOCAL => {\nREGISTER\n}",
    "const mount = (LOCAL) =>\nREGISTER\n",
    "try { work() } catch (LOCAL) {\nREGISTER\n}",
    "const mounts = { mount(LOCAL) {\nREGISTER\n} }",
    "for (let first = 0, LOCAL; first < 1; first++) {\nREGISTER\n}",
    "for (let first = 0, LOCAL; first < 1; first++)\nREGISTER\n",
])
@pytest.mark.parametrize("import_first", [True, False])
def test_lexically_shadowed_import_is_not_handler_evidence(
    tmp_path: Path, imports: str, target: str, local: str, scope: str, import_first: bool,
) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    registration = f"app.get('/orders/:id', {target})"
    scoped = scope.replace("LOCAL", local).replace("REGISTER", registration)
    source = imports + "\n" + scoped if import_first else scoped + "\n" + imports
    (repo / "server.ts").write_text(source, encoding="utf-8")
    line = source[:source.index(registration)].count("\n") + 1
    route = Route(path="/orders/:id", method="GET", file="server.ts", line=line)
    assert _handler_binding(route, source) is None
    assert scan_repo(repo).authz_candidates == []


@pytest.mark.parametrize(("imports", "target", "local"), [
    ("import { loadOrder } from './orders'", "loadOrder()", "loadOrder"),
    ("import * as orders from './orders'", "orders.loadOrder()", "orders"),
])
@pytest.mark.parametrize("scope", [
    "function unrelated(LOCAL) { use(LOCAL) }\nREGISTER",
    "function outer() {\nfunction unrelated(LOCAL) { use(LOCAL) }\nREGISTER\n}",
    "function outer(other) {\nfunction nested() {\nREGISTER\n}\n}",
    "const mount = (other) => {\nREGISTER\n}",
    "const unrelated = (LOCAL) => use(LOCAL);\nREGISTER",
])
def test_unshadowed_import_survives_unrelated_and_nested_scopes(
    tmp_path: Path, imports: str, target: str, local: str, scope: str,
) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    scoped = scope.replace("LOCAL", local).replace("REGISTER", f"app.get('/orders/:id', {target})")
    (repo / "server.ts").write_text(imports + "\n" + scoped, encoding="utf-8")
    assert len(scan_repo(repo).authz_candidates) == 1


@pytest.mark.parametrize("declaration", [
    "let loadOrder = other", "loadOrder = other", "function loadOrder() {}",
    "const { loadOrder } = other", "const { value: { loadOrder } } = other",
    "let [loadOrder] = other", "let other, loadOrder", "let other,\nloadOrder",
])
@pytest.mark.parametrize("before", [True, False])
def test_local_declarations_and_writes_veto_import_regardless_of_order(
    tmp_path: Path, declaration: str, before: bool,
) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    registration = "app.get('/orders/:id', loadOrder())"
    body = declaration + "\n" + registration if before else registration + "\n" + declaration
    (repo / "server.ts").write_text(
        "import { loadOrder } from './orders'\nfunction mount() {\n" + body + "\n}", encoding="utf-8")
    assert scan_repo(repo).authz_candidates == []


@pytest.mark.parametrize("scope", [
    "function mount(loadOrder): void {\nREGISTER\n}",
    "function mount(loadOrder): {} {\nREGISTER\n}",
    "function mount(loadOrder): (() => Handler) {\nREGISTER\n}",
    "const mount = (loadOrder): (() => Handler) => {\nREGISTER\n}",
    "const mount = (loadOrder): Handler =>\nREGISTER\n",
])
def test_unsupported_callable_type_headers_fail_closed(tmp_path: Path, scope: str) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    (repo / "server.ts").write_text(
        "import { loadOrder } from './orders'\n" + scope.replace("REGISTER", "app.get('/orders/:id', loadOrder())"),
        encoding="utf-8")
    assert scan_repo(repo).authz_candidates == []


@pytest.mark.parametrize(("imports", "target", "local"), [
    ("import { loadOrder } from './orders'", "loadOrder()", "loadOrder"),
    ("import { loadOrder as handler } from './orders'", "handler()", "handler"),
    ("import * as orders from './orders'", "orders.loadOrder()", "orders"),
])
@pytest.mark.parametrize("declaration", [
    "const first = 0, { LOCAL } = other",
    "const first = 0, { value: LOCAL } = other",
    "const first = 0, [LOCAL] = other",
    "const first = 0, { value: { LOCAL } } = other",
    "const first = 0, second = use(1, [2, 3]), { value: LOCAL } = other",
    "const first = 0,\n[LOCAL] = other",
    "const{ LOCAL } = other",
    "enum LOCAL { value }",
    "namespace LOCAL {}",
    "function* LOCAL() {}",
    "async function LOCAL() {}",
    "async function* LOCAL() {}",
    "function*LOCAL() {}",
    "async function /* binder */ * /* name */ LOCAL() {}",
    "const other = function* LOCAL() {}",
    "const first = 0, LOCAL = other",
    "let first,\nLOCAL",
])
@pytest.mark.parametrize("before", [True, False])
def test_later_destructuring_declarators_cannot_bind_an_import(
    tmp_path: Path, imports: str, target: str, local: str, declaration: str, before: bool,
) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    registration = f"app.get('/orders/:id', {target})"
    declaration = declaration.replace("LOCAL", local)
    body = declaration + "\n" + registration if before else registration + "\n" + declaration
    (repo / "server.ts").write_text(imports + "\nfunction mount() {\n" + body + "\n}", encoding="utf-8")
    assert scan_repo(repo).authz_candidates == []


def test_unrelated_later_destructuring_declarators_preserve_the_import(tmp_path: Path) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    (repo / "server.ts").write_text(
        "import { loadOrder } from './orders'\nfunction mount() {\n"
        "const first = pair('a,b', { items: [1, 2] }), /* , ignored */ { other: { value } } = config, [last] = values\n"
        "app.get('/orders/:id', loadOrder())\n}", encoding="utf-8")
    assert len(scan_repo(repo).authz_candidates) == 1


@pytest.mark.parametrize("declaration", ["const{ value: other } = config", "const { value: other } = config"])
def test_unrelated_compact_or_spaced_destructuring_preserves_import(tmp_path: Path, declaration: str) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    (repo / "server.ts").write_text(
        "import { loadOrder } from './orders'\nfunction mount() {\n" + declaration +
        "\napp.get('/orders/:id', loadOrder())\n}", encoding="utf-8")
    assert len(scan_repo(repo).authz_candidates) == 1


def test_escaped_parameter_identifier_is_not_a_literal_binding(tmp_path: Path) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    (repo / "server.ts").write_text(
        "import { loadOrder } from './orders'\nfunction mount(\\u006coadOrder) {\n"
        "app.get('/orders/:id', loadOrder())\n}", encoding="utf-8")
    assert scan_repo(repo).authz_candidates == []


@pytest.mark.parametrize(("imports", "target", "local"), [
    ("import { loadOrder } from './orders'", "loadOrder()", "loadOrder"),
    ("import { loadOrder as handler } from './orders'", "handler()", "handler"),
    ("import * as orders from './orders'", "orders.loadOrder()", "orders"),
])
@pytest.mark.parametrize("scope", [
    "function mount(LOCAL, registrar = (\nREGISTER\n)) {}",
    "const mount = (LOCAL, registrar = (\nREGISTER\n)) => {}",
    "const mounts = { mount(LOCAL, registrar = (\nREGISTER\n)) {} }",
    "function mount(LOCAL, registrar = (() => {\nREGISTER\n})()) {}",
])
@pytest.mark.parametrize("import_first", [True, False])
def test_default_parameter_registration_is_not_a_resolved_import(
    tmp_path: Path, imports: str, target: str, local: str, scope: str, import_first: bool,
) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    registration = f"app.get('/orders/:id', {target})"
    scoped = scope.replace("LOCAL", local).replace("REGISTER", registration)
    source = imports + "\n" + scoped if import_first else scoped + "\n" + imports
    (repo / "server.ts").write_text(source, encoding="utf-8")
    line = source[:source.index(registration)].count("\n") + 1
    route = Route(path="/orders/:id", method="GET", file="server.ts", line=line)
    assert _handler_binding(route, source) is None
    assert scan_repo(repo).authz_candidates == []


@pytest.mark.parametrize("prefix", ["", "function mount(other, registrar = setup()) {\n"])
def test_unshadowed_multiline_registration_ignores_its_own_argument_parentheses(tmp_path: Path, prefix: str) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    (repo / "server.ts").write_text(
        "import { loadOrder } from './orders'\n" + prefix +
        "app.get(\n '/orders/:id',\n utils.asyncHandler(loadOrder())\n)\n" + ("}\n" if prefix else ""),
        encoding="utf-8")
    assert len(scan_repo(repo).authz_candidates) == 1


@pytest.mark.parametrize("declaration", [
    "function* other() {}", "async function other() {}", "async function* other() {}", "function*other() {}",
])
def test_unrelated_function_binder_forms_preserve_import(tmp_path: Path, declaration: str) -> None:
    repo = _repo(tmp_path, LOOKUP + "    res.json(order)")
    (repo / "server.ts").write_text(
        "import { loadOrder } from './orders'\nfunction mount() {\n" + declaration +
        "\napp.get('/orders/:id', loadOrder())\n}", encoding="utf-8")
    assert len(scan_repo(repo).authz_candidates) == 1
