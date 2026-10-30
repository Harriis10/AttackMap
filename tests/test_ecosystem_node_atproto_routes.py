"""Bounded XRPC transport and route-specific auth extraction controls."""

import json
from pathlib import Path

import pytest

from attackmap.ecosystem_node_atproto import scan_node_atproto


NSID = "com.example.events.stream"
PATH = "/xrpc/" + NSID


def _repo(tmp_path: Path, source: str = "", *, kind="subscription", extra="", lexicon=True):
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "package.json").write_text(
        '{"name":"paired-atproto","dependencies":{"@atproto/xrpc-server":"*"}}', encoding="utf-8"
    )
    (tmp_path / "src/handler.ts").write_text(source, encoding="utf-8")
    (tmp_path / "src/unrelated.ts").write_text(extra, encoding="utf-8")
    if lexicon:
        (tmp_path / "lexicons").mkdir(exist_ok=True)
        (tmp_path / ("lexicons/" + NSID + ".json")).write_text(
            json.dumps({"lexicon": 1, "id": NSID, "defs": {"main": {"type": kind}}}), encoding="utf-8"
        )
    return scan_node_atproto(tmp_path)


def _call(config: str, *, kind="streamMethod") -> str:
    return "import { Server } from '@atproto/xrpc-server';\nconst server = new Server();\n" + f"server.{kind}('{NSID}', {config});\n"


def _one(result):
    assert len(result.routes) == 1
    return result.routes[0]


@pytest.mark.parametrize("kind,method", [("subscription", "WS"), ("query", "GET"), ("procedure", "POST")])
def test_declared_transport_is_specific_but_does_not_imply_auth(tmp_path, kind, method):
    route = _one(_repo(tmp_path, kind=kind))
    assert (route.path, route.method, route.auth, route.guards) == (PATH, method, "unknown", [])
    assert route.file == "lexicons/" + NSID + ".json"


@pytest.mark.parametrize("registrar,kind,method", [("streamMethod", "subscription", "WS"), ("method", "query", "GET"), ("method", "procedure", "POST")])
def test_supported_direct_verifier_is_bound_to_its_own_handler(tmp_path, registrar, kind, method):
    result = _repo(tmp_path, _call("{ auth: authVerifier, handler: async () => ({}) }", kind=registrar), kind=kind)
    route = _one(result)
    assert (route.path, route.method, route.auth, route.guards) == (PATH, method, "required", ["authVerifier"])
    assert (route.file, route.line) == ("src/handler.ts", 3)
    assert "src/handler.ts:3" in route.guard_evidence


@pytest.mark.parametrize("value", ["null", "undefined", "false", "nullCreds", "authVerifierOptional", "ctx.authVerifier.readOptional", "ctx.authVerifier.unauthenticated"])
@pytest.mark.parametrize("registrar,kind,method", [("streamMethod", "subscription", "WS"), ("method", "query", "GET")])
def test_optional_empty_verifiers_do_not_become_required_or_anonymous(tmp_path, value, registrar, kind, method):
    result = _repo(tmp_path, _call("{ auth: " + value + ", handler: async () => ({}) }", kind=registrar), kind=kind)
    route = _one(result)
    assert (route.method, route.auth, route.guards, route.guard_evidence) == (method, "unknown", [], None)
    hint = next(h for h in result.protocol_hints if h.hint == "atproto:xrpc_auth_optional:" + NSID)
    assert (hint.file, hint.line) == ("src/handler.ts", 3)
    assert value in hint.evidence_text
    assert not any(h.hint == "xrpc_auth_verifier:" + NSID for h in result.auth_hints)


@pytest.mark.parametrize("value", ["banana", "ctx.customVerifier", "makeVerifier()", "[authVerifier, nullCreds]", "async () => ({ credentials: null })"])
def test_unresolved_verifier_expression_keeps_auth_unknown(tmp_path, value):
    result = _repo(tmp_path, _call("{ auth: " + value + ", handler: async () => ({}) }"))
    assert _one(result).auth == "unknown"
    assert any(h.hint == "atproto:xrpc_auth_unresolved:" + NSID for h in result.protocol_hints)


def test_auth_after_other_top_level_fields_is_found_without_nested_decoys(tmp_path):
    result = _repo(tmp_path, _call("{ metadata: { tag: 'a,b', auth: nullCreds }, auth: requireAuth, handler: async () => ({}) }"))
    route = _one(result)
    assert (route.auth, route.guards) == ("required", ["requireAuth"])


@pytest.mark.parametrize("config", [
    "{ note: 'auth: authVerifier', handler: async () => ({}) }",
    "{ metadata: { auth: authVerifier }, handler: async () => ({}) }",
    "{ /* auth: authVerifier */ handler: async () => ({}) }",
    "{ handler: async () => { const auth = authVerifier; return {}; } }",
    "async () => { return authVerifier(); }",
])
def test_decoy_auth_does_not_certify_the_handler(tmp_path, config):
    result = _repo(tmp_path, _call(config))
    route = _one(result)
    assert (route.auth, route.guards, route.guard_evidence) == ("unknown", [], None)


@pytest.mark.parametrize("cross_file", [False, True])
def test_unbound_middleware_mount_remains_an_observation(tmp_path, cross_file):
    mount = "const unrelatedApp = express();\nunrelatedApp.use('/xrpc/com.example.events.stream', unrelatedAuth);\n"
    source = _call("{ handler: async () => ({}) }", kind="method")
    result = _repo(tmp_path, source if cross_file else mount + source, kind="query", extra=mount if cross_file else "")
    assert _one(result).auth == "unknown"
    assert any(h.hint == "node:auth_middleware_mount:unrelatedAuth" for h in result.auth_hints)
    assert not any(h.hint == "xrpc_auth_verifier:" + NSID for h in result.auth_hints)


@pytest.mark.parametrize("config", [
    "{ auth: authVerifier, ...override, handler: async () => ({}) }",
    "{ [field]: nullCreds, auth: authVerifier, handler: async () => ({}) }",
    "{ auth: authVerifier, auth: nullCreds, handler: async () => ({}) }",
    "config",
])
def test_dynamic_or_ambiguous_config_cannot_certify_auth(tmp_path, config):
    result = _repo(tmp_path, _call(config))
    assert _one(result).auth == "unknown"
    assert any(h.hint == "atproto:xrpc_auth_unresolved:" + NSID for h in result.protocol_hints)


@pytest.mark.parametrize("registrar,kind,method", [("method", "subscription", "WS"), ("streamMethod", "query", "GET")])
def test_registrar_kind_mismatch_is_not_treated_as_wiring(tmp_path, registrar, kind, method):
    result = _repo(tmp_path, _call("{ auth: authVerifier, handler: async () => ({}) }", kind=registrar), kind=kind)
    route = _one(result)
    assert (route.method, route.auth) == (method, "unknown")
    assert route.file.startswith("lexicons/")
    assert any(h.hint == "atproto:xrpc_registration_kind_mismatch:" + NSID for h in result.protocol_hints)
    assert any(h.hint == "atproto:xrpc_unwired:" + NSID for h in result.protocol_hints)


def test_stream_registration_without_lexicon_still_declares_websocket_transport(tmp_path):
    result = _repo(tmp_path, _call("{ handler: async () => ({}) }"), lexicon=False)
    assert (_one(result).method, _one(result).auth) == ("WS", "unknown")
    assert any(h.hint == "atproto:xrpc_no_lexicon:" + NSID for h in result.protocol_hints)


def test_auth_in_adjacent_registration_cannot_leak_to_first(tmp_path):
    source = _call("{ handler: async () => ({}) }") + "server.method('com.example.other.required', { auth: authVerifier, handler: async () => ({}) });"
    result = _repo(tmp_path, source)
    routes = {r.path: r for r in result.routes}
    assert routes[PATH].auth == "unknown"
    assert routes["/xrpc/com.example.other.required"].auth == "required"


def test_commented_registration_is_not_auth_wiring(tmp_path):
    result = _repo(tmp_path, "// " + _call("{ auth: authVerifier, handler: async () => ({}) }").splitlines()[-1])
    assert _one(result).auth == "unknown"
    assert _one(result).file.startswith("lexicons/")


def test_broken_registration_does_not_certify_partial_auth(tmp_path):
    result = _repo(tmp_path, _call("{ auth: authVerifier, handler: async () => ({}) }")[:-4])
    assert _one(result).auth == "unknown"
    assert _one(result).file.startswith("lexicons/")
    assert any(h.hint == "atproto:xrpc_registration_unresolved:" + NSID for h in result.protocol_hints)


def test_generated_registration_is_still_explicitly_unwired_in_this_slice(tmp_path):
    source = "import '@atproto/xrpc-server';\nserver.com.example.events.stream({ auth: authVerifier, handler: async function* () {} });"
    result = _repo(tmp_path, source)
    assert (_one(result).method, _one(result).auth) == ("WS", "unknown")
    assert any(h.hint == "atproto:xrpc_unwired:" + NSID for h in result.protocol_hints)


def test_escaped_quoted_property_name_cannot_override_auth_unnoticed(tmp_path):
    config = r"{ auth: authVerifier, 'au\u0074h': null, handler: async () => ({}) }"
    result = _repo(tmp_path, _call(config))
    assert _one(result).auth == "unknown"
    assert any(h.hint == "atproto:xrpc_auth_unresolved:" + NSID for h in result.protocol_hints)


def test_plain_quoted_auth_key_remains_supported(tmp_path):
    result = _repo(tmp_path, _call("{ 'auth': authVerifier, handler: async () => ({}) }"))
    assert _one(result).auth == "required"


def test_regex_literal_registration_decoy_is_unsupported_not_wiring(tmp_path):
    source = "const pattern = /server.method('com.example.events.stream', {auth: authVerifier})/;"
    result = _repo(tmp_path, source, kind="query")
    assert _one(result).auth == "unknown"
    assert _one(result).file.startswith("lexicons/")
    assert any("regex/division expressions unsupported" in note for note in result.limitations)


def test_division_line_no_go_retains_following_line_registration(tmp_path):
    source = "const ratio = left / right;\n" + _call("{ auth: authVerifier, handler: async () => ({}) }")
    result = _repo(tmp_path, source)
    assert (_one(result).auth, _one(result).file) == ("required", "src/handler.ts")


def test_same_line_registration_after_division_is_explicitly_unsupported(tmp_path):
    source = "const ratio = left / right; " + _call("{ auth: authVerifier, handler: async () => ({}) }").splitlines()[-1]
    result = _repo(tmp_path, source)
    assert _one(result).auth == "unknown"
    assert _one(result).file.startswith("lexicons/")
    assert any("regex/division expressions unsupported" in note for note in result.limitations)


def test_slashes_inside_literals_and_comments_do_not_hide_following_calls(tmp_path):
    source = "const url='https://example.com/a/b'; const template=`a/b`; /* a/b */\n" + _call("{ auth: authVerifier, handler: async () => ({}) }")
    result = _repo(tmp_path, source)
    assert _one(result).auth == "required"
    assert not any("regex/division expressions unsupported" in note for note in result.limitations)


def test_opaque_config_evidence_does_not_copy_secret_like_values(tmp_path):
    result = _repo(tmp_path, _call("{ auth: makeVerifier('sensitive-config-value'), handler: async () => ({}) }"))
    hint = next(h for h in result.protocol_hints if h.hint == "atproto:xrpc_auth_unresolved:" + NSID)
    assert "sensitive-config-value" not in hint.evidence_text
    assert _one(result).auth == "unknown"


def test_multiline_division_cannot_hide_a_later_auth_override(tmp_path):
    source = _call("{ auth: authVerifier,\n note: 4/2, auth: null,\n handler: async () => ({})\n }")
    result = _repo(tmp_path, source)
    assert _one(result).auth == "unknown"
    assert _one(result).file.startswith("lexicons/")
    assert any(h.hint == "atproto:xrpc_registration_unresolved:" + NSID for h in result.protocol_hints)
