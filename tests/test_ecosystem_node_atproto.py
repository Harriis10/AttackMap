"""Tests for the ATProto / Node-service ecosystem overlay (AM052 / C38).

Deterministic expected signal sets against the
``tests/fixtures/atproto-service`` fixture, silence on a non-ATProto
control repo, evidence path/line discipline, and analyzer-contract
compatibility for the registration patch delivered with AM052.
"""

from pathlib import Path

from attackmap.analyzer_contracts import (
    EXTRACTION_PROTOCOL_VERSION,
    AnalyzerMetadata,
    check_extraction_compatibility,
    normalize_analyzer_metadata,
)
from attackmap.ecosystem_node_atproto import looks_like_atproto_repo, scan_node_atproto
from attackmap.index import RepoIndex
from attackmap.models import Route

FIXTURE = Path(__file__).parent / "fixtures" / "atproto-service"
XRPC_METHODS = "src/xrpc-methods.ts"


def _scan(root: Path = FIXTURE):
    return scan_node_atproto(root)


def _route_tuples(result):
    return {(r.path, r.method, r.file, r.line, r.auth) for r in result.routes}


def _hints(items):
    return {(h.hint, h.file, h.line) for h in items}


# --- Applicability -------------------------------------------------------------


def test_detect_accepts_atproto_service_fixture() -> None:
    assert looks_like_atproto_repo(FIXTURE) is True


def test_detect_and_scan_are_silent_on_non_atproto_control(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name": "shop-api", "dependencies": {"express": "^4.19.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text(
        "const express = require('express')\n"
        "const app = express()\n"
        "app.get('/items', (req, res) => res.json([]))\n"
        "app.post('/cart', (req, res) => res.json({ok: true}))\n",
        encoding="utf-8",
    )
    (tmp_path / "data.json").write_text('{"dbUrl": "postgresql://u:p@db.internal/shop"}', encoding="utf-8")

    assert looks_like_atproto_repo(tmp_path) is False
    result = _scan(tmp_path)
    assert result.routes == []
    assert result.auth_hints == []
    assert result.service_hints == []
    assert result.protocol_hints == []
    assert result.edge_hints == []
    assert result.framework_hints == []
    assert result.external_calls == []


def test_detect_ignores_atproto_markers_that_only_live_in_test_files(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name": "shop-api", "dependencies": {"express": "^4.19.0"}}', encoding="utf-8"
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "did.test.ts").write_text(
        "it('resolves', () => expect(resolve('did:plc:abc123def')).toBeDefined())\n", encoding="utf-8"
    )

    assert looks_like_atproto_repo(tmp_path) is False


# --- XRPC surface: routes, auth resolution, wiring ------------------------------


def test_xrpc_surface_routes_with_auth_resolution() -> None:
    result = _scan()
    assert _route_tuples(result) == {
        # wired handlers: method type comes from the lexicon, auth from the
        # registration config (observed) or a covering middleware (inferred)
        ("/xrpc/com.example.status.post", "POST", XRPC_METHODS, 17, "required"),
        ("/xrpc/com.example.status.list", "GET", XRPC_METHODS, 21, "required"),
        ("/xrpc/com.example.moderation.report", "POST", XRPC_METHODS, 26, "unknown"),
        ("/xrpc/com.example.admin.purge", "ANY", XRPC_METHODS, 29, "required"),
        ("/xrpc/com.example.profile.getChecked", "ANY", XRPC_METHODS, 34, "required"),
        ("/xrpc/com.example.chat.send", "ANY", XRPC_METHODS, 40, "required"),
        # declared by a lexicon, never wired: the lexicon file is the evidence
        ("/xrpc/com.example.profile.get", "GET", "lexicons/com.example.profile.get.json", 3, "unknown"),
    }


def test_wired_route_guards_cite_their_evidence() -> None:
    result = _scan()
    by_path = {r.path: r for r in result.routes}

    post = by_path["/xrpc/com.example.status.post"]
    assert post.guards == ["authVerifier"]
    assert post.guard_evidence is not None
    assert post.guard_evidence.startswith("auth verifier 'authVerifier'")

    chat = by_path["/xrpc/com.example.chat.send"]
    assert chat.guards == ["chatAuth"]
    assert chat.guard_evidence is not None
    assert chat.guard_evidence.startswith(
        "inferred: middleware 'chatAuth' mounted at '/xrpc/com.example.chat.send'"
    )

    report = by_path["/xrpc/com.example.moderation.report"]
    assert report.guards == []
    assert report.guard_evidence is None


def test_xrpc_auth_verifier_and_no_auth_hints() -> None:
    result = _scan()
    verifier_hints = {h.hint for h in result.auth_hints if h.hint.startswith("xrpc_auth_verifier:")}
    assert verifier_hints == {
        "xrpc_auth_verifier:com.example.status.post",
        "xrpc_auth_verifier:com.example.status.list",
        "xrpc_auth_verifier:com.example.admin.purge",
        "xrpc_auth_verifier:com.example.profile.getChecked",
    }

    no_auth_hint = "xrpc_no_auth_observed:com.example.moderation.report"
    no_auth = [h for h in result.auth_hints if h.hint == no_auth_hint]
    assert len(no_auth) == 1
    assert no_auth[0].file == XRPC_METHODS
    assert no_auth[0].line == 26
    assert no_auth[0].confidence == 0.6  # inferred, weaker than observed
    assert "no observed auth verifier" in no_auth[0].evidence_text


def test_unwired_lexicon_and_missing_lexicon_inferences() -> None:
    result = _scan()
    assert _hints(result.protocol_hints) >= {
        ("atproto:xrpc_unwired:com.example.profile.get", "lexicons/com.example.profile.get.json", 3),
        ("atproto:xrpc_no_lexicon:com.example.admin.purge", XRPC_METHODS, 29),
        ("atproto:xrpc_no_lexicon:com.example.chat.send", XRPC_METHODS, 40),
        ("atproto:xrpc_no_lexicon:com.example.profile.getChecked", XRPC_METHODS, 34),
    }


def test_middleware_mounts_observed() -> None:
    result = _scan()
    assert _hints(result.auth_hints) >= {
        ("node:auth_middleware_mount:adminAuth", "src/index.ts", 15),
        ("node:auth_middleware_mount:chatAuth", "src/index.ts", 19),
    }


# --- Identity / signing hotspots -------------------------------------------------


def test_identity_and_signing_hotspots() -> None:
    result = _scan()
    assert _hints(result.auth_hints) >= {
        ("atproto:did_resolution", "src/identity.ts", 1),
        ("atproto:plc_operation", "src/identity.ts", 2),
        ("atproto:signing_key", "src/auth.ts", 1),
        ("atproto:service_auth", "src/auth.ts", 54),
        ("atproto:session_flow", "src/auth.ts", 61),
        ("atproto:did_reference", "src/feed-gen.ts", 4),
    }


# --- Service boundaries ----------------------------------------------------------


def test_service_boundary_hints() -> None:
    result = _scan()
    assert _hints(result.service_hints) >= {
        ("atproto:did_service:pds", "src/feed-gen.ts", 13),
        ("atproto:did_service:appview", "src/feed-gen.ts", 18),
        ("atproto:did_service:feedgen", "src/feed-gen.ts", 23),
        ("atproto:service_url:pds", "src/pds-client.ts", 5),
        ("atproto:service_url:appview", "src/pds-client.ts", 8),
        ("atproto:repo_event_stream", "src/firehose.ts", 1),
        ("atproto:feed_generator", "src/feed-gen.ts", 31),
    }
    assert {e.hint for e in result.edge_hints} == {
        "atproto:service_call:pds",
        "atproto:service_call:appview",
    }


def test_external_calls_include_template_xrpc_urls() -> None:
    result = _scan()
    calls = {(c.target, c.file, c.line, c.method) for c in result.external_calls}
    assert calls >= {
        # template-literal hosts emit the /xrpc/ path as the target
        ("/xrpc/com.atproto.repo.uploadBlob", "src/pds-client.ts", 11, "POST"),
        ("/xrpc/com.atproto.sync.getBlob", "src/pds-client.ts", 24, "GET"),
        ("/xrpc/com.atproto.repo.describeRepo", "src/pds-client.ts", 32, "GET"),
        ("/xrpc/app.bsky.feed.getTimeline", "src/pds-client.ts", 39, "GET"),
        # full literal URLs keep the URL
        ("https://pds.example.com/xrpc/com.atproto.sync.putBlob", "src/pds-client.ts", 18, "POST"),
        ("https://pds.example.com/xrpc/com.atproto.server.refreshSession", "src/auth.ts", 62, None),
        ("https://pds.example.com/xrpc/com.atproto.server.createSession", "src/auth.ts", 70, None),
        # event-stream subscription: verb is genuinely unknown
        ("/xrpc/com.atproto.sync.subscribeRepos", "src/firehose.ts", 12, None),
    }


def test_blob_and_namespace_protocol_hints() -> None:
    result = _scan()
    assert _hints(result.protocol_hints) >= {
        ("atproto:blob_upload", "src/pds-client.ts", 2),
        ("atproto:app_bsky_namespace", "src/pds-client.ts", 39),
    }
    assert {f"node:atproto-sdk:{name}" for name in ("xrpc-server", "identity", "crypto", "plc")} <= {
        h.hint for h in result.framework_hints
    }


# --- Evidence discipline ----------------------------------------------------------


def test_every_signal_carries_existing_file_and_positive_line() -> None:
    result = _scan()
    signals = [*result.routes, *result.auth_hints, *result.service_hints,
               *result.protocol_hints, *result.edge_hints, *result.framework_hints,
               *result.external_calls]
    assert signals, "fixture must produce signals"
    for signal in signals:
        path = FIXTURE / signal.file
        assert path.is_file(), f"evidence file missing: {signal.file}"
        assert isinstance(signal.line, int) and signal.line >= 1, f"bad line on {signal.file}"
        if not isinstance(signal, Route):
            assert signal.evidence_text, (
                f"missing evidence text for {type(signal).__name__} in {signal.file}"
            )


def test_overlay_does_not_claim_file_coverage() -> None:
    # Coverage enumeration stays with javascript-web / config; the overlay is
    # enrichment-only and must not double-count scanned files at merge time.
    result = _scan()
    assert result.files_scanned == 0
    assert result.scanned_files is None


# --- Index delegation --------------------------------------------------------------


def test_scan_uses_index_when_provided(tmp_path: Path) -> None:
    index = RepoIndex.build(FIXTURE)
    indexed = _scan(FIXTURE)
    direct = scan_node_atproto(FIXTURE, index=index)
    assert _route_tuples(indexed) == _route_tuples(direct)
    assert _hints(direct.auth_hints) == _hints(indexed.auth_hints)


# --- Analyzer-contract compatibility (real registered class) --------------------


def test_registration_class_satisfies_analyzer_contract() -> None:
    from attackmap.analyzers import BuiltinNodeAtprotoAnalyzer

    analyzer = BuiltinNodeAtprotoAnalyzer()
    assert EXTRACTION_PROTOCOL_VERSION == "1.0"

    compatibility = check_extraction_compatibility(analyzer)
    assert compatibility.compatible, compatibility.issues
    assert compatibility.analyzer == "node-atproto"

    normalized = normalize_analyzer_metadata(analyzer.metadata)
    assert normalized.name == "node-atproto"
    assert normalized.experimental is True
    assert normalized.enabled_by_default is True
    assert "atproto" in normalized.ecosystems

    # detect() gates on the same conservative markers the scan enforces.
    assert analyzer.detect(FIXTURE) is True

    result = analyzer.analyze(FIXTURE)
    assert any(r.path == "/xrpc/com.example.status.post" for r in result.routes)
