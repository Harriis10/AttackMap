"""Layered PHP / Laminas / Omeka S ecosystem analyzers (AM052 / C38).

Deterministic expected-signal tests per layer, layer silence on control
fixtures (laminas silent on plain PHP; omeka-s silent on a non-Omeka
Laminas app), evidence-line assertions against the fixture sources,
analyzer-contract compatibility, and merge behavior across the layers.
"""

from __future__ import annotations

from pathlib import Path

from attackmap.analyzers import merge_analyzer_results
from attackmap.analyzer_contracts import (
    EXTRACTION_PROTOCOL_VERSION,
    check_extraction_compatibility,
)
from attackmap.ecosystem_php import (
    OmekaSAnalyzer,
    PhpLaminasAnalyzer,
    PhpWebAnalyzer,
    has_php_source,
    looks_laminas,
    looks_omeka_s,
    scan_omeka_s_repo,
    scan_php_laminas_repo,
    scan_php_web_repo,
)
from attackmap.models import ScanResult

FIXTURES = Path(__file__).parent / "fixtures"
OMEKA = FIXTURES / "php-omeka-app"
PLAIN = FIXTURES / "php-plain-app"
LAMINAS = FIXTURES / "php-laminas-app"

MODULE_CONFIG = "module/ContactBoard/config/module.config.php"
ADMIN_CONTROLLER = "module/ContactBoard/src/Controller/BoardAdminController.php"
SITE_CONTROLLER = "module/ContactBoard/src/Controller/BoardSiteController.php"
AJAX = "src/Legacy/ajax_lookup.php"
ENTRY = "public/index.php"


def _entry(result: ScanResult) -> set[tuple[str, str, int]]:
    return {(h.hint, h.file, h.line) for h in result.entrypoint_hints}


def _auth(result: ScanResult) -> set[tuple[str, str, int]]:
    return {(h.hint, h.file, h.line) for h in result.auth_hints}


def _framework(result: ScanResult) -> set[tuple[str, str, int]]:
    return {(h.hint, h.file, h.line) for h in result.framework_hints}


def _routes(result: ScanResult) -> set[tuple[str, str, int]]:
    return {(r.path, r.method, r.line) for r in result.routes if r.file == MODULE_CONFIG}


def _source_line(rel: str, line: int) -> str:
    lines = (OMEKA / rel).read_text(encoding="utf-8").splitlines()
    return lines[line - 1]


# --- Applicability detection ---------------------------------------------------


def test_detect_matrix() -> None:
    assert has_php_source(OMEKA) and has_php_source(PLAIN) and has_php_source(LAMINAS)
    assert looks_laminas(OMEKA) and looks_laminas(LAMINAS)
    assert not looks_laminas(PLAIN)
    assert looks_omeka_s(OMEKA)
    assert not looks_omeka_s(PLAIN) and not looks_omeka_s(LAMINAS)


def test_detect_rejects_missing_root(tmp_path: Path) -> None:
    assert has_php_source(tmp_path / "nope") is False
    assert looks_laminas(tmp_path / "nope") is False
    assert looks_omeka_s(tmp_path / "nope") is False


# --- Layer 1: php-web -----------------------------------------------------------


def test_php_web_expected_signals() -> None:
    result = scan_php_web_repo(OMEKA)
    entry = _entry(result)
    assert ("php-http-input:$_GET (observed)", ENTRY, 8) in entry
    assert ("php-http-input:$_POST (observed)", AJAX, 16) in entry
    # Superglobal on the same line as a sink call: observed.
    assert ("php-input-to-sink:header (observed)", ENTRY, 10) in entry
    assert ("php-input-to-sink:shell-exec (observed)", AJAX, 18) in entry
    # Same-file variable propagation ($_GET -> $q -> ->query): inferred.
    assert ("php-input-to-sink:query (inferred)", AJAX, 14) in entry
    # Include/require edges with literal targets.
    assert ("php-include:/../config/application.config.php (observed)", ENTRY, 4) in entry
    assert ("php-include:/db.php (observed)", AJAX, 4) in entry
    assert ("php-include:/config/module.config.php (observed)", "module/ContactBoard/Module.php", 16) in entry
    # Outbound HTTP without a literal URL: observation, never an invented target.
    assert ("php-curl-outbound (observed)", "module/ContactBoard/src/Service/BoardMailer.php", 23) in entry
    assert ("php-output-escaped (observed)", AJAX, 22) in entry


def test_php_web_session_cookie_database_secrets() -> None:
    result = scan_php_web_repo(OMEKA)
    auth = _auth(result)
    assert ("php-session-start (observed)", ENTRY, 6) in auth
    assert ("php-session-regenerate-id (observed)", ENTRY, 15) in auth
    assert ("php-session-state (observed)", ENTRY, 14) in auth
    assert ("php-cookie-httponly (observed)", ENTRY, 19) in auth
    assert ("php-cookie-samesite (observed)", ENTRY, 19) in auth

    databases = {(d.kind, d.file, d.line) for d in result.databases}
    assert ("sql", "src/Legacy/db.php", 5) in databases  # new PDO(...)
    assert ("mysql", "src/Legacy/db.php", 4) in databases  # DSN literal names the driver

    secrets = {(s.name, s.file, s.line, s.kind) for s in result.secret_hints}
    assert ("pdo-password", "src/Legacy/db.php", 5, "literal") in secrets


def test_php_web_languages_and_coverage() -> None:
    result = scan_php_web_repo(OMEKA)
    assert result.languages == ["php"]
    assert result.files_scanned == len(result.scanned_files) == 15
    assert "public/index.php" in result.scanned_files
    assert "module/ContactBoard/view/board/submit.phtml" not in result.scanned_files  # phtml is omeka-layer scope


def test_php_web_plain_fixture() -> None:
    result = scan_php_web_repo(PLAIN)
    assert ("php-session-start (observed)", "public/notes.php", 6) in _auth(result)
    assert ("php-http-input:$_POST (observed)", "public/notes.php", 8) in _entry(result)
    assert ("php-include:/../lib/notes_store.php (observed)", "public/notes.php", 4) in _entry(result)
    assert ("php-output-escaped (observed)", "public/notes.php", 16) in _entry(result)


def test_php_web_no_routes_no_taint_chains() -> None:
    result = scan_php_web_repo(OMEKA)
    assert result.routes == []  # Laravel/Slim/Symfony regexes stay in the generic scanner
    assert result.taint_chains == []  # flow tracing stays in core's taint pass


# --- Layer 2: php-laminas ---------------------------------------------------------


def test_laminas_expected_signals() -> None:
    result = scan_php_laminas_repo(OMEKA)
    framework = _framework(result)
    assert ("laminas (observed)", "composer.json", 7) in framework
    assert ("laminas-module:ContactBoard (observed)", "module/ContactBoard/Module.php", 5) in framework
    assert ("laminas-service-manager (observed)", MODULE_CONFIG, 11) in framework
    assert ("laminas-service-factory:BoardMailer (observed)", MODULE_CONFIG, 11) in framework
    assert ("laminas-controllers-config (observed)", MODULE_CONFIG, 5) in framework
    assert ("laminas-import:Validator (observed)", "module/ContactBoard/src/Form/BoardForm.php", 8) in framework
    assert ("laminas-import:InputFilter (observed)", "module/ContactBoard/src/Form/BoardForm.php", 7) in framework
    assert ("laminas-input-filter (observed)", "module/ContactBoard/src/Form/BoardForm.php", 7) in framework
    assert ("laminas-form:BoardForm (observed)", "module/ContactBoard/src/Form/BoardForm.php", 16) in framework
    assert ("laminas-app-module:Omeka (observed)", "config/application.config.php", 5) in framework

    entry = _entry(result)
    assert ("laminas-controller:BoardAdminController (observed)", ADMIN_CONTROLLER, 13) in entry
    assert ("laminas-action:BoardAdminController/index (observed)", ADMIN_CONTROLLER, 22) in entry
    assert ("laminas-action:BoardAdminController/item (observed)", ADMIN_CONTROLLER, 35) in entry
    assert ("laminas-request-input:route (observed)", ADMIN_CONTROLLER, 43) in entry
    assert ("laminas-request-input:query (observed)", SITE_CONTROLLER, 30) in entry
    assert ("laminas-request-input:post (observed)", SITE_CONTROLLER, 42) in entry


def test_laminas_expected_routes() -> None:
    result = scan_php_laminas_repo(OMEKA)
    assert _routes(result) == {
        ("/admin/contact-board", "ANY", 40),
        ("/admin/contact-board/item/:id", "ANY", 52),
        ("/s/:site-slug/board", "ANY", 66),
        ("/s/:site-slug/board/submit", "ANY", 77),
    }


def test_laminas_silent_on_plain_php() -> None:
    result = scan_php_laminas_repo(PLAIN)
    assert result.framework_hints == []
    assert result.entrypoint_hints == []
    assert result.routes == []
    assert result.files_scanned == 0


def test_laminas_on_non_omeka_laminas_app() -> None:
    result = scan_php_laminas_repo(LAMINAS)
    assert ("laminas (observed)", "composer.json", 6) in _framework(result)
    assert ("laminas-module:Feedback (observed)", "module/Feedback/Module.php", 4) in _framework(result)
    assert {
        (r.path, r.line) for r in result.routes if r.file == "module/Feedback/config/module.config.php"
    } == {("/feedback", 20), ("/feedback/submit", 31)}


# --- Layer 3: omeka-s ------------------------------------------------------------


def test_omeka_expected_signals() -> None:
    result = scan_omeka_s_repo(OMEKA)
    framework = _framework(result)
    assert ("omeka-s (observed)", "composer.json", 10) in framework
    assert ("omeka-s-module:ContactBoard (observed)", "module/ContactBoard/Module.php", 4) in framework

    entry = _entry(result)
    # API resources, media ingestion and route families from module.config.php.
    assert ("omeka-api-adapter:board_items (observed)", MODULE_CONFIG, 20) in entry
    assert ("omeka-media-ingester:board_upload (observed)", MODULE_CONFIG, 25) in entry
    assert ("omeka-media-renderer:board_upload (observed)", MODULE_CONFIG, 30) in entry
    assert ("omeka-admin-route:/admin/contact-board (observed)", MODULE_CONFIG, 40) in entry
    assert ("omeka-site-route:/s/:site-slug/board (observed)", MODULE_CONFIG, 66) in entry
    assert ("omeka-site-route:/s/:site-slug/board/submit (observed)", MODULE_CONFIG, 77) in entry
    # The child inherits its admin prefix; composition is marked as inferred.
    assert ("omeka-admin-route:/admin/contact-board/item/:id (inferred)", MODULE_CONFIG, 52) in entry
    # API classes and service markers.
    assert ("omeka-api-adapter-class:BoardItemAdapter (observed)", "module/ContactBoard/src/Api/Adapter/BoardItemAdapter.php", 13) in entry
    assert ("omeka-api-representation:BoardItemRepresentation (observed)", "module/ContactBoard/src/Api/Representation/BoardItemRepresentation.php", 9) in entry
    assert ("omeka-api-manager (observed)", ADMIN_CONTROLLER, 6) in entry
    assert ("omeka-file-store (observed)", "module/ContactBoard/src/Media/Ingester/BoardUpload.php", 8) in entry
    assert ("omeka-upload-request (observed)", "module/ContactBoard/src/Media/Ingester/BoardUpload.php", 26) in entry
    # View-script output encoding.
    assert ("php-output-escaped (observed)", "module/ContactBoard/view/board/submit.phtml", 7) in entry
    assert ("php-output-unescaped (observed)", "module/ContactBoard/view/board/submit.phtml", 9) in entry

    # Admin authentication plugin.
    assert ("omeka-identity-plugin (observed)", ADMIN_CONTROLLER, 25) in _auth(result)

    # Route records are emitted here too (deduped against php-laminas at merge).
    assert _routes(result) == {
        ("/admin/contact-board", "ANY", 40),
        ("/admin/contact-board/item/:id", "ANY", 52),
        ("/s/:site-slug/board", "ANY", 66),
        ("/s/:site-slug/board/submit", "ANY", 77),
    }


def test_omeka_silent_on_non_omeka_laminas_app() -> None:
    result = scan_omeka_s_repo(LAMINAS)
    assert result.framework_hints == []
    assert result.entrypoint_hints == []
    assert result.auth_hints == []
    assert result.routes == []
    assert result.files_scanned == 0


def test_omeka_scans_phtml_views() -> None:
    result = scan_omeka_s_repo(OMEKA)
    assert "module/ContactBoard/view/board/submit.phtml" in result.scanned_files


# --- Evidence assertions ----------------------------------------------------------


def test_evidence_lines_match_source() -> None:
    result = scan_php_web_repo(OMEKA)
    by_hint = {(h.hint, h.file): h for h in result.entrypoint_hints}
    sink = by_hint[("php-input-to-sink:header (observed)", ENTRY)]
    assert "header(" in sink.evidence_text and "$_GET" in sink.evidence_text
    assert "header(" in _source_line(ENTRY, sink.line)

    inferred = by_hint[("php-input-to-sink:query (inferred)", AJAX)]
    assert "->query(" in _source_line(AJAX, inferred.line)
    assert "$q" in _source_line(AJAX, inferred.line)
    assert inferred.confidence < 0.7  # downgraded vs observed

    laminas = scan_php_laminas_repo(OMEKA)
    route = next(r for r in laminas.routes if r.path == "/admin/contact-board")
    assert "'route' => '/admin/contact-board'" in _source_line(MODULE_CONFIG, route.line)

    omeka = scan_omeka_s_repo(OMEKA)
    unescaped = next(
        h for h in omeka.entrypoint_hints
        if h.hint == "php-output-unescaped (observed)"
    )
    assert "$visitorNote" in _source_line(unescaped.file, unescaped.line)


def test_observed_vs_inferred_labels_everywhere() -> None:
    for result in (
        scan_php_web_repo(OMEKA),
        scan_php_laminas_repo(OMEKA),
        scan_omeka_s_repo(OMEKA),
    ):
        hints = [
            *(h.hint for h in result.entrypoint_hints),
            *(h.hint for h in result.auth_hints),
            *(h.hint for h in result.framework_hints),
        ]
        assert hints, "fixture must produce hints"
        for hint in hints:
            assert hint.endswith("(observed)") or hint.endswith("(inferred)"), hint


def test_every_signal_carries_location_evidence() -> None:
    for result in (
        scan_php_web_repo(OMEKA),
        scan_php_laminas_repo(OMEKA),
        scan_omeka_s_repo(OMEKA),
    ):
        for family in (
            result.entrypoint_hints, result.auth_hints, result.framework_hints,
            result.databases, result.secret_hints, result.external_calls,
        ):
            for hint in family:
                assert hint.file
                assert hint.line is not None and hint.line >= 1
                assert hint.evidence_text  # cited source text
        for route in result.routes:
            assert route.file and route.line is not None


# --- Analyzer contract --------------------------------------------------------------


def test_extraction_protocol_compatibility() -> None:
    assert EXTRACTION_PROTOCOL_VERSION == "1.0"
    for analyzer in (PhpWebAnalyzer(), PhpLaminasAnalyzer(), OmekaSAnalyzer()):
        report = check_extraction_compatibility(analyzer)
        assert report.compatible, report.issues
        assert report.analyzer == analyzer.name
        assert report.protocol_version == EXTRACTION_PROTOCOL_VERSION


def test_analyzer_analyze_returns_scanresult() -> None:
    for analyzer, root in (
        (PhpWebAnalyzer(), OMEKA),
        (PhpWebAnalyzer(), PLAIN),
        (PhpLaminasAnalyzer(), LAMINAS),
        (OmekaSAnalyzer(), OMEKA),
    ):
        result = analyzer.analyze(root)
        assert isinstance(result, ScanResult)
        assert ScanResult.model_validate(result.model_dump())  # round-trips the schema
        assert analyzer.metadata.name in {"php-web", "php-laminas", "omeka-s"}


def test_php_web_analyzer_keeps_generic_scanner_coverage(tmp_path: Path) -> None:
    # Claiming .php away from the default analyzer must not lose the
    # generic pass: Laravel-style routes still come out of php-web, and
    # coverage counts each file once.
    (tmp_path / "routes.php").write_text(
        "<?php\nRoute::get('/items', 'ItemList::class');\n", encoding="utf-8"
    )
    result = PhpWebAnalyzer().analyze(tmp_path)
    assert any(r.path == "/items" and r.method == "GET" for r in result.routes)
    assert result.languages == ["php"]
    assert result.scanned_files == ["routes.php"]
    assert result.files_scanned == 1


def test_metadata_follows_layer_convention() -> None:
    # Broad language layer first (priority 0-49), framework (50-149), app overlay (150+).
    assert PhpWebAnalyzer().metadata.priority < PhpLaminasAnalyzer().metadata.priority < OmekaSAnalyzer().metadata.priority
    assert PhpWebAnalyzer().metadata.priority < 50
    assert 50 <= PhpLaminasAnalyzer().metadata.priority < 150
    assert OmekaSAnalyzer().metadata.priority >= 150
    # Experimental maturity is honest for the enrichment layers.
    assert PhpLaminasAnalyzer().metadata.experimental is True
    assert OmekaSAnalyzer().metadata.experimental is True


# --- Merge behavior ------------------------------------------------------------------


def test_merge_across_layers_dedups_routes() -> None:
    merged = merge_analyzer_results([
        scan_php_web_repo(OMEKA),
        scan_php_laminas_repo(OMEKA),
        scan_omeka_s_repo(OMEKA),
    ], root=OMEKA)
    # php-laminas and omeka-s both emit the 4 module.config routes: deduped.
    assert len([r for r in merged.routes if r.file == MODULE_CONFIG]) == 4
    assert merged.languages == ["php"]
    hints = {h.hint for h in merged.entrypoint_hints}
    assert "php-input-to-sink:header (observed)" in hints
    assert "omeka-media-ingester:board_upload (observed)" in hints
    assert "laminas-controller:BoardAdminController (observed)" in hints


def test_index_path_matches_direct_walk() -> None:
    from attackmap.index import RepoIndex

    index = RepoIndex.build(OMEKA)
    direct = scan_php_web_repo(OMEKA)
    indexed = scan_php_web_repo(OMEKA, index=index)
    assert _entry(direct) == _entry(indexed)
    assert _auth(direct) == _auth(indexed)
    assert indexed.files_scanned == direct.files_scanned

    laminas_direct = scan_php_laminas_repo(OMEKA)
    laminas_indexed = scan_php_laminas_repo(OMEKA, index=index)
    assert _framework(laminas_direct) == _framework(laminas_indexed)
    assert {r.path for r in laminas_direct.routes} == {r.path for r in laminas_indexed.routes}

    omeka_direct = scan_omeka_s_repo(OMEKA)
    omeka_indexed = scan_omeka_s_repo(OMEKA, index=index)
    assert _entry(omeka_direct) == _entry(omeka_indexed)
