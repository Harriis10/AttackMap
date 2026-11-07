"""Scoped static Laminas route-tree extraction, shared with the Omeka overlay."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.ecosystem_php import scan_omeka_s_repo, scan_php_laminas_repo


SCANNERS = (scan_php_laminas_repo, scan_omeka_s_repo)
CONFIG = "module/Demo/config/module.config.php"


def _scan(tmp_path: Path, source: str, scanner):
    config = tmp_path / CONFIG
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(source, encoding="utf-8")
    (tmp_path / "composer.json").write_text(
        '{"require":{"laminas/laminas-mvc":"^3.0","omeka/omeka-s":"^4.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "module/Demo/Module.php").write_text(
        "<?php namespace Demo; class Module extends \\Omeka\\Module\\AbstractModule {}",
        encoding="utf-8",
    )
    return scanner(tmp_path)


def _tree(parent: str = "/admin") -> str:
    return """<?php
return [
    'router' => ['routes' => [
        'parent' => [
            'type' => 'Literal',
            'options' => ['route' => '%s', 'defaults' => ['controller' => 'Board', 'action' => 'index']],
            'may_terminate' => true,
            'child_routes' => [
                'item' => [
                    'type' => \\Laminas\\Router\\Http\\Segment::class,
                    'options' => ['route' => '/item/:id', 'defaults' => ['action' => 'show']],
                    'may_terminate' => true,
                    'child_routes' => [
                        'edit' => ['type' => 'Literal', 'options' => ['route' => '/edit', 'defaults' => ['action' => 'edit']]],
                    ],
                ],
                'list' => ['type' => 'Literal', 'options' => ['route' => '/list']],
            ],
        ],
        'other' => [
            'type' => 'Literal',
            'options' => ['route' => '/public', 'defaults' => ['controller' => 'PublicBoard']],
            'child_routes' => [
                'item' => ['type' => 'Literal', 'options' => ['route' => '/item']],
            ],
        ],
        'absolute' => ['type' => 'Literal', 'options' => ['route' => '/health']],
    ]],
];
""" % parent


@pytest.mark.parametrize("scanner", SCANNERS)
def test_nested_routes_keep_parent_scope_and_duplicate_local_names(tmp_path, scanner):
    result = _scan(tmp_path, _tree(), scanner)
    assert {r.path for r in result.routes} == {
        "/admin", "/admin/item/:id", "/admin/item/:id/edit", "/admin/list",
        "/public/item", "/health",
    }
    assert all(r.file == CONFIG and r.auth == "unknown" and not r.guards for r in result.routes)
    child = next(r for r in result.routes if r.path == "/admin/item/:id/edit")
    assert child.line == 14
    hints = {h.hint: h for h in result.entrypoint_hints}
    controller = hints["laminas-route-default-controller:/admin/item/:id/edit=>Board (inferred)"]
    assert controller.line == 6
    assert "parent/item/edit" in controller.evidence_text
    assert "line 6" in controller.evidence_text and "line 14" in controller.evidence_text
    assert "laminas-route-default-action:/admin/item/:id/edit=>edit (observed)" in hints
    assert "laminas-route-default-controller:/public/item=>PublicBoard (inferred)" in hints


@pytest.mark.parametrize("scanner", SCANNERS)
def test_paired_wrong_parent_does_not_invent_admin_route(tmp_path, scanner):
    result = _scan(tmp_path, _tree("/private"), scanner)
    paths = {r.path for r in result.routes}
    assert "/private/item/:id/edit" in paths
    assert not any(p.startswith("/admin") for p in paths)
    assert "/item/:id" not in paths


@pytest.mark.parametrize("scanner", SCANNERS)
def test_legacy_arrays_comments_and_literal_slashes_are_preserved(tmp_path, scanner):
    source = r'''<?php
return array(
    'router' => array('routes' => array(
        'flat' => array('type' => 'Literal', 'options' => array('route' => '/flat//path/')),
        // 'fake' => ['options' => ['route' => '/comment']]],
        'root' => array(
            'type' => 'Literal', 'options' => array('route' => '/root/'),
            /* ], 'route' => '/block-comment' */
            'child_routes' => array('child' => array(
                'type' => 'Literal', 'options' => array('route' => 'child'),
            )),
        ),
    )),
);
'''
    result = _scan(tmp_path, source, scanner)
    assert {r.path for r in result.routes} == {"/flat//path/", "/root/child"}


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("expression", ["$prefix", "'/api' . $version", '"/api/$version"', "makePath()"])
def test_dynamic_parent_and_descendants_remain_explicitly_unsupported(tmp_path, scanner, expression):
    source = """<?php return ['router' => ['routes' => [
        'dynamic' => ['type' => 'Literal', 'options' => ['route' => %s],
            'child_routes' => ['child' => ['type' => 'Literal', 'options' => ['route' => '/child']]]],
        'safe' => ['type' => 'Literal', 'options' => ['route' => '/safe']],
    ]]];""" % expression
    result = _scan(tmp_path, source, scanner)
    assert {r.path for r in result.routes} == {"/safe"}
    assert any("laminas-route-unsupported:dynamic:dynamic-path" in h.hint for h in result.framework_hints)
    assert any("laminas-route-unsupported:dynamic/child:unresolved-parent" in h.hint for h in result.framework_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_dynamic_child_does_not_contaminate_static_sibling_or_defaults(tmp_path, scanner):
    source = """<?php return ['router' => ['routes' => [
        'parent' => ['type' => 'Literal', 'options' => ['route' => '/api', 'defaults' => ['controller' => 'Board']],
            'child_routes' => [
                'dynamic' => ['type' => 'Literal', 'options' => ['route' => $dynamic]],
                'static' => ['type' => 'Literal', 'options' => ['route' => '/list', 'defaults' => ['controller' => $controller]]],
            ]],
    ]]];"""
    result = _scan(tmp_path, source, scanner)
    assert {r.path for r in result.routes} == {"/api/list"}
    assert not any("laminas-route-default-controller:/api/list" in h.hint for h in result.entrypoint_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_nonrouting_arrays_and_wrongly_nested_children_are_not_routes(tmp_path, scanner):
    source = """<?php
$unrelated = ['router' => ['routes' => ['fake' => ['options' => ['route' => '/variable']]]]];
return [
    'cache' => ['route' => '/cache', 'options' => ['route' => '/unrelated']],
    'docs' => "'route' => '/string'",
    'router' => ['routes' => [
        'flat' => ['type' => 'Literal', 'options' => ['route' => '/flat',
            'child_routes' => ['misplaced' => ['type' => 'Literal', 'options' => ['route' => '/misplaced']]]]],
    ]],
];"""
    result = _scan(tmp_path, source, scanner)
    assert {r.path for r in result.routes} == {"/flat"}


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("source", [
    "<?php return ['router' => ['routes' => ['bad' => ['options' => ['route' => '/broken']]]];",
    "<?php return ['router' => ['routes' => ['bad' => ['options' => ['route' => '/bad'], 'options' => ['route' => '/duplicate']]]]];",
    "<?php return ['router' => ['routes' => ['bad' => ['options' => ['route' => '/bad']] + $extra]]];",
])
def test_malformed_or_ambiguous_arrays_do_not_fabricate_routes(tmp_path, scanner, source):
    assert _scan(tmp_path, source, scanner).routes == []


@pytest.mark.parametrize("scanner", SCANNERS)
def test_unsupported_route_types_and_absolute_urls_are_not_http_paths(tmp_path, scanner):
    source = """<?php return ['router' => ['routes' => [
        'host' => ['type' => 'Hostname', 'options' => ['route' => ':sub.example.com'],
            'child_routes' => ['child' => ['type' => 'Literal', 'options' => ['route' => '/child']]]],
        'regex' => ['type' => 'Regex', 'options' => ['route' => '/(.*)']],
        'url' => ['type' => 'Literal', 'options' => ['route' => 'https://example.com/path']],
    ]]];"""
    result = _scan(tmp_path, source, scanner)
    assert result.routes == []
    assert any("unsupported-type" in h.hint for h in result.framework_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_route_defaults_class_reference_and_unrelated_auth_are_evidence_only(tmp_path, scanner):
    source = """<?php
use Laminas\\Authentication\\AuthenticationService;
return ['router' => ['routes' => [
    'public' => ['type' => 'Literal', 'options' => ['route' => '/public', 'defaults' => [
        'controller' => Controller\\PublicController::class, 'action' => 'index',
    ]]],
]]];"""
    result = _scan(tmp_path, source, scanner)
    assert [(r.path, r.auth, r.guards) for r in result.routes] == [("/public", "unknown", [])]
    assert any("=>Controller\\PublicController::class (observed)" in h.hint for h in result.entrypoint_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_nonterminating_parent_is_only_a_prefix(tmp_path, scanner):
    source = _tree().replace("'may_terminate' => true,", "'may_terminate' => false,", 1)
    result = _scan(tmp_path, source, scanner)
    assert "/admin" not in {r.path for r in result.routes}
    assert "/admin/item/:id" in {r.path for r in result.routes}


def test_omeka_classification_uses_composed_parent_path(tmp_path):
    result = _scan(tmp_path, _tree(), scan_omeka_s_repo)
    assert any(h.hint == "omeka-admin-route:/admin/item/:id (inferred)" for h in result.entrypoint_hints)
    assert not any(h.hint.startswith("omeka-route:/item") for h in result.entrypoint_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_segment_syntax_and_double_slashes_are_not_normalized(tmp_path, scanner):
    source = """<?php return ['router' => ['routes' => [
        'parent' => ['type' => 'Segment', 'options' => ['route' => '/api[/:version]/'],
            'child_routes' => ['child' => ['type' => 'Segment', 'options' => ['route' => '/items[/:id]']]]],
    ]]];"""
    assert {r.path for r in _scan(tmp_path, source, scanner).routes} == {"/api[/:version]//items[/:id]"}


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("route_type", ["Literal", "Segment", "Method", "Hostname", "Scheme"])
def test_empty_paths_and_nonpath_wrappers_are_explicitly_unsupported(tmp_path, scanner, route_type):
    source = """<?php return ['router' => ['routes' => [
        'wrapper' => ['type' => '%s', 'options' => ['route' => ''],
            'child_routes' => ['child' => ['type' => 'Literal', 'options' => ['route' => '/child']]]],
    ]]];""" % route_type
    result = _scan(tmp_path, source, scanner)
    assert result.routes == []
    expected = "empty-path" if route_type in {"Literal", "Segment"} else "unsupported-type"
    assert any(f"laminas-route-unsupported:wrapper:{expected}" in h.hint for h in result.framework_hints)
    assert any("wrapper/child:unresolved-parent" in h.hint for h in result.framework_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_chain_routes_are_not_truncated_to_the_first_segment(tmp_path, scanner):
    source = """<?php return ['router' => ['routes' => [
        'chain' => ['type' => 'Literal', 'options' => ['route' => '/api'],
            'chain_routes' => [['type' => 'Literal', 'options' => ['route' => '/child']]]],
    ]]];"""
    result = _scan(tmp_path, source, scanner)
    assert result.routes == []
    assert any("chain:unsupported-chain" in h.hint for h in result.framework_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("array", [
    "['router' => ['routes' => ['safe' => ['type' => 'Literal', 'options' => ['route' => '/safe']]]], ...$overrides]",
    "['router' => ['routes' => ['safe' => ['type' => 'Literal', 'options' => ['route' => '/safe']], $name => $definition]]]",
    "['router' => ['routes' => ['safe' => ['type' => 'Literal', 'options' => ['route' => '/safe', ...$options]]]]]",
])
def test_dynamic_array_keys_cannot_override_literal_route_ownership(tmp_path, scanner, array):
    result = _scan(tmp_path, "<?php return " + array + ";", scanner)
    assert result.routes == []
    assert any("unsupported:" in h.hint for h in result.framework_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_dynamic_defaults_cannot_reuse_an_inherited_controller(tmp_path, scanner):
    source = """<?php return ['router' => ['routes' => [
        'parent' => ['type' => 'Literal', 'options' => ['route' => '/api', 'defaults' => ['controller' => 'Board']],
            'child_routes' => ['child' => ['type' => 'Literal', 'options' => [
                'route' => '/child', 'defaults' => ['action' => 'index', ...$defaults],
            ]]]],
    ]]];"""
    result = _scan(tmp_path, source, scanner)
    assert {r.path for r in result.routes} == {"/api/child"}
    assert not any("laminas-route-default-" in h.hint for h in result.entrypoint_hints)
    assert any("parent/child:dynamic-defaults" in h.hint for h in result.framework_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_heredoc_and_conditional_returned_configs_are_not_static_routes(tmp_path, scanner):
    for source in (
        "<?php $doc = <<<'PHP'\nreturn ['router' => ['routes' => ['fake' => ['type' => 'Literal', 'options' => ['route' => '/fake']]]]];\nPHP;",
        "<?php if ($enabled) return ['router' => ['routes' => ['fake' => ['type' => 'Literal', 'options' => ['route' => '/conditional']]]]];",
        "<?php ?>return ['router' => ['routes' => ['fake' => ['type' => 'Literal', 'options' => ['route' => '/html']]]]];",
    ):
        assert _scan(tmp_path, source, scanner).routes == []


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("prefix, route_type", [
    ("namespace App; use Custom\\Literal;", "Literal::class"),
    ("namespace App;", "Laminas\\Router\\Http\\Literal::class"),
    ("", "\\Literal::class"),
    ("", "\\Segment::class"),
    ("", "'Literal::class'"),
])
def test_unresolved_class_aliases_are_not_assumed_to_be_builtin_routes(tmp_path, scanner, prefix, route_type):
    source = """<?php %s return ['router' => ['routes' => [
        'custom' => ['type' => %s, 'options' => ['route' => '/unproven']],
    ]]];""" % (prefix, route_type)
    result = _scan(tmp_path, source, scanner)
    assert result.routes == []
    assert any("custom:unsupported-type" in h.hint for h in result.framework_hints)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_fully_qualified_builtin_type_ignores_unrelated_custom_import(tmp_path, scanner):
    source = """<?php namespace App; use Custom\\Literal;
return ['router' => ['routes' => [
    'builtin' => ['type' => \\Laminas\\Router\\Http\\Literal::class, 'options' => ['route' => '/builtin']],
    'string-name' => ['type' => 'Laminas\\Router\\Http\\Segment', 'options' => ['route' => '/literal-string[/:id]']],
]]];"""
    assert {r.path for r in _scan(tmp_path, source, scanner).routes} == {"/builtin", "/literal-string[/:id]"}
