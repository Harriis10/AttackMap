"""Tests for cross-repo contract linking (#146b)."""

from __future__ import annotations

import pytest

from attackmap.contracts import ContractLink, DeploymentAliases, link_contracts
from attackmap.models import ExternalCall, Route, ScanResult


def _scan(root: str, *, routes=None, calls=None) -> ScanResult:
    return ScanResult(root=root, routes=list(routes or []), external_calls=list(calls or []))


def _client(root: str, target: str, method: str | None = "GET") -> ScanResult:
    return _scan(root, calls=[ExternalCall(target=target, method=method, file="c.py", line=3)])


def _server(root: str, path: str, method: str = "GET") -> ScanResult:
    return _scan(root, routes=[Route(path=path, method=method, file="s.py", line=5)])


# ---------------------------------------------------------------------------
# core matching
# ---------------------------------------------------------------------------


def test_links_concatenated_client_url_to_templated_route() -> None:
    # requests.get("http://b/api/orders/" + oid) — captured up to trailing slash.
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/orders/")),
            ("b", _server("b", "/api/orders/<id>")),
        ]
    )
    assert len(links) == 1
    lk = links[0]
    assert lk.client_repo == "a" and lk.server_repo == "b"
    assert lk.method == "GET"
    assert lk.path_template == "api/orders/*"
    assert lk.server_route_path == "/api/orders/<id>"
    assert lk.client_line == 3 and lk.server_line == 5
    assert lk.resolution == "observed" and lk.destination == "b"


def test_links_literal_id_to_template() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "https://b/users/12345")),
            ("b", _server("b", "/users/{id}")),
        ]
    )
    assert len(links) == 1
    assert links[0].path_template == "users/*"
    assert links[0].resolution == "observed"
    assert links[0].destination == "b"


def test_collection_route_not_confused_with_detail() -> None:
    # No trailing slash → collection call; must NOT match the /{id} detail route.
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/orders")),
            ("b", _server("b", "/api/orders/{id}")),
        ]
    )
    assert links == []


# ---------------------------------------------------------------------------
# method compatibility
# ---------------------------------------------------------------------------


def test_method_mismatch_does_not_link() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/items/1", method="POST")),
            ("b", _server("b", "/api/items/{id}", method="GET")),
        ]
    )
    assert links == []


def test_unknown_client_method_matches_any() -> None:
    # fetch(...) → method None → matches the route's method.
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/items/1", method=None)),
            ("b", _server("b", "/api/items/{id}", method="DELETE")),
        ]
    )
    assert len(links) == 1
    assert links[0].method == "DELETE"


# ---------------------------------------------------------------------------
# precision guards
# ---------------------------------------------------------------------------


def test_no_self_links_within_one_repo() -> None:
    scan = _scan(
        "solo",
        routes=[Route(path="/api/orders/{id}", method="GET", file="s.py", line=1)],
        calls=[ExternalCall(target="http://solo/api/orders/9", method="GET", file="c.py", line=2)],
    )
    assert link_contracts([("solo", scan)]) == []


def test_infra_paths_excluded() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "http://b/health")),
            ("b", _server("b", "/health")),
        ]
    )
    assert links == []


def test_all_variable_path_not_linked() -> None:
    # No static segment to anchor on → too generic.
    links = link_contracts(
        [
            ("a", _client("a", "http://b/12345")),
            ("b", _server("b", "/{id}")),
        ]
    )
    assert links == []


def test_unrelated_paths_do_not_link() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "http://b/api/widgets/1")),
            ("b", _server("b", "/api/gadgets/{id}")),
        ]
    )
    assert links == []


def test_deterministic_and_deduped() -> None:
    a = _scan(
        "a",
        calls=[
            ExternalCall(target="http://b/api/orders/1", method="GET", file="c.py", line=1),
            ExternalCall(target="http://b/api/orders/2", method="GET", file="c.py", line=1),
        ],
    )
    b = _server("b", "/api/orders/{id}")
    links = link_contracts([("a", a), ("b", b)])
    # Same (client file/line, server route) collapses to one link.
    assert len(links) == 1
    assert isinstance(links[0], ContractLink)


# ---------------------------------------------------------------------------
# Codex review regressions (#146b)
# ---------------------------------------------------------------------------


def test_test_and_vendored_callers_excluded() -> None:
    # A call from a test/fixture or vendored file is not production architecture.
    for bad_file in ("tests/test_client.py", "vendor/lib/http.js"):
        client = ScanResult(
            root="a",
            external_calls=[ExternalCall(target="http://b/api/orders/1", method="GET", file=bad_file)],
        )
        server = _server("b", "/api/orders/{id}")
        assert link_contracts([("a", client), ("b", server)]) == [], bad_file


def test_two_verbs_same_target_survive_merge() -> None:
    # merge identity now includes method, so GET+POST /items don't collapse (#146b).
    from attackmap.analyzers import merge_analyzer_results

    r1 = ScanResult(
        root="a", external_calls=[ExternalCall(target="http://b/api/items/1", method="GET", file="c.py")]
    )
    r2 = ScanResult(
        root="a", external_calls=[ExternalCall(target="http://b/api/items/1", method="POST", file="c.py")]
    )
    merged = merge_analyzer_results([r1, r2], root="a")
    methods = {c.method for c in merged.external_calls if c.target == "http://b/api/items/1"}
    assert methods == {"GET", "POST"}


def test_bare_fetch_defaults_to_get_and_parses_init_method(tmp_path) -> None:
    from attackmap.scanner import scan_repo

    (tmp_path / "client.js").write_text(
        'fetch("http://b/api/items/1");\n'
        'fetch("http://b/api/items/2", { method: "POST" });\n',
        encoding="utf-8",
    )
    scan = scan_repo(tmp_path)
    by_target = {c.target: c.method for c in scan.external_calls}
    assert by_target.get("http://b/api/items/1") == "GET"
    assert by_target.get("http://b/api/items/2") == "POST"


# ---------------------------------------------------------------------------
# destination identity resolution (C28 / AM039)
# ---------------------------------------------------------------------------


def test_unresolved_host_is_candidate_not_observed() -> None:
    # Same path and method, but the destination names a service that is not
    # the server repo: path similarity alone must not create an observed link.
    links = link_contracts(
        [
            ("a", _client("a", "http://order-svc/api/orders/9")),
            ("b", _server("b", "/api/orders/{id}")),
        ]
    )
    assert len(links) == 1
    lk = links[0]
    assert lk.resolution == "candidate"
    assert lk.resolution_reason == "unresolved_host"
    assert lk.destination == "order-svc"


def test_dns_suffix_does_not_resolve_by_truncation() -> None:
    # b.internal is not repo "b": no hostname truncation without an alias (C28).
    links = link_contracts(
        [
            ("a", _client("a", "https://b.internal/users/12345")),
            ("b", _server("b", "/users/{id}")),
        ]
    )
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "unresolved_host"
    assert links[0].destination == "b.internal"


def test_auth_api_and_auth_worker_stay_distinct() -> None:
    auth_api = _server("auth-api", "/sessions/{id}")
    auth_worker = _server("auth-worker", "/sessions/{id}")
    links = link_contracts(
        [
            ("web", _client("web", "http://auth-api/sessions/7")),
            ("auth-api", auth_api),
            ("auth-worker", auth_worker),
        ]
    )
    by_server = {lk.server_repo: lk for lk in links}
    assert by_server["auth-api"].resolution == "observed"
    assert by_server["auth-worker"].resolution == "candidate"
    assert by_server["auth-worker"].resolution_reason == "unresolved_host"


def test_relative_target_without_authority_is_candidate() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "/users/12345")),
            ("b", _server("b", "/users/{id}")),
        ]
    )
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "no_destination"
    assert links[0].destination is None


def test_explicit_port_keeps_link_candidate() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "http://b:8080/users/12345")),
            ("b", _server("b", "/users/{id}")),
        ]
    )
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "explicit_port"
    assert links[0].destination == "b:8080"


def test_ambiguous_identity_is_candidate_for_both_owners() -> None:
    # Two repos answer to the name "svc": a call to svc cannot resolve to one.
    links = link_contracts(
        [
            ("web", _client("web", "http://svc/users/1")),
            ("svc", _server("svc", "/users/{id}")),
            ("mirror", _scan("mirror-root/svc", routes=[Route(path="/users/{id}", method="GET", file="s.py", line=2)])),
        ]
    )
    assert {lk.server_repo: lk.resolution for lk in links} == {
        "svc": "candidate",
        "mirror": "candidate",
    }
    assert all(lk.resolution_reason == "unresolved_host" or lk.resolution_reason == "ambiguous_identity"
               for lk in links)


def test_root_directory_name_is_a_valid_identity() -> None:
    server = _scan("C:/repos/gateway", routes=[Route(path="/users/{id}", method="GET", file="s.py", line=9)])
    links = link_contracts(
        [
            ("a", _client("a", "http://gateway/users/5")),
            ("gw", server),
        ]
    )
    assert len(links) == 1
    assert links[0].resolution == "observed"
    assert links[0].destination == "gateway"


def test_case_sensitive_host_normalized_for_identity_only() -> None:
    links = link_contracts(
        [
            ("a", _client("a", "http://B-Service/users/5")),
            ("b-service", _server("b-service", "/users/{id}")),
        ]
    )
    assert len(links) == 1
    assert links[0].resolution == "observed"
    assert links[0].destination == "b-service"


# ---------------------------------------------------------------------------
# deployment aliases (C28 / AM040)
# ---------------------------------------------------------------------------


def test_no_aliases_kwarg_matches_default_and_empty() -> None:
    # Backward compatibility: None and an empty declaration set are the same
    # identity-only resolution as not passing aliases at all.
    scans = [
        ("web", _client("web", "https://auth-api.internal/sessions/9")),
        ("auth-api", _server("auth-api", "/sessions/{id}")),
        ("feed-generator", _server("feed-generator", "/sessions/{id}")),
    ]
    assert link_contracts(scans) == link_contracts(scans, aliases=None)
    assert link_contracts(scans) == link_contracts(scans, aliases=DeploymentAliases())


def test_exact_host_alias_resolves_public_name() -> None:
    links = link_contracts(
        [
            ("web-app", _client("web-app", "https://auth.bsky.social/sessions/9")),
            ("auth-api", _server("auth-api", "/sessions/{id}")),
        ],
        aliases=DeploymentAliases(hosts={"auth.bsky.social": "auth-api"}),
    )
    assert len(links) == 1
    assert links[0].resolution == "observed"
    assert links[0].destination == "auth.bsky.social"


def test_alias_naming_another_repo_stays_candidate() -> None:
    # The declaration positively names auth-api; the same path served by a
    # different repo must not inherit the resolution.
    links = link_contracts(
        [
            ("web-app", _client("web-app", "https://auth.bsky.social/sessions/9")),
            ("auth-worker", _server("auth-worker", "/sessions/{id}")),
        ],
        aliases=DeploymentAliases(hosts={"auth.bsky.social": "auth-api"}),
    )
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "unresolved_host"


def test_alias_naming_a_repo_outside_the_fleet_is_ignored() -> None:
    links = link_contracts(
        [
            ("web", _client("web", "http://edge/users/1")),
            ("auth-api", _server("auth-api", "/users/{id}")),
        ],
        aliases=DeploymentAliases(hosts={"edge": "gateway-svc"}),
    )
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "unresolved_host"


def test_declared_dns_suffix_strips_whole_repo_identity() -> None:
    # ".internal" is declared: auth-worker.internal strips to the whole identity
    # "auth-worker" — it must not drift onto the similarly-named auth-api.
    links = link_contracts(
        [
            ("web", _client("web", "https://auth-worker.internal/sessions/1")),
            ("auth-api", _server("auth-api", "/sessions/{id}")),
            ("auth-worker", _server("auth-worker", "/sessions/{id}")),
        ],
        aliases=DeploymentAliases(dns_suffixes=(".internal",)),
    )
    by_server = {lk.server_repo: lk for lk in links}
    assert by_server["auth-worker"].resolution == "observed"
    assert by_server["auth-api"].resolution == "candidate"
    assert by_server["auth-api"].resolution_reason == "unresolved_host"


def test_host_port_alias_resolves_ported_call() -> None:
    aliases = DeploymentAliases(host_ports={"auth-api:8443": "auth-api"})
    bound = link_contracts(
        [
            ("web", _client("web", "https://auth-api:8443/sessions/9")),
            ("auth-api", _server("auth-api", "/sessions/{id}")),
        ],
        aliases=aliases,
    )
    assert len(bound) == 1
    assert bound[0].resolution == "observed"
    assert bound[0].destination == "auth-api:8443"
    # A different port on the same host: the binding does not vouch for it.
    unbound = link_contracts(
        [
            ("web", _client("web", "https://auth-api:9999/sessions/9")),
            ("auth-api", _server("auth-api", "/sessions/{id}")),
        ],
        aliases=aliases,
    )
    assert len(unbound) == 1
    assert unbound[0].resolution == "candidate"
    assert unbound[0].resolution_reason == "explicit_port"


def test_alias_colliding_with_repo_identity_is_ambiguous() -> None:
    # "gateway" is declared for auth-api but is also feed-generator's checkout
    # directory: the host names two repos, so neither may claim it.
    links = link_contracts(
        [
            ("web", _client("web", "http://gateway/users/1")),
            ("auth-api", _server("auth-api", "/users/{id}")),
            (
                "feed-generator",
                _scan(
                    "C:/repos/gateway",
                    routes=[Route(path="/users/{id}", method="GET", file="s.py", line=2)],
                ),
            ),
        ],
        aliases=DeploymentAliases(hosts={"gateway": "auth-api"}),
    )
    assert {lk.server_repo: lk.resolution for lk in links} == {
        "auth-api": "candidate",
        "feed-generator": "candidate",
    }
    assert all(lk.resolution_reason == "ambiguous_identity" for lk in links)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"hosts": {"": "auth-api"}},
        {"hosts": {"auth.bsky.social": ""}},
        {"hosts": {"auth.bsky.social:8443": "auth-api"}},  # port belongs in host_ports
        {"hosts": {"https://x/y": "auth-api"}},  # not a bare hostname
        {"host_ports": {"auth-api": "auth-api"}},  # no port
        {"host_ports": {"auth-api:http": "auth-api"}},  # non-numeric port
        {"dns_suffixes": ("internal",)},  # missing leading dot
        {"dns_suffixes": (".",)},  # empty namespace
        {"proxies": {"": "auth-api"}},
        {"proxies": {"edge": ""}},
        {"proxies": {"edge:8080": "auth-api"}},  # not a bare hostname
        {"proxies": {"edge": "auth-api"}, "hosts": {"edge": "auth-api"}},  # alias and proxy
        {"service_ports": {"auth-api": 0}},
        {"service_ports": {"auth-api": 70000}},
        {"service_ports": {"auth-api": "https"}},  # non-numeric port
        {"service_protocols": {"auth-api": "grpc"}},  # unmodeled protocol
        {"service_protocols": {"auth-api": ""}},
        {"source_files": {"": "f.yaml"}},  # empty key
        {"source_files": {"service_ports:auth-api:8443": ""}},  # empty path
        {"source_files": {"bogus:auth-api": "f.yaml"}},  # unknown declaration prefix
    ],
)
def test_malformed_alias_declarations_raise(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        DeploymentAliases(**kwargs)


# ---------------------------------------------------------------------------
# protocol agreement (C28)
# ---------------------------------------------------------------------------


def test_scheme_mismatch_on_same_host_stays_candidate() -> None:
    # The host positively identifies the server, but the call's scheme
    # contradicts the declared protocol: same host, different scheme — a
    # candidate with an explicit reason, never a silently observed link.
    aliases = DeploymentAliases(service_protocols={"b": "https"})
    https = link_contracts(
        [("a", _client("a", "https://b/users/5")), ("b", _server("b", "/users/{id}"))],
        aliases=aliases,
    )
    assert len(https) == 1
    assert https[0].resolution == "observed"
    assert https[0].scheme == "https"
    http = link_contracts(
        [("a", _client("a", "http://b/users/5")), ("b", _server("b", "/users/{id}"))],
        aliases=aliases,
    )
    assert len(http) == 1
    assert http[0].resolution == "candidate"
    assert http[0].resolution_reason == "scheme_mismatch"
    assert http[0].destination == "b"


def test_scheme_check_requires_both_sides_declared() -> None:
    # One-sided declarations change nothing: an undeclared server resolves an
    # http call exactly as before; a scheme-less call declares nothing either.
    plain = link_contracts(
        [("a", _client("a", "http://b/users/5")), ("b", _server("b", "/users/{id}"))]
    )
    assert plain[0].resolution == "observed"
    declared_client_only = link_contracts(
        [("a", _client("a", "http://b/users/5")), ("b", _server("b", "/users/{id}"))],
        aliases=DeploymentAliases(service_protocols={"other": "https"}),
    )
    assert declared_client_only[0].resolution == "observed"


def test_scheme_mismatch_candidate_names_contradicting_declaration() -> None:
    # The candidate cites the protocol declaration its scheme contradicted —
    # with the declaring file when the declaration was extracted from one — so
    # an inspector sees exactly which config kept the link a candidate.
    aliases = DeploymentAliases(
        service_protocols={"b": "https"},
        source_files={"service_protocols:b:https": "b/k8s/service.yaml"},
    )
    fleet = [("a", _client("a", "http://b/users/5")), ("b", _server("b", "/users/{id}"))]
    mismatch = link_contracts(fleet, aliases=aliases)
    assert mismatch[0].resolution == "candidate"
    assert mismatch[0].resolution_reason == "scheme_mismatch"
    assert mismatch[0].alias_provenance == "service_protocols:b:https (b/k8s/service.yaml)"
    # The agreeing scheme still resolves observed, by identity (no provenance).
    agreeing = link_contracts(
        [("a", _client("a", "https://b/users/5")), ("b", _server("b", "/users/{id}"))],
        aliases=aliases,
    )
    assert agreeing[0].resolution == "observed"
    assert agreeing[0].alias_provenance is None


def test_scheme_mismatch_without_citable_declaration_keeps_provenance_none() -> None:
    # Identities that disagree with each other (fleet id and directory name
    # declared with different schemes) still mismatch a scheme in neither
    # camp, but no single declaration vouches — provenance stays None rather
    # than guessing one.
    links = link_contracts(
        [
            ("a", _client("a", "ftp://b/users/5")),
            ("b", _scan("C:/repos/alt-name", routes=[Route(path="/users/{id}", method="GET", file="s.py", line=1)])),
        ],
        aliases=DeploymentAliases(
            service_protocols={"b": "https", "alt-name": "http"},
        ),
    )
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "scheme_mismatch"
    assert links[0].alias_provenance is None


# ---------------------------------------------------------------------------
# declared proxies (C28)
# ---------------------------------------------------------------------------


def test_proxy_fronted_call_is_observed_via_proxy_not_direct() -> None:
    links = link_contracts(
        [
            ("web", _client("web", "http://edge.internal/users/5")),
            ("auth-api", _server("auth-api", "/users/{id}")),
            ("feed-generator", _server("feed-generator", "/users/{id}")),
        ],
        aliases=DeploymentAliases(proxies={"edge.internal": "auth-api"}),
    )
    by_server = {lk.server_repo: lk for lk in links}
    proxied = by_server["auth-api"]
    assert proxied.resolution == "observed_via_proxy"
    assert proxied.proxy_host == "edge.internal"
    assert proxied.destination == "edge.internal"
    assert proxied.alias_provenance == "proxies:edge.internal"
    assert proxied.resolution_reason == ""
    # The proxy fronts auth-api only: feed-generator keeps a plain candidate.
    assert by_server["feed-generator"].resolution == "candidate"
    assert by_server["feed-generator"].resolution_reason == "unresolved_host"


def test_proxy_call_scheme_not_compared_to_backend_protocol() -> None:
    # The proxy decouples the client→proxy leg from what the backend serves:
    # an http call through the proxy resolves even when the backend declares
    # https.
    links = link_contracts(
        [
            ("web", _client("web", "http://edge.internal/users/5")),
            ("auth-api", _server("auth-api", "/users/{id}")),
        ],
        aliases=DeploymentAliases(
            proxies={"edge.internal": "auth-api"},
            service_protocols={"auth-api": "https"},
        ),
    )
    assert len(links) == 1
    assert links[0].resolution == "observed_via_proxy"


def test_proxy_host_colliding_with_repo_identity_is_ambiguous() -> None:
    # "auth-api" is the backend's own identity AND a declared proxy host: the
    # declarations conflict, so nothing resolves.
    links = link_contracts(
        [
            ("web", _client("web", "http://auth-api/users/5")),
            ("auth-api", _server("auth-api", "/users/{id}")),
        ],
        aliases=DeploymentAliases(proxies={"auth-api": "auth-api"}),
    )
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "ambiguous_identity"


def test_ported_call_to_proxy_host_stays_candidate() -> None:
    # The proxy declaration is host-level and cannot vouch for a port; the
    # ported host itself identifies no repo directly, so the call stays an
    # unresolved candidate — never an observed seam through the proxy.
    links = link_contracts(
        [
            ("web", _client("web", "http://edge.internal:8080/users/5")),
            ("auth-api", _server("auth-api", "/users/{id}")),
        ],
        aliases=DeploymentAliases(proxies={"edge.internal": "auth-api"}),
    )
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "unresolved_host"


# ---------------------------------------------------------------------------
# server-declared listen ports (C28)
# ---------------------------------------------------------------------------


def test_declared_listen_port_resolves_ported_call() -> None:
    aliases = DeploymentAliases(service_ports={"auth-api": 8443})
    links = link_contracts(
        [
            ("web", _client("web", "https://auth-api:8443/sessions/9")),
            ("auth-api", _server("auth-api", "/sessions/{id}")),
        ],
        aliases=aliases,
    )
    assert len(links) == 1
    assert links[0].resolution == "observed"
    assert links[0].alias_provenance == "service_ports:auth-api:8443"


def test_declared_listen_port_does_not_vouch_for_other_ports() -> None:
    aliases = DeploymentAliases(service_ports={"auth-api": 8443})
    links = link_contracts(
        [
            ("web", _client("web", "https://auth-api:9999/sessions/9")),
            ("auth-api", _server("auth-api", "/sessions/{id}")),
        ],
        aliases=aliases,
    )
    assert len(links) == 1
    assert links[0].resolution == "candidate"
    assert links[0].resolution_reason == "explicit_port"


def test_listen_port_declared_under_alias_identity_still_resolves() -> None:
    # The port map addresses repos by any of their identity names, so a repo
    # whose fleet id differs from its checkout name still vouches for its port.
    aliases = DeploymentAliases(
        hosts={"auth.bsky.social": "auth-api"},
        service_ports={"auth-api": 8443},
    )
    links = link_contracts(
        [
            ("web", _client("web", "https://auth.bsky.social:8443/sessions/9")),
            ("auth-api", _server("auth-api", "/sessions/{id}")),
        ],
        aliases=aliases,
    )
    assert len(links) == 1
    assert links[0].resolution == "observed"
    assert links[0].alias_provenance == "service_ports:auth-api:8443"


# ---------------------------------------------------------------------------
# alias provenance (C28)
# ---------------------------------------------------------------------------


def test_alias_resolutions_record_provenance_identity_does_not() -> None:
    aliases = DeploymentAliases(
        hosts={"auth.bsky.social": "auth-api"},
        dns_suffixes=(".internal",),
    )
    links = link_contracts(
        [
            (
                "web",
                _scan(
                    "web",
                    calls=[
                        ExternalCall(target="http://auth-api/users/1", method="GET", file="c.py", line=1),
                        ExternalCall(target="http://auth.bsky.social/users/2", method="GET", file="c.py", line=2),
                        ExternalCall(target="http://worker.internal/users/3", method="GET", file="c.py", line=3),
                    ],
                ),
            ),
            ("auth-api", _server("auth-api", "/users/{id}")),
            (
                "worker",
                _scan(
                    "C:/deploy/worker",
                    routes=[Route(path="/users/{id}", method="GET", file="s.py", line=1)],
                ),
            ),
        ],
        aliases=aliases,
    )
    by_target = {lk.client_target: lk for lk in links if lk.resolution == "observed"}
    assert set(by_target) == {
        "http://auth-api/users/1",
        "http://auth.bsky.social/users/2",
        "http://worker.internal/users/3",
    }
    assert by_target["http://auth-api/users/1"].alias_provenance is None
    assert by_target["http://auth.bsky.social/users/2"].alias_provenance == "hosts:auth.bsky.social"
    assert by_target["http://worker.internal/users/3"].alias_provenance == "dns_suffix:.internal"


# ---------------------------------------------------------------------------
# config-extracted declaration provenance (C28)
# ---------------------------------------------------------------------------


def test_config_extracted_declarations_carry_their_declaring_file() -> None:
    # source_files (config-file extraction) appends the declaring file to the
    # provenance string; CLI declarations (no source entry) stay bare.
    aliases = DeploymentAliases(
        service_ports={"auth-api": 8443},
        proxies={"edge.internal": "auth-api"},
        source_files={
            "service_ports:auth-api:8443": "auth-api/k8s/service.yaml",
            "proxies:edge.internal": "auth-api/deploy/nginx/edge.conf",
        },
    )
    links = link_contracts(
        [
            (
                "web",
                _scan(
                    "web",
                    calls=[
                        ExternalCall(target="http://auth-api:8443/users/1", method="GET", file="c.py", line=1),
                        ExternalCall(target="http://edge.internal/users/2", method="GET", file="c.py", line=2),
                    ],
                ),
            ),
            ("auth-api", _server("auth-api", "/users/{id}")),
        ],
        aliases=aliases,
    )
    by_target = {lk.client_target: lk for lk in links}
    direct = by_target["http://auth-api:8443/users/1"]
    assert direct.resolution == "observed"
    assert direct.alias_provenance == "service_ports:auth-api:8443 (auth-api/k8s/service.yaml)"
    proxied = by_target["http://edge.internal/users/2"]
    assert proxied.resolution == "observed_via_proxy"
    assert proxied.alias_provenance == "proxies:edge.internal (auth-api/deploy/nginx/edge.conf)"


def test_source_files_without_a_matching_declaration_change_nothing() -> None:
    # A source entry keyed for a declaration that never resolves a link (here:
    # a different port) never surfaces — provenance strings stay bare.
    aliases = DeploymentAliases(
        service_ports={"auth-api": 8443},
        source_files={"service_ports:auth-api:9999": "auth-api/k8s/other.yaml"},
    )
    links = link_contracts(
        [
            ("a", _client("a", "http://auth-api:8443/users/5")),
            ("auth-api", _server("auth-api", "/users/{id}")),
        ],
        aliases=aliases,
    )
    assert links[0].alias_provenance == "service_ports:auth-api:8443"


# ---------------------------------------------------------------------------
# three-service reference system (C28 / AM040)
# ---------------------------------------------------------------------------


def _reference_fleet():
    """The C28 proof fixture: ``web-app`` calls into ``auth-api`` and
    ``feed-generator``. Hyphenated names throughout; ``feed-generator`` is
    deployed under a directory (``gateway``) distinct from its repo id; the two
    servers share one endpoint path (``/users/{id}``) so host identity — not
    path shape — must pick the server. The declarations cover the full C28
    service-resolution scope: exact hosts, a DNS suffix, a host:port binding,
    a declared listen port, a declared served scheme, and a declared proxy
    fronting ``auth-api``."""
    web_app = _scan(
        "C:/deploy/web-app",
        calls=[
            ExternalCall(target="http://auth-api/sessions/9", method="GET", file="src/client.py", line=10),
            ExternalCall(target="http://auth-api/users/42", method="GET", file="src/client.py", line=11),
            ExternalCall(target="https://feed-generator.internal/feeds/77", method="GET", file="src/client.py", line=12),
            ExternalCall(target="http://gateway/users/5", method="GET", file="src/client.py", line=13),
            ExternalCall(target="https://auth.bsky.social/sessions/2", method="GET", file="src/client.py", line=14),
            ExternalCall(target="http://auth-api:8081/users/7", method="GET", file="src/client.py", line=15),
            ExternalCall(target="http://feed-generator:9000/feeds/3", method="GET", file="src/client.py", line=16),
            ExternalCall(target="http://feed-generator.internal/feeds/9", method="GET", file="src/client.py", line=17),
            ExternalCall(target="https://feed-generator:9000/feeds/5", method="GET", file="src/client.py", line=18),
            ExternalCall(target="https://feed-generator:9443/feeds/8", method="GET", file="src/client.py", line=19),
            ExternalCall(target="http://edge.internal/users/6", method="GET", file="src/client.py", line=20),
            ExternalCall(target="http://edge.internal/sessions/4", method="GET", file="src/client.py", line=21),
        ],
    )
    auth_api = _scan(
        "C:/deploy/auth-api",
        routes=[
            Route(path="/sessions/{id}", method="GET", file="src/sessions.py", line=1),
            Route(path="/users/{id}", method="GET", file="src/users.py", line=2),
        ],
    )
    feed_generator = _scan(
        "C:/deploy/gateway",
        routes=[
            Route(path="/users/{id}", method="GET", file="src/profiles.py", line=3),
            Route(path="/feeds/{id}", method="GET", file="src/feeds.py", line=4),
        ],
    )
    aliases = DeploymentAliases(
        hosts={"auth.bsky.social": "auth-api", "gateway": "auth-api"},
        host_ports={"auth-api:8081": "auth-api"},
        dns_suffixes=(".internal",),
        proxies={"edge.internal": "auth-api"},
        service_ports={"feed-generator": 9000},
        service_protocols={"feed-generator": "https"},
    )
    return [("web-app", web_app), ("auth-api", auth_api), ("feed-generator", feed_generator)], aliases


def test_three_service_reference_system_with_declared_aliases() -> None:
    fleet, aliases = _reference_fleet()
    links = link_contracts(fleet, aliases)

    observed = [lk for lk in links if lk.resolution == "observed"]
    # Exactly the explicitly supported direct edges resolve — identity
    # (sessions), shared-path disambiguated by host (users -> auth-api), the
    # declared DNS suffix (feeds -> feed-generator), the public alias
    # (auth.bsky.social), the declared port binding (auth-api:8081), and the
    # declared listen port (feed-generator:9000) — and nothing else.
    assert {(lk.client_repo, lk.server_repo, lk.path_template) for lk in observed} == {
        ("web-app", "auth-api", "sessions/*"),
        ("web-app", "auth-api", "users/*"),
        ("web-app", "feed-generator", "feeds/*"),
    }
    assert all(lk.resolution_reason == "" for lk in observed)
    assert {lk.destination for lk in observed} == {
        "auth-api",
        "feed-generator.internal",
        "auth.bsky.social",
        "auth-api:8081",
        "feed-generator:9000",
    }
    # Alias provenance (C28): every alias-resolved observed link names the
    # declaration that vouched for it; identity matches carry none.
    assert {lk.destination: lk.alias_provenance for lk in observed} == {
        "auth-api": None,
        "feed-generator.internal": "dns_suffix:.internal",
        "auth.bsky.social": "hosts:auth.bsky.social",
        "auth-api:8081": "host_ports:auth-api:8081",
        "feed-generator:9000": "service_ports:feed-generator:9000",
    }

    # Proxy-fronted calls resolve as observed seams through the declared
    # proxy — never direct edges, never unprovenanced.
    via_proxy = [lk for lk in links if lk.resolution == "observed_via_proxy"]
    assert {(lk.server_repo, lk.path_template) for lk in via_proxy} == {
        ("auth-api", "sessions/*"),
        ("auth-api", "users/*"),
    }
    assert all(
        lk.proxy_host == "edge.internal"
        and lk.alias_provenance == "proxies:edge.internal"
        and lk.destination == "edge.internal"
        and lk.resolution_reason == ""
        for lk in via_proxy
    )

    candidates = {
        (lk.server_repo, lk.path_template, lk.resolution_reason)
        for lk in links
        if lk.resolution == "candidate"
    }
    assert candidates == {
        # shared path, destination names the other service
        ("feed-generator", "users/*", "unresolved_host"),
        # "gateway" is declared for auth-api but is feed-generator's directory:
        # ambiguous for both, observed for neither
        ("auth-api", "users/*", "ambiguous_identity"),
        ("feed-generator", "users/*", "ambiguous_identity"),
        # same host as a resolving call but plain http against the declared
        # https surface — ported or suffixed, a scheme contradiction kills it
        ("feed-generator", "feeds/*", "scheme_mismatch"),
        # explicit port no declaration vouches for
        ("feed-generator", "feeds/*", "explicit_port"),
    }
    # The two scheme-mismatched call sites stay individually inspectable.
    mismatched = [lk for lk in links if lk.resolution_reason == "scheme_mismatch"]
    assert {lk.client_target for lk in mismatched} == {
        "http://feed-generator:9000/feeds/3",
        "http://feed-generator.internal/feeds/9",
    }
    assert all(lk.scheme == "http" for lk in mismatched)
    # Every candidate call site stays individually inspectable with its authority.
    ported = [lk for lk in links if lk.client_target == "https://feed-generator:9443/feeds/8"]
    assert len(ported) == 1
    assert ported[0].destination == "feed-generator:9443"
    # 12 calls -> 16 (client, server, call-site) links: 6 observed direct,
    # 2 observed via the declared proxy, 8 candidate.
    assert len(links) == 16 and len(observed) == 6 and len(via_proxy) == 2


def test_three_service_reference_system_without_aliases() -> None:
    # The same fleet with no declarations resolves strictly by identity: the
    # DNS-suffixed and public hostnames stay candidates, the port bindings and
    # listen ports are gone, and "gateway" now resolves to feed-generator
    # alone (its directory name) — the alias is what made it ambiguous
    # instead. None of the new declaration kinds resolves anything on its own.
    fleet, _aliases = _reference_fleet()
    links = link_contracts(fleet)

    assert {(lk.client_repo, lk.server_repo, lk.path_template)
            for lk in links if lk.resolution == "observed"} == {
        ("web-app", "auth-api", "sessions/*"),
        ("web-app", "auth-api", "users/*"),
        ("web-app", "feed-generator", "users/*"),
    }
    assert not [lk for lk in links if lk.resolution == "observed_via_proxy"]
    reasons = {(lk.client_target, lk.resolution_reason)
               for lk in links if lk.resolution == "candidate"}
    assert ("https://feed-generator.internal/feeds/77", "unresolved_host") in reasons
    assert ("https://auth.bsky.social/sessions/2", "unresolved_host") in reasons
    assert ("http://auth-api:8081/users/7", "explicit_port") in reasons
    assert ("http://feed-generator:9000/feeds/3", "explicit_port") in reasons
    # The calls exercising the new declarations: without them every one is an
    # unresolved host or an unvouched explicit port.
    assert ("http://feed-generator.internal/feeds/9", "unresolved_host") in reasons
    assert ("https://feed-generator:9000/feeds/5", "explicit_port") in reasons
    assert ("https://feed-generator:9443/feeds/8", "explicit_port") in reasons
    assert ("http://edge.internal/users/6", "unresolved_host") in reasons
    assert ("http://edge.internal/sessions/4", "unresolved_host") in reasons
