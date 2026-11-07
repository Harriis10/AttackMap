"""Owned candidate regressions; no scan, provider, GUI or canonical writes."""
from dataclasses import asdict, replace
from itertools import permutations

import pytest

from attackmap.contracts import ContractLink, DeploymentAliases, link_contracts
from attackmap.crossrepo import find_cross_boundary_flows, find_trust_gaps
from attackmap.models import BolaCandidate, ExternalCall, Route, ScanResult, TaintChain


def linked(calls, *, method="GET", aliases=None):
    server = ScanResult(root="api", routes=[Route(path="/Api/Items/{id}", method=method, file="public.py", line=7)])
    return link_contracts([("client", ScanResult(root="client", external_calls=list(calls))), ("api", server)], aliases), server


def call(host, *, method="GET", scheme="https", instance="42"):
    return ExternalCall(target=f"{scheme}://{host}/Api/Items/{instance}", method=method, file="client.py", line=3)


def test_distinct_same_line_authorities_are_order_invariant():
    outputs = [linked(order)[0] for order in permutations([call("api"), call("unresolved")])]
    assert [asdict(x) for x in outputs[0]] == [asdict(x) for x in outputs[1]]
    assert {(x.destination, x.resolution) for x in outputs[0]} == {("api", "observed"), ("unresolved", "candidate")}


@pytest.mark.parametrize("order", list(permutations(["GET", "POST", None])))
def test_any_route_preserves_concrete_caller_verb_and_unknown(order):
    links, server = linked([call("api", method=method) for method in order], method="ANY")
    assert {x.client_method for x in links} == {"GET", "POST", None}
    assert len(links) == 3
    gaps = find_trust_gaps(links, [("client", ScanResult(root="client")), ("api", server)],
        {"api": {("public.py", "ANY", "/Api/Items/{id}"): False}})
    assert len(gaps) == 1 and gaps[0].method == "POST"


@pytest.mark.parametrize("order", list(permutations(["http", "https"])))
def test_same_authority_distinct_schemes_keep_protocol_gate(order):
    links, _ = linked([call("api", scheme=scheme) for scheme in order],
        aliases=DeploymentAliases(service_protocols={"api": "https"}))
    assert {(x.scheme, x.resolution, x.resolution_reason) for x in links} == {
        ("http", "candidate", "scheme_mismatch"), ("https", "observed", "")}


def test_same_normalized_authority_scheme_and_verb_still_collapse_instances():
    links, _ = linked([call("API:08443", method="get", scheme="HTTPS", instance="41"),
                       call("api:8443", method="GET", instance="42")],
        aliases=DeploymentAliases(service_ports={"api": 8443}))
    assert len(links) == 1 and links[0].destination == "api:8443"
    assert links[0].scheme == "https" and links[0].client_method == "GET"
    assert links[0].resolution == "observed"


@pytest.mark.parametrize("order", list(permutations(["alias-one", "alias-two"])))
def test_distinct_declared_aliases_keep_each_origin(order):
    links, _ = linked([call(host) for host in order], aliases=DeploymentAliases(
        hosts={"alias-one": "api", "alias-two": "api"},
        source_files={"hosts:alias-one": "edge/one.conf", "hosts:alias-two": "edge/two.conf"}))
    assert len(links) == 2
    assert {x.alias_provenance for x in links} == {"hosts:alias-one (edge/one.conf)", "hosts:alias-two (edge/two.conf)"}
    assert {x.resolution for x in links} == {"observed"}


def seam(**changes):
    return replace(ContractLink(client_repo="client", server_repo="api", method="GET", path_template="Api/Items/*",
        client_target="https://api/Api/Items/42", client_file="client.py", client_line=3,
        server_route_path="/Api/Items/{id}", server_file="public.py", server_line=7,
        destination="api", resolution="observed"), **changes)


def signal(basis, file, *, path="/Api/Items/{id}", method="GET", hops=0):
    if basis == "taint":
        return TaintChain(route_path=path, route_method=method, route_file=file,
            sink_kind="sql_execute", sink_file=file + ".db", sink_line=20, hops=hops)
    return BolaCandidate(route_path=path, route_method=method, route_file=file,
        route_line=11, id_param=file, reaches_db=True, has_ownership_check=False)


def flows(basis, signals, *, link=None):
    attribute = "taint_chains" if basis == "taint" else "authz_candidates"
    return find_cross_boundary_flows([link or seam()], [("client", ScanResult(root="client")),
        ("api", ScanResult(root="api", **{attribute: list(signals)}))])


@pytest.mark.parametrize("basis", ["taint", "bola"])
@pytest.mark.parametrize("wrong_file", ["private.py", "Public.py"])
def test_same_route_and_method_in_different_or_case_distinct_file_cannot_supply_flow(basis, wrong_file):
    assert flows(basis, [signal(basis, wrong_file)]) == []


@pytest.mark.parametrize("basis", ["taint", "bola"])
@pytest.mark.parametrize("reverse", [False, True])
def test_matching_handler_positive_control_ignores_better_wrong_handler(basis, reverse):
    signals = [signal(basis, "private.py", hops=0), signal(basis, "public.py", hops=2)]
    if reverse: signals.reverse()
    result = flows(basis, signals)
    assert len(result) == 1
    assert result[0].server_file == ("public.py.db" if basis == "taint" else "public.py")


@pytest.mark.parametrize("basis", ["taint", "bola"])
@pytest.mark.parametrize("mismatch", ["path_case", "method"])
def test_exact_file_does_not_override_case_sensitive_path_or_method(basis, mismatch):
    candidate = signal(basis, "public.py", path="/api/items/{id}" if mismatch == "path_case" else "/Api/Items/{id}",
        method="POST" if mismatch == "method" else "GET")
    assert flows(basis, [candidate]) == []


@pytest.mark.parametrize("basis", ["taint", "bola"])
@pytest.mark.parametrize("resolution", ["candidate", "observed_via_proxy"])
def test_no_non_direct_observed_flow_even_when_handler_matches(basis, resolution):
    assert flows(basis, [signal(basis, "public.py")], link=seam(resolution=resolution)) == []


@pytest.mark.parametrize("order", list(permutations(["api", "edge.internal"])))
def test_same_line_proxy_and_direct_leg_remain_distinct_and_proxy_cannot_supply_flow(order):
    links, _ = linked([call(host) for host in order], aliases=DeploymentAliases(proxies={"edge.internal": "api"}))
    assert len(links) == 2
    assert {x.resolution for x in links} == {"observed", "observed_via_proxy"}
    server = ScanResult(root="api", taint_chains=[signal("taint", "public.py")])
    found = find_cross_boundary_flows(links, [("client", ScanResult(root="client")), ("api", server)])
    assert len(found) == 1 and found[0].client_target.startswith("https://api/")
