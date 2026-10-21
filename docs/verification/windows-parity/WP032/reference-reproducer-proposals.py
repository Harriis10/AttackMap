"""UNEXECUTED WP032 fixture proposals; no canonical source/test modification.

Pure in-memory setups only. Expected improvements are comments, not fabricated
passing assertions. An implementation owner can turn each into focused tests.
"""
from attackmap.contracts import ContractLink, link_contracts
from attackmap.crossrepo import find_cross_boundary_flows
from attackmap.finding_presentation import FindingPresentationIndex
from attackmap.models import (BolaCandidate, ExploitabilityFactor, ExploitabilityScore,
                              ExternalCall, Finding, Route, ScanResult, TaintChain)


def r1_same_line_distinct_authority_order():
    calls = [ExternalCall(target=f"https://{host}/Api/Users/42", method="GET", file="client.py", line=3)
             for host in ("api", "unresolved")]
    server = ScanResult(root="api", routes=[Route(path="/Api/Users/{id}", method="GET", file="server.py", line=7)])
    # Compare sets from these two outputs: authority/resolution must not be first-wins.
    return [link_contracts([("client", ScanResult(root="client", external_calls=order)), ("api", server)])
            for order in (calls, list(reversed(calls)))]


def r2_wrong_handler_taint_or_bola():
    link = ContractLink(client_repo="client", server_repo="api", method="GET", path_template="items/*",
        client_target="https://api/items/42", client_file="client.py", client_line=3,
        server_route_path="/items/{id}", server_file="public.py", server_line=7,
        resolution="observed", destination="api")
    taint = TaintChain(route_path="/items/{id}", route_method="GET", route_file="private.py",
        sink_kind="sql_execute", sink_file="private_db.py", sink_line=22, hops=1)
    bola = BolaCandidate(route_path="/items/{id}", route_method="GET", route_file="private.py",
        id_param="id", reaches_db=True, has_ownership_check=False)
    # Neither signal belongs to link.server_file. Expected future result: [] for both.
    return [find_cross_boundary_flows([link], [("client", ScanResult(root="client")),
            ("api", ScanResult(root="api", routes=[Route(path="/items/{id}", method="GET", file="public.py")], **signals))])
            for signals in ({"taint_chains": [taint]}, {"authz_candidates": [bola]})]


def r3_equal_score_is_not_owned_reference():
    scores = [ExploitabilityScore(subject=f"GET /{name} -> {sink}", route=f"/{name}", method="GET",
        sink_kind=sink, location=f"{name}.py:10", score=60, raw_score=60, tier="high",
        factors=[ExploitabilityFactor(name=name, points=60)])
        for name, sink in (("intended", "sql_execute"), ("unrelated", "eval"))]
    finding = Finding(title="Synthetic aggregate", rule_id="taint-sql", severity="high", mitigation="Review",
        exploitability=60, exploitability_tier="high", locations=[{"file": "intended.py", "line": 10}])
    # Existing value-match output may contain both; a producer ref must select one,
    # or output must clearly remain unlinked candidates rather than owned factors.
    return FindingPresentationIndex(ScanResult(root="fixture"), scores).for_finding(finding)
