"""Tests for multi-repo fleet mode (#146a)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from attackmap.cli import app
from attackmap.contracts import ContractLink, DeploymentAliases
from attackmap.fleet import (
    FleetRepoResult,
    FleetScan,
    fleet_repo_ids,
    fleet_summary_json,
    render_fleet_graph_mermaid,
    render_fleet_summary,
)
from attackmap.models import Finding, ScanResult

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _norm(output: str) -> str:
    """Typer renders BadParameter in a Rich error panel that wraps the message
    across bordered lines at narrow terminal widths — so a raw substring check
    is width-dependent. Strip ANSI + box-drawing and collapse whitespace so the
    message reassembles regardless of wrapping."""
    text = _ANSI.sub("", output)
    text = re.sub(r"[│╭╮╰╯─]", " ", text)
    return " ".join(text.split())


def _finding(title: str, severity: str) -> Finding:
    return Finding(title=title, severity=severity, mitigation="x")


def _result(repo_id: str, findings: list[Finding]) -> FleetRepoResult:
    return FleetRepoResult(
        repo_id=repo_id,
        root=f"/repos/{repo_id}",
        report_dir=f"/out/{repo_id}",
        scan=ScanResult(root=f"/repos/{repo_id}"),
        findings=findings,
    )


# ---------------------------------------------------------------------------
# repo id disambiguation
# ---------------------------------------------------------------------------


def test_fleet_repo_ids_slugifies_and_disambiguates() -> None:
    ids = fleet_repo_ids(
        [Path("/a/My Service"), Path("/b/my-service"), Path("/c/service")]
    )
    assert ids == ["my-service", "my-service-2", "service"]


def test_fleet_repo_ids_stable_and_unique() -> None:
    ids = fleet_repo_ids([Path("/x/api"), Path("/y/api"), Path("/z/api")])
    assert ids == ["api", "api-2", "api-3"]
    assert len(set(ids)) == 3


def test_fleet_repo_ids_unique_against_preexisting_suffix() -> None:
    # `api`, `api`, `api-2`: the disambiguated 2nd (`api-2`) must not collide
    # with the 3rd input's own name — else reports overwrite each other.
    ids = fleet_repo_ids([Path("/x/api"), Path("/y/api"), Path("/z/api-2")])
    assert len(set(ids)) == 3
    assert ids == ["api", "api-2", "api-2-2"]


# ---------------------------------------------------------------------------
# summary rendering
# ---------------------------------------------------------------------------


def test_render_fleet_summary_counts_by_severity() -> None:
    fleet = FleetScan(
        results=[
            _result("svc-a", [_finding("SQLi", "high"), _finding("weak-tls", "medium")]),
            _result("svc-b", [_finding("info", "low")]),
        ]
    )
    md = render_fleet_summary(fleet)
    assert "2 repositories analyzed · 3 finding(s) total." in md
    assert "| `svc-a` | 1 | 1 | 0 | 2 |" in md
    assert "| `svc-b` | 0 | 0 | 1 | 1 |" in md
    assert "[svc-a/](svc-a/)" in md
    assert "SQLi" in md  # top findings listed


def test_fleet_summary_json_shape() -> None:
    fleet = FleetScan(results=[_result("svc-a", [_finding("SQLi", "high")])])
    data = fleet_summary_json(fleet)
    assert data["repo_count"] == 1
    assert data["total_findings"] == 1
    repo = data["repos"][0]
    assert repo["repo_id"] == "svc-a"
    assert repo["severity_counts"] == {"high": 1, "medium": 0, "low": 0}
    assert data["cross_repo_links"] == []


# ---------------------------------------------------------------------------
# cross-repo links (#146b) rendering
# ---------------------------------------------------------------------------


def _link() -> ContractLink:
    return ContractLink(
        client_repo="client",
        server_repo="server",
        method="GET",
        path_template="api/orders/*",
        client_target="http://order-svc/api/orders/",
        client_file="c.py",
        client_line=3,
        server_route_path="/api/orders/<id>",
        server_file="s.py",
        server_line=5,
    )


def test_summary_lists_cross_repo_links() -> None:
    fleet = FleetScan(
        results=[_result("client", []), _result("server", [])], links=[_link()]
    )
    md = render_fleet_summary(fleet)
    assert "Cross-repo links" in md
    assert "1 observed client→server contract link(s)" in md
    assert "`client`" in md and "`server`" in md
    assert "/api/orders/<id>" in md and "c.py:3" in md


def test_fleet_graph_mermaid_has_edge_citing_both_sides() -> None:
    fleet = FleetScan(
        results=[_result("client", []), _result("server", [])], links=[_link()]
    )
    graph = render_fleet_graph_mermaid(fleet)
    assert "flowchart LR" in graph
    assert '"client"' in graph and '"server"' in graph
    assert "GET /api/orders/*" in graph
    assert "-->" in graph  # a directed cross-repo edge exists


def test_fleet_summary_json_includes_links() -> None:
    fleet = FleetScan(results=[_result("client", []), _result("server", [])], links=[_link()])
    data = fleet_summary_json(fleet)
    assert len(data["cross_repo_links"]) == 1
    link = data["cross_repo_links"][0]
    assert link["client_repo"] == "client" and link["server_repo"] == "server"
    assert link["client_location"] == "c.py:3"
    assert link["server_location"] == "s.py:5"


def _proxied_link() -> ContractLink:
    # A proxy-fronted seam (C28): observed through the declared proxy, with
    # the proxy identity and the resolving declaration carried on the link.
    return ContractLink(
        client_repo="client",
        server_repo="server",
        method="GET",
        path_template="api/orders/*",
        client_target="http://edge.internal/api/orders/",
        client_file="c.py",
        client_line=3,
        server_route_path="/api/orders/<id>",
        server_file="s.py",
        server_line=5,
        scheme="http",
        resolution="observed_via_proxy",
        alias_provenance="proxies:edge.internal",
        proxy_host="edge.internal",
    )


def test_summary_renders_provenance_and_via_proxy_links() -> None:
    aliased = ContractLink(
        client_repo="client",
        server_repo="server",
        method="GET",
        path_template="api/orders/*",
        client_target="https://orders.bsky.social/api/orders/",
        client_file="c.py",
        client_line=3,
        server_route_path="/api/orders/<id>",
        server_file="s.py",
        server_line=5,
        alias_provenance="hosts:orders.bsky.social",
    )
    fleet = FleetScan(
        results=[_result("client", []), _result("server", [])],
        links=[_link(), aliased, _proxied_link()],
    )
    md = render_fleet_summary(fleet)
    # Provenance is rendered next to each observed link; identity-resolved
    # links say so plainly.
    assert "hosts:orders.bsky.social" in md
    assert "repo identity" in md
    # Via-proxy links get their own section, distinct from direct edges.
    assert "1 observed link(s) via a declared proxy" in md
    assert "`edge.internal`" in md
    assert "proxies:edge.internal" in md


def test_mermaid_routes_via_proxy_links_through_proxy_node() -> None:
    fleet = FleetScan(
        results=[_result("client", []), _result("server", [])],
        links=[_link(), _proxied_link()],
    )
    graph = render_fleet_graph_mermaid(fleet)
    # The proxy appears as its own node; the proxied seam routes through it
    # (client → proxy → server) instead of a direct client→server edge.
    assert '"proxy: edge.internal"' in graph
    assert graph.index("R0") < graph.index('["proxy: edge.internal"]')  # stable node block
    assert "-->|\"GET /api/orders/*\"| P0" in graph
    assert "P0 -->|\"GET /api/orders/*\"| R1" in graph
    # The direct observed link keeps its own unproxied edge.
    assert "R0 -->|\"GET /api/orders/*\"| R1" in graph


def test_fleet_summary_json_carries_provenance_scheme_and_proxy() -> None:
    fleet = FleetScan(
        results=[_result("client", []), _result("server", [])], links=[_proxied_link()]
    )
    data = fleet_summary_json(fleet)
    link = data["cross_repo_links"][0]
    assert link["resolution"] == "observed_via_proxy"
    assert link["proxy_host"] == "edge.internal"
    assert link["alias_provenance"] == "proxies:edge.internal"
    assert link["scheme"] == "http"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

_APP = """\
from flask import Flask, request
app = Flask(__name__)


@app.route("/x")
def x():
    return request.args["q"]
"""


def _repo(root: Path, name: str, body: str = _APP) -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "app.py").write_text(body, encoding="utf-8")
    return d


def test_single_repo_writes_reports_flat_no_fleet_summary(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "solo")
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(repo), "-o", str(out)])
    assert result.exit_code == 0, result.output
    # Single-repo path is unchanged: reports land flat, no fleet artifacts.
    assert (out / "attackmap-report.json").exists()
    assert not (out / "fleet-summary.md").exists()


def test_multi_repo_writes_per_repo_dirs_and_fleet_summary(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(a), str(b), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-summary.md").exists()
    assert (out / "fleet-summary.json").exists()
    assert (out / "svca" / "attackmap-report.json").exists()
    assert (out / "svcb" / "attackmap-report.json").exists()
    assert "2 repositories" in result.output


def test_multi_repo_rejects_single_repo_only_flags(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    result = runner.invoke(app, ["analyze", str(a), str(b), "--hunt"])
    assert result.exit_code != 0
    assert "multi-repo mode" in _norm(result.output)


def test_multi_repo_missing_path_errors(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    result = runner.invoke(app, ["analyze", str(a), str(tmp_path / "nope")])
    assert result.exit_code != 0
    assert "does not exist" in _norm(result.output)


def test_multi_repo_links_client_to_server_end_to_end(tmp_path: Path) -> None:
    client = tmp_path / "client"
    client.mkdir()
    (client / "app.py").write_text(
        'import requests\n\n\ndef get(oid):\n'
        '    return requests.get("http://order-svc/api/orders/" + oid)\n',
        encoding="utf-8",
    )
    server = tmp_path / "server"
    server.mkdir()
    (server / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n\n"
        '@app.route("/api/orders/<id>")\ndef order(id):\n'
        '    return db.execute("SELECT * FROM orders WHERE id=" + id)\n',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(client), str(server), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "fleet-graph.md").exists()
    data = json.loads((out / "fleet-summary.json").read_text())
    links = data["cross_repo_links"]
    assert len(links) == 1
    assert links[0]["client_repo"] == "client"
    assert links[0]["server_repo"] == "server"
    assert links[0]["server_route_path"] == "/api/orders/<id>"
    assert "1 cross-repo link(s)" in result.output


def test_multi_repo_cross_boundary_flow_end_to_end(tmp_path: Path) -> None:
    # client forwards an external id to server, which trusts it into raw SQL (#146c AC1).
    client = tmp_path / "client"
    client.mkdir()
    (client / "app.py").write_text(
        'import requests\n\n\ndef get(oid):\n'
        '    return requests.get("http://order-svc/api/orders/" + oid)\n',
        encoding="utf-8",
    )
    server = tmp_path / "order-svc"  # the call's host must identify this repo (C28)
    server.mkdir()
    (server / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n\n"
        '@app.route("/api/orders/<id>")\ndef order(id):\n'
        '    return db.execute("SELECT * FROM orders WHERE id=" + id)\n',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(client), str(server), "-o", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "fleet-summary.json").read_text())
    flows = data["cross_boundary_flows"]
    assert len(flows) == 1
    f = flows[0]
    assert f["basis"] == "taint" and f["detail"] == "sql_execute"
    assert f["client_repo"] == "client" and f["server_repo"] == "order-svc"
    assert f["speculative"] is True
    # cites both sides
    assert f["client_location"].startswith("app.py")
    assert "SPECULATIVE" in (out / "fleet-summary.md").read_text()


def test_multi_repo_validates_progress_format(tmp_path: Path) -> None:
    # --progress-format is validated before the fleet branch, same as single-repo.
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    result = runner.invoke(
        app, ["analyze", str(a), str(b), "--progress-format", "bogus", "-o", str(tmp_path / "out")]
    )
    assert result.exit_code != 0
    assert "progress-format must be one of" in _norm(result.output)


def test_multi_repo_trust_gap_end_to_end(tmp_path: Path) -> None:
    # client POSTs to a server write route that has no auth control (#146d AC2).
    client = tmp_path / "client"
    client.mkdir()
    (client / "app.py").write_text(
        'import requests\n\n\ndef submit(oid):\n'
        '    return requests.post("http://order-svc/api/orders/" + oid)\n',
        encoding="utf-8",
    )
    server = tmp_path / "order-svc"  # the call's host must identify this repo (C28)
    server.mkdir()
    (server / "api.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n\n"
        '@app.route("/api/orders/<id>", methods=["POST"])\ndef upd(id):\n'
        "    return save(id)\n",  # no auth marker anywhere
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = runner.invoke(app, ["analyze", str(client), str(server), "-o", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "fleet-summary.json").read_text())
    gaps = data["trust_gaps"]
    assert len(gaps) == 1
    assert gaps[0]["client_repo"] == "client" and gaps[0]["server_repo"] == "order-svc"
    assert gaps[0]["method"] == "POST"
    assert gaps[0]["speculative"] is True
    assert "Trust-assumption gaps" in (out / "fleet-summary.md").read_text()


# ---------------------------------------------------------------------------
# service-resolution declarations end to end (C28)
# ---------------------------------------------------------------------------

_SEAM_FLEET = Path(__file__).parent / "fixtures" / "service-seam-fleet"


def test_service_resolution_flags_thread_to_fleet_links(tmp_path: Path) -> None:
    # The checked-in seam fixture (web-app -> auth-api) proves each new flag
    # end to end: --via-proxy, --service-port, --service-protocol, and the
    # existing --service-alias all reach link_contracts and show up in the
    # fleet summary with resolutions, reasons, and provenance.
    web_app = _SEAM_FLEET / "web-app"
    auth_api = _SEAM_FLEET / "auth-api"
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "analyze", str(web_app), str(auth_api), "-o", str(out),
            "--via-proxy", "edge.internal=auth-api",
            "--service-port", "auth-api=8443",
            "--service-protocol", "auth-api=https",
            "--service-alias", "auth.bsky.social=auth-api",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads((out / "fleet-summary.json").read_text())
    by_target = {lk["client_target"]: lk for lk in data["cross_repo_links"]}
    assert len(by_target) == 4
    proxied = by_target["https://edge.internal/users/"]
    assert proxied["resolution"] == "observed_via_proxy"
    assert proxied["proxy_host"] == "edge.internal"
    assert proxied["alias_provenance"] == "proxies:edge.internal"
    assert by_target["https://auth-api:8443/users/"]["resolution"] == "observed"
    assert (
        by_target["https://auth-api:8443/users/"]["alias_provenance"]
        == "service_ports:auth-api:8443"
    )
    insecure = by_target["http://auth-api:8443/users/"]
    assert insecure["resolution"] == "candidate"
    assert insecure["resolution_reason"] == "scheme_mismatch"
    assert insecure["scheme"] == "http"
    public = by_target["https://auth.bsky.social/users/"]
    assert public["resolution"] == "observed"
    assert public["alias_provenance"] == "hosts:auth.bsky.social"
    # Markdown and mermaid render the proxied seam and provenance distinctly.
    md = (out / "fleet-summary.md").read_text()
    assert "via a declared proxy" in md and "edge.internal" in md
    assert "hosts:auth.bsky.social" in md
    graph = (out / "fleet-graph.md").read_text()
    assert "proxy: edge.internal" in graph


def test_service_declaration_flags_reject_malformed_values(tmp_path: Path) -> None:
    a = _repo(tmp_path, "svcA")
    b = _repo(tmp_path, "svcB")
    result = runner.invoke(
        app, ["analyze", str(a), str(b), "-o", str(tmp_path / "out"), "--service-port", "svcA=https"]
    )
    assert result.exit_code != 0
    assert "service port" in _norm(result.output)
    result = runner.invoke(
        app, ["analyze", str(a), str(b), "-o", str(tmp_path / "out"), "--via-proxy", "svcA:8080=svcB"]
    )
    assert result.exit_code != 0
    assert "bare hostname" in _norm(result.output)


def test_service_declaration_flags_rejected_for_single_repo(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "solo")
    result = runner.invoke(
        app, ["analyze", str(repo), "-o", str(tmp_path / "out"), "--via-proxy", "edge=solo"]
    )
    assert result.exit_code != 0
    assert "multi-repo fleet scans only" in _norm(result.output)


# ---------------------------------------------------------------------------
# config-file seam extraction end to end (C28)
# ---------------------------------------------------------------------------

_DEPLOY_FLEET = Path(__file__).parent / "fixtures" / "deployment-seam-fleet"


def test_config_files_resolve_fleet_seams_without_cli_flags(tmp_path: Path) -> None:
    # The counterpart of the CLI-flag test above, with NO flags: k8s Service
    # + compose + nginx configs in the scanned repos declare the seams, and
    # link_contracts resolves them with file provenance. Negative controls
    # (undeclared port, multi-backend upstream) stay candidates with reasons.
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(_DEPLOY_FLEET / "web-app"),
            str(_DEPLOY_FLEET / "auth-api"),
            str(_DEPLOY_FLEET / "feed-generator"),
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads((out / "fleet-summary.json").read_text())
    by_target = {lk["client_target"]: lk for lk in data["cross_repo_links"]}
    assert len(by_target) == 5
    # Listen port declared by a k8s Service manifest.
    k8s = by_target["http://auth-api:8443/users/"]
    assert k8s["resolution"] == "observed"
    assert k8s["alias_provenance"] == "service_ports:auth-api:8443 (auth-api/k8s/service.yaml)"
    # Listen port declared by docker-compose.
    compose = by_target["http://feed-generator:9000/feeds/"]
    assert compose["resolution"] == "observed"
    assert compose["alias_provenance"] == (
        "service_ports:feed-generator:9000 (feed-generator/docker-compose.yml)"
    )
    # Proxy declared by an nginx single-backend upstream.
    proxied = by_target["http://edge.internal/users/"]
    assert proxied["resolution"] == "observed_via_proxy"
    assert proxied["proxy_host"] == "edge.internal"
    assert proxied["alias_provenance"] == "proxies:edge.internal (auth-api/deploy/nginx/edge.conf)"
    # Negative controls stay candidates with reasons, never guesses.
    wrong_port = by_target["http://auth-api:9999/users/"]
    assert wrong_port["resolution"] == "candidate"
    assert wrong_port["resolution_reason"] == "explicit_port"
    ambiguous = by_target["http://edge-multiple.internal/users/"]
    assert ambiguous["resolution"] == "candidate"
    assert ambiguous["resolution_reason"] == "unresolved_host"
    # Skipped extractions surface as explicit notes, and the config-extracted
    # provenance renders in the summary.
    assert "Config extraction:" in result.output
    assert "multi_backend" in result.output
    assert "malformed" in result.output
    md = (out / "fleet-summary.md").read_text()
    assert "auth-api/k8s/service.yaml" in md
    assert "via a declared proxy" in md


def test_cli_service_port_overrides_config_declaration(tmp_path: Path) -> None:
    # CLI declarations beat same-key config entries: --service-port
    # auth-api=9999 overrides the k8s Service's 8443, so 9999 resolves with a
    # bare (CLI) provenance and 8443 falls back to an unvouched explicit port.
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(_DEPLOY_FLEET / "web-app"),
            str(_DEPLOY_FLEET / "auth-api"),
            str(_DEPLOY_FLEET / "feed-generator"),
            "-o",
            str(out),
            "--service-port", "auth-api=9999",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads((out / "fleet-summary.json").read_text())
    by_target = {lk["client_target"]: lk for lk in data["cross_repo_links"]}
    assert by_target["http://auth-api:9999/users/"]["resolution"] == "observed"
    assert by_target["http://auth-api:9999/users/"]["alias_provenance"] == (
        "service_ports:auth-api:9999"
    )
    assert by_target["http://auth-api:8443/users/"]["resolution"] == "candidate"
    assert by_target["http://auth-api:8443/users/"]["resolution_reason"] == "explicit_port"
    # Untouched config declarations still apply.
    assert by_target["http://feed-generator:9000/feeds/"]["resolution"] == "observed"


def test_effective_deployment_aliases_merges_and_falls_back(tmp_path: Path) -> None:
    from attackmap.scan_service import ScanRequest, _effective_deployment_aliases

    fleet = Path(__file__).parent / "fixtures" / "deployment-seam-fleet"
    repos = [fleet / "web-app", fleet / "auth-api", fleet / "feed-generator"]
    # No CLI declarations: the config-extracted set is the effective one.
    base, notes = _effective_deployment_aliases(ScanRequest(repo_paths=repos, output=tmp_path))
    assert base is not None
    assert base.service_ports["auth-api"] == 8443
    assert base.proxies == {"edge.internal": "auth-api"}
    assert notes
    # CLI overrides a config key without inheriting its file provenance.
    cli_overridden, _ = _effective_deployment_aliases(
        ScanRequest(
            repo_paths=repos,
            output=tmp_path,
            deployment_aliases=DeploymentAliases(service_ports={"auth-api": 9999}),
        )
    )
    assert cli_overridden.service_ports["auth-api"] == 9999
    assert "service_ports:auth-api:9999" not in cli_overridden.source_files
    assert cli_overridden.proxies == {"edge.internal": "auth-api"}  # config entries kept
    # Conflicting topologies (CLI alias vs config proxy on one host): the CLI
    # set alone is used, with an explicit note.
    cli_conflict, conflict_notes = _effective_deployment_aliases(
        ScanRequest(
            repo_paths=repos,
            output=tmp_path,
            deployment_aliases=DeploymentAliases(hosts={"edge.internal": "auth-api"}),
        )
    )
    assert cli_conflict.hosts == {"edge.internal": "auth-api"}
    assert cli_conflict.proxies == {}
    assert any("conflicted" in n for n in conflict_notes)
