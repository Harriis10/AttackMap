"""Windows GUI: CLI contract, loopback, runner, watch, views."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from attackmap.ui.config import ScanConfig, analyze_argv, filter_unknown_flags
from attackmap.ui.output import fleet_dir, previous_report_path, reports_dir
from attackmap.ui.report import decode_report, fixture_report_path, web_root
from attackmap.ui.runner import ScanRunner, child_python_env
from attackmap.ui.server import LoopbackApp, make_server
from attackmap.ui.suppress_write import append_suppression
from attackmap.ui.watch import Watcher

FIX = Path(__file__).parent / "fixtures" / "ui" / "juice-shop-report.json"


def _post(url: str, body: dict, token: str) -> dict:
    req = Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-AttackMap-Token": token},
        method="POST",
    )
    with urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get(url: str, token: str | None = None) -> dict:
    headers = {"X-AttackMap-Token": token} if token else {}
    req = Request(url, headers=headers)
    with urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_exploitability_window_matches_fixture_rows() -> None:
    css = (web_root() / "src" / "exploitability.css").read_text(encoding="utf-8")
    html = (web_root() / "index.html").read_text(encoding="utf-8")
    app = (web_root() / "src" / "app.js").read_text(encoding="utf-8")
    assert "Run scan" in html
    assert "Exploitability" in html
    assert "AI Review" in html
    assert "Overview" in html
    assert "Settings" in html
    assert "prompt(\"Repository path\"" not in app
    assert "Pick folder" in html
    assert ".score" in css and "critical" in css
    assert "Segoe UI" in css or "Segoe UI" in (web_root() / "src" / "app.css").read_text(
        encoding="utf-8"
    )
    report = decode_report(json.loads(FIX.read_text(encoding="utf-8")))
    assert report.finding_count == 2
    rows = report.exploitability
    assert rows[0].score == 100
    assert rows[0].subject.startswith("POST /api/Feedbacks")
    assert rows[0].tier == "critical"
    assert rows[1].location == "routes/chat.ts:149"
    assert "renderExploitability" in app
    assert report.severity_counts["high"] == 2
    assert report.top_path is not None


def test_fixture_report_ships_with_the_ui() -> None:
    path = fixture_report_path()
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["exploitability"][0]["score"] == 100


def test_child_python_env_puts_src_on_path() -> None:
    env = child_python_env()
    src = str(Path(__file__).resolve().parents[1] / "src")
    assert src in env["PYTHONPATH"].split(os.pathsep)


def test_analyze_argv_uses_module_not_path_exe(tmp_path: Path) -> None:
    argv = analyze_argv(tmp_path, tmp_path / "out", cve=True, llm="none")
    assert argv[1:3] == ["-m", "attackmap"]
    assert "analyze" in argv
    assert "--progress-format" in argv and "json" in argv
    assert "--format" in argv and "all" in argv


def test_scan_config_matches_macos_flags(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "reports"
    cfg = ScanConfig(repos=[repo], output=out, llm_mode="review", provider="claude")
    args = cfg.cli_args()
    assert args[:2] == ["analyze", str(repo.resolve())]
    assert "--format" in args and "all" in args
    assert "--llm" in args
    assert "--llm-provider" not in args
    hunt = ScanConfig(
        repos=[repo],
        output=out,
        llm_mode="huntVerify",
        provider="openai",
        jury={"verifyVotes": 5, "lenses": 1, "rounds": 1, "budget": 0},
    )
    hargs = hunt.cli_args()
    assert "--hunt" in hargs and "--verify" in hargs
    assert hargs[hargs.index("--llm-provider") + 1] == "openai"
    assert "--verify-votes" in hargs and "5" in hargs
    assert "--hunt-lenses" not in hargs
    fleet = ScanConfig(repos=[repo, tmp_path / "b"], output=out, llm_mode="review", run_cve=True)
    (tmp_path / "b").mkdir()
    fargs = fleet.cli_args()
    assert "--llm" not in fargs
    assert "--cve" in fargs
    assert str((tmp_path / "b").resolve()) in fargs


def test_unknown_capability_flags_are_dropped() -> None:
    args = ["analyze", "r", "--recall", "--cve", "--hunt"]
    kept = filter_unknown_flags(args, {"--cve"})
    assert "--cve" in kept
    assert "--recall" not in kept
    assert "--hunt" not in kept


def test_module_prefix_never_dropped_by_capability_filter() -> None:
    args = ["python", "-m", "attackmap", "analyze", "repo", "--cve"]
    kept = filter_unknown_flags(args, {"--cve"})
    assert kept[:4] == ["python", "-m", "attackmap", "analyze"]
    assert "--cve" in kept


def test_reports_dir_is_outside_repo_and_stable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    repo = tmp_path / "DVWA"
    repo.mkdir()
    first = reports_dir(repo)
    second = reports_dir(repo)
    assert first == second
    assert "AttackMap" in str(first)
    assert "scans" in str(first)
    assert not first.is_relative_to(repo)
    assert previous_report_path(repo).parent == first.parent
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    fleet = fleet_dir([a, b])
    assert "fleet" in str(fleet)
    assert not fleet.is_relative_to(a)


def test_loopback_binds_localhost_and_requires_token() -> None:
    app = LoopbackApp()
    httpd = make_server(app)
    host, port = httpd.server_address[:2]
    assert host in {"127.0.0.1", "localhost"}
    assert app.token
    try:
        with pytest.raises(HTTPError) as err:
            urlopen(f"http://127.0.0.1:{port}/api/state", timeout=2)
        assert err.value.code == 403
        body = _get(f"http://127.0.0.1:{port}/api/state?token={app.token}", app.token)
        assert "report" not in body or body.get("report") is None
        assert body["status"] == "idle"
        assert body.get("findingCount") in (0, None)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_state_poll_omits_full_report() -> None:
    app = LoopbackApp(decode_report(json.loads(FIX.read_text(encoding="utf-8"))))
    httpd = make_server(app)
    _, port = httpd.server_address[:2]
    try:
        body = _get(f"http://127.0.0.1:{port}/api/state?token={app.token}", app.token)
        assert "findings" not in (body.get("report") or {})
        assert body.get("hasReport") is True
        report = _get(f"http://127.0.0.1:{port}/api/report?token={app.token}", app.token)
        assert report["findingCount"] == 2
        assert report["exploitability"][0]["score"] == 100
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_runner_stderr_tail_reaches_state(tmp_path: Path) -> None:
    fail = tmp_path / "fail.py"
    fail.write_text("import sys\nprint('Error: missing php-web', file=sys.stderr)\nsys.exit(1)\n", encoding="utf-8")
    events: list[dict] = []
    done: list[tuple[int, Path | None, str]] = []
    runner = ScanRunner()
    runner.start(
        tmp_path,
        tmp_path / "out",
        on_progress=events.append,
        on_done=lambda code, report, tail="": done.append((code, report, tail)),
        argv=[sys.executable, str(fail)],
    )
    for _ in range(50):
        if done:
            break
        time.sleep(0.05)
    assert done
    code, report, tail = done[0]
    assert code == 1
    assert report is None
    assert "missing php-web" in tail


def test_runner_writes_report_outside_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    repo = tmp_path / "mini"
    repo.mkdir()
    (repo / "app.py").write_text("print(1)\n", encoding="utf-8")
    script = tmp_path / "ok.py"
    script.write_text(
        "import json, pathlib, sys\n"
        "out = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out / 'attackmap-report.json').write_text(json.dumps({'findings': [], 'exploitability': []}))\n",
        encoding="utf-8",
    )
    app = LoopbackApp()
    httpd = make_server(app)
    _, port = httpd.server_address[:2]
    try:
        original = ScanRunner.start

        def fake_start(self, repo_path, output, **kwargs):  # type: ignore[no-untyped-def]
            kwargs["argv"] = [
                sys.executable,
                str(script),
                "analyze",
                str(repo_path),
                "--output",
                str(output),
            ]
            return original(self, repo_path, output, **kwargs)

        monkeypatch.setattr(ScanRunner, "start", fake_start)
        req = Request(
            f"http://127.0.0.1:{port}/api/run?token={app.token}",
            data=json.dumps({"repo": str(repo)}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-AttackMap-Token": app.token},
            method="POST",
        )
        with urlopen(req, timeout=30) as resp:
            json.loads(resp.read().decode("utf-8"))
        for _ in range(80):
            body = _get(f"http://127.0.0.1:{port}/api/state?token={app.token}", app.token)
            if body["status"] in {"done", "failed"}:
                break
            time.sleep(0.05)
        assert body["status"] == "done"
        assert not (repo / "reports").exists()
        assert body["output"]
        assert "AttackMap" in body["output"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_runner_cancel_sets_flag(tmp_path: Path) -> None:
    runner = ScanRunner()
    assert runner.running is False
    runner._proc = type("P", (), {"poll": lambda self: None, "pid": 1, "terminate": lambda self: None})()
    runner.running = True
    runner.cancel()
    assert runner.running is False


def test_watch_does_not_overlap(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    hits: list[int] = []
    box: dict[str, Watcher] = {}

    def on_change() -> None:
        hits.append(1)
        box["w"].notify()

    watch = Watcher(tmp_path, tmp_path / "reports", on_change, debounce_s=0.01)
    box["w"] = watch
    watch.notify()
    assert hits == [1]
    watch.notify()
    assert hits == [1, 1]


def test_watch_ignores_report_dir(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    reports = tmp_path / "out"
    repo.mkdir()
    reports.mkdir()
    (repo / "a.py").write_text("x\n", encoding="utf-8")
    watch = Watcher(repo, reports, lambda: None)
    assert watch.should_ignore(reports / "attackmap-report.json")
    assert watch.should_ignore(repo / ".git" / "HEAD")
    assert not watch.should_ignore(repo / "a.py")


def test_lmstudio_scan_needs_no_api_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LM Studio (OpenAI-compatible local endpoint) must not require a stored key."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    repo = tmp_path / "mini"
    repo.mkdir()
    (repo / "app.py").write_text("print(1)\n", encoding="utf-8")
    app = LoopbackApp()
    # Ensure no key is present for either provider.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from attackmap.ui.secrets import child_llm_env

    env = child_llm_env("openai", "http://localhost:1234/v1")
    assert env["OPENAI_API_KEY"]
    assert env["OPENAI_BASE_URL"] == "http://localhost:1234/v1"
    # Server must not fail the run for a missing key when base_url is set.
    app.provider = "openai"
    app.base_url = "http://localhost:1234/v1"
    app.llm_mode = "review"
    from attackmap.ui.server import _start_scan

    # Stub the runner so no real subprocess starts; we only check the gate.
    class _Stub:
        running = False

        def start(self, *a, **k):  # noqa: ANN001
            pass

    app.runner = _Stub()  # type: ignore[assignment]
    _start_scan(app, {"repo": str(repo)})
    assert app.status != "failed" or "No API key" not in (app.error or "")


def test_append_suppression_keeps_existing(tmp_path: Path) -> None:
    path = tmp_path / ".attackmap-suppress.yaml"
    path.write_text("version: 1\nsuppress:\n  - id: old\n    reason: prior\n", encoding="utf-8")
    append_suppression(path, {"id": "new", "reason": "accepted"})
    text = path.read_text(encoding="utf-8")
    assert "old" in text and "new" in text


def test_real_mini_scan_renders_overview(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    repo = tmp_path / "mini-app"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import os\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.get('/user')\n"
        "def user():\n"
        "    return os.popen(request.args['q']).read()\n",
        encoding="utf-8",
    )
    app = LoopbackApp()
    httpd = make_server(app)
    _, port = httpd.server_address[:2]
    try:
        req = Request(
            f"http://127.0.0.1:{port}/api/run?token={app.token}",
            data=json.dumps({"repo": str(repo)}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-AttackMap-Token": app.token},
            method="POST",
        )
        with urlopen(req, timeout=30) as resp:
            json.loads(resp.read().decode("utf-8"))
        body = {}
        for _ in range(400):
            body = _get(f"http://127.0.0.1:{port}/api/state?token={app.token}", app.token)
            if body["status"] in {"done", "failed"}:
                break
            time.sleep(0.25)
        assert body["status"] == "done", body.get("error") or body.get("stderrTail")
        assert "findings" not in (body.get("report") or {})
        report = _get(f"http://127.0.0.1:{port}/api/report?token={app.token}", app.token)
        assert report["findingCount"] >= 0
        assert "severityCounts" in report
        assert not (repo / "reports").exists()
        html = (web_root() / "src" / "app.js").read_text(encoding="utf-8")
        assert "renderOverview" in html and "renderFindings" in html
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_launch_opens_dark_splash_then_loads_url() -> None:
    src = (Path(__file__).resolve().parents[1] / "src" / "attackmap" / "ui" / "launch.py").read_text(
        encoding="utf-8"
    )
    assert "html=_SPLASH_HTML" in src
    assert "window.load_url" in src
    assert "#141414" in src


def test_html_has_macos_parity_chrome() -> None:
    html = (web_root() / "index.html").read_text(encoding="utf-8")
    js = (web_root() / "src" / "app.js").read_text(encoding="utf-8")
    for label in (
        "Overview",
        "Findings",
        "Exploitability",
        "Attack paths",
        "Attack surface",
        "Diagrams",
        "Review",
        "AI Review",
        "Diff",
        "Fleet",
        "Dependencies",
        "Secrets",
        "CI workflows",
        "Data flows",
        "Analyzers",
        "Recall",
        "Watch",
        "CVE",
    ):
        assert label in html or label in js
    assert "mermaid" in js.lower() or (web_root() / "src" / "mermaid-lite.js").is_file()
    assert "Pick a repository" in js or "Pick a repository" in html
    single = web_root().resolve()
    assert single.as_posix().endswith("attackmap/ui/web") or "ui" in single.as_posix()


def test_markdown_renderer_covers_review_syntax() -> None:
    md = (web_root() / "src" / "markdown.js").read_text(encoding="utf-8")
    for feature in ('<h${level}>', "<strong>", "<li>", "md-table", "<blockquote>", "<pre", "MERMAID"):
        assert feature in md
    css = (web_root() / "src" / "app.css").read_text(encoding="utf-8")
    for selector in (".md-table", ".empty-state", ".m-row", "pre.code"):
        assert selector in css


def test_exploitability_empty_state_explains_taint() -> None:
    js = (web_root() / "src" / "app.js").read_text(encoding="utf-8")
    assert "No route→sink exploitability paths" in js
    assert "taint chains" in js
    assert "renderDependencies" in js


def test_decode_report_keeps_inventory_sections() -> None:
    report = decode_report(json.loads(FIX.read_text(encoding="utf-8")))
    payload = report.as_json()
    assert payload["severityCounts"]["high"] == 2
    assert isinstance(payload["dependencies"], list)
    assert isinstance(payload["secrets"], list)
    assert isinstance(payload["suppressed"], list) and payload["suppressed"]
    assert payload["diagrams"]["paths"].startswith("# Attack paths")
