"""Windows GUI: static exploitability chrome, loopback, runner, watch."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attackmap.ui.report import decode_report, fixture_report_path, web_root
from attackmap.ui.runner import ScanRunner, analyze_argv
from attackmap.ui.server import LoopbackApp, make_server
from attackmap.ui.watch import Watcher

FIX = Path(__file__).parent / "fixtures" / "ui" / "juice-shop-report.json"


def test_exploitability_window_matches_fixture_rows() -> None:
    css = (web_root() / "src" / "exploitability.css").read_text(encoding="utf-8")
    html = (web_root() / "index.html").read_text(encoding="utf-8")
    app = (web_root() / "src" / "app.js").read_text(encoding="utf-8")
    assert "Run scan" in html
    assert "Exploitability" in html
    assert "AI Review" in html
    assert ".score" in css and "critical" in css
    assert "Segoe UI" in css
    assert "Cascadia Mono" in css
    report = decode_report(json.loads(FIX.read_text(encoding="utf-8")))
    assert report.finding_count == 2
    rows = report.exploitability
    assert rows[0].score == 100
    assert rows[0].subject.startswith("POST /api/Feedbacks")
    assert rows[0].tier == "critical"
    assert rows[1].location == "routes/chat.ts:149"
    assert "renderExploitability" in app


def test_fixture_report_ships_with_the_ui() -> None:
    path = fixture_report_path()
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["exploitability"][0]["score"] == 100


def test_analyze_argv_uses_module_not_path_exe(tmp_path: Path) -> None:
    argv = analyze_argv(tmp_path, tmp_path / "out", cve=True, llm="none")
    assert argv[1:3] == ["-m", "attackmap"]
    assert "analyze" in argv
    assert "--progress-format" in argv and "json" in argv


def test_loopback_binds_localhost_and_requires_token() -> None:
    app = LoopbackApp(decode_report(json.loads(FIX.read_text(encoding="utf-8"))))
    httpd = make_server(app)
    host, port = httpd.server_address[:2]
    assert host in {"127.0.0.1", "localhost"}
    assert app.token
    try:
        from urllib.error import HTTPError
        from urllib.request import urlopen

        with pytest.raises(HTTPError) as err:
            urlopen(f"http://127.0.0.1:{port}/api/state", timeout=2)
        assert err.value.code == 403
        with urlopen(f"http://127.0.0.1:{port}/api/state?token={app.token}", timeout=2) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        assert body["view"] == "exploitability" or "exploitability" in body
        assert body["report"]["findingCount"] == 2
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_runner_cancel_sets_flag(tmp_path: Path) -> None:
    runner = ScanRunner()
    assert runner.running is False
    runner._proc = type("P", (), {"poll": lambda self: None, "pid": 1})()
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
