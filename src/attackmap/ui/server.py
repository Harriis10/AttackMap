"""Loopback HTTP server for the Windows GUI (127.0.0.1 only)."""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .report import GuiReport, decode_report, fixture_report_path, load_report_file, web_root
from .runner import ScanRunner
from .secrets import child_llm_env
from .watch import Watcher

WEBVIEW2_INSTALL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"


class LoopbackApp:
    def __init__(self, report: GuiReport | None = None) -> None:
        self.token = secrets.token_urlsafe(24)
        self.report = report
        self.repo: Path | None = None
        self.output: Path | None = None
        self.status = "idle"
        self.progress: dict = {}
        self.exit_code: int | None = None
        self.error: str | None = None
        self.cve = False
        self.llm = "none"
        self.modules = "auto"
        self.watch = False
        self.runner = ScanRunner()
        self.watcher: Watcher | None = None
        self._lock = threading.Lock()

    def state(self) -> dict:
        with self._lock:
            report = self.report.as_json() if self.report else None
            return {
                "status": self.status,
                "progress": self.progress,
                "exitCode": self.exit_code,
                "error": self.error,
                "repo": str(self.repo) if self.repo else None,
                "cve": self.cve,
                "llm": self.llm,
                "modules": self.modules,
                "watch": self.watch,
                "running": self.runner.running,
                "view": "exploitability",
                "report": report,
                "llmOffBoxWarning": (
                    "Heuristic only stays on this machine. Enabling an LLM provider "
                    "sends an evidence pack off-box."
                    if self.llm not in {"none", "None (heuristic only)"}
                    else None
                ),
            }


def _handler(app: LoopbackApp):
    root = web_root()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _ok_token(self) -> bool:
            q = parse_qs(urlparse(self.path).query)
            header = self.headers.get("X-AttackMap-Token", "")
            token = (q.get("token") or [header])[0]
            return secrets.compare_digest(token, app.token)

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: object) -> None:
            self._send(code, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/index.html"}:
                html = (root / "index.html").read_bytes()
                self._send(200, html, "text/html; charset=utf-8")
                return
            if parsed.path.startswith("/src/"):
                rel = parsed.path.lstrip("/")
                path = (root / rel).resolve()
                if not str(path).startswith(str(root.resolve())) or not path.is_file():
                    self._send(404, b"not found", "text/plain")
                    return
                ctype = "text/css" if path.suffix == ".css" else "text/javascript"
                self._send(200, path.read_bytes(), ctype)
                return
            if not self._ok_token():
                self._json(403, {"error": "forbidden"})
                return
            if parsed.path == "/api/state":
                self._json(200, app.state())
                return
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._ok_token():
                self._json(403, {"error": "forbidden"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                body = {}
            parsed = urlparse(self.path)
            if parsed.path == "/api/config":
                app.repo = Path(body["repo"]).resolve() if body.get("repo") else app.repo
                app.cve = bool(body.get("cve", app.cve))
                app.llm = str(body.get("llm", app.llm))
                app.modules = str(body.get("modules", app.modules))
                self._json(200, app.state())
                return
            if parsed.path == "/api/run":
                _start_scan(app, body)
                self._json(200, app.state())
                return
            if parsed.path == "/api/cancel":
                app.runner.cancel()
                app.status = "cancelled"
                self._json(200, app.state())
                return
            if parsed.path == "/api/watch":
                app.watch = bool(body.get("enabled"))
                _sync_watch(app)
                self._json(200, app.state())
                return
            self._json(404, {"error": "not found"})

    return Handler


def _start_scan(app: LoopbackApp, body: dict) -> None:
    if body.get("repo"):
        app.repo = Path(body["repo"]).resolve()
    app.cve = bool(body.get("cve", app.cve))
    app.llm = str(body.get("llm", app.llm))
    app.modules = str(body.get("modules", app.modules))
    if app.repo is None or not app.repo.exists():
        app.status = "failed"
        app.error = "Pick a repository folder first."
        return
    if app.runner.running:
        return
    app.output = app.repo / "reports"
    app.status = "running"
    app.error = None
    app.exit_code = None
    baseline = app.output / "attackmap-report.json" if app.watch else None

    def on_progress(event: dict) -> None:
        app.progress = event
        app.status = "running"

    def on_done(code: int, report: Path | None) -> None:
        app.exit_code = code
        if code == 0 and report is not None:
            app.report = load_report_file(report, app.repo.name if app.repo else "repo")
            app.status = "done"
            app.error = None
        else:
            app.status = "failed"
            app.error = f"Scan exited with code {code} and no report." if report is None else f"Scan exited {code}."

    app.runner.start(
        app.repo,
        app.output,
        on_progress=on_progress,
        on_done=on_done,
        env=child_llm_env(app.llm),
        cve=app.cve,
        llm=app.llm,
        modules=app.modules,
        baseline=baseline if baseline and baseline.is_file() else None,
    )


def _sync_watch(app: LoopbackApp) -> None:
    if app.watcher is not None:
        app.watcher.stop()
        app.watcher = None
    if not app.watch or app.repo is None:
        return
    out = app.output or (app.repo / "reports")

    def on_quiet() -> None:
        if app.runner.running:
            return
        _start_scan(app, {})

    app.watcher = Watcher(app.repo, out, on_quiet)
    app.watcher.start()


def make_server(app: LoopbackApp, start: bool = True) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(app))
    if start:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def load_fixture_app() -> LoopbackApp:
    path = fixture_report_path()
    report = decode_report(json.loads(path.read_text(encoding="utf-8")), "juice-shop")
    return LoopbackApp(report)
