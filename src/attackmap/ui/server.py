"""Loopback HTTP server for the Windows GUI (127.0.0.1 only)."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import ScanConfig
from .output import fleet_dir, reports_dir, rotate_previous
from .report import GuiReport, decode_report, fixture_report_path, load_report_file, web_root
from .runner import ScanRunner, child_python_env
from .secrets import child_llm_env, has_llm_key, save_llm_key
from .suppress_write import append_suppression
from .watch import Watcher

WEBVIEW2_INSTALL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

_RECENTS_LIMIT = 12


class LoopbackApp:
    def __init__(self, report: GuiReport | None = None) -> None:
        self.token = secrets.token_urlsafe(24)
        self.report = report
        self.repos: list[Path] = []
        self.output: Path | None = None
        self.status = "idle"
        self.progress: dict = {}
        self.exit_code: int | None = None
        self.error: str | None = None
        self.stderr_tail = ""
        self.cve = False
        self.recall = False
        self.llm_mode = "none"
        self.provider = "claude"
        self.model: str | None = None
        self.effort: str | None = None
        self.fast = False
        self.base_url: str = ""
        self.modules: list[str] = []
        self.watch = False
        self.no_suppress = False
        self.use_baseline = True
        self.fail_on_new_high = False
        self.runner = ScanRunner()
        self.watcher: Watcher | None = None
        self.capabilities: set[str] | None = None
        self.available_modules: list[dict] = []
        self._caps_loaded = False
        self.missing: list[dict] = []
        self.recents: list[dict] = _load_recents()
        self._lock = threading.Lock()

    def _ensure_caps(self) -> set[str]:
        if self._caps_loaded:
            return self.capabilities or set()
        threading.Thread(target=self._load_caps_bg, daemon=True).start()
        return set()

    def _load_caps_bg(self) -> None:
        if self._caps_loaded:
            return
        caps = _load_capabilities()
        modules = _load_modules()
        self.capabilities = caps
        self.available_modules = modules
        self._caps_loaded = True

    @property
    def repo(self) -> Path | None:
        return self.repos[0] if self.repos else None

    @repo.setter
    def repo(self, value: Path | None) -> None:
        if value is None:
            self.repos = []
        else:
            self.repos = [value]

    def state(self) -> dict:
        with self._lock:
            return {
                "status": self.status,
                "progress": self.progress,
                "exitCode": self.exit_code,
                "error": self.error,
                "stderrTail": self.stderr_tail,
                "repo": str(self.repo) if self.repo else None,
                "repos": [str(p) for p in self.repos],
                "output": str(self.output) if self.output else None,
                "cve": self.cve,
                "recall": self.recall,
                "llm": self.llm_mode,
                "llmMode": self.llm_mode,
                "provider": self.provider,
                "model": self.model,
                "baseUrl": self.base_url,
                "modules": self.modules or ["auto"],
                "watch": self.watch,
                "running": self.runner.running,
                "hasReport": self.report is not None,
                "findingCount": self.report.finding_count if self.report else 0,
                "newCount": self.report.new_count if self.report else 0,
                "resolvedCount": self.report.resolved_count if self.report else 0,
                "capabilities": sorted(self.capabilities) if self.capabilities else [],
                "availableModules": self.available_modules,
                "missingAnalyzers": self.missing,
                "recents": self.recents,
                "hasAnthropicKey": has_llm_key("claude"),
                "hasOpenAIKey": has_llm_key("openai"),
                "llmOffBoxWarning": (
                    "Heuristic only stays on this machine. Enabling an LLM provider "
                    "sends an evidence pack off-box."
                    if self.llm_mode not in {"none", "None (heuristic only)"}
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
            token = header or (q.get("token") or [""])[0]
            try:
                return bool(token) and secrets.compare_digest(str(token), app.token)
            except (TypeError, ValueError):
                return False

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: object) -> None:
            self._send(code, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        def _body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length < 0 or length > 1_000_000:
                self._json(400, {"error": "invalid body"})
                return
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return {}
            return data if isinstance(data, dict) else {}

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/index.html"}:
                html = (root / "index.html").read_bytes()
                self._send(200, html, "text/html; charset=utf-8")
                return
            if parsed.path.startswith("/src/"):
                rel = parsed.path.lstrip("/")
                path = (root / rel).resolve()
                try:
                    ok = path.is_relative_to(root.resolve())
                except (OSError, ValueError):
                    ok = False
                if not ok or not path.is_file():
                    self._send(404, b"not found", "text/plain")
                    return
                ctype = {
                    ".css": "text/css",
                    ".js": "text/javascript",
                    ".json": "application/json",
                }.get(path.suffix, "application/octet-stream")
                self._send(200, path.read_bytes(), ctype)
                return
            if not self._ok_token():
                self._json(403, {"error": "forbidden"})
                return
            if parsed.path == "/api/state":
                self._json(200, app.state())
                return
            if parsed.path == "/api/report":
                if app.report is None:
                    self._json(404, {"error": "no report"})
                    return
                self._json(200, app.report.as_json())
                return
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._ok_token():
                self._json(403, {"error": "forbidden"})
                return
            body = self._body()
            parsed = urlparse(self.path)
            if parsed.path == "/api/config":
                _apply_config(app, body)
                self._json(200, app.state())
                return
            if parsed.path == "/api/pick":
                chosen = _pick_folders(multi=bool(body.get("multi")))
                if chosen:
                    app.repos = [Path(p).resolve() for p in chosen]
                    _refresh_missing(app)
                self._json(200, {**app.state(), "picked": [str(p) for p in app.repos]})
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
            if parsed.path == "/api/settings":
                if body.get("anthropicKey"):
                    save_llm_key(str(body["anthropicKey"]), "claude")
                if body.get("openaiKey"):
                    save_llm_key(str(body["openaiKey"]), "openai")
                self._json(200, app.state())
                return
            if parsed.path == "/api/reveal":
                if app.output and app.output.exists() and hasattr(os, "startfile"):
                    os.startfile(app.output)  # noqa: S606 — user-opened local folder
                self._json(200, app.state())
                return
            if parsed.path == "/api/suppress":
                if app.repo is None:
                    self._json(400, {"error": "no repo"})
                    return
                dest = app.repo / ".attackmap-suppress.yaml"
                append_suppression(dest, body)
                self._json(200, {"ok": True, "path": str(dest)})
                return
            self._json(404, {"error": "not found"})

    return Handler


def _apply_config(app: LoopbackApp, body: dict) -> None:
    if body.get("repo"):
        app.repos = [Path(body["repo"]).resolve()]
    if body.get("repos"):
        app.repos = [Path(p).resolve() for p in body["repos"]]
    app.cve = bool(body.get("cve", app.cve))
    app.recall = bool(body.get("recall", app.recall))
    app.llm_mode = str(body.get("llmMode") or body.get("llm") or app.llm_mode)
    app.provider = str(body.get("provider") or app.provider)
    if "model" in body:
        app.model = str(body["model"]).strip() or None
    if "baseUrl" in body:
        app.base_url = str(body["baseUrl"]).strip()
    if "modules" in body:
        raw = body["modules"]
        app.modules = [raw] if isinstance(raw, str) else list(raw)
    app.no_suppress = bool(body.get("noSuppress", app.no_suppress))
    app.use_baseline = bool(body.get("useBaseline", app.use_baseline))
    app.fail_on_new_high = bool(body.get("failOnNewHigh", app.fail_on_new_high))
    if app.repos:
        _refresh_missing(app)


def _start_scan(app: LoopbackApp, body: dict) -> None:
    _apply_config(app, body)
    if not app.repos or not app.repos[0].exists():
        app.status = "failed"
        app.error = "Pick a repository folder first."
        return
    if app.runner.running:
        return
    llm_active = app.llm_mode not in {"none", "None (heuristic only)", ""}
    is_local_openai = app.provider.lower().startswith("openai") and bool(app.base_url)
    if llm_active and not is_local_openai and not has_llm_key(app.provider):
        app.status = "failed"
        app.error = f"No API key stored for {app.provider}. Open Settings and save a key, or keep heuristic-only mode."
        return
    _refresh_missing(app)
    fleet = len(app.repos) > 1
    app.output = fleet_dir(app.repos) if fleet else reports_dir(app.repos[0])
    baseline = None
    if not fleet and app.use_baseline:
        baseline = rotate_previous(app.repos[0], app.output)
    app.status = "running"
    app.error = None
    app.exit_code = None
    app.stderr_tail = ""
    app.progress = {"event": "begin", "label": "Starting scan"}
    cfg = ScanConfig(
        repos=app.repos,
        output=app.output,
        run_cve=app.cve,
        modules=[m for m in app.modules if m and m.lower() != "auto"],
        llm_mode=app.llm_mode,
        provider=app.provider,
        model=app.model,
        recall=app.recall,
        no_suppress=app.no_suppress,
        baseline=baseline if app.use_baseline else None,
        fail_on_new_high=app.fail_on_new_high,
        capabilities=app.capabilities if app._caps_loaded else None,
    )
    argv = [sys.executable, "-m", "attackmap", *cfg.cli_args()]

    def on_progress(event: dict) -> None:
        app.progress = event
        app.status = "running"

    def on_done(code: int, report: Path | None, tail: str = "") -> None:
        app.exit_code = code
        app.stderr_tail = tail
        if report is not None and report.is_file() and (code == 0 or (report.is_file() and "failing per --fail-on-new-high" in tail)):
            name = app.repos[0].name if app.repos else "repo"
            app.report = load_report_file(report, name)
            app.status = "done"
            app.error = None
            _remember(app)
        else:
            app.status = "failed"
            detail = tail.strip() or f"Scan exited with code {code} and no report."
            app.error = detail
            if app.missing:
                names = ", ".join(item.get("plugin") or item.get("analyzer_name") or "?" for item in app.missing)
                app.error = f"{detail}\nMissing recommended analyzers: {names}"

    # Run in-process: the GUI is frozen (attackmap.exe), so sys.executable
    # cannot be used to re-spawn `python -m attackmap` (-m is invalid there).
    import threading

    from attackmap.pipeline import AnalyzeOptions, run_scan

    def _run() -> None:
        report = app.output / "attackmap-report.json" if app.output else None
        try:
            options = AnalyzeOptions(
                repo_path=app.repos[0].resolve(),
                output=(app.output or (app.repos[0] / "reports")).resolve(),
                output_format="all",
                analyzers=None,
                recall=app.recall,
                cve=app.cve,
                no_suppress=app.no_suppress,
                suppress_file=str(cfg.suppress_file) if cfg.suppress_file else None,
                baseline=str(cfg.baseline) if cfg.baseline else None,
                fail_on_new_high=app.fail_on_new_high,
                progress_format="json",
                llm=app.llm_mode == "review",
                llm_provider=app.provider,
                llm_model=app.model,
                llm_backend="api",
                hunt=app.llm_mode == "hunt",
                verify=app.llm_mode in {"huntVerify", "hunt+verify"},
                remediate=app.llm_mode == "remediate",
                triage=app.llm_mode == "triage",
            )
            import os

            env = child_llm_env(
                app.provider if app.llm_mode not in {"none", ""} else "none",
                app.base_url if app.provider.lower().startswith("openai") else None,
            )
            for key, value in env.items():
                os.environ[key] = value
            state = run_scan(options)
            code = state.exit_code
        except Exception as exc:  # noqa: BLE001 — surface as failed scan
            app.stderr_tail = f"{type(exc).__name__}: {exc}"
            code = 1
        on_done(code, report if report and report.is_file() else None, app.stderr_tail)

    app.runner.running = True
    app.runner._proc = None
    threading.Thread(target=lambda: (_run(), setattr(app.runner, "running", False)), daemon=True).start()


def _sync_watch(app: LoopbackApp) -> None:
    if app.watcher is not None:
        app.watcher.stop()
        app.watcher = None
    if not app.watch or not app.repos:
        return
    out = app.output or reports_dir(app.repos[0])

    def on_quiet() -> None:
        if app.runner.running:
            return
        _start_scan(app, {})

    app.watcher = Watcher(app.repos[0], out, on_quiet)
    app.watcher.start()


def _refresh_missing(app: LoopbackApp) -> None:
    if not app.repos:
        app.missing = []
        return
    try:
        from attackmap.suggest import detect_ecosystems

        app.missing = [
            {"plugin": s.plugin, "analyzer_name": s.analyzer_name, "pip_install": s.pip_install, "signals": list(s.matched_signals)}
            for s in detect_ecosystems(app.repos[0])
            if not s.installed
        ]
    except Exception:
        app.missing = []


def _remember(app: LoopbackApp) -> None:
    if not app.repos or not app.output:
        return
    entry = {"name": app.repos[0].name, "path": str(app.repos[0]), "output": str(app.output)}
    recents = [item for item in _load_recents() if item.get("path") != entry["path"]]
    recents.insert(0, entry)
    app.recents = recents[:_RECENTS_LIMIT]
    path = _recents_path()
    path.write_text(json.dumps(app.recents, indent=2), encoding="utf-8")


def _recents_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".attackmap")
    folder = Path(base) / "AttackMap"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "recents.json"


def _load_recents() -> list[dict]:
    path = _recents_path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _load_capabilities() -> set[str] | None:
    try:
        raw = subprocess.check_output(
            [sys.executable, "-m", "attackmap", "capabilities"],
            text=True,
            timeout=20,
            stderr=subprocess.DEVNULL,
            env=child_python_env(),
        )
        payload = json.loads(raw)
        options = set(payload.get("analyze", {}).get("options") or [])
        return options or None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _load_modules() -> list[dict]:
    try:
        raw = subprocess.check_output(
            [sys.executable, "-m", "attackmap", "modules", "--json"],
            text=True,
            timeout=20,
            stderr=subprocess.DEVNULL,
            env=child_python_env(),
        )
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def _pick_folders(multi: bool = False) -> list[str]:
    if threading.current_thread() is not threading.main_thread():
        return []
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.wm_attributes("-topmost", 1)
        chosen: list[str] = []
        first = filedialog.askdirectory(title="Select a repository")
        if first:
            chosen.append(first)
        while multi:
            nxt = filedialog.askdirectory(title="Add another repository (cancel to finish)")
            if not nxt:
                break
            chosen.append(nxt)
        root.destroy()
        return chosen
    except Exception:
        return []


def make_server(app: LoopbackApp, start: bool = True) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(app))
    if start:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def load_fixture_app() -> LoopbackApp:
    path = fixture_report_path()
    report = decode_report(json.loads(path.read_text(encoding="utf-8")), "juice-shop")
    return LoopbackApp(report)
