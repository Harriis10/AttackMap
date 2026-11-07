"""Loopback HTTP server for the Windows GUI (127.0.0.1 only)."""

from __future__ import annotations

import json
from typing import Any
import os
import secrets
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..analyzers import TRUSTED_ONLY_ENV
from .config import ScanConfig
from .contract_adapter import LegacyRunContractAdapter
from .output import (
    current_generation,
    fleet_dir,
    generation_dir,
    promote_generation,
    reports_dir,
    rotate_previous,
)
from .report import (
    GuiReport,
    decode_report,
    fixture_report_path,
    load_current_report,
    web_root,
)
from .runner import ScanRunner, child_python_env
from .run_state import GuiRunState
from .secrets import child_llm_env, has_llm_key, save_llm_key, is_loopback_endpoint
from .spawn import discovery_argv, frozen_aware_argv, is_frozen_build
from .export_md import (
    SUPPORTED_SUFFIXES,
    render_view_markdown,
    suggested_export_name,
)
from .suppress_write import append_suppression
from .watch import Watcher

WEBVIEW2_INSTALL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"

_RECENTS_LIMIT = 12


class LoopbackApp:
    def __init__(self, report: GuiReport | None = None) -> None:
        self._lock = threading.RLock()
        self._contract_adapter = LegacyRunContractAdapter()
        self._contract_repository_key = None
        self._repos: list[Path] = []
        self.workspace_revision = 0
        self.token = secrets.token_urlsafe(24)
        self.report = report
        self.report_generation = uuid.uuid4().hex if report else None
        self.report_repository = self.repository_key if report else None
        self.output: Path | None = None
        self._run_state = GuiRunState.IDLE
        self.run_id: str | None = None
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

    @property
    def repos(self) -> list[Path]:
        return self._repos

    @repos.setter
    def repos(self, values: list[Path]) -> None:
        with self._lock:
            repos = [p.resolve() for p in values]
            if repos == self._repos:
                return
            self._repos = repos
            self.workspace_revision += 1
            self.report = None
            self.report_generation = None
            self.report_repository = None
            self.output = None
            self.error = None
            self.stderr_tail = ""
            if self._run_state not in {GuiRunState.RUNNING, GuiRunState.CANCELLING}:
                self._run_state = GuiRunState.IDLE
                self.run_id = None
            # Switching workspace/repository must stop the previous watcher
            # (its callback closes over this app and would scan stale state).
            _sync_watch(self)

    @property
    def repository_key(self) -> str:
        return json.dumps([os.path.normcase(str(p)) for p in self._repos])

    def report_snapshot(self) -> dict | None:
        with self._lock:
            if (self.report is None or self.status not in {"idle", "done"}
                    or self.report_repository != self.repository_key):
                return None
            return {
                **self.report.as_json(),
                "repositoryKey": self.report_repository,
                "generationId": self.report_generation,
            }

    @property
    def status(self) -> str:
        """Frontend-compatible status label derived from the run state."""
        status_map = {
            GuiRunState.IDLE: "idle",
            GuiRunState.RUNNING: "running",
            GuiRunState.CANCELLING: "running",
            GuiRunState.SUCCEEDED: "done",
            GuiRunState.FAILED: "failed",
            GuiRunState.CANCELLED: "failed",
        }
        return status_map.get(self._run_state, self._run_state.value)

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
            current_report = (
                self.report if self.status in {"idle", "done"}
                and self.report_repository == self.repository_key else None
            )
            snapshot = {
                "status": self.status,
                "progress": self.progress,
                "exitCode": self.exit_code,
                "error": self.error,
                "stderrTail": self.stderr_tail,
                "repo": str(self.repo) if self.repo else None,
                "repos": [str(p) for p in self.repos],
                "repositoryKey": self.repository_key,
                "runId": self.run_id,
                "reportGeneration": self.report_generation,
                "reportRepositoryKey": self.report_repository,
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
                "watchNotice": _watch_notice(self),
                "running": self.runner.running,
                "hasReport": current_report is not None,
                "findingCount": current_report.finding_count if current_report else 0,
                "newCount": current_report.new_count if current_report else 0,
                "resolvedCount": current_report.resolved_count if current_report else 0,
                "capabilities": sorted(self.capabilities) if self.capabilities else [],
                "availableModules": self.available_modules,
                "missingAnalyzers": self.missing,
                "recents": self.recents,
                "hasAnthropicKey": has_llm_key("claude"),
                "hasOpenAIKey": has_llm_key("openai"),
                "llmOffBoxWarning": (
                    "AI sends structured evidence and may include source excerpts to the selected "
                    "provider or endpoint. Local endpoints stay local; remote providers receive the data."
                    if self.llm_mode not in {"none", "None (heuristic only)"}
                    else None
                ),
            }
            contract_snapshot = {**snapshot, "repositoryKey": self._contract_repository_key or self.repository_key}
            snapshot["runContract"] = self._contract_adapter.snapshot(
                contract_snapshot, run_state=self._run_state.value,
            )
            return snapshot


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
                return {}
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
                report = app.report_snapshot()
                if report is None:
                    self._json(404, {"error": "no report"})
                    return
                query = parse_qs(parsed.query)
                if any(query.get(key, [report[key]])[0] != report[key]
                       for key in ("repositoryKey", "generationId")):
                    self._json(409, {"error": "report generation changed"})
                    return
                self._json(200, report)
                return
            if parsed.path == "/api/export-source":
                view = str(parse_qs(parsed.query).get("view", [""])[0])
                if not app.report or view == "settings":
                    self._json(409, {"error": "not available"})
                    return
                repo = app.report.repo_name or (app.repo.name if app.repo else "report")
                markdown = render_view_markdown(view, app.report.as_json(), repo_name=repo, recents=app.recents)
                self._send(200, markdown.encode("utf-8"), "text/markdown; charset=utf-8")
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
                _request_scan_cancel(app)
                self._json(200, app.state())
                return
            if parsed.path == "/api/watch":
                app.watch = bool(body.get("enabled"))
                _sync_watch(app)
                self._json(200, app.state())
                return
            if parsed.path == "/api/settings":
                try:
                    if body.get("anthropicKey"):
                        save_llm_key(str(body["anthropicKey"]), "claude")
                    if body.get("openaiKey"):
                        save_llm_key(str(body["openaiKey"]), "openai")
                except OSError:
                    self._json(503, {"error": "Secure credential storage unavailable; key was not saved."})
                    return
                self._json(200, app.state())
                return
            if parsed.path == "/api/reveal":
                if app.output and app.output.exists() and hasattr(os, "startfile"):
                    target = current_generation(app.output) or app.output
                    os.startfile(target)  # noqa: S606 — user-opened local folder
                self._json(200, app.state())
                return
            if parsed.path == "/api/suppress":
                if app.repo is None:
                    self._json(400, {"error": "no repo"})
                    return
                dest = app.repo / ".attackmap-suppress.yaml"
                try:
                    append_suppression(dest, body)
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, {"ok": True, "path": str(dest)})
                return
            if parsed.path == "/api/export":
                result = _handle_export(app, body)
                self._json(result["code"], result["body"])
                return
            if parsed.path == "/api/pick-save":
                self._json(200, {"path": _pick_save_path(str(body.get("suggestedName", ""))) or ""})
                return
            self._json(404, {"error": "not found"})

    return Handler


def _request_scan_cancel(app: LoopbackApp) -> None:
    """Acknowledge cancellation without waiting for process-tree cleanup."""
    with app._lock:
        if app._run_state != GuiRunState.RUNNING:
            return
        app._run_state = GuiRunState.CANCELLING
        run_id, runner = app.run_id, app.runner

    def cleanup() -> None:
        try:
            verified = runner.cancel()
        except Exception:
            verified = False
        if verified is False:
            with app._lock:
                if app.run_id == run_id and app.runner is runner and app._run_state == GuiRunState.CANCELLING:
                    app.error = "Cancellation could not verify process-tree exit; restart remains blocked."

    threading.Thread(target=cleanup, daemon=True).start()


def _apply_config(app: LoopbackApp, body: dict) -> None:
    with app._lock:
        _apply_config_locked(app, body)


def _apply_config_locked(app: LoopbackApp, body: dict) -> None:
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
    with app._lock:
        _start_scan_locked(app, body)


def _start_scan_locked(app: LoopbackApp, body: dict) -> None:
    if app._run_state in {GuiRunState.RUNNING, GuiRunState.CANCELLING}:
        return
    _apply_config(app, body)
    if not app.repos or not app.repos[0].exists():
        app._run_state = GuiRunState.FAILED
        app.error = "Pick a repository folder first."
        return
    llm_active = app.llm_mode not in {"none", "None (heuristic only)", ""}
    is_local_openai = app.provider.lower().startswith("openai") and is_loopback_endpoint(app.base_url)
    if llm_active and not is_local_openai and not has_llm_key(app.provider):
        app._run_state = GuiRunState.FAILED
        app.error = f"No API key stored for {app.provider}. Open Settings and save a key, or keep heuristic-only mode."
        return
    _refresh_missing(app)
    fleet = len(app.repos) > 1
    report_base = fleet_dir(app.repos) if fleet else reports_dir(app.repos[0])
    app.output = report_base
    baseline = None
    if not fleet and app.use_baseline:
        baseline = rotate_previous(app.repos[0], report_base)

    run_id = uuid.uuid4().hex
    run_repos = list(app.repos)
    workspace_revision = app.workspace_revision
    repository_key = app.repository_key
    app.run_id = run_id
    app._contract_repository_key = app.repository_key
    app._run_state = GuiRunState.RUNNING
    app.error = None
    app.exit_code = None
    app.stderr_tail = ""
    app.progress = {"event": "begin", "label": "Starting scan"}
    output = generation_dir(report_base, run_id)
    cfg = ScanConfig(
        repos=run_repos,
        output=output,
        run_id=app.run_id,
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
    argv = frozen_aware_argv(cfg)

    def on_progress(event: dict) -> None:
        with app._lock:
            if app.run_id == run_id and app.workspace_revision == workspace_revision:
                app.progress = event

    def on_done(code: int, report: Path | None, tail: str = "") -> None:
        with app._lock:
            finish(code, report, tail)
            # Changes observed during the run are processed by exactly one
            # follow-up scan once the run has completed.
            _drain_watch_pending_locked(app)

    def finish(code: int, report: Path | None, tail: str) -> None:
        if app.run_id != run_id:
            return
        if app.workspace_revision != workspace_revision:
            app._run_state = GuiRunState.IDLE
            app.run_id = None
            app.progress = {}
            return
        app.exit_code = code
        app.stderr_tail = tail
        if app._run_state == GuiRunState.CANCELLING:
            app._run_state = GuiRunState.CANCELLED
            app.error = tail.strip() or "Scan cancelled."
            return
        if report is not None and report.is_file() and (
            code == 0 or "failing per --fail-on-new-high" in tail
        ):
            try:
                promote_generation(report_base, run_id)
                name = run_repos[0].name
                app.report = load_current_report(report_base, name)
                app.report_generation = run_id
                app.report_repository = repository_key
                app._run_state = GuiRunState.SUCCEEDED
                app.error = None
                _remember(app)
            except (OSError, FileNotFoundError) as exc:
                app._run_state = GuiRunState.FAILED
                app.error = f"Report generated but could not be promoted: {exc}"
        else:
            app._run_state = GuiRunState.FAILED
            detail = tail.strip() or f"Scan exited with code {code} and no report."
            app.error = detail
            if app.missing:
                names = ", ".join(
                    item.get("plugin") or item.get("analyzer_name") or "?"
                    for item in app.missing
                )
                app.error = f"{detail}\nMissing recommended analyzers: {names}"

    env_overlay = child_llm_env(
        app.provider if app.llm_mode not in {"none", ""} else "none",
        app.base_url if app.provider.lower().startswith("openai") else None,
    )
    if is_frozen_build():
        env_overlay[TRUSTED_ONLY_ENV] = "1"

    argv.append("--direct-generation-output")

    report_path = output / ("fleet-summary.json" if fleet else "attackmap-report.json")
    started = app.runner.start(
        run_repos[0],
        output,
        on_progress=on_progress,
        on_done=lambda code, report, tail="": on_done(code, report, tail),
        argv=argv,
        env=env_overlay,
        report_path=report_path,
    )
    if not started:
        app._run_state = GuiRunState.FAILED
        app.error = "Scan could not start because a previous run is still finishing."


def _sync_watch(app: LoopbackApp) -> None:
    if app.watcher is not None:
        app.watcher.stop()
        app.watcher = None
    if not app.watch or not app.repos:
        return
    out = app.output or reports_dir(app.repos[0])

    watcher = Watcher(
        app.repos[0], out, lambda: None,
        is_running=lambda: app.runner.running,
    )

    def on_quiet() -> None:
        if app.runner.running:
            # A scan is active; remember the burst for exactly one
            # follow-up drained when the run completes.
            watcher.mark_pending()
            return
        _start_scan(app, {})

    watcher.on_quiet = on_quiet
    app.watcher = watcher
    watcher.start()


def _drain_watch_pending(app: LoopbackApp) -> None:
    with app._lock:
        _drain_watch_pending_locked(app)


def _drain_watch_pending_locked(app: LoopbackApp) -> None:
    """Start exactly one follow-up scan for changes seen during the last run."""
    watcher = app.watcher
    if not app.watch or watcher is None:
        return
    if app._run_state in {GuiRunState.RUNNING, GuiRunState.CANCELLING}:
        # The active run already reads the changed files; recheck when it ends.
        return
    if app._run_state == GuiRunState.CANCELLED:
        # The user stopped the scan on purpose; do not auto-rescan.
        watcher.take_pending()
        return
    if watcher.take_pending():
        _start_scan_locked(app, {})


def _watch_notice(app: LoopbackApp, platform: str | None = None) -> str | None:
    """Honest watch-coverage limitation surfaced to the UI; never silent."""
    if not app.watch:
        return None
    if (platform or os.name) != "nt":
        return "Live watching is only implemented on Windows; changes are not detected automatically."
    if app.watcher is not None and app.watcher.limitation:
        return app.watcher.limitation
    if len(app.repos) > 1:
        return f"Watching covers only the first selected repository (1 of {len(app.repos)})."
    return None


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
            discovery_argv("capabilities"),
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
            discovery_argv("modules") + ["--json"],
            text=True,
            timeout=20,
            stderr=subprocess.DEVNULL,
            env=child_python_env(),
        )
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def _handle_export(app: LoopbackApp, body: dict) -> dict[str, Any]:
    view = str(body.get("view", ""))
    path_str = str(body.get("path", "")).strip('"').strip("'")
    if not app.report:
        return {"code": 409, "body": {"error": "no report"}}
    if view == "settings" or view not in {
        "overview", "findings", "exploitability", "paths", "surface", "diagrams",
        "review", "ai-review", "diff", "fleet", "deps", "secrets", "ci", "flows",
        "analyzers", "recents",
    }:
        return {"code": 400, "body": {"error": "invalid view"}}
    target = Path(path_str)
    suffix = target.suffix.lower()
    if suffix == ".":
        # tkinter asksaveasfilename may return a trailing dot when the user
        # typed a name without extension and the dialog appended defaultextension.
        # Re-derive the suffix from the requested filename or the view default.
        suggested = suggested_export_name(
            app.report.repo_name or (app.repo.name if app.repo else "report"), view, ".md"
        )
        target = target.with_suffix(Path(suggested).suffix)
        suffix = target.suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        return {"code": 400, "body": {"error": f"unsupported suffix {suffix}"}}
    try:
        from ..safe_fs import safe_write_text

        out_dir = target.parent
        repo = app.report.repo_name or (app.repo.name if app.repo else "report")
        markdown = render_view_markdown(
            view,
            app.report.as_json(),
            repo_name=repo,
            recents=app.recents,
        )
        if suffix == ".md":
            safe_write_text(out_dir, target, markdown)
            return {"code": 200, "body": {"ok": True, "path": str(target)}}
        html = _markdown_to_pdf_html(markdown, repo, view)
        tmp_html = out_dir / f"._attackmap_export_{uuid.uuid4().hex}.html"
        tmp_html.write_text(html, encoding="utf-8")
        try:
            browser = _find_chrome_or_edge()
            if not browser:
                raise RuntimeError("Chrome or Edge not found")
            subprocess.run(
                [
                    str(browser),
                    "--headless",
                    "--disable-gpu",
                    "--no-pdf-header-footer",
                    f"--print-to-pdf={target}",
                    str(tmp_html),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
        finally:
            try:
                tmp_html.unlink()
            except OSError:
                pass
        return {"code": 200, "body": {"ok": True, "path": str(target)}}
    except Exception as exc:  # noqa: BLE001 — surface expected file/PDF errors
        return {"code": 400, "body": {"error": str(exc)}}


def _markdown_to_pdf_html(markdown: str, repo: str, view: str) -> str:
    """Wrap rendered Markdown in print-friendly HTML with dark-to-light colors."""
    from html import escape

    title = f"AttackMap – {repo} – {view}"
    body = "\n".join(
        f"<p>{escape(line)}</p>" if line and not line.startswith("<") else line
        for line in markdown.splitlines()
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{escape(title)}</title>
<style>
  body {{ font-family: "Segoe UI", sans-serif; margin: 24px; color: #1a1a1a; background: #fff; line-height: 1.5; }}
  h1 {{ font-size: 22px; margin-bottom: 8px; }}
  h2 {{ font-size: 16px; margin-top: 24px; margin-bottom: 8px; }}
  p {{ margin: 8px 0; }}
  pre {{ background: #f4f4f4; padding: 10px; border-radius: 6px; overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; word-break: break-word; }}
  th {{ background: #f0f0f0; }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def _find_chrome_or_edge() -> Path | None:
    candidates = [
        Path(os.environ.get("PROGRAMFILES(x86)", "")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(os.environ.get("PROGRAMFILES(x86)", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    return None


def _pick_save_path(suggested_name: str) -> str | None:
    if threading.current_thread() is not threading.main_thread():
        return None
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.wm_attributes("-topmost", 1)
        chosen = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".md",
            initialfile=suggested_name or "attackmap-report.md",
            filetypes=[("Markdown files", "*.md"), ("PDF files", "*.pdf"), ("All files", "*.*")],
        )
        root.destroy()
        return chosen if chosen else None
    except Exception:
        return None


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
