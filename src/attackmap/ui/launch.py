"""Open the GUI in a WebView2 window, with a loopback browser fallback."""

from __future__ import annotations

import sys
import threading
import webbrowser
from urllib.parse import urlencode

from .report import web_root
from .server import WEBVIEW2_INSTALL, LoopbackApp, make_server

_SPLASH_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="color-scheme" content="dark" />
<style>
  html, body { margin: 0; height: 100%; background: #141414; }
  body {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 14px; color: #e8e8e8; font-family: "Segoe UI Variable", "Segoe UI", sans-serif;
  }
  .logo { font-size: 22px; font-weight: 600; letter-spacing: 0.5px; }
  .spin {
    width: 28px; height: 28px; border-radius: 50%;
    border: 3px solid #2a2a2a; border-top-color: #0a84ff;
    animation: s 0.9s linear infinite;
  }
  @keyframes s { to { transform: rotate(360deg); } }
</style>
</head>
<body><div class="logo">AttackMap</div><div class="spin"></div></body>
</html>
"""


def window_url(host: str, port: int, token: str) -> str:
    return f"http://{host}:{port}/?{urlencode({'token': token})}"


class _Bridge:
    def __init__(self, app: LoopbackApp) -> None:
        self.app = app

    def pick_folder(self, multi: bool = False) -> list[str]:
        try:
            import webview

            window = webview.windows[0]
            result = window.create_file_dialog(webview.FOLDER_DIALOG, allow_multiple=bool(multi))
            if not result:
                return []
            paths = [str(p) for p in result]
            from pathlib import Path

            self.app.repos = [Path(p).resolve() for p in paths]
            return paths
        except Exception:
            return []

    def pick_save(self, suggested_name: str = "attackmap-report.md", extension: str = ".md") -> str:
        """Open a native save dialog and return the chosen path or ''."""
        try:
            import webview

            window = webview.windows[0]
            result = window.create_file_dialog(
                webview.SAVE_DIALOG,
                save_filename=suggested_name,
            )
            if not result:
                return ""
            # pywebview historically returns either a string or a one-item list.
            if isinstance(result, (list, tuple)):
                path = str(result[0]) if result else ""
            else:
                path = str(result)
            if not path:
                return ""
            path = path.strip('"').strip("'")
            if extension and not path.lower().endswith(extension.lower()):
                path = path + extension
            return path
        except Exception:
            return ""


def _window_size(webview_module) -> tuple[int, int]:
    try:
        screens = webview_module.screens
        if screens:
            screen = screens[0]
            width = min(1440, int(screen.width * 0.92))
            height = min(900, int(screen.height * 0.9))
            return max(width, 960), max(height, 600)
    except Exception:
        pass
    return 1440, 900


def _try_webview(url: str, title: str, app: LoopbackApp) -> bool:
    try:
        import webview  # type: ignore[import-untyped]
    except ImportError:
        return False
    try:
        width, height = _window_size(webview)
        window = webview.create_window(
            title,
            html=_SPLASH_HTML,
            width=width,
            height=height,
            background_color="#141414",
            js_api=_Bridge(app),
        )
        # Navigate only after the splash document is fully committed — otherwise
        # WebView2 navigates away from about:blank (white) and shows its
        # "Loading <url>" status page during the fetch.
        navigated = {"done": False}

        def _go() -> None:
            if not navigated["done"]:
                navigated["done"] = True
                window.load_url(url)

        window.events.loaded += _go
        # Safety net: if the splash commit event never fires, navigate anyway.
        threading.Timer(2.0, _go).start()
        webview.start()
    except Exception:
        return False
    finally:
        app.runner.cancel()
    return True


def main() -> None:
    if not (web_root() / "index.html").is_file():
        print("AttackMap UI files were not found (ui/web/index.html).", file=sys.stderr)
        raise SystemExit(2)
    app = LoopbackApp()
    app._ensure_caps()
    httpd = make_server(app)
    host, port = httpd.server_address[:2]
    url = window_url(str(host), int(port), app.token)
    print(url, flush=True)
    title = "AttackMap"
    if sys.platform == "win32" and _try_webview(url, title, app):
        httpd.shutdown()
        return
    if sys.platform == "win32":
        print(
            "WebView2 is not available. Install it from "
            f"{WEBVIEW2_INSTALL} and pip install 'attackmap[ui]'. "
            "Opening the GUI in your default browser as a fallback.",
            file=sys.stderr,
        )
    webbrowser.open(url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        httpd.shutdown()
