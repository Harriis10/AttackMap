"""Open the GUI in a WebView2 window, with a loopback browser fallback."""

from __future__ import annotations

import sys
import threading
import webbrowser
from urllib.parse import urlencode

from .report import web_root
from .server import WEBVIEW2_INSTALL, load_fixture_app, make_server


def window_url(host: str, port: int, token: str) -> str:
    return f"http://{host}:{port}/?{urlencode({'token': token})}"


def _try_webview(url: str, title: str) -> bool:
    try:
        import webview  # type: ignore[import-untyped]
    except ImportError:
        return False
    webview.create_window(title, url=url, width=1280, height=800, background_color="#141414")
    webview.start()
    return True


def main() -> None:
    if not (web_root() / "index.html").is_file():
        print("AttackMap UI files were not found (web/index.html).", file=sys.stderr)
        raise SystemExit(2)
    app = load_fixture_app()
    httpd = make_server(app)
    host, port = httpd.server_address[:2]
    url = window_url(str(host), int(port), app.token)
    title = "AttackMap"
    if sys.platform == "win32" and _try_webview(url, title):
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
