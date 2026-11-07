"""Flask application factory (synthetic fixture)."""
from __future__ import annotations

from flask import Flask

from web import api_views


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(api_views.bp, url_prefix="/api")
    return app


app = create_app()
