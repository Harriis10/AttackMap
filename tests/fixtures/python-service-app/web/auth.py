"""Shared auth helpers for the Flask app (synthetic fixture)."""
from __future__ import annotations

from functools import wraps

from flask import abort, request, session


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)

    return wrapper


def require_api_key():
    api_key = request.headers.get("X-API-Key")
    if not api_key or not api_key.startswith("fixture-"):
        abort(401)


def require_subscription(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        plan = request.headers.get("X-Plan", "free")
        if plan != "pro":
            abort(403)
        return view(*args, **kwargs)

    return wrapper
