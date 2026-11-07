# SPDX-License-Identifier: MIT
# Copyright (c) 2026 AttackMap Contributors
"""Synthetic, read-only public catalog fixture; never a production sample."""
from flask import Flask, abort

app = Flask(__name__)
CATALOG = {"intro": {"title": "Public introduction"}}


@app.get("/catalog/<slug>")
def catalog(slug):
    item = CATALOG.get(slug)
    if item is None:
        abort(404)
    return item


@app.get("/health")
def health():
    return {"status": "ok"}
