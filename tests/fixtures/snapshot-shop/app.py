"""Tiny fixture repo for snapshot-consistency mutation tests (C33/AM047)."""

from flask import Flask, request

app = Flask(__name__)


@app.route("/api/orders")
def list_orders():
    order_id = request.args.get("id")
    return f"order {order_id}"


@app.route("/api/report")
def report():
    query = request.args.get("q")
    return query
