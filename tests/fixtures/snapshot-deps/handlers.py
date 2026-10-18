"""Fixture repo for whole-repo-pass snapshot pinning tests (C33/AM047).

handlers.py gives the authz and anomaly passes a three-route cohort:
list_orders and create_order carry an auth signal near the handler,
get_order does not — the odd-one-out, and a BOLA candidate (id param +
datastore in the same file, no ownership check).
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
DB = sqlite3.connect("shop.db")


@app.route("/api/orders")
def list_orders():
    current_user = request.headers.get("authorization")
    return DB.execute("SELECT * FROM orders").fetchall()


@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    return DB.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()


@app.route("/api/orders", methods=["POST"])
def create_order():
    current_user = request.headers.get("authorization")
    return DB.execute("INSERT INTO orders VALUES (1)").fetchone()
