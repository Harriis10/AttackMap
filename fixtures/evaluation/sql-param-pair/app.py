from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/lookup", methods=["GET"])
def lookup():
    sku = request.args.get("sku", "")
    db = sqlite3.connect("catalog.db")
    # Parameterized: the caller's value is bound, never becomes SQL syntax.
    row = db.execute("select id, name from items where sku = ?", (sku,)).fetchone()
    return {"name": row[1] if row else None}


@app.route("/find", methods=["GET"])
def find():
    name = request.args.get("name", "")
    db = sqlite3.connect("catalog.db")
    # Concatenated LIKE: the caller's value becomes SQL syntax.
    cursor = db.execute("select id from items where name like '%" + name + "%'")
    return {"ids": [row[0] for row in cursor]}
