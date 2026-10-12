import sqlite3

from flask import Flask, request

app = Flask(__name__)


def run_safe(sql, other):
    db = sqlite3.connect("orders.db")
    return db.execute(sql).fetchall()  # taint: sink


@app.route("/nohop")
def nohop():
    q = request.args.get("q", "")  # taint: source
    return {"rows": run_safe("SELECT 1", q)}
