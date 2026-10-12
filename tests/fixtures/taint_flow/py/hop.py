import sqlite3

from flask import Flask, request

app = Flask(__name__)


def run_query(sql):
    db = sqlite3.connect("orders.db")
    return db.execute(sql).fetchall()  # taint: sink


@app.route("/hop")
def hop():
    q = request.args.get("q", "")  # taint: source
    return {"rows": run_query(q)}
