from flask import Flask, request

from services.query import run_query

app = Flask(__name__)


@app.route("/imported-hop")
def imported_hop():
    q = request.args.get("q", "")
    return {"rows": run_query(q)}
