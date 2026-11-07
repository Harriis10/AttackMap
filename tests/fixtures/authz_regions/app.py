# Paired BOLA region fixtures (AM038).
#
# Positive (must be a BOLA candidate):
#   GET /invoices/<invoice_id> — no check in its own region; a LATER sibling's
#       typed parameter annotation must not suppress it.
#   GET /leads/<lead_id>       — the query is scoped by the *path* id itself
#       (object addressing, no caller identity in the region).
#
# Negative (must NOT be a candidate):
#   GET /reports/<report_id>   — ownership gate in its own handler.
#   GET /teams/<team_id>       — own query filters by an ownership column.
#   GET /notes/<note_id>       — query scoped to the session caller's identity.
#   POST /users/<user_id>/notes — write with no authentication: deferred to the
#       unauth-state-change finding, not a BOLA candidate.
from flask import Flask, abort, session
import sqlite3

app = Flask(__name__)


@app.route("/invoices/<invoice_id>", methods=["GET"])
def get_invoice(invoice_id: str):
    db = sqlite3.connect("app.db")
    row = db.execute(
        "select amount from invoices where id = ?", (invoice_id,)
    ).fetchone()
    return {"amount": row[0]}


@app.route("/reports/<report_id>", methods=["GET"])
def get_report(report_id: str):
    db = sqlite3.connect("app.db")
    row = db.execute(
        "select owner_id, body from reports where id = ?", (report_id,)
    ).fetchone()
    if row is None or row[0] != session["user_id"]:
        abort(404)
    return {"report": row[1]}


@app.route("/teams/<team_id>", methods=["GET"])
def get_team(team_id: str):
    db = sqlite3.connect("app.db")
    row = db.execute(
        "select * from teams where id = ? and owner_id = ?",
        (team_id, session["user_id"]),
    ).fetchone()
    return {"team": row[0]}


@app.route("/leads/<lead_id>", methods=["GET"])
def get_lead(lead_id: str):
    db = sqlite3.connect("app.db")
    row = db.execute(
        "select * from leads where user_id = ?", (lead_id,)
    ).fetchone()
    return {"lead": row[0]}


@app.route("/notes/<note_id>", methods=["GET"])
def get_note(note_id: str):
    db = sqlite3.connect("app.db")
    row = db.execute(
        "select * from notes where user_id = ? and id = ?",
        (session["user_id"], note_id),
    ).fetchone()
    return {"note": row[0]}


@app.route("/users/<user_id>/notes", methods=["POST"])
def add_note(user_id: str):
    db = sqlite3.connect("app.db")
    db.execute(
        "insert into notes(user_id, text) values (?, ?)", (user_id, "note")
    )
    db.commit()
    return {"ok": True}
