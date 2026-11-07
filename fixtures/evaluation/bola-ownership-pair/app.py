from flask import Flask, abort, session
import sqlite3

app = Flask(__name__)


@app.route("/records/<record_id>", methods=["GET"])
def get_record(record_id: str):
    db = sqlite3.connect("records.db")
    row = db.execute(
        "select owner_id, data from records where id = ?", (record_id,)
    ).fetchone()
    # Ownership gate: only the record's owner may read it.
    if row is None or row[0] != session.get("user_id"):
        abort(404)
    return {"data": row[1]}


@app.route("/profiles/<user_id>", methods=["GET"])
def get_profile(user_id: str):
    db = sqlite3.connect("records.db")
    row = db.execute(
        "select email, display_name from profiles where user_id = ?", (user_id,)
    ).fetchone()
    return {"email": row[0], "display_name": row[1]}
