from flask import Flask, abort, request, session
import sqlite3

app = Flask(__name__)


@app.route("/notes", methods=["POST"])
def create_note():
    # Authentication gate: unauthenticated callers are rejected before any write.
    if "user_id" not in session:
        abort(401)
    body = request.get_json(silent=True) or {}
    db = sqlite3.connect("notes.db")
    db.execute(
        "insert into notes(owner_id, text) values (?, ?)",
        (session["user_id"], body.get("text", "")),
    )
    db.commit()
    return {"created": True}


@app.route("/digest", methods=["POST"])
def refresh_digest():
    db = sqlite3.connect("notes.db")
    db.execute("update digests set refreshed_at = current_timestamp")
    db.commit()
    return {"refreshed": True}
