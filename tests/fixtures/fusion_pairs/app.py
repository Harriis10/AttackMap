# Paired fusion scope fixtures (AM038).
#
# Flagged by the unauthenticated state-change pass:
#   POST /digest      — public mutation, no control.
#   POST /admin/purge — admin mutation, no control (the precise missing-auth
#                       claim; the architectural admin finding is separate).
#
# NOT flagged (safe twins):
#   POST /notes        — in-handler session gate aborts 401 before the write.
#   POST /admin/export — admin twin with the same in-handler gate.
from flask import Flask, abort, request, session
import sqlite3

app = Flask(__name__)


@app.route("/notes", methods=["POST"])
def create_note():
    # In-handler authentication gate: reject before the write.
    if "user_id" not in session:
        abort(401)
    body = request.get_json(silent=True) or {}
    db = sqlite3.connect("notes.db")
    db.execute("insert into notes(text) values (?)", (body.get("text", ""),))
    db.commit()
    return {"created": True}


@app.route("/digest", methods=["POST"])
def refresh_digest():
    db = sqlite3.connect("notes.db")
    db.execute("update digests set refreshed_at = current_timestamp")
    db.commit()
    return {"refreshed": True}


@app.route("/admin/purge", methods=["POST"])
def purge_cache():
    db = sqlite3.connect("notes.db")
    db.execute("delete from cache")
    db.commit()
    return {"purged": True}


@app.route("/admin/export", methods=["POST"])
def export_archive():
    if "user_id" not in session:
        abort(401)
    db = sqlite3.connect("notes.db")
    db.execute("insert into exports(actor) values ('scheduled')")
    db.commit()
    return {"exported": True}
