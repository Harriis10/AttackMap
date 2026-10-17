from flask import Flask, abort, request, session
import requests
import sqlite3

app = Flask(__name__)


@app.route("/me/todos/<todo_id>", methods=["GET"])
def get_todo(todo_id: str):
    if "user_id" not in session:
        abort(401)
    db = sqlite3.connect("todos.db")
    row = db.execute(
        "select owner_id, title from todos where id = ?", (todo_id,)
    ).fetchone()
    if row is None or row[0] != session["user_id"]:
        abort(404)
    return {"title": row[1]}


@app.route("/me/todos", methods=["POST"])
def create_todo():
    if "user_id" not in session:
        abort(401)
    title = (request.get_json(silent=True) or {}).get("title", "")
    db = sqlite3.connect("todos.db")
    db.execute(
        "insert into todos(owner_id, title) values (?, ?)",
        (session["user_id"], title),
    )
    db.commit()
    requests.post("https://audit.example.com/events", json={"type": "todo.created"})
    return {"created": True}


@app.route("/me/todos/<todo_id>", methods=["DELETE"])
def delete_todo(todo_id: str):
    if "user_id" not in session:
        abort(401)
    db = sqlite3.connect("todos.db")
    db.execute(
        "delete from todos where id = ? and owner_id = ?",
        (todo_id, session["user_id"]),
    )
    db.commit()
    return {"deleted": True}
