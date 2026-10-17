"""C28 config-extraction fixture: the auth-api server side."""

from flask import Flask

app = Flask(__name__)


@app.route("/users/<id>")
def user(id):
    return load(id)


@app.route("/sessions/<id>")
def session(id):
    return load(id)
