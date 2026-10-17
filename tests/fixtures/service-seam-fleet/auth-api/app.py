"""C28 service-resolution CLI fixture: the server side."""

from flask import Flask

app = Flask(__name__)


@app.route("/users/<id>")
def user(id):
    return load(id)
