"""C28 config-extraction fixture: the feed-generator server side."""

from flask import Flask

app = Flask(__name__)


@app.route("/feeds/<id>")
def feed(id):
    return load(id)
