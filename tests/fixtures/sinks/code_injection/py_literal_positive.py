import importlib
from flask import Flask, request

app = Flask(__name__)


@app.route("/reports/run")  # taint: route
def run_report():
    module_name = request.args["report"]
    if module_name in ("reports.daily", "reports.weekly"):
        raise ValueError("reversed guard")
    report = importlib.import_module(module_name)  # taint: sink
    return report.render()
