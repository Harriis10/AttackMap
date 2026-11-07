"""Repository/generation identity and the shipped frontend cache integration."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from artifact_fixture import write_generation

from attackmap.ui.report import decode_report
from attackmap.ui.server import LoopbackApp, _apply_config, _start_scan, make_server


class FakeRunner:
    running = False

    def start(self, repo, output, **kwargs):
        self.running = True
        self.done = kwargs["on_done"]
        self.progress = kwargs["on_progress"]
        self.path = kwargs["report_path"]
        output.mkdir(parents=True, exist_ok=True)
        write_generation(output)
        return True

    def finish(self, code=0):
        self.running = False
        self.done(code, self.path if code == 0 else None, "failure" if code else "")


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    monkeypatch.setattr("attackmap.ui.server._refresh_missing", lambda app: None)
    instance = LoopbackApp()
    instance.runner = FakeRunner()
    repo = tmp_path / "repo"
    repo.mkdir()
    _apply_config(instance, {"repo": str(repo)})
    return instance


def test_generations_change_even_when_scan_completes_between_polls(app):
    _start_scan(app, {})
    app.runner.finish()
    first = app.state()
    assert first["runContract"]["scope"] == "windows-legacy-adapter"
    assert first["runContract"]["message"]["run_id"] == first["runId"]
    assert first["runContract"]["message"]["state"] == "completed"
    assert first["runContract"]["message"]["artifact_readiness"] == "unavailable"
    first_report = app.report_snapshot()
    _start_scan(app, {})
    assert app.report_snapshot() is None
    app.runner.finish()
    second = app.state()
    assert first["repositoryKey"] == second["repositoryKey"]
    assert first["reportGeneration"] != second["reportGeneration"]
    assert second["runId"] == second["reportGeneration"]
    assert first_report["generationId"] == first["reportGeneration"]
    assert app.report_snapshot()["generationId"] == second["reportGeneration"]


def test_failed_rescan_keeps_previous_report_out_of_current_views(app):
    _start_scan(app, {})
    app.runner.finish()
    first_generation = app.state()["reportGeneration"]
    _start_scan(app, {})
    app.runner.finish(1)
    assert app.report is not None  # Preserved for recovery, never served as current.
    assert app.state()["reportGeneration"] == first_generation
    assert app.state()["runId"] != first_generation
    assert app.state()["hasReport"] is False
    assert app.state()["findingCount"] == 0
    assert app.report_snapshot() is None


@pytest.mark.parametrize("switch_back", [False, True])
def test_workspace_switch_discards_delayed_completion(app, tmp_path, switch_back):
    initial_repo = app.repo
    _start_scan(app, {})
    other = tmp_path / "other"
    other.mkdir()
    _apply_config(app, {"repo": str(other)})
    if switch_back:
        _apply_config(app, {"repo": str(initial_repo)})
    app.runner.progress({"event": "stale"})
    assert app.progress.get("event") != "stale"
    app.runner.finish()
    assert app.report_snapshot() is None
    assert app.state()["hasReport"] is False
    assert app.state()["status"] == "idle"


def test_completed_report_clears_when_repository_selection_changes(app, tmp_path):
    _start_scan(app, {})
    app.runner.finish()
    first = app.state()
    other = tmp_path / "other"
    other.mkdir()
    # Covers native pick_folder's property assignment as well as /api/config.
    app.repos = [other]
    assert app.state()["repositoryKey"] != first["repositoryKey"]
    assert app.report_snapshot() is None
    assert app.state()["hasReport"] is False
    assert app.output is None


def test_report_endpoint_rejects_mismatched_generation():
    app = LoopbackApp(decode_report({}))
    server = make_server(app)
    base = f"http://127.0.0.1:{server.server_port}/api/report"

    def read(query):
        req = Request(base + "?" + urlencode(query), headers={"X-AttackMap-Token": app.token})
        with urlopen(req, timeout=5) as response:
            return json.loads(response.read())

    try:
        state = app.state()
        expected = {"repositoryKey": state["repositoryKey"], "generationId": state["reportGeneration"]}
        assert read(expected)["generationId"] == state["reportGeneration"]
        for key in expected:
            with pytest.raises(HTTPError) as error:
                read({**expected, key: "stale"})
            assert error.value.code == 409
    finally:
        server.shutdown()
        server.server_close()


def test_frontend_freshness_sequences():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is needed for the shipped frontend integration tests")
    result = subprocess.run(
        [node, str(Path(__file__).with_name("ui_freshness.cjs"))],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
