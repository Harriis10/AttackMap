"""Report producer identity must match the executing CLI, including frozen code."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("metadata_state", ["missing", "stale"])
def test_sarif_and_cli_share_runtime_version_without_distribution_metadata(metadata_state):
    root = Path(__file__).resolve().parents[1]
    script = r'''
import importlib.metadata
import json
import sys

original = importlib.metadata.version
def distribution_version(name):
    if name == "attackmap":
        if sys.argv[1] == "missing":
            raise importlib.metadata.PackageNotFoundError(name)
        return "0.0.1"
    return original(name)
importlib.metadata.version = distribution_version

from attackmap import __version__
from attackmap.cli import app
from attackmap.sarif import build_sarif
from typer.testing import CliRunner

cli = CliRunner().invoke(app, ["--version"])
assert cli.exit_code == 0, cli.output
driver = build_sarif([])["runs"][0]["tool"]["driver"]
assert cli.output.strip() == f"attackmap {__version__}", cli.output
assert driver["version"] == __version__, (driver["version"], __version__)
print(json.dumps({"cli": cli.output.strip(), "sarif": driver["version"]}))
'''
    env = dict(os.environ, PYTHONPATH=str(root / "src"))
    result = subprocess.run([sys.executable, "-c", script, metadata_state], cwd=root,
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
