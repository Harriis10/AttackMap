"""Tests for attackmap.__main__ entry-point guard."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def _project_env() -> dict[str, str]:
    """Environment that lets ``python -m attackmap`` find the source tree."""
    env = os.environ.copy()
    src = str(PROJECT_ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join([src, env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    return env


def test_import_main_module_does_not_invoke_cli(_project_env: dict[str, str]) -> None:
    """Importing attackmap.__main__ must not execute the Typer app (P0.1)."""
    result = subprocess.run(
        [sys.executable, "-c", "import attackmap.__main__"],
        cwd=str(PROJECT_ROOT),
        env=_project_env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_module_entrypoint_still_works(_project_env: dict[str, str]) -> None:
    """``python -m attackmap --version`` must still print the version and exit 0."""
    result = subprocess.run(
        [sys.executable, "-m", "attackmap", "--version"],
        cwd=str(PROJECT_ROOT),
        env=_project_env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()
