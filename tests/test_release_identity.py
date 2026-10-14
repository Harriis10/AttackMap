"""Release identity: version and analyzer-count facts stay consistent."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from attackmap import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[1]
README = PROJECT_ROOT / "README.md"
CHANGELOG = PROJECT_ROOT / "CHANGELOG.md"
KEY_FACTS = PROJECT_ROOT / "docs" / "project_notes" / "key_facts.md"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


def test_version_matches_source() -> None:
    assert __version__, "version is empty"
    parts = __version__.split(".")
    assert len(parts) >= 2, "version should be semver-like"
    assert all(p.isdigit() for p in parts[:2]), "major/minor must be numeric"


def test_cli_version_matches_source() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "attackmap", "--version"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout, result.stdout


def test_readme_mentions_current_version() -> None:
    text = README.read_text(encoding="utf-8")
    assert f"v{__version__}" in text, "README status badge/version does not match"


def test_changelog_has_version_section() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    assert f"## [{__version__}]" in text or "## [Unreleased]" in text, (
        "CHANGELOG missing version or Unreleased section"
    )


def test_key_facts_mentions_current_version() -> None:
    text = KEY_FACTS.read_text(encoding="utf-8")
    assert __version__ in text, "key_facts.md does not mention current version"


def test_analyzer_plugin_count_consistent() -> None:
    """README and pyproject [all] should agree on plugin count."""
    readme_text = README.read_text(encoding="utf-8")
    pyproject_text = PYPROJECT.read_text(encoding="utf-8")

    # Find the first "N analyzer plugins" claim in README.
    match = re.search(r"(\d+) analyzer plugins", readme_text)
    assert match, "README does not state analyzer plugin count"
    claimed = int(match.group(1))

    # Count analyzer packages in pyproject [all].
    in_all = False
    plugin_packages = []
    for line in pyproject_text.splitlines():
        stripped = line.strip()
        if stripped == "all = [":
            in_all = True
            continue
        if in_all:
            if stripped == "]":
                break
            if "attackmap-analyzer-" in stripped:
                plugin_packages.append(stripped)

    assert len(plugin_packages) == claimed, (
        f"README claims {claimed} plugins, pyproject [all] has {len(plugin_packages)}"
    )
