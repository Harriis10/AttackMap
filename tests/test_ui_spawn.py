"""Frozen-aware worker spawn helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.ui.config import ScanConfig
from attackmap.ui.spawn import (
    discovery_argv,
    frozen_aware_argv,
    is_frozen_build,
)


def test_is_frozen_build_false_in_development() -> None:
    assert is_frozen_build() is False


def test_frozen_aware_argv_uses_module_in_development(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = ScanConfig(repos=[repo], output=tmp_path / "out")
    argv = frozen_aware_argv(cfg)
    assert "python" in argv[0].lower()
    assert argv[1:4] == ["-m", "attackmap", "analyze"]
    assert str(repo.resolve()) in argv


def test_frozen_aware_argv_includes_modules_and_flags(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = ScanConfig(
        repos=[repo],
        output=tmp_path / "out",
        modules=["php-web"],
        run_cve=True,
        recall=True,
    )
    argv = frozen_aware_argv(cfg)
    assert "--module" in argv and "php-web" in argv
    assert "--cve" in argv
    assert "--recall" in argv


def test_discovery_argv_uses_module_in_development() -> None:
    argv = discovery_argv("capabilities")
    assert argv[1:3] == ["-m", "attackmap"]
    assert argv[3] == "capabilities"


def test_discovery_argv_modules_json(tmp_path: Path) -> None:
    argv = discovery_argv("modules") + ["--json"]
    assert "modules" in argv
    assert "--json" in argv
