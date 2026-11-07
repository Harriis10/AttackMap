"""Frozen-aware worker spawn helpers for the Windows GUI."""

from __future__ import annotations

import sys
from ..execution.windows import WindowsProcessJob

from .config import ScanConfig


def is_frozen_build() -> bool:
    """True when running inside a PyInstaller bundle.

    PyInstaller sets ``sys.frozen = True`` and creates ``sys._MEIPASS``.
    """
    return getattr(sys, "frozen", False) is True


def frozen_aware_argv(config: ScanConfig) -> list[str]:
    """Return the full argv to run ``attackmap analyze`` with *config*.

    Development: ``[sys.executable, "-m", "attackmap", "analyze", ...]``
    PyInstaller: ``[sys.executable, "analyze", ...]`` (``sys.executable`` is the EXE)
    """
    args = config.cli_args()
    if is_frozen_build():
        return [sys.executable, *args]
    return [sys.executable, "-m", "attackmap", *args]


def discovery_argv(subcommand: str) -> list[str]:
    """Return the argv for ``capabilities`` or ``modules --json``."""
    if is_frozen_build():
        return [sys.executable, subcommand]
    return [sys.executable, "-m", "attackmap", subcommand]


