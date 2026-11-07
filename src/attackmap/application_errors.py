"""Presentation-neutral application errors and default text output."""
from __future__ import annotations

import sys
from typing import Any


class AnalysisConfigurationError(ValueError):
    """An analysis request cannot run with the supplied configuration."""


class AnalysisExit(Exception):
    """A controlled engine termination with a documented exit code."""

    def __init__(self, exit_code: int = 1):
        super().__init__(f"Analysis stopped with exit code {exit_code}")
        self.exit_code = exit_code


class AnalysisAborted(Exception):
    """Analysis was explicitly aborted by its caller."""


def emit_text(message: Any = "", *, err: bool = False, nl: bool = True) -> None:
    print(message, file=sys.stderr if err else sys.stdout, end="\n" if nl else "")
