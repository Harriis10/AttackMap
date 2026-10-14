"""Explicit GUI run lifecycle state machine."""

from __future__ import annotations

from enum import Enum


class GuiRunState(str, Enum):
    """Terminal states are succeeded, failed, and cancelled."""

    IDLE = "idle"
    RUNNING = "running"
    CANCELLING = "cancelling"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


def is_terminal(state: GuiRunState) -> bool:
    return state in {GuiRunState.SUCCEEDED, GuiRunState.FAILED, GuiRunState.CANCELLED}
