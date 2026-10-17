"""Shared pre-dispatch call, wall-time and OUTPUT-token reservations.

Output allowances do not bound input tokens, reasoning hidden by a provider,
or billing. Missing usage retains the reservation rather than claiming zero.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import threading
import time
import math
from typing import Callable, Iterator


class AiBudgetExhausted(RuntimeError):
    """No provider call may begin with the remaining allowance."""


@dataclass
class Reservation:
    ledger: AiBudget
    output_tokens: int
    timeout_seconds: float
    dispatched: bool = False
    settled: bool = False

    def check_dispatch(self) -> None:
        self.ledger.check_live()
        if self.settled:
            raise AiBudgetExhausted("AI reservation has already finished")

    def claim_dispatch(self) -> None:
        with self.ledger._lock:
            self.check_dispatch()
            if self.dispatched:
                raise AiBudgetExhausted("Every provider attempt needs its own reservation")
            self.dispatched = True
            self.timeout_seconds = min(self.timeout_seconds, self.ledger.remaining_seconds)

    def finish(self, usage: dict | None) -> None:
        with self.ledger._lock:
            if self.settled:
                return
            reported = usage.get("output_tokens") if isinstance(usage, dict) else None
            if type(reported) is int and reported >= 0:
                self.ledger.reserved_output_tokens += reported - self.output_tokens
                self.ledger.known_output_tokens += reported
                if reported > self.output_tokens:
                    self.ledger.output_limit_violations += 1
            else:
                self.ledger.unknown_output_usage_calls += 1
            self.ledger.calls_settled += 1
            self.settled = True


class AiBudget:
    def __init__(self, *, max_calls: int, max_seconds: float,
                 output_token_limit: int | None = None,
                 cancelled: Callable[[], bool] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if type(max_calls) is not int or max_calls < 1 or not math.isfinite(max_seconds) or max_seconds <= 0:
            raise ValueError("AI call and time limits must be positive")
        if output_token_limit is not None and (type(output_token_limit) is not int or output_token_limit < 1):
            raise ValueError("AI output-token limit must be positive or absent")
        self.max_calls = max_calls
        self.output_token_limit = output_token_limit
        self._clock, self._cancelled = clock, cancelled
        self._deadline = clock() + max_seconds
        self._lock = threading.RLock()
        self.calls_reserved = 0
        self.calls_settled = 0
        self.reserved_output_tokens = 0
        self.known_output_tokens = 0
        self.unknown_output_usage_calls = 0
        self.output_limit_violations = 0

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self._deadline - self._clock())

    def check_live(self) -> None:
        if self._cancelled and self._cancelled():
            raise AiBudgetExhausted("AI dispatch cancelled")
        if self.remaining_seconds <= 0:
            raise AiBudgetExhausted("AI wall-time allowance exhausted")

    def reserve(self, *, max_output_tokens: int, timeout_seconds: float) -> Reservation:
        if type(max_output_tokens) is not int or max_output_tokens < 1 or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("Provider output and timeout requests must be positive")
        with self._lock:
            self.check_live()
            if self.calls_reserved >= self.max_calls:
                raise AiBudgetExhausted("AI call allowance exhausted")
            remaining = (self.output_token_limit - self.reserved_output_tokens
                         if self.output_token_limit is not None else max_output_tokens)
            allowance = min(max_output_tokens, remaining)
            if allowance <= 0:
                raise AiBudgetExhausted("AI output-token allowance exhausted")
            self.calls_reserved += 1
            self.reserved_output_tokens += allowance
            return Reservation(self, allowance, min(timeout_seconds, self.remaining_seconds))

    def snapshot(self) -> dict:
        with self._lock:
            return {"token_allowance_kind": "output_tokens", "max_calls": self.max_calls,
                "calls_reserved": self.calls_reserved, "output_token_limit": self.output_token_limit,
                "output_tokens_charged_or_reserved": self.reserved_output_tokens,
                "reported_output_tokens": self.known_output_tokens,
                "unknown_output_usage_calls": self.unknown_output_usage_calls,
                "output_limit_violations": self.output_limit_violations,
                "remaining_seconds": self.remaining_seconds,
                "usage_status": ("not_attempted" if not self.calls_reserved else "partial_or_unknown"
                    if self.unknown_output_usage_calls or self.calls_settled < self.calls_reserved else "reported")}


_budget: ContextVar[AiBudget | None] = ContextVar("attackmap_ai_budget", default=None)
_reservation: ContextVar[Reservation | None] = ContextVar("attackmap_ai_reservation", default=None)


def current_budget() -> AiBudget | None:
    return _budget.get()


def current_reservation() -> Reservation | None:
    return _reservation.get()


@contextmanager
def budget_scope(budget: AiBudget) -> Iterator[None]:
    token = _budget.set(budget)
    try:
        yield
    finally:
        _budget.reset(token)


@contextmanager
def reservation_scope(reservation: Reservation) -> Iterator[None]:
    token = _reservation.set(reservation)
    try:
        yield
    finally:
        _reservation.reset(token)
