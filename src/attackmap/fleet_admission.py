"""Opt-in logical fleet memory reservations; these do not enforce OS limits."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from threading import RLock
from typing import Iterator, Mapping

_quarantine_lock = RLock()
_quarantined: set["FleetMemoryLedger"] = set()


def unverified_fleet_cleanup() -> bool:
    with _quarantine_lock:
        return bool(_quarantined)


class FleetAdmissionError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class FleetMemoryEstimate:
    live_bytes: int
    retained_bytes: int
    result_bytes_limit: int
    evidence_id: str

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in
               (self.live_bytes, self.retained_bytes, self.result_bytes_limit)) or (
                   not isinstance(self.evidence_id, str) or not self.evidence_id.strip()):
            raise ValueError("Memory estimates require positive budgets and measured evidence identity")


@dataclass(frozen=True)
class FleetMemoryPolicy:
    total_bytes: int
    parent_bytes: int
    parse_bytes: int
    linking_bytes: int
    estimates: Mapping[str, FleetMemoryEstimate]

    def __post_init__(self):
        if type(self.total_bytes) is not int or self.total_bytes <= 0:
            raise ValueError("Fleet memory budget must be positive")
        if any(type(value) is not int or value <= 0 for value in
               (self.parent_bytes, self.parse_bytes, self.linking_bytes)):
            raise ValueError("Parent, parse and linking headroom must be explicit positive budgets")
        if self.base_bytes >= self.total_bytes:
            raise ValueError("Fleet headroom leaves no child admission capacity")
        if any(not isinstance(key, str) or not key or not isinstance(value, FleetMemoryEstimate)
               for key, value in self.estimates.items()):
            raise ValueError("Each repository ID requires a typed measured memory estimate")
        # Freeze caller-owned mappings so concurrent changes cannot alter admission.
        from types import MappingProxyType
        object.__setattr__(self, "estimates", MappingProxyType(dict(self.estimates)))

    @property
    def base_bytes(self) -> int:
        return self.parent_bytes + self.parse_bytes + self.linking_bytes


class FleetMemoryLedger:
    def __init__(self, policy: FleetMemoryPolicy):
        self.policy = policy
        self._lock = RLock()
        self._active: dict[str, FleetReservation] = {}
        self._retained: dict[str, int] = {}
        self._blocked = False
        self._cancelled = False
        self._peak_reserved = policy.base_bytes

    def _used(self) -> int:
        return (self.policy.base_bytes + sum(self._retained.values()) +
                sum(r.estimate.live_bytes + r.estimate.retained_bytes for r in self._active.values()))

    def reserve(self, key: str) -> FleetReservation | None:
        with self._lock:
            if self._cancelled:
                raise FleetAdmissionError("fleet_admission_cancelled", "Fleet admission cancelled")
            if self._blocked:
                raise FleetAdmissionError("fleet_cleanup_unknown", "Previous worker cleanup is unverified; no further admission")
            estimate = self.policy.estimates.get(key)
            if estimate is None:
                raise FleetAdmissionError("fleet_memory_unknown", f"No measured memory reservation for {key}")
            if key in self._active or key in self._retained:
                raise ValueError(f"Duplicate child admission: {key}")
            charge = estimate.live_bytes + estimate.retained_bytes
            # If retained parent results alone prevent admission, waiting cannot help.
            if self.policy.base_bytes + sum(self._retained.values()) + charge > self.policy.total_bytes:
                raise FleetAdmissionError("fleet_memory_capacity", f"Memory reservation for {key} cannot fit alongside retained results")
            if self._used() + charge > self.policy.total_bytes:
                return None
            reservation = FleetReservation(self, key, estimate)
            self._active[key] = reservation
            self._peak_reserved = max(self._peak_reserved, self._used())
            return reservation

    def cancel(self):
        with self._lock:
            self._cancelled = True

    def verified_cleanup(self, reservation: FleetReservation):
        with self._lock:
            reservation.process_cleanup_verified = True
            if reservation.cleanup_unknown:
                self.settle(reservation, cleanup_verified=True, keep_result=False)

    def settle(self, reservation: FleetReservation, *, cleanup_verified: bool, keep_result: bool):
        with self._lock:
            if reservation.settled:
                return
            # A verified callback racing an uncertainty report always wins.
            cleanup_verified = cleanup_verified or reservation.process_cleanup_verified
            if not cleanup_verified:
                self._blocked = True
                reservation.cleanup_unknown = True
                with _quarantine_lock:
                    _quarantined.add(self)
                return  # preserve the whole charge until cleanup can be verified
            if keep_result:
                self._retained[reservation.key] = reservation.estimate.retained_bytes
            self._active.pop(reservation.key)
            reservation.settled = True
            if not any(r.cleanup_unknown for r in self._active.values()):
                with _quarantine_lock:
                    _quarantined.discard(self)

    def snapshot(self) -> dict:
        with self._lock:
            return {"policy": "opt_in_measured_reservations", "os_enforced": False,
                    "memory_qualification": "reservation_estimates_only",
                    "total_bytes": self.policy.total_bytes, "headroom_bytes": self.policy.base_bytes,
                    "parent_headroom_bytes": self.policy.parent_bytes,
                    "parse_headroom_bytes": self.policy.parse_bytes,
                    "linking_headroom_bytes": self.policy.linking_bytes,
                    "reserved_bytes": self._used(), "peak_reserved_bytes": self._peak_reserved,
                    "retained_result_bytes": sum(self._retained.values()),
                    "active_children": list(self._active),
                    "cleanup_unknown": any(r.cleanup_unknown for r in self._active.values()),
                    "admission_stopped_after_cleanup_uncertainty": self._blocked,
                    "cancelled": self._cancelled,
                    "estimates": {key: {"live_bytes": value.live_bytes, "retained_bytes": value.retained_bytes,
                                         "result_bytes_limit": value.result_bytes_limit, "evidence_id": value.evidence_id}
                                  for key, value in self.policy.estimates.items()}}


@dataclass
class FleetReservation:
    ledger: FleetMemoryLedger
    key: str
    estimate: FleetMemoryEstimate
    settled: bool = False
    cleanup_unknown: bool = False
    process_cleanup_verified: bool = True  # no process has been started yet


_reservation: ContextVar[FleetReservation | None] = ContextVar("fleet_memory_reservation", default=None)


def current_reservation() -> FleetReservation | None:
    return _reservation.get()


@contextmanager
def reservation_scope(reservation: FleetReservation | None) -> Iterator[None]:
    token = _reservation.set(reservation)
    try:
        yield
    finally:
        _reservation.reset(token)
