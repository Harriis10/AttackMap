"""Bounded retention of completed report generations (AM043/C30).

Retention keeps the newest completed generations plus a soft byte budget per
output base. Cleanup never removes the current generation (named by the
pointer, validated or not), pinned runs, or runs a caller reports as active.
Only directories positively identified as finalized AttackMap generations are
ever deletion candidates; staged runs, diagnostics, compatibility exports, and
user files are left untouched. A finalized generation that no longer validates
is treated as an interrupted-cleanup leftover and removed unless protected.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .artifact_manifest import ARTIFACT_TYPE, MANIFEST_FILENAME, PINS_FILENAME, SCHEMA_VERSION
from .artifact_publisher import (
    _bounded_diagnostic_json,
    _component,
    _safe,
    current_generation,
    validate_generation,
)
from .safe_fs import safe_write_text

DEFAULT_KEEP_COMPLETED = 20
DEFAULT_SOFT_BUDGET_BYTES = 2 * 1024**3  # 2 GiB soft budget per output base.
_PINS_MAX = 10_000
_PINS_READ_LIMIT = 100_000

# Retention reasons for retained generations.
_REASON_CURRENT = "current"
_REASON_PINNED = "pinned"
_REASON_ACTIVE = "active"
_REASON_RECENT = "recent"
_REASON_UNREADABLE = "unreadable"
# Reasons for deleted generations.
_REASON_BEYOND_WINDOW = "beyond_keep_completed"
_REASON_BUDGET = "over_soft_budget"
_REASON_LEFTOVER = "interrupted_cleanup"


@dataclass(frozen=True)
class GenerationRecord:
    run_id: str
    folder: Path
    created_at: str
    size_bytes: int  # -1 when the directory cannot be measured.
    valid: bool  # passes full generation validation.
    finalized: bool  # manifest marks the generation as immutable.


@dataclass(frozen=True)
class GenerationAction:
    run_id: str
    reason: str
    size_bytes: int
    error: str | None = None


@dataclass(frozen=True)
class RetentionResult:
    keep_completed: int
    soft_budget_bytes: int
    dry_run: bool
    retained: list[GenerationAction]
    deleted: list[GenerationAction]
    bytes_freed: int
    protected_bytes: int
    budget_overage_bytes: int
    non_generation_children: int


def read_pins(base: Path) -> set[str]:
    """Return pinned run IDs; a corrupt pins file raises instead of guessing."""
    path = _safe(Path(base) / PINS_FILENAME)
    if not path.exists():
        return set()
    payload = _bounded_diagnostic_json(path) if path.stat().st_size <= _PINS_READ_LIMIT else None
    if payload is None:
        raise ValueError("Pinned generations metadata is unreadable")
    pinned = payload.get("pinned")
    if (payload.get("schema_version") != "1.0" or not isinstance(pinned, list)
            or len(pinned) > _PINS_MAX or len(set(pinned)) != len(pinned)):
        raise ValueError("Invalid pinned generations metadata")
    for name in pinned:
        if not isinstance(name, str):
            raise ValueError("Invalid pinned generations metadata")
        _component(name)
    return set(pinned)


def _write_pins(base: Path, pins: set[str]) -> None:
    payload = {"schema_version": "1.0", "pinned": sorted(pins)}
    tmp = _safe(Path(base) / f".pins-{uuid.uuid4().hex}.tmp")
    safe_write_text(base, tmp, json.dumps(payload, indent=2) + "\n")
    with tmp.open("r+b") as handle:
        os.fsync(handle.fileno())
    os.replace(tmp, _safe(Path(base) / PINS_FILENAME))


def pin_generation(base: Path, run_id: str) -> set[str]:
    """Pin an existing finalized generation so cleanup always keeps it."""
    pins = read_pins(base)
    if run_id in pins:
        return pins
    record = _find_generation(base, run_id)
    if record is None or not record.valid or not record.finalized:
        raise ValueError("Cannot pin an unknown, incomplete, or invalid generation")
    pins.add(_component(run_id))
    _write_pins(base, pins)
    return pins


def unpin_generation(base: Path, run_id: str) -> set[str]:
    pins = read_pins(base)
    if run_id not in pins:
        raise ValueError("Generation is not pinned")
    pins.remove(run_id)
    _write_pins(base, pins)
    return pins


def _directory_size(folder: Path) -> int:
    total = 0
    stack = [folder]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    else:
                        total += entry.stat(follow_symlinks=False).st_size
        except OSError:
            return -1
    return total


def _generation_record(folder: Path, run_id: str) -> GenerationRecord | None:
    """Classify one child directory; ``None`` means "not a finalized generation"."""
    manifest_path = folder / MANIFEST_FILENAME
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file():
            return None
        manifest = _bounded_diagnostic_json(manifest_path)
        if (manifest.get("artifact_type") != ARTIFACT_TYPE
                or manifest.get("schema_version") != SCHEMA_VERSION
                or manifest.get("generation_id") != run_id):
            return None
        finalized = manifest.get("publication", {}).get("immutable") is True
        if not finalized:
            return None  # Staged but unpublished: owned by its active run.
    except (OSError, ValueError, TypeError):
        return None
    try:
        validate_generation(folder)
        valid = True
    except (OSError, ValueError, TypeError):
        valid = False
    return GenerationRecord(run_id=run_id, folder=folder,
                            created_at=str(manifest.get("created_at", "")),
                            size_bytes=_directory_size(folder), valid=valid, finalized=True)


def enumerate_generations(base: Path) -> tuple[list[GenerationRecord], int]:
    """List finalized generations under *base* plus the count of other child directories.

    Non-directory entries (pointer, marker, compatibility exports) are expected
    and not counted. Symlinked directories are never recognized.
    """
    base = Path(base)
    records: list[GenerationRecord] = []
    non_generation = 0
    if not base.is_dir():
        return records, non_generation
    with os.scandir(base) as entries:
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            if entry.name == "diagnostics":
                continue  # Engine-owned failure records, not generations.
            record = _generation_record(Path(entry.path), entry.name)
            if record is None:
                non_generation += 1
            else:
                records.append(record)
    records.sort(key=lambda record: (record.created_at, record.run_id))
    return records, non_generation


def _find_generation(base: Path, run_id: str) -> GenerationRecord | None:
    folder = _safe(Path(base) / _component(run_id))
    if not folder.is_dir():
        return None
    return _generation_record(folder, run_id)


def _pointer_named_generation(base: Path) -> str | None:
    try:
        pointer = _bounded_diagnostic_json(_safe(Path(base) / "current-generation.json"))
        value = pointer.get("generation")
        return _component(value) if isinstance(value, str) else None
    except (OSError, ValueError, TypeError):
        return None


def apply_retention(base: Path, *,
                    keep_completed: int = DEFAULT_KEEP_COMPLETED,
                    soft_budget_bytes: int = DEFAULT_SOFT_BUDGET_BYTES,
                    active_run_ids: Iterable[str] = (),
                    dry_run: bool = False) -> RetentionResult:
    """Delete old unprotected generations beyond the count window and soft budget."""
    base = Path(base)
    if keep_completed < 1:
        raise ValueError("keep_completed must keep at least the latest generation")
    if soft_budget_bytes < 1:
        raise ValueError("soft_budget_bytes must be positive")
    pins = read_pins(base)  # Corrupt metadata aborts retention before any deletion.
    active = {str(run_id) for run_id in active_run_ids}
    records, non_generation = enumerate_generations(base)

    current = current_generation(base)
    current_id = current.name if current is not None else None
    pointer_named = _pointer_named_generation(base)

    def protection(record: GenerationRecord) -> str | None:
        if record.run_id in (current_id, pointer_named):
            return _REASON_CURRENT
        if record.run_id in pins:
            return _REASON_PINNED
        if record.run_id in active:
            return _REASON_ACTIVE
        return None

    retained: list[GenerationAction] = []
    deleted: list[GenerationAction] = []
    bytes_freed = 0

    def remove(record: GenerationRecord, reason: str) -> None:
        nonlocal bytes_freed
        if record.size_bytes < 0:
            retained.append(GenerationAction(record.run_id, _REASON_UNREADABLE, record.size_bytes))
            return
        if dry_run:
            deleted.append(GenerationAction(record.run_id, reason, record.size_bytes))
            return
        try:
            shutil.rmtree(record.folder)
        except OSError as exc:
            deleted.append(GenerationAction(record.run_id, reason, record.size_bytes, error=str(exc)))
            return
        deleted.append(GenerationAction(record.run_id, reason, record.size_bytes))
        bytes_freed += record.size_bytes

    completed = [record for record in records if record.valid]
    # Finalized but invalid directories are leftovers of an interrupted cleanup
    # (or irrecoverable corruption); finish their removal unless protected.
    for record in (r for r in records if not r.valid):
        guarded = protection(record)
        if guarded is not None:
            retained.append(GenerationAction(record.run_id, guarded, record.size_bytes))
        elif record.size_bytes < 0:
            retained.append(GenerationAction(record.run_id, _REASON_UNREADABLE, record.size_bytes))
        else:
            remove(record, _REASON_LEFTOVER)

    recent_ids = {record.run_id for record in completed[-keep_completed:]}
    kept: list[GenerationRecord] = []
    for record in completed:
        guarded = protection(record)
        if guarded is not None:
            retained.append(GenerationAction(record.run_id, guarded, record.size_bytes))
        elif record.run_id not in recent_ids:
            remove(record, _REASON_BEYOND_WINDOW)
        else:
            kept.append(record)

    protected_ids = {current_id, pointer_named, *pins, *active}
    protected_bytes = sum(record.size_bytes for record in records
                          if record.size_bytes > 0 and record.run_id in protected_ids)
    retained_bytes = sum(record.size_bytes for record in kept if record.size_bytes > 0) + protected_bytes
    # Soft budget: trim the oldest unprotected retained generations first.
    for record in kept:
        if retained_bytes <= soft_budget_bytes:
            break
        if protection(record) is not None:
            continue
        remove(record, _REASON_BUDGET)
        if record.size_bytes > 0:
            retained_bytes -= record.size_bytes
    for record in kept:
        if record.folder.exists() or dry_run:
            reason = protection(record) or _REASON_RECENT
            if not any(action.run_id == record.run_id for action in deleted + retained):
                retained.append(GenerationAction(record.run_id, reason, record.size_bytes))

    return RetentionResult(
        keep_completed=keep_completed, soft_budget_bytes=soft_budget_bytes, dry_run=dry_run,
        retained=retained, deleted=deleted, bytes_freed=bytes_freed,
        protected_bytes=protected_bytes,
        budget_overage_bytes=max(0, protected_bytes - soft_budget_bytes),
        non_generation_children=non_generation,
    )


def retain_after_publish(base: Path, *,
                         keep_completed: int = DEFAULT_KEEP_COMPLETED,
                         soft_budget_bytes: int = DEFAULT_SOFT_BUDGET_BYTES,
                         active_run_ids: Iterable[str] = (),
                         echo: Callable[..., None] | None = None) -> RetentionResult | None:
    """Apply retention after a successful publication; failures never fail the scan."""
    try:
        return apply_retention(base, keep_completed=keep_completed,
                               soft_budget_bytes=soft_budget_bytes, active_run_ids=active_run_ids)
    except Exception as exc:  # Best-effort cleanup after a committed publication.
        if echo is not None:
            echo(f"Warning: generation retention skipped: {exc}", err=True)
        return None
