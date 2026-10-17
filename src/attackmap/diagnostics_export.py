"""Redacted, source-free diagnostic export for an AttackMap output base (AM043/C30).

The export supports troubleshooting without exposing code or credentials: it
reads only manifests, run-manifest timing/diagnostic contexts, terminal
diagnostics, pin state, and a dry-run retention summary. Report sections and
their source excerpts are never read. Every free-text string is redacted and
the payload is bounded, so the preview a user inspects is byte-identical to
the bundle written by :func:`export_diagnostics`.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .artifact_manifest import MANIFEST_FILENAME
from .artifact_publisher import _bounded_diagnostic_json, current_generation
from .diagnostics import context_from_run_manifest
from .redact import redact_text
from .retention import _pointer_named_generation, apply_retention, enumerate_generations, read_pins
from .safe_fs import safe_write_text

EXPORT_SCHEMA_VERSION = "1.0"
EXPORT_TYPE = "attackmap_diagnostic_export"
EXPORT_FILENAME = "attackmap-diagnostics.json"
MAX_GENERATIONS = 50
MAX_TERMINAL_DIAGNOSTICS = 100

_TERMINAL_STATE = {"failed", "cancelled"}


def _outcome_for(status) -> str:
    return "completed" if status in {"completed", "success", "succeeded", "ok", "policy_failed"} else "unknown"


def _stage_summary(context) -> dict:
    stages = [{"stage_id": stage.stage_id, "outcome": stage.outcome,
               "duration_milliseconds": stage.duration_milliseconds}
              for stage in context.stages[:128]]
    analyzers = [{"name": analyzer.name, "version": analyzer.version,
                  "version_status": analyzer.version_status}
                 for analyzer in context.analyzers.items[:128]]
    coverage = {"status": context.coverage.status,
                "accepted_file_count": context.coverage.accepted_file_count,
                "analyzer_error_count": context.coverage.analyzer_error_count,
                "limitation_count": context.coverage.limitation_count}
    fleet = None
    if context.fleet.status != "not_started":
        fleet = {"status": context.fleet.status, "requested_count": context.fleet.requested_count,
                 "completed_count": context.fleet.completed_count, "failed_count": context.fleet.failed_count,
                 "cancelled_count": context.fleet.cancelled_count}
    return {"outcome": context.outcome, "policy_outcome": context.policy_outcome,
            "stages": stages, "analyzers": analyzers, "coverage": coverage, "fleet": fleet}


def _generation_entry(base: Path, record, *, pinned, current_id) -> dict:
    entry = {"run_id": record.run_id, "created_at": record.created_at,
             "size_bytes": record.size_bytes, "valid": record.valid,
             "current": record.run_id == current_id, "pinned": record.run_id in pinned}
    try:
        manifest = _bounded_diagnostic_json(record.folder / MANIFEST_FILENAME)
        state = manifest.get("exit_state", {})
        identity = manifest.get("run_identity", {})
        entry["status"] = state.get("status") if isinstance(state, dict) else None
        entry["exit_code"] = state.get("exit_code") if isinstance(state, dict) else None
        entry["profile"] = "fleet" if manifest.get("generation_profile") == "fleet" else "scan"
        entry["repo_root"] = redact_text(identity.get("repo_root")) if isinstance(identity, dict) else None
        entry["repo_name"] = identity.get("repo_name") if isinstance(identity, dict) else None
    except (OSError, ValueError):
        entry["manifest"] = "unreadable"
    try:
        timing = _bounded_diagnostic_json(record.folder / "run-manifest.json")
        context = context_from_run_manifest(timing, outcome=_outcome_for(entry.get("status")))
        entry["context"] = _stage_summary(context)
    except (OSError, ValueError, TypeError):
        entry["context"] = {"state": "unavailable"}
    return entry


def _terminal_entries(base: Path, limit: int) -> list[dict]:
    folder = base / "diagnostics"
    entries: list[dict] = []
    if not folder.is_dir():
        return entries
    for child in sorted(folder.iterdir(), key=lambda path: path.name, reverse=True):
        if len(entries) >= limit:
            break
        if not child.is_dir():
            continue
        try:
            payload = _bounded_diagnostic_json(child / "terminal-diagnostic.json")
        except (OSError, ValueError):
            continue
        if payload.get("run_id") != child.name or payload.get("state") not in _TERMINAL_STATE:
            continue  # Foreign file with a known name stays out of the export.
        entry = {"run_id": child.name, "state": payload.get("state"),
                 "error": redact_text(payload.get("error")) if payload.get("error") else None}
        if isinstance(payload.get("scan_timing"), dict):
            entry["scan_timing"] = payload["scan_timing"]
        try:
            context = context_from_run_manifest({"diagnostic_context": payload["diagnostic_context"]},
                                                outcome=payload.get("state"))
            entry["context"] = _stage_summary(context)
        except (KeyError, TypeError, ValueError):
            pass
        entries.append(entry)
    return entries


def _retention_posture(base: Path) -> dict:
    try:
        result = apply_retention(base, dry_run=True)
    except Exception as exc:  # Retention posture is diagnostic, never fatal.
        return {"mode": "unavailable", "error": redact_text(str(exc)) or str(exc.__class__.__name__)}
    return {"mode": "dry_run_summary", "keep_completed": result.keep_completed,
            "soft_budget_bytes": result.soft_budget_bytes,
            "retained_count": len(result.retained), "planned_deletion_count": len(result.deleted),
            "planned_bytes_freed": sum(action.size_bytes for action in result.deleted if action.size_bytes > 0),
            "protected_bytes": result.protected_bytes,
            "budget_overage_bytes": result.budget_overage_bytes,
            "non_generation_children": result.non_generation_children}


def collect_diagnostic_export(base: Path, *,
                              max_generations: int = MAX_GENERATIONS) -> dict:
    """Build the bounded, redacted export payload without writing anything."""
    base = Path(base)
    if not base.is_dir():
        raise ValueError(f"Not an AttackMap output base: {base}")
    if not 1 <= max_generations <= 500:
        raise ValueError("max_generations must be between 1 and 500")
    current = current_generation(base)
    current_id = current.name if current is not None else None
    pointer_named = _pointer_named_generation(base)
    try:
        pinned = sorted(read_pins(base))
        pins_section: dict | list = pinned
    except (OSError, ValueError) as exc:
        pins_section = {"error": redact_text(str(exc)) or "unreadable"}
        pinned = []
    records, _ = enumerate_generations(base)
    payload = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "export_type": EXPORT_TYPE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output_base": redact_text(str(base)) or str(base),
        "current_generation": ({"generation": current_id, "state": "valid"} if current_id
                               else {"generation": pointer_named, "state": "invalid"} if pointer_named
                               else {"generation": None, "state": "absent"}),
        "pinned": pins_section,
        "retention": _retention_posture(base),
        "generations": [_generation_entry(base, record, pinned=pinned, current_id=current_id)
                        for record in list(reversed(records))[:max_generations]],
        "generation_count": len(records),
        "terminal_diagnostics": _terminal_entries(base, MAX_TERMINAL_DIAGNOSTICS),
    }
    return payload


def export_diagnostics(base: Path, target: Path, *,
                       max_generations: int = MAX_GENERATIONS) -> tuple[dict, Path]:
    """Collect once and write the exact previewed payload to *target*."""
    payload = collect_diagnostic_export(base, max_generations=max_generations)
    target = Path(target)
    safe_write_text(target.parent, target, json.dumps(payload, indent=2) + "\n")
    return payload, target
