"""Preview, explicitly apply, and undo a reasoned exact-ID suppression.

Plans/receipts are local configuration snapshots, not authorization tokens.
The caller retains the receipt for undo and confirms apply separately.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import date, datetime, timezone
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

import yaml

from .finding_identity import finding_id, identity_migration_note, identity_scheme, legacy_finding_id
from .models import Finding
from .safe_fs import UnsafePathError

_NAMES = (".attackmap-suppress.yaml", ".attackmap-suppress.yml")
_LIMIT = 2_000_000
_VERSION = "1.0"


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _safe_root(repo_root: str | Path) -> Path:
    root = Path(repo_root).absolute()
    for path in (root, *root.parents):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise UnsafePathError("Suppression actions cannot use redirected repository paths")
    if not root.is_dir():
        raise ValueError("Repository directory is unavailable")
    return root


def _target(root: Path, relative: str) -> Path:
    if relative not in _NAMES:
        raise UnsafePathError("Suppression actions only write the repository suppression file")
    path = root / relative
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise UnsafePathError("Suppression file cannot be redirected")
    if path.exists() and not path.is_file():
        raise UnsafePathError("Suppression destination is not a regular file")
    return path


def _read(path: Path) -> str | None:
    if not path.exists():
        return None
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        raw = stream.read(_LIMIT + 1)
    if len(raw) > _LIMIT:
        raise ValueError("Suppression file exceeds the local action size limit")
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Suppression file must be UTF-8") from exc


def _text(value, name: str, *, required: bool = False, maximum: int = 2000) -> str:
    if not isinstance(value, str) or "\0" in value or len(value) > maximum:
        raise ValueError(f"Invalid suppression {name}")
    result = value.strip()
    if required and not result:
        raise ValueError(f"Suppression {name} is required")
    return result


def _record(finding: Finding | Mapping) -> dict:
    if isinstance(finding, Finding):
        finding = finding.model_dump(mode="json")
    if not isinstance(finding, Mapping):
        raise ValueError("Finding must be a recorded finding object")
    record = {key: finding.get(key) for key in ("title", "rule_id", "entity_id", "id")}
    record["title"] = _text(record["title"], "finding title", required=True)
    if record["rule_id"] is not None:
        record["rule_id"] = _text(record["rule_id"], "rule ID", maximum=200)
    if record["entity_id"] is not None:
        record["entity_id"] = _text(record["entity_id"], "entity ID", maximum=1000)
    current = finding_id(record)
    if record["id"] is not None and record["id"] not in {current, legacy_finding_id(record["title"])}:
        raise ValueError("Unrecognized finding identity; reload the report and review its reference")
    return record


def _entry(record: dict, options: dict, action_id: str, created_at: str) -> tuple[dict, dict]:
    reason = _text(options.get("reason"), "reason", required=True)
    owner = _text(options.get("owner", ""), "owner", maximum=200)
    ticket = _text(options.get("ticket", ""), "ticket", maximum=1000)
    report_run = _text(options.get("report_run_id", ""), "report run ID", maximum=200)
    origin = options.get("origin", "desktop")
    if origin not in {"desktop", "cli", "api"}:
        raise ValueError("Unsupported suppression action origin")
    if type(options.get("legacy_reviewed", False)) is not bool:
        raise ValueError("Legacy review must be an explicit boolean")
    expires = options.get("expires")
    if expires is not None:
        if not isinstance(expires, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", expires):
            raise ValueError("Suppression expiry must be an ISO date")
        try:
            date.fromisoformat(expires)
        except ValueError as exc:
            raise ValueError("Suppression expiry must be an ISO date") from exc
    identity, scheme = finding_id(record), identity_scheme(record)
    legacy = legacy_finding_id(record["title"])
    requires_review = scheme == "legacy-title/v1" or record.get("id") == legacy != identity
    review = {"finding_id": identity, "identity_scheme": scheme, "recorded_id": record.get("id"),
        "legacy_id": legacy, "legacy_review_required": requires_review,
        "legacy_reviewed": options.get("legacy_reviewed", False),
        "notice": identity_migration_note(record) or ("Legacy report ID maps to the current rule/entity identity; review this change." if requires_review else None)}
    entry = {"id": identity, "reason": reason}
    entry.update({key: value for key, value in (("owner", owner), ("ticket", ticket), ("expires", expires)) if value})
    entry["provenance"] = {"action_id": action_id, "created_at": created_at, "origin": origin,
        "report_run_id": report_run, "identity_scheme": scheme, "recorded_id": record.get("id")}
    return entry, review


def _render(before: str | None, entry: dict) -> str:
    try:
        data = yaml.safe_load(before) if before else {}
    except yaml.YAMLError as exc:
        raise ValueError("Existing suppression file is not valid YAML") from exc
    data = {} if data is None else data
    if not isinstance(data, dict) or type(data.get("version", 1)) is not int or data.get("version", 1) != 1:
        raise ValueError("Unsupported suppression file structure or version")
    entries = data.get("suppress", [])
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise ValueError("Existing suppression entries must be objects")
    if any(item.get("id") == entry["id"] for item in entries):
        raise ValueError("An exact suppression for this finding already exists")
    data["version"] = 1
    data["suppress"] = [*entries, entry]
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def _plan_id(plan: dict) -> str:
    body = {key: value for key, value in plan.items() if key not in {"plan_id", "diff"}}
    return _hash(json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode())


def preview_suppression_action(repo_root: str | Path, finding: Finding | Mapping, *, reason: str,
        owner: str = "", ticket: str = "", expires: str | None = None, report_run_id: str = "",
        origin: str = "desktop", legacy_reviewed: bool = False) -> dict:
    root = _safe_root(repo_root)
    relative = next((name for name in _NAMES if _target(root, name).exists()), _NAMES[0])
    before = _read(_target(root, relative))
    record = _record(finding)
    options = dict(reason=reason, owner=owner, ticket=ticket, expires=expires,
                   report_run_id=report_run_id, origin=origin, legacy_reviewed=legacy_reviewed)
    action_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    entry, review = _entry(record, options, action_id, created_at)
    after = _render(before, entry)
    plan = {"kind": "attackmap_suppression_plan", "schema_version": _VERSION, "action_id": action_id,
        "created_at": created_at, "repo_root": str(root), "relative_path": relative,
        "finding": record, "options": options, "entry": entry, "identity_review": review,
        "before_text": before, "after_text": after,
        "before_sha256": _hash(before.encode()) if before is not None else None,
        "after_sha256": _hash(after.encode()),
        "can_apply": not review["legacy_review_required"] or legacy_reviewed}
    plan["plan_id"] = _plan_id(plan)
    plan["diff"] = "".join(difflib.unified_diff((before or "").splitlines(keepends=True),
        after.splitlines(keepends=True), fromfile=relative, tofile=relative))
    return plan


def _validate_plan(value: Mapping) -> dict:
    if not isinstance(value, Mapping):
        raise ValueError("Suppression plan must be an object")
    plan = dict(value)
    required = {"kind", "schema_version", "action_id", "created_at", "repo_root", "relative_path",
        "finding", "options", "entry", "identity_review", "before_text", "after_text",
        "before_sha256", "after_sha256", "can_apply", "plan_id", "diff"}
    if set(plan) != required or plan["kind"] != "attackmap_suppression_plan" or plan["schema_version"] != _VERSION:
        raise ValueError("Unsupported suppression plan")
    if not isinstance(plan["action_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", plan["action_id"]):
        raise ValueError("Invalid suppression action ID")
    if not isinstance(plan["created_at"], str) or not isinstance(plan["options"], dict):
        raise ValueError("Invalid suppression plan metadata")
    if set(plan["options"]) != {"reason", "owner", "ticket", "expires", "report_run_id", "origin", "legacy_reviewed"}:
        raise ValueError("Unsupported suppression plan options")
    before, after = plan["before_text"], plan["after_text"]
    if before is not None and (not isinstance(before, str) or len(before.encode()) > _LIMIT):
        raise ValueError("Invalid suppression before snapshot")
    record = _record(plan["finding"])
    entry, review = _entry(record, plan["options"], plan["action_id"], plan["created_at"])
    if (entry != plan["entry"] or review != plan["identity_review"] or _render(before, entry) != after
            or plan["before_sha256"] != (_hash(before.encode()) if before is not None else None)
            or not isinstance(after, str) or len(after.encode()) > _LIMIT
            or plan["after_sha256"] != _hash(after.encode()) or plan["plan_id"] != _plan_id(plan)
            or plan["diff"] != "".join(difflib.unified_diff((before or "").splitlines(keepends=True),
                after.splitlines(keepends=True), fromfile=plan["relative_path"], tofile=plan["relative_path"]))
            or plan["can_apply"] is not (not review["legacy_review_required"] or review["legacy_reviewed"])):
        raise ValueError("Suppression plan changed; create a fresh preview")
    return plan


def _check_current(path: Path, expected: str | None) -> None:
    text = _read(path)
    actual = _hash(text.encode()) if text is not None else None
    if actual != expected:
        raise ValueError("Suppression file changed; create a fresh preview or review undo manually")


def _replace(root: Path, relative: str, text: str, expected: str | None) -> None:
    target = _target(_safe_root(root), relative)
    _check_current(target, expected)
    temporary = root / f".attackmap-suppression-{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    committed = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        _target(_safe_root(root), relative)
        _check_current(target, expected)
        os.replace(temporary, target)
        committed = True
    finally:
        if not committed and temporary.exists():
            temporary.unlink()


def apply_suppression_action(plan: Mapping) -> dict:
    plan = _validate_plan(plan)
    if not plan["can_apply"]:
        raise ValueError("Legacy finding identity requires explicit review before applying suppression")
    root = _safe_root(plan["repo_root"])
    recovery = recover_suppression_action(plan)
    if recovery["status"] == "applied":
        return recovery["receipt"]
    expires = plan["options"].get("expires")
    if expires and date.fromisoformat(expires) < date.today():
        raise ValueError("Suppression expiry is already past")
    if plan["relative_path"] != _NAMES[0] and _target(root, _NAMES[0]).exists():
        raise ValueError("A higher-priority suppression file appeared; create a fresh preview")
    _replace(root, plan["relative_path"], plan["after_text"], plan["before_sha256"])
    return {"kind": "attackmap_suppression_receipt", "schema_version": _VERSION,
            "status": "applied", "plan": plan}


def undo_suppression_action(receipt: Mapping) -> dict:
    if (not isinstance(receipt, Mapping) or set(receipt) != {"kind", "schema_version", "status", "plan"}
            or receipt["kind"] != "attackmap_suppression_receipt" or receipt["schema_version"] != _VERSION
            or receipt["status"] != "applied"):
        raise ValueError("Unsupported suppression receipt")
    plan = _validate_plan(receipt["plan"])
    root = _safe_root(plan["repo_root"])
    target = _target(root, plan["relative_path"])
    _check_current(target, plan["after_sha256"])
    if plan["before_text"] is None:
        _target(_safe_root(root), plan["relative_path"])
        _check_current(target, plan["after_sha256"])
        target.unlink()
    else:
        _replace(root, plan["relative_path"], plan["before_text"], plan["after_sha256"])
    return {"status": "undone", "action_id": plan["action_id"], "relative_path": plan["relative_path"]}


def recover_suppression_action(plan: Mapping) -> dict:
    """Recover interrupted action state from a durably retained validated plan."""
    plan = _validate_plan(plan)
    root = _safe_root(plan["repo_root"])
    target = _target(root, plan["relative_path"])
    text = _read(target)
    actual = _hash(text.encode()) if text is not None else None
    if actual == plan["after_sha256"]:
        return {"status": "applied", "receipt": {"kind": "attackmap_suppression_receipt",
            "schema_version": _VERSION, "status": "applied", "plan": plan},
            "message": "The saved action's exact after snapshot is present; Undo is available."}
    if actual == plan["before_sha256"]:
        return {"status": "not_applied", "message": "The original snapshot is present; no action change remains."}
    return {"status": "review_required", "message": "Suppression file differs from both snapshots; review manually without overwriting it."}


def execute_suppression_action(operation: str, payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Suppression action payload must be an object")
    if operation == "suppression_preview":
        allowed = {"repo_root", "finding", "reason", "owner", "ticket", "expires", "report_run_id", "origin", "legacy_reviewed"}
        if not {"repo_root", "finding", "reason"} <= payload.keys() or payload.keys() - allowed:
            raise ValueError("Unsupported suppression preview payload")
        plan = preview_suppression_action(**payload)
        return {"status": "preview", "message": "Review the exact finding ID and changes before applying.", "plan": plan}
    if operation == "suppression_apply" and set(payload) == {"plan"}:
        receipt = apply_suppression_action(payload["plan"])
        return {"status": "applied", "message": "Suppression saved. Rescan to update the report; retain the receipt for Undo.", "receipt": receipt}
    if operation == "suppression_undo" and set(payload) == {"receipt"}:
        result = undo_suppression_action(payload["receipt"])
        return {**result, "message": "Suppression change undone. Rescan to update the report."}
    if operation in {"suppression_recover", "suppression_undo"} and set(payload) == {"plan"}:
        recovery = recover_suppression_action(payload["plan"])
        if operation == "suppression_undo" and recovery["status"] == "applied":
            return {**undo_suppression_action(recovery["receipt"]),
                    "message": "Recovered suppression change undone. Rescan to update the report."}
        return recovery
    raise ValueError("Unsupported suppression action")
