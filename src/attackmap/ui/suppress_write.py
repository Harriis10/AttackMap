"""Append a suppression entry safely, without YAML injection or symlink escape."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..safe_fs import UnsafePathError, safe_write_text
from ..suppress import _FINDING_ID_RE, is_match_everything_glob


def _validate_suppression_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a suppression entry.

    Mirrors the rules in ``attackmap.suppress.parse_suppress_text`` so the GUI
    cannot write an entry the CLI would later reject.
    """
    reason = str(entry.get("reason") or "").strip()
    if not reason:
        raise ValueError("A suppression reason is required.")

    normalized: dict[str, Any] = {"reason": reason}

    sup_id = entry.get("id")
    if sup_id is not None:
        if not isinstance(sup_id, str):
            raise ValueError("'id' must be a 16-hex finding id string")
        sup_id = sup_id.strip()
        if not _FINDING_ID_RE.match(sup_id):
            raise ValueError(f"'id' {sup_id!r} is not a 16-hex finding id")
        normalized["id"] = sup_id

    rule = entry.get("rule")
    if rule is not None:
        if not isinstance(rule, str) or not rule.strip():
            raise ValueError("'rule' must be a rule id string")
        normalized["rule"] = rule.strip()

    paths = entry.get("paths", entry.get("path"))
    if paths is not None:
        if isinstance(paths, str):
            glob_list = [paths]
        elif isinstance(paths, list) and all(isinstance(p, str) for p in paths):
            glob_list = [p for p in paths if isinstance(p, str)]
        else:
            raise ValueError("'paths' must be a string or a list of strings")
        glob_list = [g.strip() for g in glob_list if g.strip()]
        for g in glob_list:
            if is_match_everything_glob(g):
                raise ValueError(
                    f"path {g!r} would suppress every file in the repo; scope it"
                )
        normalized["paths"] = glob_list

    expires = entry.get("expires")
    if expires is not None:
        from datetime import date

        if isinstance(expires, date):
            expires = expires.isoformat()
        if not isinstance(expires, str):
            raise ValueError("'expires' must be a YYYY-MM-DD date")
        try:
            date.fromisoformat(expires.strip())
        except ValueError as exc:
            raise ValueError("'expires' must be a YYYY-MM-DD date") from exc
        normalized["expires"] = expires.strip()

    for key in ("owner", "ticket"):
        value = entry.get(key)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"'{key}' must be a string")
            normalized[key] = value.strip() or None

    if normalized.get("owner") is None:
        normalized.pop("owner", None)
    if normalized.get("ticket") is None:
        normalized.pop("ticket", None)

    if not (normalized.get("id") or normalized.get("rule") or normalized.get("paths")):
        raise ValueError("entry must have at least one selector: id, rule, or path/paths")

    return normalized


def append_suppression(path: Path, entry: dict[str, Any], *, root: Path | None = None) -> None:
    """Append *entry* to the suppress file at *path*.

    Validates the entry, serializes it with ``yaml.safe_dump``, and writes it
    through ``safe_write_text`` so symlinks/junctions and out-of-repo paths are
    refused.
    """
    normalized = _validate_suppression_entry(entry)
    root = root or path.parent

    if path.is_file():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"existing suppress file is not valid YAML: {exc}") from exc
    else:
        data = {}

    if not isinstance(data, dict):
        raise ValueError("existing suppress file must be a YAML mapping")

    version = data.get("version", 1)
    if version != 1:
        raise ValueError(f"unsupported suppress file version: {version!r}")

    entries = data.get("suppress", [])
    if not isinstance(entries, list):
        raise ValueError("existing 'suppress' key must be a list")

    entries.append(normalized)
    data["version"] = 1
    data["suppress"] = entries

    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    try:
        safe_write_text(root, path, text)
    except UnsafePathError as exc:
        raise ValueError(str(exc)) from exc
