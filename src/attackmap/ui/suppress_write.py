"""Append a suppression entry without rewriting unrelated YAML content."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def append_suppression(path: Path, entry: dict[str, Any]) -> None:
    reason = str(entry.get("reason") or "").strip()
    if not reason:
        raise ValueError("A suppression reason is required.")
    existing = path.read_text(encoding="utf-8") if path.is_file() else "version: 1\nsuppress:\n"
    if "suppress:" not in existing:
        existing = existing.rstrip() + "\nsuppress:\n"
    lines = ["  -"]
    for key in ("id", "rule", "path", "reason", "owner", "ticket", "expires"):
        if entry.get(key):
            lines.append(f"    {key}: {entry[key]}")
    paths = entry.get("paths")
    if isinstance(paths, list) and paths:
        lines.append("    paths:")
        for item in paths:
            lines.append(f"      - {item}")
    text = existing.rstrip() + "\n" + "\n".join(lines) + "\n"
    path.write_text(text, encoding="utf-8")
