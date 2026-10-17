"""Versioned finding identity and explicit migration of legacy title references."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .models import Finding

_LEGACY_DEPENDENCY = re.compile(r"^Vulnerable dependency: (\S+)@(\S+) \(([^()]+)\)$")


def dependency_entity_id(ecosystem: str, name: str, version: str) -> str:
    canonical = json.dumps([ecosystem, name, version], ensure_ascii=True, separators=(",", ":"))
    return "dependency/v1:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _field(finding: Finding | Mapping[str, Any], key: str, default=None):
    return getattr(finding, key, default) if isinstance(finding, Finding) else finding.get(key, default)


def _entity(finding: Finding | Mapping[str, Any]) -> str | None:
    explicit = _field(finding, "entity_id")
    if isinstance(explicit, str) and explicit:
        return explicit
    if _field(finding, "rule_id") == "vulnerable-dependency":
        # Exact historical core emitter format, not a similarity/rename heuristic.
        match = _LEGACY_DEPENDENCY.fullmatch(str(_field(finding, "title", "")))
        if match:
            name, version, ecosystem = match.groups()
            return dependency_entity_id(ecosystem, name, version)
    return None


def identity_migration_note(finding: Finding | Mapping[str, Any]) -> str | None:
    if not _field(finding, "rule_id"):
        return "Legacy finding without rule_id retains title identity; review title/rule renames."
    if _field(finding, "rule_id") == "vulnerable-dependency" and _entity(finding) is None:
        return "Legacy vulnerable-dependency finding has no recoverable package entity; review its reference."
    return None


def identity_scheme(finding: Finding | Mapping[str, Any]) -> str:
    if identity_migration_note(finding):
        return "legacy-title/v1"
    return "rule-entity/v2" if _entity(finding) is not None else "rule-aggregate/v2"


def legacy_finding_id(title: str) -> str:
    return hashlib.sha256(title.encode("utf-8")).hexdigest()[:16]


def finding_id(finding: Finding | Mapping[str, Any] | str) -> str:
    """Identify a rule aggregate; a string explicitly requests legacy title identity.

    Locations have their own fingerprints, so adding another instance does not
    replace the aggregate's identity. Rule-less plugin output remains legacy.
    """
    if isinstance(finding, str):
        return legacy_finding_id(finding)
    rule, title = _field(finding, "rule_id"), str(_field(finding, "title", ""))
    entity = _entity(finding)
    if not isinstance(rule, str) or not rule or identity_migration_note(finding):
        return legacy_finding_id(title)
    key = "attackmap-finding/v2\x00rule-aggregate\x00" + rule
    if entity is not None:
        key += "\x00entity\x00" + entity
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


@dataclass
class IdentityMigration:
    aliases: dict[str, str] = field(default_factory=dict)
    notices: list[str] = field(default_factory=list)


def legacy_id_aliases(records: Iterable[Mapping[str, Any]]) -> IdentityMigration:
    """Derive old-id → stable-id aliases from recorded titles and explicit rules.

    No title similarity or file rename inference is used. Ambiguous and
    rule-less records remain visible for review and never acquire an alias.
    """
    result = IdentityMigration()
    candidates: dict[str, set[str]] = {}
    for record in records:
        title, rule = record.get("title"), record.get("rule_id")
        if not isinstance(title, str) or not isinstance(rule, str) or not rule:
            result.notices.append("Legacy finding without title/rule_id cannot be migrated; review its reference.")
            continue
        note = identity_migration_note(record)
        if note:
            result.notices.append(note)
            continue
        old, new = legacy_finding_id(title), finding_id(record)
        recorded = record.get("id")
        if recorded is not None and recorded not in (old, new):
            result.notices.append(f"Unrecognized finding id {recorded!r}; review its reference.")
            continue
        candidates.setdefault(old, set()).add(new)
    for old, targets in sorted(candidates.items()):
        if len(targets) != 1:
            result.notices.append(f"Ambiguous legacy finding id {old}; review its reference.")
        else:
            result.aliases[old] = next(iter(targets))
    return result
