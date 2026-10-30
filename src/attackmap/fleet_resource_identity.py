"""Qualified static datastore declaration extraction and pure projection.

Only explicit normalized signals are accepted. This module never parses
connection strings, source snippets, legacy hints or environment values, and a
match establishes neither runtime connectivity nor data flow.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import posixpath
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from itertools import combinations
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from .redact import redact_text


DATASTORE_DECLARATION_SCHEMA_VERSION = "1.0"
MAX_DATASTORE_DECLARATIONS = 256
MAX_DATASTORE_REPOSITORIES = 16
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def _public_identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value) or redact_text(value) != value:
        raise ValueError("Expected a non-secret literal identifier")
    if value.lower() in {"unknown", "unresolved", "redacted"}:
        raise ValueError("Unresolved identity is not a qualified declaration")
    return value


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)


class QualifiedDatastoreIdentity(_Contract):
    scope: str
    protocol: Literal["postgresql", "mysql", "mongodb", "redis"]
    host: str
    port: int
    namespace: str
    resource: str

    @field_validator("scope", "namespace", "resource")
    @classmethod
    def literal_identifier(cls, value: str) -> str:
        return _public_identifier(value)

    @field_validator("port")
    @classmethod
    def explicit_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("An explicit valid port is required")
        return value

    @field_validator("host")
    @classmethod
    def qualified_host(cls, value: str) -> str:
        # No URI parsing: userinfo, paths, query strings and substitutions are
        # inadmissible, including secrets hidden in otherwise valid URLs.
        if not value or len(value) > 253 or value != value.strip() or "%" in value:
            raise ValueError("Expected a literal qualified host")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            host = value.lower().removesuffix(".")
            labels = host.split(".")
            if len(labels) < 2 or not re.search(r"[a-z]", labels[-1]) or host.endswith(".localhost") or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                raise ValueError("Expected a literal qualified host") from None
            return host
        unicast = getattr(address, "ipv4_mapped", None) or address
        if (unicast.is_loopback or unicast.is_unspecified or unicast.is_link_local or unicast.is_multicast
                or (unicast.version == 4 and int(unicast) == 0xFFFFFFFF)):
            raise ValueError("Host-local or non-unicast addresses do not establish shared identity")
        return address.compressed


class DatastoreSource(_Contract):
    repository_root: str
    file: str
    line: int
    observation_id: str
    source_analyzer: str

    @field_validator("observation_id", "source_analyzer")
    @classmethod
    def literal_identifier(cls, value: str) -> str:
        return _public_identifier(value)

    @field_validator("repository_root")
    @classmethod
    def absolute_root(cls, value: str) -> str:
        if len(value) > 4096 or any(ord(char) < 32 for char in value) or redact_text(value) != value:
            raise ValueError("Expected a non-secret absolute repository root")
        if re.match(r"^[A-Za-z]:[\\/]", value):
            if any(part.endswith((".", " ")) for part in re.split(r"[\\/]", value[3:])):
                raise ValueError("Windows repository components must not end in a dot or space")
            return ntpath.normcase(ntpath.normpath(value)).replace("\\", "/")
        if not value.startswith("/") or value.startswith("//") or "\\" in value:
            raise ValueError("Expected an absolute local repository root")
        return posixpath.normpath(value)

    @field_validator("file")
    @classmethod
    def relative_file(cls, value: str) -> str:
        value = value.replace("\\", "/")
        if (not value or len(value) > 4096 or value.startswith("/") or ":" in value
                or any(part in {"", ".", ".."} for part in value.split("/"))
                or any(ord(char) < 32 for char in value) or redact_text(value) != value):
            raise ValueError("Expected a non-secret repository-relative source file")
        return value

    @field_validator("line")
    @classmethod
    def known_line(cls, value: int) -> int:
        if value < 1:
            raise ValueError("A positive source line is required")
        return value


class DatastoreDeclaration(_Contract):
    schema_version: Literal["1.0"]
    identity: QualifiedDatastoreIdentity
    operation: Literal["read", "write", "read_write"]
    source: DatastoreSource


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _id(kind: str, value: Any) -> str:
    return kind + "-" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def extract_shared_datastore_declarations(signals: Sequence[Any], repository_root: str) -> dict:
    """Adapt only explicit qualified normalized database signals.

    Legacy database hints, incomplete declarations, conflicting observations and
    ambiguous producer metadata are rejected without exporting their raw values.
    """
    declarations, rejected = [], 0
    identity_fields = ("scope", "protocol", "host", "namespace", "resource")
    for signal in signals:
        properties = signal.properties
        if (signal.kind != "database"
                or properties.get("shared_datastore_declaration") != DATASTORE_DECLARATION_SCHEMA_VERSION):
            continue
        # Unknown remains eligible for the explicit static/declared contract;
        # known non-production observations cannot establish fleet associations.
        if signal.source_role in {"test", "fixture", "mock", "example"}:
            rejected += 1
            continue
        analyzers = {origin.analyzer for origin in signal.origins if origin.analyzer}
        port = properties.get("port", "")
        if (signal.evidence_kind != "static_extraction" or signal.conflicts
                or len(analyzers) != 1 or not re.fullmatch(r"[0-9]{1,5}", port)):
            rejected += 1
            continue
        record = {
            "schema_version": DATASTORE_DECLARATION_SCHEMA_VERSION,
            "identity": {**{field: properties.get(field) for field in identity_fields},
                         "port": int(port)},
            "operation": properties.get("operation"),
            "source": {"repository_root": repository_root, "file": signal.file,
                       "line": signal.line, "observation_id": signal.observation_id,
                       "source_analyzer": next(iter(analyzers))},
        }
        try:
            validated = DatastoreDeclaration.model_validate(record)
        except ValidationError:
            rejected += 1
            continue
        declarations.append(validated.model_dump(mode="json"))
    return {"declarations": declarations, "rejected": rejected}


def project_shared_datastores(declarations: Sequence[Mapping[str, Any]]) -> dict:
    """Validate all records before projecting declared, undirected associations.

    Matching requires every identity field, and both sides must carry their own
    source reference. Conflicting declarations for one analyzer observation are
    quarantined; one repository alone never establishes a shared resource.
    """
    if len(declarations) > MAX_DATASTORE_DECLARATIONS:
        raise ValueError("Shared datastore declaration count exceeds the prepared contract limit")
    try:
        validated = [DatastoreDeclaration.model_validate(record).model_dump(mode="json")
                     for record in declarations]
    except ValidationError:
        validated = None
    # Raise outside the handler so neither the message nor exception context
    # retains a raw Pydantic input (its errors()/json() expose inputs by default).
    if validated is None:
        raise ValueError("Invalid shared datastore declaration; no projection was produced")
    if len({record["source"]["repository_root"] for record in validated}) > MAX_DATASTORE_REPOSITORIES:
        raise ValueError("Shared datastore repository count exceeds the prepared contract limit")
    by_observation: dict[tuple, dict[str, dict]] = defaultdict(dict)
    for record in validated:
        source = record["source"]
        key = (source["repository_root"], source["source_analyzer"], source["observation_id"])
        by_observation[key][_canonical(record)] = record

    qualified: dict[str, list[dict]] = defaultdict(list)
    evidence: dict[str, dict] = {}
    ambiguous = []
    for key, variants in sorted(by_observation.items()):
        refs = []
        for record in variants.values():
            reference = record["source"]
            evidence_id = _id("datastore-evidence", reference)
            evidence[evidence_id] = {"id": evidence_id, **reference}
            refs.append(evidence_id)
        if len(variants) != 1:
            ambiguous.append({"id": _id("datastore-ambiguity", key),
                              "reason": "conflicting_declarations_for_source_observation",
                              "evidence_refs": sorted(set(refs))})
            continue
        record = next(iter(variants.values()))
        resource_id = _id("datastore-resource", record["identity"])
        qualified[resource_id].append({**record, "evidence_refs": refs})

    resources, associations, unmatched = [], [], []
    for resource_id, records in sorted(qualified.items()):
        by_root: dict[str, list[dict]] = defaultdict(list)
        for record in records:
            by_root[record["source"]["repository_root"]].append(record)
        resources.append({"id": resource_id, "identity": records[0]["identity"],
                          "basis": "explicit_static_declarations", "resolution": "declared",
                          "repository_count": len(by_root)})
        if len(by_root) == 1:
            unmatched.append({"resource_id": resource_id, "reason": "no_other_repository_declares_resource",
                              "evidence_refs": sorted({ref for record in records for ref in record["evidence_refs"]})})
        for left, right in combinations(sorted(by_root), 2):
            endpoints = [{"repository_root": root,
                          "operations": sorted({record["operation"] for record in by_root[root]}),
                          "evidence_refs": sorted({ref for record in by_root[root] for ref in record["evidence_refs"]})}
                         for root in (left, right)]
            associations.append({"id": _id("shared-datastore", [resource_id, left, right]),
                                 "kind": "shared_datastore", "resource_id": resource_id,
                                 "directed": False, "resolution": "declared",
                                 "basis": "matching_explicit_qualified_resource_declarations",
                                 "endpoints": endpoints,
                                 "evidence_refs": sorted({ref for endpoint in endpoints for ref in endpoint["evidence_refs"]})})
    return {"schema_version": DATASTORE_DECLARATION_SCHEMA_VERSION,
            "kind": "shared_datastore_declarations", "production_extraction": "normalized_database_signals",
            "resources": resources, "associations": sorted(associations, key=lambda row: row["id"]),
            "evidence": sorted(evidence.values(), key=lambda row: row["id"]),
            "unmatched": unmatched, "ambiguous": ambiguous,
            "limitations": ["Only explicit qualified normalized database signals are admitted; legacy hints remain unqualified.",
                            "Static declarations do not establish runtime connectivity or directed data flow."]}


__all__ = ["DATASTORE_DECLARATION_SCHEMA_VERSION", "MAX_DATASTORE_DECLARATIONS",
           "MAX_DATASTORE_REPOSITORIES", "DatastoreDeclaration", "DatastoreSource",
           "QualifiedDatastoreIdentity", "extract_shared_datastore_declarations",
           "project_shared_datastores"]
