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
MAX_MESSAGING_DECLARATIONS = 256
MAX_MESSAGING_REPOSITORIES = 16
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
        if (not value or len(value) > 253 or value != value.strip() or "%" in value
                or redact_text(value) != value):
            raise ValueError("Expected a literal qualified host")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            host = value.lower().removesuffix(".")
            if redact_text(host) != host:
                raise ValueError("Expected a non-secret literal qualified host")
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


class QualifiedMessagingIdentity(_Contract):
    """Exact owner-asserted Kafka topic identity; no bootstrap/alias discovery."""

    scope: str
    protocol: Literal["kafka"]
    transport: Literal["plaintext", "tls"]
    host: str
    port: int
    namespace: str
    channel: str

    @field_validator("scope", "namespace", "channel")
    @classmethod
    def literal_identifier(cls, value: str) -> str:
        return _public_identifier(value)

    @field_validator("host")
    @classmethod
    def qualified_host(cls, value: str) -> str:
        return QualifiedDatastoreIdentity.qualified_host(value)

    @field_validator("port")
    @classmethod
    def explicit_port(cls, value: int) -> int:
        return QualifiedDatastoreIdentity.explicit_port(value)


class MessagingDeclaration(_Contract):
    schema_version: Literal["1.0"]
    identity: QualifiedMessagingIdentity
    operation: Literal["publish", "consume"]
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


def extract_framework_datastore_candidates(signals, repository_root: str) -> dict:
    """Validate framework observations separately from owner assertions.

    The declaration validator supplies identity hygiene only. No owner marker is
    written back to the original observation or exposed to the fleet consumer.
    """
    candidates = []
    rejected = 0
    for signal in signals:
        if signal.properties.get("framework_datastore_candidate") != "1.0":
            continue
        if (signal.properties.get("config_format") != "rails_database_yml"
                or signal.properties.get("access_basis") != "explicit_replica_setting"
                or signal.file != "config/database.yml"
                or signal.properties.get("shared_datastore_declaration") is not None
                or {origin.analyzer for origin in signal.origins} != {"config"}):
            rejected += 1
            continue
        properties = {**signal.properties, "shared_datastore_declaration": "1.0"}
        validated = extract_shared_datastore_declarations(
            [signal.model_copy(update={"properties": properties})], repository_root)
        candidates.extend(validated["declarations"])
        rejected += validated["rejected"]
    return {"candidates": candidates, "rejected": rejected}


def project_framework_datastore_candidates(candidates) -> dict:
    """Project contextual config matches as candidates, never deployment facts.

    Separate ID domains prevent automatic facts and owner assertions from
    coalescing, including when their literal identity fields happen to match.
    """
    projected = project_shared_datastores(candidates)
    identifiers = {item["id"]: "framework-" + item["id"]
                   for collection in ("resources", "associations", "evidence", "ambiguous")
                   for item in projected[collection]}

    def separate(value, key=None):
        if isinstance(value, str):
            return identifiers.get(value, value) if key in {"id", "resource_id", "evidence_refs"} else value
        if isinstance(value, list):
            return [separate(item, key) for item in value]
        if isinstance(value, dict):
            return {field: separate(item, field) for field, item in value.items()}
        return value
    projected = separate(projected)
    projected["kind"] = "framework_datastore_candidates"
    projected["production_extraction"] = "literal_rails_database_yml"
    for resource in projected["resources"]:
        resource.update(basis="literal_framework_config", resolution="candidate")
    for association in projected["associations"]:
        association.update(basis="matching_literal_framework_config_context", resolution="candidate")
    for item in projected["unmatched"]:
        item["reason"] = "no_other_repository_has_matching_framework_config_context"
    projected["limitations"] = [
        "Rails environment names provide configuration context, not deployment identity.",
        "Matching literal framework settings are candidates; runtime connectivity and IO are unverified."]
    return projected


def extract_messaging_declarations(signals: Sequence[Any], repository_root: str) -> dict:
    """Admit explicit static declarations, never generic queue/protocol hints."""
    declarations, rejected = [], 0
    for signal in signals:
        properties = signal.properties
        if properties.get("producer_consumer_declaration") != "1.0":
            continue
        analyzers = {origin.analyzer for origin in signal.origins if origin.analyzer}
        port = properties.get("port", "")
        if (signal.kind != "protocol" or signal.evidence_kind != "static_extraction"
                or signal.source_role in {"test", "fixture", "mock", "example", "generated"}
                or signal.conflicts or len(analyzers) != 1 or any(not origin.analyzer for origin in signal.origins)
                or not re.fullmatch(r"[0-9]{1,5}", port)):
            rejected += 1
            continue
        try:
            record = MessagingDeclaration.model_validate({
                "schema_version": "1.0",
                "identity": {**{field: properties.get(field) for field in (
                    "scope", "protocol", "transport", "host", "namespace", "channel")}, "port": int(port)},
                "operation": properties.get("operation"),
                "source": {"repository_root": repository_root, "file": signal.file, "line": signal.line,
                           "observation_id": signal.observation_id, "source_analyzer": next(iter(analyzers))},
            })
        except ValidationError:
            rejected += 1
            continue
        declarations.append(record.model_dump(mode="json"))
    return {"declarations": declarations, "rejected": rejected}


def project_producer_consumer(declarations: Sequence[Mapping[str, Any]]) -> dict:
    """Match exact qualified owner declarations as declared direction only.

    A topic pair is never a verified message-delivery path. Conflicting source
    observations are quarantined before pairing across distinct repositories.
    """
    if len(declarations) > MAX_MESSAGING_DECLARATIONS:
        raise ValueError("Messaging declaration count exceeds the prepared contract limit")
    try:
        validated = [MessagingDeclaration.model_validate(record).model_dump(mode="json")
                     for record in declarations]
    except ValidationError:
        validated = None
    if validated is None:
        raise ValueError("Invalid messaging declaration; no projection was produced")
    if len({record["source"]["repository_root"] for record in validated}) > MAX_MESSAGING_REPOSITORIES:
        raise ValueError("Messaging repository count exceeds the prepared contract limit")
    by_observation: dict[tuple, dict[str, dict]] = defaultdict(dict)
    for record in validated:
        source = record["source"]
        key = (source["repository_root"], source["source_analyzer"], source["observation_id"])
        by_observation[key][_canonical(record)] = record
    evidence, qualified, ambiguous = {}, defaultdict(list), []
    for key, variants in sorted(by_observation.items()):
        refs = []
        for record in variants.values():
            reference = record["source"]
            evidence_id = _id("messaging-evidence", reference)
            evidence[evidence_id] = {"id": evidence_id, **reference}
            refs.append(evidence_id)
        if len(variants) != 1:
            ambiguous.append({"id": _id("messaging-ambiguity", key),
                              "reason": "conflicting_declarations_for_source_observation",
                              "evidence_refs": sorted(set(refs))})
            continue
        record = next(iter(variants.values()))
        qualified[_id("messaging-resource", record["identity"])].append(
            {**record, "evidence_refs": refs})
    resources, associations, unmatched = [], [], []
    for resource_id, records in sorted(qualified.items()):
        by_operation = {operation: defaultdict(list) for operation in ("publish", "consume")}
        for record in records:
            by_operation[record["operation"]][record["source"]["repository_root"]].append(record)
        resources.append({"id": resource_id, "identity": records[0]["identity"],
                          "basis": "explicit_static_declarations", "resolution": "declared",
                          "repository_count": len({record["source"]["repository_root"] for record in records})})
        paired = set()
        for publisher, producers in sorted(by_operation["publish"].items()):
            for consumer, consumers in sorted(by_operation["consume"].items()):
                if publisher == consumer:
                    continue
                endpoints = [{"repository_root": root, "operation": operation,
                              "evidence_refs": sorted({ref for record in observations for ref in record["evidence_refs"]})}
                             for root, operation, observations in (
                                 (publisher, "publish", producers), (consumer, "consume", consumers))]
                paired.update(((publisher, "publish"), (consumer, "consume")))
                associations.append({"id": _id("producer-consumer", [resource_id, publisher, consumer]),
                    "kind": "producer_consumer", "resource_id": resource_id, "directed": True,
                    "resolution": "declared", "basis": "matching_explicit_qualified_topic_declarations",
                    "endpoints": endpoints,
                    "evidence_refs": sorted({ref for endpoint in endpoints for ref in endpoint["evidence_refs"]})})
        for operation, repositories in sorted(by_operation.items()):
            for root, observations in sorted(repositories.items()):
                if (root, operation) not in paired:
                    unmatched.append({"id": _id("messaging-unmatched", [resource_id, root, operation]),
                        "resource_id": resource_id, "repository_root": root, "operation": operation,
                        "reason": "no_other_repository_declares_complementary_operation",
                        "evidence_refs": sorted({ref for record in observations for ref in record["evidence_refs"]})})
    return {"schema_version": "1.0", "kind": "producer_consumer_declarations",
            "production_extraction": "explicit_normalized_messaging_signals",
            "resources": resources, "associations": sorted(associations, key=lambda item: item["id"]),
            "evidence": sorted(evidence.values(), key=lambda item: item["id"]),
            "unmatched": sorted(unmatched, key=lambda item: item["id"]), "ambiguous": ambiguous,
            "limitations": ["Only explicit qualified Kafka topic owner declarations are supported; general messaging connectivity remains unanalysed.",
                            "Declared direction does not establish runtime connectivity, delivery, subscription, ordering or continuous data flow."]}


__all__ = ["DATASTORE_DECLARATION_SCHEMA_VERSION", "MAX_DATASTORE_DECLARATIONS",
           "MAX_DATASTORE_REPOSITORIES", "DatastoreDeclaration", "DatastoreSource",
           "QualifiedDatastoreIdentity", "extract_shared_datastore_declarations",
           "project_shared_datastores", "extract_framework_datastore_candidates",
           "project_framework_datastore_candidates", "MAX_MESSAGING_DECLARATIONS",
           "MAX_MESSAGING_REPOSITORIES", "QualifiedMessagingIdentity", "MessagingDeclaration",
           "extract_messaging_declarations", "project_producer_consumer"]
