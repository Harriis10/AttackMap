"""Opt-in AttackMap resource declarations; never infer identity from URLs."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath

import yaml
from pydantic import ValidationError
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from .evidence import classify_source_path
from .fleet_resource_identity import (DatastoreDeclaration, MAX_DATASTORE_DECLARATIONS,
                                      MessagingDeclaration, MAX_MESSAGING_DECLARATIONS)
from .models import ScanResult, Signal, SignalOrigin

_MARKER = "attackmap_datastores"
_PREFIX = "tag:yaml.org,2002:"
_MAX_BYTES = 256_000
_MAX_EVENTS = 8192


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_json_constant(value):
    raise ValueError("Non-JSON constant")


def _mapping(node: object) -> dict:
    if not isinstance(node, MappingNode) or node.tag != _PREFIX + "map":
        raise ValueError("Expected a literal mapping")
    result = {}
    for key, value in node.value:
        if not isinstance(key, ScalarNode) or key.tag != _PREFIX + "str" or key.value in result:
            raise ValueError("Ambiguous mapping key")
        result[key.value] = value
    return result


def _literal(node: object, *, port: bool = False):
    if not isinstance(node, ScalarNode):
        raise ValueError("Expected a literal scalar")
    if port:
        if node.tag != _PREFIX + "int" or not re.fullmatch(r"[1-9][0-9]{0,4}", node.value):
            raise ValueError("Expected an explicit decimal port")
        return int(node.value)
    if node.tag != _PREFIX + "str":
        raise ValueError("Expected a literal string")
    return node.value


def extract_config_datastores(content: str, relative: str, result: ScanResult) -> None:
    _extract_config_declarations(content, relative, result, marker=_MARKER,
        contract=DatastoreDeclaration, identity_fields={"scope", "protocol", "host", "port", "namespace", "resource"},
        family="datastore", kind="database", property_marker="shared_datastore_declaration",
        limit=MAX_DATASTORE_DECLARATIONS)


def extract_config_messaging(content: str, relative: str, result: ScanResult) -> None:
    _extract_config_declarations(content, relative, result, marker="attackmap_messaging",
        contract=MessagingDeclaration, identity_fields={"scope", "protocol", "transport", "host", "port", "namespace", "channel"},
        family="messaging", kind="protocol", property_marker="producer_consumer_declaration",
        limit=MAX_MESSAGING_DECLARATIONS)


def _extract_config_declarations(content: str, relative: str, result: ScanResult, *,
        marker: str, contract: type, identity_fields: set[str], family: str,
        kind: str, property_marker: str, limit: int) -> None:
    """Emit only versioned opt-in YAML/JSON declarations with exact source marks.

    Parse no credentials, perform no substitution, and never retain rejected
    values or parser errors. Bounded event validation rejects aliases and deep
    documents before composing a node tree (no YAML object construction).
    """
    if PurePosixPath(relative).suffix.lower() not in {".yaml", ".yml", ".json"} or marker not in content:
        return
    if classify_source_path(relative) in {"test", "fixture", "mock", "example", "generated"}:
        return
    try:
        if len(content.encode("utf-8")) > _MAX_BYTES:
            raise ValueError("Declaration file exceeds bound")
        if PurePosixPath(relative).suffix.lower() == ".json":
            json.loads(content, object_pairs_hook=_unique_object, parse_constant=_invalid_json_constant)
        depth = 0
        for count, event in enumerate(yaml.parse(content, Loader=yaml.SafeLoader), 1):
            if count > _MAX_EVENTS or isinstance(event, yaml.events.AliasEvent):
                raise ValueError("Ambiguous or oversized document")
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
                if depth > 32:
                    raise ValueError("Document exceeds depth bound")
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
        root = _mapping(yaml.compose(content, Loader=yaml.SafeLoader))
        if marker not in root:
            return
        envelope = _mapping(root[marker])
        if set(envelope) != {"schema_version", "declarations"} or _literal(envelope["schema_version"]) != "1.0":
            raise ValueError("Unknown declaration envelope")
        declarations = envelope["declarations"]
        if (not isinstance(declarations, SequenceNode) or declarations.tag != _PREFIX + "seq"
                or len(declarations.value) > limit):
            raise ValueError("Expected bounded declarations")
        # Validate the entire file before emitting; one malformed declaration
        # cannot leave an apparently complete partial set behind.
        pending = []
        role = classify_source_path(relative)
        for ordinal, node in enumerate(declarations.value):
            fields = _mapping(node)
            if set(fields) != {"identity", "operation"}:
                raise ValueError("Unknown declaration fields")
            identity = _mapping(fields["identity"])
            if set(identity) != identity_fields:
                raise ValueError("Incomplete qualified identity")
            values = {key: _literal(value, port=key == "port") for key, value in identity.items()}
            line = node.start_mark.line + 1
            observation = "obs-" + hashlib.sha256(f"{relative}:{line}:{family}:{ordinal}".encode()).hexdigest()
            record = contract.model_validate({
                "schema_version": "1.0", "identity": values, "operation": _literal(fields["operation"]),
                "source": {"repository_root": result.root, "file": relative, "line": line,
                           "observation_id": observation, "source_analyzer": "config"},
            })
            properties = {property_marker: "1.0", "operation": record.operation,
                          **{key: str(value) for key, value in record.identity.model_dump().items()}}
            classification = dict(classification_version="1.0", source_role=role,
                                  evidence_kind="static_extraction", classification_basis="unknown")
            pending.append(Signal(kind=kind, label=f"declared_{family}:{line}:{ordinal}", file=relative,
                line=line, confidence=1.0, observation_id=observation, properties=properties,
                evidence_text=f"Explicit AttackMap qualified {family} declaration (static; runtime unverified).",
                origins=[SignalOrigin(analyzer="config", file=relative, line=line,
                                      properties=dict(properties), **classification)], **classification))
        result.signals.extend(pending)
    except (ValueError, ValidationError, yaml.YAMLError, RecursionError):
        note = f"An opt-in {family} declaration file was rejected: malformed, ambiguous, unsupported, secret-bearing, or beyond extraction bounds."
        if note not in result.limitations:
            result.limitations.append(note)
