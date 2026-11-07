"""Deterministic, renderer-independent fleet architecture from supplied core facts.

This is a static projection, not a runtime reachability graph. Repository roots,
core report slugs and optional transport child IDs are separate identities. No
filesystem access, endpoint discovery, or cross-repository name matching occurs.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
import posixpath
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from .fleet_resource_identity import (MAX_DATASTORE_DECLARATIONS, MAX_DATASTORE_REPOSITORIES,
                                      extract_shared_datastore_declarations, project_shared_datastores,
                                      extract_framework_datastore_candidates, project_framework_datastore_candidates,
                                      MAX_MESSAGING_DECLARATIONS, MAX_MESSAGING_REPOSITORIES,
                                      extract_messaging_declarations, project_producer_consumer)
from .redact import redact_text
from .topology import _file_service_names, _infer_from_layout, build_service_graph

if TYPE_CHECKING:
    from .fleet import FleetScan
    from .models import ScanResult


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _id(kind: str, *identity: Any) -> str:
    return f"{kind}-" + hashlib.sha256(_canonical(identity).encode()).hexdigest()


def _root(value: str) -> str:
    # Lexical normalization only: resolving a root would read today's filesystem
    # instead of the supplied child snapshot. Windows identities are case-insensitive.
    if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith(("\\\\", "//")):
        return ntpath.normcase(ntpath.normpath(value)).replace("\\", "/")
    return posixpath.normpath(value)


def _text(value: Any) -> str:
    return redact_text(str(value)) or ""


def _line(value: Any) -> int | None:
    return value if type(value) is int and value > 0 else None


def _unique(items: list[dict]) -> list[dict]:
    return [item for _, item in sorted({_canonical(item): item for item in items}.items())]


class _Evidence:
    def __init__(self, scan: ScanResult, repo_id: str, repository_id: str):
        self.repo_id = repo_id
        self.repository_id = repository_id
        self.signals: dict[tuple[str, str], list] = defaultdict(list)
        # Preserve supplied observation IDs as well as the normalized core view.
        # Some legacy normalization paths re-key a preserved observation.
        for signal in [*scan.signals, *scan.all_signals()]:
            self.signals[signal.kind, signal.file].append(signal)

    def ref(self, kind: str, file: str | None, line: int | None = None,
            observation_id: str | None = None, source_analyzer: str | None = None) -> dict:
        source_line = _line(line) if file else None
        return {"repo_id": self.repository_id, "core_repo_id": self.repo_id,
                "kind": kind, "file": _text(file) if file else None, "line": source_line,
                "observation_id": observation_id, "source_analyzer": source_analyzer,
                "basis": "supplied_static_source_location",
                "location_status": "known" if file and source_line is not None else
                                   "file_only" if file else "unknown",
                "location_reason": None if file and source_line is not None else
                                   "file_not_supplied" if not file else
                                   "line_not_supplied" if line is None else "invalid_source_line"}

    def refs(self, kind: str, file: str, line: int | None = None,
             label: str | None = None) -> list[dict]:
        refs = [self.ref(kind, file, line)] if file else []
        for signal in self.signals.get((kind, file), ()):
            if signal.line != line or (label is not None and signal.label != label):
                continue
            refs.append(self.ref(kind, signal.file, signal.line, signal.observation_id))
            for origin in signal.origins:
                refs.append(self.ref(kind, origin.file, origin.line, signal.observation_id,
                                     origin.analyzer))
        return _unique(refs)

    def matching_refs(self, kinds: tuple[str, ...], file: str, label: str) -> list[dict]:
        refs = []
        for kind in kinds:
            for signal in self.signals.get((kind, file), ()):
                if signal.label == label:
                    refs.extend(self.refs(kind, file, signal.line, label))
        return _unique(refs) if refs else [self.ref("source_file", file)] if file else []


def build_fleet_architecture(
    fleet: FleetScan, requested_repos: Sequence[Mapping[str, Any]] | None = None,
) -> dict:
    """Project a fleet, preserving requested children even without a result.

    ``requested_repos`` records require ``root`` and may provide ``requested_id``
    (also accepted as ``child_id`` or ``id``), ``repo_id``, ``status``, and explicit
    ``run_id``, ``generation``, ``snapshot_id`` or ``report_hash``. Roots establish
    joins; a basename or transport GUID never establishes a core report slug.
    Duplicate roots, transport IDs or result roots are rejected as ambiguous.
    An explicit requested set rejects foreign result/failure roots rather than
    incorporating an unrequested or stale snapshot into the fleet generation.
    """
    requested: dict[str, dict] = {}
    transport_ids: set[str] = set()
    for record in requested_repos or ():
        root = record.get("root")
        if not isinstance(root, str) or not root:
            raise ValueError("Requested repository requires a nonempty root")
        key = _root(root)
        if key in requested:
            raise ValueError("Duplicate requested repository root")
        child_id = record.get("requested_id", record.get("child_id", record.get("id")))
        if child_id is not None:
            if not isinstance(child_id, str) or not child_id or child_id in transport_ids:
                raise ValueError("Requested repository child identity must be unique")
            transport_ids.add(child_id)
        requested[key] = dict(record, requested_id=child_id)

    results = {}
    for result in fleet.results:
        key = _root(result.root)
        if requested_repos is not None and key not in requested:
            raise ValueError("Fleet result root was not requested")
        if _root(result.scan.root) != key:
            raise ValueError("Fleet result and child snapshot roots disagree")
        if key in results:
            raise ValueError("Duplicate fleet result root")
        results[key] = result
    failures: dict[str, dict] = {}
    for failure in fleet.failed:
        key = _root(failure["root"])
        if requested_repos is not None and key not in requested:
            raise ValueError("Fleet failure root was not requested")
        if key in failures or key in results:
            raise ValueError("Conflicting fleet result/failure root")
        failures[key] = failure

    repositories: list[dict] = []
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    by_slug: dict[str, list[dict]] = defaultdict(list)
    contexts: dict[str, dict] = {}
    framework_candidates = []
    rejected_framework_candidates = 0
    datastore_declarations: list[dict] = []
    rejected_datastore_declarations = 0
    messaging_declarations = []
    rejected_messaging_declarations = 0
    limitations = {
        "Static analysis does not establish runtime reachability or control enforcement.",
        "Child snapshots are independent; fleet capture is not a globally atomic snapshot.",
        "Repository overview paths do not establish connected paths through individual services.",
        "Core service topology uses repository-local names and heuristic ownership; namespace, deployment and port identity are not established by these local nodes.",
        "Cross-repository producer/consumer identities are unanalysed: existing hints lack qualified endpoint, namespace and operation identity.",
        "Shared-datastore associations are static declarations, not runtime connectivity or directed data flow.",
        "RPC, protobuf and OpenAPI connectivity is unanalysed; names and protocol declarations do not establish links.",
    }

    def node(node_id: str, repo_id: str | None, kind: str, label: str,
             refs: list[dict], **extra: Any) -> None:
        nodes[node_id] = {"id": node_id, "repo_id": repo_id, "kind": kind,
                          "label": _text(label), "parent_id": extra.pop("parent_id", None),
                          "evidence_refs": _unique(refs), **extra}

    def edge(source: str, target: str, kind: str, identity: Any,
             refs: list[dict], resolution: str, **extra: Any) -> None:
        edge_id = _id("edge", kind, source, target, identity, resolution,
                      extra.get("resolution_reason"), extra.get("provenance"))
        edges[edge_id] = {"id": edge_id, "source": source, "target": target,
                          "kind": kind, "directed": extra.pop("directed", True), "resolution": resolution,
                          "evidence_refs": _unique(refs), **extra}

    def contains(parent: str, child: str, refs: list[dict], basis: str) -> None:
        edge(parent, child, "containment", [parent, child], refs, "declared", basis=basis)

    for root in sorted(set(requested) | set(results) | set(failures)):
        request = requested.get(root, {})
        result, failure = results.get(root), failures.get(root)
        repo_id = result.repo_id if result else failure.get("repo_id") if failure else request.get("repo_id")
        repository_id = _id("repository", root)
        status = ("partial" if result and (result.scan.analyzer_errors or result.scan.limitations) else
                  "completed" if result else "failed" if failure else request.get("status", "unavailable"))
        if not result and not failure and status in {"success", "completed", "partial"}:
            status = "unavailable"  # A transport status cannot stand in for a supplied snapshot.
        if status not in {"completed", "partial", "failed", "skipped", "cancelled", "unavailable", "queued", "running"}:
            status = "unavailable"
        snapshot = getattr(result.scan, "scan_snapshot", None) if result else None
        repository = {"id": repository_id, "repo_id": repo_id, "root": root,
                      "label": _text(repo_id or root),
                      "requested_id": request.get("requested_id"), "status": status,
                      "report_dir": _text(result.report_dir) if result else None,
                      "snapshot_id": snapshot.snapshot_id if snapshot else request.get("snapshot_id"),
                      "run_id": request.get("run_id"), "generation": request.get("generation"),
                      "report_hash": request.get("report_hash"),
                      "snapshot_available": result is not None}
        repositories.append(repository)
        if repo_id:
            by_slug[repo_id].append(repository)
        node(repository_id, repository_id, "repository", repo_id or root, [], status=status,
             root=root, requested_id=request.get("requested_id"), basis="requested_root")
        if not result:
            limitations.add(f"Repository {repository_id} has no available child snapshot; absence of links is unknown.")
            continue
        scan = result.scan
        evidence = _Evidence(scan, repo_id, repository_id)
        graph = build_service_graph(scan)
        owners = _file_service_names(scan)

        def owner(file: str, owners=owners) -> str | None:
            explicit = {name.strip() for name in owners.get(file, ()) if name.strip()}
            if len(explicit) == 1:
                return next(iter(explicit))
            return None if explicit else _infer_from_layout(file)

        def owner_basis(file: str, owners=owners) -> str:
            explicit = {name.strip() for name in owners.get(file, ()) if name.strip()}
            return "analyzer_hint_file_owner" if len(explicit) == 1 else "layout_inferred_file_owner"

        known_local = {name for file in owners for name in [owner(file)] if name}
        for modeled in graph.nodes:
            for file in modeled.files_seen:
                owned = owner(file)
                if owned:
                    known_local.add(owned)
        service_ids = {modeled.name: _id("component", root, "service_topology", modeled.name)
                       for modeled in graph.nodes}
        for modeled in sorted(graph.nodes, key=lambda item: item.name):
            component_id = service_ids[modeled.name]
            local = modeled.name in known_local
            refs = []
            for file in sorted(modeled.files_seen):
                matching = evidence.matching_refs(("service", "auth", "edge"), file,
                                                  "service_name:" + modeled.name)
                refs.extend(matching if local else [evidence.ref("source_file", file)])
            node(component_id, repository_id, "service" if local else "component", modeled.name,
                 refs, parent_id=repository_id, role=_text(modeled.role),
                 basis="core_service_topology", ownership="modeled_local" if local else "unknown")
            contains(repository_id, component_id, refs, "repository_observation_scope")
        for modeled in graph.edges:
            source, target = service_ids[modeled.source], service_ids[modeled.target]
            families = ("edge", "auth", "service") if modeled.kind == "analyzer-declared" else ("external_call",)
            refs = evidence.matching_refs(families, modeled.file, modeled.evidence)
            edge(source, target, modeled.kind, [root, modeled.source, modeled.target,
                 modeled.kind, modeled.file, modeled.evidence], refs, "inferred",
                 basis="core_service_topology", confidence=None, scope="repository")
        for database in scan.databases:
            refs = evidence.refs("database", database.file, database.line, database.kind)
            component_id = _id("component", root, "database_hint", database.file,
                               database.line, database.kind)
            parent = service_ids.get(owner(database.file), repository_id)
            node(component_id, repository_id, "datastore", database.kind, refs, parent_id=parent,
                 basis="static_database_hint", qualified_identity=None)
            contains(parent, component_id, refs, "database_hint_source_scope")
        framework = extract_framework_datastore_candidates(scan.signals, scan.root)
        framework_candidates.extend(framework["candidates"])
        rejected_framework_candidates += framework["rejected"]
        extracted = extract_shared_datastore_declarations(scan.signals, scan.root)
        datastore_declarations.extend(extracted["declarations"])
        rejected_datastore_declarations += extracted["rejected"]
        messaging = extract_messaging_declarations(scan.signals, scan.root)
        messaging_declarations.extend(messaging["declarations"])
        rejected_messaging_declarations += messaging["rejected"]
        contexts[repository_id] = {"evidence": evidence, "owner": owner,
                                   "owner_basis": owner_basis, "root": root,
                                   "repository": repository, "service_ids": service_ids}

    def endpoint(slug: str, file: str) -> tuple[dict, str, str] | None:
        matches = by_slug.get(slug, ())
        if len(matches) != 1 or not matches[0]["snapshot_available"]:
            limitations.add("A cross-repository HTTP link has an unavailable or ambiguous core repository identity; link omitted.")
            return None
        repository = matches[0]
        context = contexts[repository["id"]]
        component = context["service_ids"].get(context["owner"](file))
        return repository, component or repository["id"], context["owner_basis"](file) if component else "repository_only"

    declaration_contexts = {_root(context["root"]): context for context in contexts.values()}
    for link in sorted(fleet.links, key=lambda item: _canonical(asdict(item))):
        client = endpoint(link.client_repo, link.client_file)
        server = endpoint(link.server_repo, link.server_file)
        if client is None or server is None:
            continue
        client_repo, source, source_resolution = client
        server_repo, target, target_resolution = server
        refs = contexts[client_repo["id"]]["evidence"].refs(
            "external_call", link.client_file, link.client_line, link.client_target)
        refs += contexts[server_repo["id"]]["evidence"].refs(
            "route", link.server_file, link.server_line, f"{link.method} {link.server_route_path}")
        for declaration in link.declaration_refs:
            context = declaration_contexts.get(_root(declaration.repository_root))
            if context is None:
                limitations.add("A deployment declaration has no available child snapshot; its source reference is unavailable.")
                continue
            reference = context["evidence"].ref("deployment_declaration", declaration.file, declaration.line)
            reference["basis"] = "supplied_static_config_declaration"
            # Attribution does not establish identical captured config bytes
            # across independently scanned children and parent extraction.
            reference["snapshot_binding"] = "unverified"
            refs.append(reference)
        identity = [client_repo["id"], server_repo["id"], link.client_file, _line(link.client_line),
                    link.client_method, link.client_target, link.server_file, _line(link.server_line),
                    link.method, link.server_route_path, link.destination, link.scheme]
        if link.server_namespace is not None or link.server_service_name is not None:
            identity.extend([link.server_namespace, link.server_service_name])
        relation_id = _id("relation", "http_contract", identity)
        details = {"relation_id": relation_id, "basis": "core_contract_link",
                   "confidence": None, "scope": "cross_repository",
                   "resolution_reason": _text(link.resolution_reason),
                   "method": link.method, "client_method": link.client_method,
                   "path_template": _text(link.path_template),
                   "client_target": _text(link.client_target),
                   "server_route_path": _text(link.server_route_path),
                   "destination": _text(link.destination) if link.destination else None,
                   "scheme": link.scheme,
                   "server_namespace": link.server_namespace,
                   "server_service_name": link.server_service_name,
                   "server_port": link.server_port,
                   "server_protocol": link.server_protocol,
                   "provenance": _text(link.alias_provenance) if link.alias_provenance else None,
                   "endpoint_resolution": {"source": source_resolution, "target": target_resolution}}
        if link.resolution == "observed_via_proxy":
            if not link.proxy_host:
                limitations.add("An observed_via_proxy link lacks its declared intermediary; link omitted.")
                continue
            # A proxy declaration is qualified by its full authority and protocol;
            # a short service name never unifies two external components.
            proxy = _id("proxy", link.scheme, link.proxy_host)
            previous = nodes.get(proxy, {}).get("evidence_refs", [])
            node(proxy, None, "external", link.proxy_host, previous + refs,
                 basis="core_declared_proxy", component_role="proxy", authority=_text(link.proxy_host), scheme=link.scheme)
            edge(source, proxy, "cross_repo_http_call", [identity, "client_to_proxy"], refs,
                 link.resolution, **details, leg="client_to_proxy")
            edge(proxy, target, "cross_repo_http_call", [identity, "proxy_to_server"], refs,
                 link.resolution, **details, leg="proxy_to_server")
        else:
            edge(source, target, "cross_repo_http_call", [identity, "direct"], refs,
                 link.resolution, **details, leg="direct")

    shared_limit_reason = None
    if len(datastore_declarations) > MAX_DATASTORE_DECLARATIONS:
        shared_limit_reason = "declaration_count_exceeds_prepared_limit"
    elif len({record["source"]["repository_root"] for record in datastore_declarations}) > MAX_DATASTORE_REPOSITORIES:
        shared_limit_reason = "repository_count_exceeds_prepared_limit"
    shared = project_shared_datastores([] if shared_limit_reason else datastore_declarations)
    candidate_limit = (len(framework_candidates) > MAX_DATASTORE_DECLARATIONS
        or len({item["source"]["repository_root"] for item in framework_candidates}) > MAX_DATASTORE_REPOSITORIES)
    framework = project_framework_datastore_candidates([] if candidate_limit else framework_candidates)
    owner_shared_counts = {name: len(shared[name]) for name in ("resources", "associations", "unmatched", "ambiguous")}
    framework_evidence_ids = {item["id"] for item in framework["evidence"]}
    if framework_candidates or rejected_framework_candidates:
        limitations.update(framework["limitations"])
    if candidate_limit:
        limitations.add("Framework datastore candidate input exceeds a prepared contract limit; candidate projection was omitted.")
    if rejected_framework_candidates:
        limitations.add("Invalid framework datastore candidates were omitted without an association.")
    for collection in ("resources", "associations", "evidence", "unmatched", "ambiguous"):
        shared[collection].extend(framework[collection])
    contexts_by_root = {context["root"]: context for context in contexts.values()}
    shared_evidence = {}
    for item in shared["evidence"]:
        context = contexts_by_root[item["repository_root"]]
        shared_evidence[item["id"]] = context["evidence"].ref(
            "framework_datastore_candidate" if item["id"] in framework_evidence_ids else "shared_datastore_declaration", item["file"], item["line"],
            item["observation_id"], item["source_analyzer"])

    resource_evidence: dict[str, set[str]] = defaultdict(set)
    for item in [*shared["associations"], *shared["unmatched"]]:
        resource_evidence[item["resource_id"]].update(item["evidence_refs"])
    for resource in shared["resources"]:
        identity = resource["identity"]
        refs = [shared_evidence[ref] for ref in sorted(resource_evidence[resource["id"]])]
        node(resource["id"], None, "datastore",
             f'{identity["host"]}:{identity["port"]}/{identity["namespace"]}/{identity["resource"]}',
             refs, basis=resource["basis"], resolution=resource["resolution"],
             repository_count=resource["repository_count"], qualified_identity=identity)
    for association in shared["associations"]:
        endpoints = [{"repository_id": contexts_by_root[item["repository_root"]]["repository"]["id"],
                      "operations": item["operations"]} for item in association["endpoints"]]
        source, target = (item["repository_id"] for item in endpoints)
        refs = [shared_evidence[ref] for ref in association["evidence_refs"]]
        edge(source, target, "shared_datastore", association["id"], refs,
             association["resolution"], directed=False, relation_id=association["id"],
             basis=association["basis"], confidence=None, scope="cross_repository",
             resource_id=association["resource_id"], endpoints=endpoints)

    shared_datastore_unresolved = []
    if shared_limit_reason:
        shared_datastore_unresolved.append({
            "id": _id("datastore-unresolved", {"kind": "shared_datastore", "reason": shared_limit_reason}),
            "kind": "shared_datastore", "reason": shared_limit_reason,
            "resource_id": None, "evidence_refs": []})
        limitations.add("Shared datastore input exceeds a prepared contract limit; datastore projection was omitted and other architecture was preserved.")
    for item in [*shared["unmatched"], *shared["ambiguous"]]:
        shared_datastore_unresolved.append({
            "id": item.get("id") or _id("datastore-unresolved", item),
            "kind": "shared_datastore", "reason": item["reason"],
            "resource_id": item.get("resource_id"),
            "evidence_refs": [shared_evidence[ref] for ref in item["evidence_refs"]]})
    if owner_shared_counts["unmatched"]:
        limitations.add("A qualified datastore declared by only one repository remains unmatched; no association was created.")
    if owner_shared_counts["ambiguous"]:
        limitations.add("Conflicting datastore declarations for one source observation were quarantined as ambiguous.")
    if rejected_datastore_declarations:
        limitations.add("Invalid, incomplete, conflicting or non-production normalized datastore declarations were omitted without an association.")

    producer_consumer_unresolved = []
    messaging_limit_reason = None
    messaging_coverage = None
    if messaging_declarations or rejected_messaging_declarations:
        if len(messaging_declarations) > MAX_MESSAGING_DECLARATIONS:
            messaging_limit_reason = "declaration_count_exceeds_prepared_limit"
        elif len({record["source"]["repository_root"] for record in messaging_declarations}) > MAX_MESSAGING_REPOSITORIES:
            messaging_limit_reason = "repository_count_exceeds_prepared_limit"
        messaging = project_producer_consumer([] if messaging_limit_reason else messaging_declarations)
        limitations.discard("Cross-repository producer/consumer identities are unanalysed: existing hints lack qualified endpoint, namespace and operation identity.")
        limitations.update(messaging["limitations"])
        messaging_evidence = {}
        for item in messaging["evidence"]:
            context = contexts_by_root[item["repository_root"]]
            messaging_evidence[item["id"]] = context["evidence"].ref(
                "producer_consumer_declaration", item["file"], item["line"],
                item["observation_id"], item["source_analyzer"])
        messaging_resource_refs = defaultdict(set)
        for item in [*messaging["associations"], *messaging["unmatched"]]:
            messaging_resource_refs[item["resource_id"]].update(item["evidence_refs"])
        for resource in messaging["resources"]:
            identity = resource["identity"]
            refs = [messaging_evidence[ref] for ref in sorted(messaging_resource_refs[resource["id"]])]
            node(resource["id"], None, "component",
                 f'{identity["host"]}:{identity["port"]}/{identity["namespace"]}/{identity["channel"]}',
                 refs, component_role="messaging_topic", basis=resource["basis"],
                 resolution="declared", qualified_identity=identity,
                 repository_count=resource["repository_count"])
        for association in messaging["associations"]:
            endpoints = [{"repository_id": contexts_by_root[item["repository_root"]]["repository"]["id"],
                          "operation": item["operation"],
                          "evidence_refs": sorted(_id("evidence", messaging_evidence[ref]) for ref in item["evidence_refs"])}
                         for item in association["endpoints"]]
            edge(endpoints[0]["repository_id"], endpoints[1]["repository_id"],
                 "producer_consumer", association["id"],
                 [messaging_evidence[ref] for ref in association["evidence_refs"]], "declared",
                 directed=True, relation_id=association["id"], resource_id=association["resource_id"],
                 basis=association["basis"], confidence=None, scope="cross_repository",
                 direction_basis="declared_publish_to_consume", endpoints=endpoints)
        for item in [*messaging["unmatched"], *messaging["ambiguous"]]:
            producer_consumer_unresolved.append({
                "id": item["id"], "kind": "producer_consumer", "reason": item["reason"],
                "resource_id": item.get("resource_id"),
                "evidence_refs": [messaging_evidence[ref] for ref in item["evidence_refs"]]})
        if messaging_limit_reason:
            producer_consumer_unresolved.append({
                "id": _id("messaging-unresolved", messaging_limit_reason), "kind": "producer_consumer",
                "reason": messaging_limit_reason, "resource_id": None, "evidence_refs": []})
            limitations.add("Messaging input exceeds a prepared contract limit; messaging projection was omitted and other architecture was preserved.")
        if rejected_messaging_declarations:
            limitations.add("Invalid, incomplete, conflicting or non-production normalized messaging declarations were omitted without a relationship.")
        messaging_coverage = {"status": "supported", "basis": "explicit_qualified_static_declarations",
            "analysis_status": "explicit_normalized_kafka_topic_signals_only", "resolution": "declared",
            "declaration_count": len(messaging_declarations), "rejected_declaration_count": rejected_messaging_declarations,
            "projection_omitted": bool(messaging_limit_reason),
            **{name + "_count": len(messaging[plural]) for name, plural in (
                ("resource", "resources"), ("association", "associations"), ("unmatched", "unmatched"), ("ambiguous", "ambiguous"))}}

    evidence_registry: dict[str, dict] = {}
    for item in [*nodes.values(), *edges.values(), *shared_datastore_unresolved, *producer_consumer_unresolved]:
        refs = []
        for reference in item["evidence_refs"]:
            evidence_id = _id("evidence", reference)
            evidence_registry[evidence_id] = {"id": evidence_id, **reference}
            refs.append(evidence_id)
        item["evidence_refs"] = sorted(set(refs))
    statuses = Counter(item["status"] for item in repositories)
    return {"schema_version": "1.0", "kind": "fleet_architecture",
            "repositories": sorted(repositories, key=lambda item: item["id"]),
            "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
            "edges": sorted(edges.values(), key=lambda item: item["id"]),
            "evidence": sorted(evidence_registry.values(), key=lambda item: item["id"]),
            "shared_datastore_unresolved": sorted(shared_datastore_unresolved, key=lambda item: item["id"]),
            **({"producer_consumer_unresolved": sorted(producer_consumer_unresolved, key=lambda item: item["id"])}
               if messaging_coverage is not None else {}),
            "coverage": {"requested_repositories": len(requested) if requested_repos is not None else len(repositories),
                         "available_repositories": len(results), "repository_statuses": dict(sorted(statuses.items())),
                         "completed_repositories": statuses["completed"], "failed_repositories": statuses["failed"],
                         "partial_repositories": statuses["partial"],
                         "repository_results_complete": bool(repositories) and all(item["status"] == "completed" for item in repositories),
                         "complete": False,
                         "atomic_snapshot": False,
                         "protocols": {"http": {"status": "supported", "basis": "supplied_core_contract_links", "analysis_status": "supplied_links_only"},
                                       "producer_consumer": messaging_coverage or {"status": "unanalysed", "reason": "missing_qualified_identity_and_operation"},
                                       "shared_datastore": {"status": "supported", "basis": "explicit_qualified_static_declarations",
                                                            "analysis_status": "explicit_normalized_signals_only",
                                                            **({"framework_static_candidates": {
                                                                "format": "rails_database_yml", "resolution": "candidate",
                                                                "scope_basis": "configuration_environment_not_deployment",
                                                                "candidate_count": len(framework_candidates),
                                                                "rejected_count": rejected_framework_candidates,
                                                                "projection_omitted": candidate_limit,
                                                                "resource_count": len(framework["resources"]),
                                                                "association_count": len(framework["associations"])}}
                                                               if framework_candidates or rejected_framework_candidates else {}),
                                                            "declaration_count": len(datastore_declarations),
                                                            "rejected_declaration_count": rejected_datastore_declarations,
                                                            "resource_count": owner_shared_counts["resources"],
                                                            "association_count": owner_shared_counts["associations"],
                                                            "unmatched_count": owner_shared_counts["unmatched"],
                                                            "ambiguous_count": owner_shared_counts["ambiguous"],
                                                            "extraction_contract": {"kind": "shared_datastore_declaration", "schema_version": "1.0",
                                                                                    "status": "supported", "production_extraction": shared["production_extraction"]}},
                                       "rpc_schema": {"status": "unanalysed", "reason": "no_qualified_cross_repository_contract"}}},
            "limitations": sorted(limitations)}


def aggregate_fleet_architecture(architecture: Mapping[str, Any]) -> dict:
    """Return a reversible repo overview, never a detail-path reachability graph.

    Proxy nodes remain endpoints. Every presentation edge retains its canonical
    IDs; direction, kind, resolution and proxy leg form separate groups.
    """
    nodes = {item["id"]: item for item in architecture["nodes"]}

    def ancestor(node_id: str) -> str:
        seen: set[str] = set()
        while nodes[node_id].get("parent_id"):
            if node_id in seen:
                raise ValueError("Containment cycle")
            seen.add(node_id)
            node_id = nodes[node_id]["parent_id"]
        return node_id

    groups: dict[tuple, list[str]] = defaultdict(list)
    for edge in architecture["edges"]:
        if edge["kind"] == "containment":
            continue
        source, target = ancestor(edge["source"]), ancestor(edge["target"])
        key = (source, target, edge["kind"], edge["directed"], edge["resolution"], edge.get("leg"), edge.get("basis"))
        groups[key].append(edge["id"])
    edges = [{"id": _id("overview", key), "source": key[0], "target": key[1],
              "kind": key[2], "directed": key[3], "resolution": key[4], "leg": key[5], "basis": key[6],
              "underlying_edge_ids": sorted(set(ids)), "count": len(set(ids))}
             for key, ids in groups.items()]
    return {"schema_version": "1.0", "kind": "fleet_architecture_overview",
            "nodes": sorted((item for item in nodes.values() if not item.get("parent_id")), key=lambda item: item["id"]),
            "edges": sorted(edges, key=lambda item: item["id"]),
            "path_semantics": "presentation_only_not_detail_reachability"}


__all__ = ["build_fleet_architecture", "aggregate_fleet_architecture"]
