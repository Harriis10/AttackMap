"""Network-free capability discovery and fail-closed desktop preflight."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from . import __version__
from .progress import PROGRESS_PROTOCOL_VERSION
from .provider_options import ProviderOptions, ProviderOptionsV13
from .run_contract import RunRequest, ScanOptions, ScanOptionsV12, ScanOptionsV13, ScanOptionsV15, SUPPORTED_SCHEMA_VERSIONS
from .desktop_ai import MODES, provider_mode

CAPABILITIES_SCHEMA_VERSION = 1
_UNWIRED_FIELDS = frozenset({
    "repos", "repositories", "repo_paths", "repository_paths", "repository_ids", "fleet",
    "mode", "llm_mode", "ai_mode", "llm", "baseline",
    "suppress_file", "jury", "effort", "fast", "backend", "resource_limits",
    "fail_on_new_high", "hunt", "verify", "remediate", "triage", "incremental", "max_workers",
    "llm_effort", "llm_backend", "llm_speed", "verify_votes", "hunt_lenses", "hunt_rounds", "hunt_budget",
})


def _options_model(version: str):
    if version == "1.4":
        from .desktop_fleet import FleetScanOptions
        return FleetScanOptions
    if version == "1.5":
        return ScanOptionsV15
    return ScanOptionsV13 if version in {"1.3", "1.4"} else ScanOptionsV12 if version == "1.2" else ScanOptions


def _provider_model(version: str):
    return ProviderOptionsV13 if version in {"1.3", "1.4", "1.5"} else ProviderOptions


def module_inventory(metadata: list[Any]) -> list[dict]:
    """Same installed-only records used by CLI modules --json; no remote lookup."""
    return [{"name": meta.name, "display_name": meta.display_name or meta.name,
             "description": meta.description, "scope": meta.scope,
             "ecosystems": list(meta.ecosystems), "enabled_by_default": meta.enabled_by_default,
             "priority": meta.priority, "experimental": meta.experimental} for meta in metadata]


def build_analyzer_catalog_payload() -> dict:
    """Discover once in the selected engine; never infer execution from inventory."""
    from .analyzer_catalog import get_analyzer_catalog
    from .analyzer_profiles import analyzer_profile_inventory
    snapshot = get_analyzer_catalog()
    inventory = module_inventory(list(snapshot.metadata))
    catalog = snapshot.to_dict()
    profiles = analyzer_profile_inventory(snapshot.metadata)
    identity = executable_identity()
    for name, value in (("modules", inventory), ("analyzer_catalog", catalog), ("analyzer_profiles", profiles)):
        identity[f"{name}_sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    return {"schema": 1, "engine_identity": identity, "modules": inventory,
            "analyzer_catalog": catalog, "analyzer_profiles": profiles}


def executable_identity(path: Path | None = None) -> dict:
    """Content identity, not a version-string cache key. Never execute a candidate."""
    candidate = path or Path(sys.executable)
    if not candidate.is_absolute() or not candidate.is_file():
        raise ValueError("Engine identity is unavailable")
    candidate = candidate.resolve(strict=True)
    before = candidate.stat()
    with candidate.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    after = candidate.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("Engine changed during identity capture")
    result = {"path": str(candidate), "sha256": checksum, "size_bytes": after.st_size,
              "runtime_kind": "Frozen" if getattr(sys, "frozen", False) else "Python"}
    if not getattr(sys, "frozen", False):
        # The Python host is unchanged when source code is replaced. Bind both.
        source = hashlib.sha256()
        for name in ("__init__.py", "cli.py", "desktop_capabilities.py", "desktop_actions.py", "desktop_graph.py",
                     "desktop_worker.py", "desktop_fleet.py", "run_contract.py", "provider_options.py", "desktop_ai.py",
                     "scan_service.py", "pipeline.py", "analyzers.py", "analyzer_catalog.py",
                     "analyzer_profiles.py", "analyzer_run_ledger.py", "analyzer_contracts.py", "models.py", "plugins_lock.py", "merge.py",
                     "ecosystem_php.py", "ecosystem_python.py", "ecosystem_node_atproto.py",
                     "scanner.py", "config_scanner.py"):
            source.update(name.encode("ascii"))
            source.update(Path(__file__).with_name(name).read_bytes())
        result["source_sha256"] = source.hexdigest()
    return result


def build_capabilities(app: Any, *, metadata: list[Any] | None = None) -> dict:
    """Discover CLI flags from registration; desktop fields from typed contracts."""
    import typer
    from .llm_review import FAST_CAPABLE_MODELS, OPENAI_EFFORT_MAP
    catalog_payload = build_analyzer_catalog_payload() if metadata is None else None
    root = typer.main.get_command(app)
    commands = getattr(root, "commands", {})
    options: set[str] = set()
    multi_repo = False
    for param in getattr(commands.get("analyze"), "params", []):
        options.update(opt for opt in [*getattr(param, "opts", []), *getattr(param, "secondary_opts", [])]
                       if opt.startswith("--"))
        if getattr(param, "param_type_name", "") == "argument" and getattr(param, "nargs", 1) == -1:
            multi_repo = True
    if catalog_payload is not None:
        inventory = catalog_payload["modules"]
        identity = catalog_payload["engine_identity"]
        analyzer_details = {name: catalog_payload[name] for name in ("analyzer_catalog", "analyzer_profiles")}
    else:
        inventory = module_inventory(metadata)
        identity = executable_identity()
        identity["modules_sha256"] = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
        # Injected metadata is not evidence about implementation provenance.
        from .analyzer_profiles import analyzer_profile_inventory
        analyzer_details = {"analyzer_profiles": analyzer_profile_inventory(metadata)}
    return {"schema": CAPABILITIES_SCHEMA_VERSION, "version": __version__,
            "commands": sorted(commands), "analyze": {"options": sorted(options), "multi_repo": multi_repo},
            "progress_protocol": PROGRESS_PROTOCOL_VERSION, "engine_identity": identity,
            "modules": inventory,
            **analyzer_details,
            "desktop": {"schema_versions": list(SUPPORTED_SCHEMA_VERSIONS),
                        "actions_schema_versions": ["1.1"],
                        "operations": ["capabilities", "preflight"],
                        "scan_options": sorted(ScanOptionsV12.model_fields),
                        "scan_options_by_schema": {version: sorted(_options_model(version).model_fields)
                                                   for version in SUPPORTED_SCHEMA_VERSIONS},
                        "scan_option_metadata": {name: field.json_schema_extra
                                                 for name, field in ScanOptionsV12.model_fields.items()
                                                 if field.json_schema_extra},
                        "provider_options": sorted(ProviderOptionsV13.model_fields),
                        "provider_options_by_schema": {version: sorted(_provider_model(version).model_fields) for version in SUPPORTED_SCHEMA_VERSIONS},
                        "modes": list(MODES),
                        "modes_by_schema": {version: list(MODES) if version in {"1.3", "1.5"} else ["none", "review"] for version in SUPPORTED_SCHEMA_VERSIONS},
                        "provider_tuning": {"minimum_schema": "1.3", "backends": ["api"],
                            "jury_votes": {"minimum": 1, "maximum": 7, "mode": "hunt_verify", "default": 3},
                            "effort": ["low", "medium", "high", "xhigh", "max"],
                            "openai_effort_mapping": dict(OPENAI_EFFORT_MAP),
                            "speed": ["standard", "fast"],
                            "fast_speed": {"provider": "claude", "backend": "api", "models": sorted(FAST_CAPABLE_MODELS)}},
                        "providers": ["openai", "claude"],
                        "provider_backend": "api", "multi_repo": False,
                        "fleet_by_schema": {"1.4": {"kind": "fleet_request", "multi_repo": True,
                            "minimum_repositories": 2, "maximum_repositories": 16,
                            "maximum_workers": 4, "modes": ["none"],
                            "request_fields": ["repositories", "max_workers"],
                            "scan_options": sorted(_options_model("1.4").model_fields),
                            "events": ["fleet_child", "fleet_terminal"],
                            "unsupported": ["AI", "baseline", "baseline_policies", "suppress_file", "secrets_history"]}},
                        "limitations": ["Installed analyzers are not a repository applicability result.",
                                        "No provider connectivity or model response is tested by discovery.",
                                        "Fleet AI is unsupported. Strict output caps prevent CLI backend execution.",
                                        "Discovery proves option mapping, not provider/model availability or completed responses.",
                                        "Identity supports cache invalidation, not publisher authentication."]}}


def validate_desktop_request(payload: Any) -> RunRequest:
    """Reject explicit unwired options before permissive envelope parsing/dispatch.

    Unknown envelope metadata retains the run contract's additive compatibility.
    Unknown scan/provider fields and reserved unwired feature fields never pass.
    All failures deliberately omit input values and validation exception details.
    """
    try:
        if not isinstance(payload, dict) or payload.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError
        fleet = payload.get("schema_version") == "1.4" and payload.get("kind") == "fleet_request"
        allowed_fleet = {"repositories", "max_workers"} if fleet else set()
        if (_UNWIRED_FIELDS - allowed_fleet).intersection(payload):
            raise ValueError
        options = payload.get("options", {})
        options_model = _options_model(payload.get("schema_version"))
        if not isinstance(options, dict) or set(options) - set(options_model.model_fields):
            raise ValueError
        provider = options.get("provider", {})
        if not isinstance(provider, dict) or set(provider) - set(_provider_model(payload.get("schema_version")).model_fields):
            raise ValueError
        if fleet:
            from .desktop_fleet import FleetRunRequest
            return FleetRunRequest.model_validate(payload)
        if payload.get("schema_version") == "1.4":
            raise ValueError
        return RunRequest.model_validate(payload)
    except Exception:
        raise ValueError("Desktop request is unsupported or malformed; no scan was started.") from None


def preflight_capabilities(document: Any, *, request: Any = None,
                           expected_identity: Any = None) -> dict:
    """Pure validation of a discovered document; never probe/fallback-launch an exe."""
    def result(status: str) -> dict:
        return {"supported": status == "compatible", "status": status}
    if not isinstance(document, dict) or type(document.get("schema")) is not int:
        return result("malformed")
    if document["schema"] != CAPABILITIES_SCHEMA_VERSION:
        return result("incompatible_capabilities_schema")
    desktop = document.get("desktop")
    if desktop is None:
        return result("legacy_engine_unsupported")
    identity = document.get("engine_identity")
    def string_list(value: Any) -> bool:
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    if (not isinstance(desktop, dict) or not isinstance(identity, dict)
            or not isinstance(identity.get("sha256"), str) or len(identity["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in identity["sha256"])
            or not isinstance(identity.get("path"), str)
            or not Path(identity["path"]).is_absolute()
            or type(identity.get("size_bytes")) is not int or identity["size_bytes"] < 1
            or identity.get("runtime_kind") not in ("Python", "Frozen")
            or not string_list(desktop.get("schema_versions"))
            or not string_list(document.get("commands"))
            or any(not string_list(desktop.get(key)) for key in ("scan_options", "provider_options", "modes", "providers"))):
        return result("malformed")
    if expected_identity is not None and expected_identity != identity:
        return result("engine_changed")
    if not {"desktop-worker", "desktop-action"}.issubset(document["commands"]):
        return result("missing_desktop_commands")
    if not set(SUPPORTED_SCHEMA_VERSIONS).intersection(desktop["schema_versions"]):
        return result("incompatible_run_schema")
    if request is not None:
        try:
            validated = validate_desktop_request(request)
            if validated.schema_version not in desktop["schema_versions"]:
                return result("unsupported_request")
            if validated.kind == "fleet_request" and not desktop.get("fleet_by_schema", {}).get("1.4", {}).get("multi_repo"):
                return result("unsupported_request")
            raw_options = request.get("options", {})
            supported_options = desktop.get("scan_options_by_schema", {}).get(validated.schema_version, desktop.get("scan_options", []))
            if validated.kind == "fleet_request":
                fleet_options = desktop.get("fleet_by_schema", {}).get("1.4", {}).get("scan_options")
                # Old 1.4 engines never proved profile transport. Keep their
                # existing options compatible, but require explicit opt-in for profiles.
                supported_options = fleet_options if fleet_options is not None else [name for name in supported_options if name != "analyzer_profile"]
            requested_options = set(raw_options)
            if validated.kind == "fleet_request" and raw_options.get("analyzer_profile") is None:
                requested_options.discard("analyzer_profile")
            if requested_options - set(supported_options):
                return result("unsupported_request")
            provider = raw_options.get("provider", {})
            if set(provider) - set(desktop.get("provider_options", [])):
                return result("unsupported_request")
            mode = provider_mode(validated.options.provider)
            if mode not in desktop.get("modes", []):
                return result("unsupported_request")
            if validated.options.provider.provider not in desktop.get("providers", []):
                return result("unsupported_request")
            installed = document.get("modules")
            if (not isinstance(installed, list) or any(not isinstance(item, dict)
                    or not isinstance(item.get("name"), str) for item in installed)):
                return result("malformed")
            if set(validated.modules) - {item["name"] for item in installed}:
                return result("unsupported_request")
            profile = getattr(validated.options, "analyzer_profile", None)
            if profile is not None:
                profiles = document.get("analyzer_profiles", {})
                if profiles.get("schema_version") != "1.0":
                    return result("unsupported_request")
                matches = [item for item in profiles.get("profiles", []) if item.get("qualified_name") == profile]
                if len(matches) != 1 or matches[0].get("available") is not True:
                    return result("unsupported_request")
                from .analyzer_contracts import AnalyzerMetadata
                from .analyzer_profiles import resolve_analyzer_profile
                selected = resolve_analyzer_profile(profile, [AnalyzerMetadata.model_validate(item) for item in installed])
                if list(selected.module_names or ()) != matches[0].get("module_names", []):
                    return result("unsupported_request")
        except Exception:
            return result("unsupported_request")
    return result("compatible")
