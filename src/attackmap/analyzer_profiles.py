"""Versioned, offline analyzer selection profiles.

Profiles select analyzer names from an effective installed inventory. They do
not discover, install, load, detect, or execute analyzers. Runtime applicability
and merge order remain the analyzer runner's responsibility.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from .analyzer_contracts import AnalyzerMetadata, normalize_analyzer_metadata


ANALYZER_PROFILES_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class AnalyzerProfile:
    name: str
    display_name: str
    version: str
    description: str
    module_names: tuple[str, ...]
    experimental_module_names: tuple[str, ...] = ()

    @property
    def qualified_name(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def selection_mode(self) -> str:
        return "automatic" if self.name == "automatic" else "explicit"

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "version": self.version,
            "qualified_name": self.qualified_name,
            "description": self.description,
            "selection_mode": self.selection_mode,
            "module_names": list(self.module_names),
            "experimental_module_names": list(self.experimental_module_names),
        }


_PROFILES = (
    AnalyzerProfile(
        name="automatic",
        display_name="Automatic",
        version="1.0",
        description="Use installed default-enabled analyzers, each subject to runtime detection.",
        module_names=(),
    ),
    AnalyzerProfile(
        name="node-atproto",
        display_name="Node / ATProto",
        version="1.0",
        description="JavaScript base, config, fallback, Node service and ATProto layers; includes experimental modules.",
        module_names=("javascript-web", "node-service", "config", "atproto", "default", "node-atproto"),
        experimental_module_names=("node-service", "atproto", "node-atproto"),
    ),
    AnalyzerProfile(
        name="php-laminas-omeka",
        display_name="PHP / Laminas / Omeka S",
        version="1.0",
        description="PHP base, config, fallback, Laminas and Omeka S layers; includes experimental modules.",
        module_names=("php-web", "config", "php-laminas", "default", "omeka-s"),
        experimental_module_names=("php-laminas", "omeka-s"),
    ),
    AnalyzerProfile(
        name="python",
        display_name="Python",
        version="1.0",
        description="Python plugin, web base, config, fallback and service overlay; includes experimental modules.",
        module_names=("python", "python-web", "config", "python-service", "default"),
        experimental_module_names=("python-service",),
    ),
)


class AnalyzerProfileError(ValueError):
    """A profile cannot be resolved without changing its declared selection."""


class MissingProfileModulesError(AnalyzerProfileError):
    def __init__(self, profile: AnalyzerProfile, missing_module_names: tuple[str, ...]) -> None:
        self.profile_name = profile.name
        self.profile_version = profile.version
        self.missing_module_names = missing_module_names
        super().__init__(
            f"Analyzer profile '{profile.qualified_name}' requires missing modules: "
            f"{', '.join(missing_module_names)}. No modules were installed or substituted."
        )


@dataclass(frozen=True)
class AnalyzerProfileSelection:
    profile: AnalyzerProfile
    # None preserves the runner's existing Automatic/default-enabled path.
    module_names: tuple[str, ...] | None
    candidate_module_names: tuple[str, ...]
    experimental_module_names: tuple[str, ...]
    opt_in_module_names: tuple[str, ...]

    @property
    def profile_version(self) -> str:
        return self.profile.version

    @property
    def qualified_name(self) -> str:
        return self.profile.qualified_name

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.profile.name,
            "profile_version": self.profile_version,
            "qualified_name": self.qualified_name,
            "selection_mode": self.profile.selection_mode,
            "module_names": None if self.module_names is None else list(self.module_names),
            "candidate_module_names": list(self.candidate_module_names),
            "experimental_module_names": list(self.experimental_module_names),
            "opt_in_module_names": list(self.opt_in_module_names),
        }


def get_analyzer_profiles() -> tuple[AnalyzerProfile, ...]:
    """Return immutable definitions in stable presentation order."""
    return _PROFILES


def _installed_metadata(
    values: Iterable[AnalyzerMetadata | Mapping[str, object]],
) -> dict[str, AnalyzerMetadata]:
    installed: dict[str, AnalyzerMetadata] = {}
    for value in values:
        metadata = normalize_analyzer_metadata(dict(value) if isinstance(value, Mapping) else value)
        if metadata.name in installed:
            raise AnalyzerProfileError(
                f"Duplicate installed analyzer name '{metadata.name}'; profiles require an effective, deduplicated inventory."
            )
        installed[metadata.name] = metadata
    return installed


def _candidate_metadata(
    profile: AnalyzerProfile, installed: Mapping[str, AnalyzerMetadata],
) -> list[AnalyzerMetadata]:
    candidates = (
        (metadata for metadata in installed.values() if metadata.enabled_by_default)
        if profile.selection_mode == "automatic"
        else (installed[name] for name in profile.module_names if name in installed)
    )
    return sorted(candidates, key=lambda metadata: (metadata.priority, metadata.name))


def analyzer_profile_inventory(
    installed_metadata: Iterable[AnalyzerMetadata | Mapping[str, object]],
) -> dict[str, object]:
    """Serialize definitions and availability against a supplied engine inventory.

    Expanded names are candidates before detect(), never an execution ledger.
    Static experimental names describe the profile revision; installed flags
    describe the effective implementations supplied by this engine.
    """
    installed = _installed_metadata(installed_metadata)
    profiles: list[dict[str, object]] = []
    for profile in _PROFILES:
        missing = [name for name in profile.module_names if name not in installed]
        candidates = _candidate_metadata(profile, installed)
        profiles.append({
            **profile.as_dict(),
            "available": not missing,
            "missing_module_names": missing,
            "expanded_module_names": (
                [metadata.name for metadata in candidates]
                if profile.selection_mode == "automatic" else list(profile.module_names)
            ),
            "installed_experimental_module_names": [metadata.name for metadata in candidates if metadata.experimental],
            "opt_in_module_names": [metadata.name for metadata in candidates if not metadata.enabled_by_default],
        })
    return {"schema_version": ANALYZER_PROFILES_SCHEMA_VERSION, "profiles": profiles}


def resolve_analyzer_profile(
    profile_name: str,
    installed_metadata: Iterable[AnalyzerMetadata | Mapping[str, object]],
    *,
    explicit_modules: Sequence[str] | None = None,
) -> AnalyzerProfileSelection:
    """Resolve one profile offline; missing layers fail rather than downgrade.

    Both a canonical name and its qualified ``name@version`` are accepted.
    Supplying explicit modules alongside any profile is a selection conflict.
    """
    profile = next((item for item in _PROFILES if profile_name in (item.name, item.qualified_name)), None)
    if profile is None:
        available = ", ".join(item.qualified_name for item in _PROFILES)
        raise AnalyzerProfileError(f"Unknown analyzer profile '{profile_name}'. Available profiles: {available}.")
    if explicit_modules:
        raise AnalyzerProfileError("An analyzer profile cannot be combined with explicit --module selections.")
    installed = _installed_metadata(installed_metadata)
    missing = tuple(name for name in profile.module_names if name not in installed)
    if missing:
        raise MissingProfileModulesError(profile, missing)
    candidates = _candidate_metadata(profile, installed)
    return AnalyzerProfileSelection(
        profile=profile,
        module_names=None if profile.selection_mode == "automatic" else profile.module_names,
        candidate_module_names=tuple(metadata.name for metadata in candidates),
        experimental_module_names=tuple(metadata.name for metadata in candidates if metadata.experimental),
        opt_in_module_names=tuple(metadata.name for metadata in candidates if not metadata.enabled_by_default),
    )
