"""Offline profile contracts and preservation of runner selection semantics."""

from dataclasses import FrozenInstanceError
import json

import pytest

from attackmap import analyzers
from attackmap.analyzer_contracts import AnalyzerMetadata
from attackmap.analyzer_profiles import (
    ANALYZER_PROFILES_SCHEMA_VERSION,
    AnalyzerProfileError,
    MissingProfileModulesError,
    analyzer_profile_inventory,
    get_analyzer_profiles,
    resolve_analyzer_profile,
)


PROFILE_MODULES = {
    "automatic": (),
    "node-atproto": ("javascript-web", "node-service", "config", "atproto", "default", "node-atproto"),
    "php-laminas-omeka": ("php-web", "config", "php-laminas", "default", "omeka-s"),
    "python": ("python", "python-web", "config", "python-service", "default"),
}


@pytest.fixture
def builtin_metadata():
    return [analyzer.metadata.model_copy(deep=True) for analyzer in analyzers.get_builtin_repository_analyzers()]


@pytest.fixture
def full_metadata(builtin_metadata):
    # Simulate the selected effective implementations, not plugin discovery.
    return [
        *builtin_metadata,
        AnalyzerMetadata(name="python", priority=10, experimental=False, enabled_by_default=True),
        AnalyzerMetadata(name="node-service", priority=25, experimental=True, enabled_by_default=False),
        AnalyzerMetadata(name="atproto", priority=90, experimental=True, enabled_by_default=False),
    ]


def _profile(payload, name):
    return next(profile for profile in payload["profiles"] if profile["name"] == name)


def test_definitions_have_versioned_membership_and_are_immutable():
    profiles = get_analyzer_profiles()
    assert {profile.name: profile.module_names for profile in profiles} == PROFILE_MODULES
    assert all(profile.version == "1.0" for profile in profiles)
    assert [profile.qualified_name for profile in profiles] == [f"{name}@1.0" for name in PROFILE_MODULES]
    with pytest.raises(FrozenInstanceError):
        profiles[1].module_names = ()


@pytest.mark.parametrize("name", ["node-atproto", "php-laminas-omeka", "python"])
def test_explicit_profiles_retain_base_and_overlay_layers(name, full_metadata):
    selection = resolve_analyzer_profile(name, full_metadata)
    assert selection.module_names == PROFILE_MODULES[name]
    assert {"default", "config"} <= set(selection.module_names)
    assert selection.qualified_name == f"{name}@1.0"
    assert resolve_analyzer_profile(selection.qualified_name, full_metadata) == selection


def test_automatic_preserves_dynamic_default_enabled_universe(full_metadata):
    added = AnalyzerMetadata(name="future-default", priority=3, experimental=True, enabled_by_default=True)
    selection = resolve_analyzer_profile("automatic", [*full_metadata, added])
    expected = tuple(
        metadata.name for metadata in sorted([*full_metadata, added], key=lambda value: (value.priority, value.name))
        if metadata.enabled_by_default
    )
    assert selection.module_names is None
    assert selection.candidate_module_names == expected
    assert "future-default" in selection.candidate_module_names
    assert not {"atproto", "node-service"} & set(selection.candidate_module_names)
    assert selection.opt_in_module_names == ()


def test_profiles_resolve_without_discovery_detection_or_installation(monkeypatch, full_metadata):
    def forbidden(*args, **kwargs):
        pytest.fail("Profile resolution must only inspect the supplied metadata")

    monkeypatch.setattr(analyzers, "get_registered_analyzers", forbidden)
    monkeypatch.setattr(analyzers, "discover_installed_analyzers", forbidden)
    monkeypatch.setattr(analyzers, "select_requested_analyzers", forbidden)
    monkeypatch.setattr(analyzers, "_should_run_analyzer", forbidden)
    assert resolve_analyzer_profile("node-atproto", full_metadata).module_names == PROFILE_MODULES["node-atproto"]
    assert len(analyzer_profile_inventory(full_metadata)["profiles"]) == 4


def test_builtin_only_engine_reports_missing_plugin_layers(builtin_metadata):
    assert len(builtin_metadata) == 9
    inventory = analyzer_profile_inventory(builtin_metadata)
    assert _profile(inventory, "automatic")["available"] is True
    assert _profile(inventory, "php-laminas-omeka")["available"] is True
    assert _profile(inventory, "node-atproto")["missing_module_names"] == ["node-service", "atproto"]
    assert _profile(inventory, "python")["missing_module_names"] == ["python"]
    with pytest.raises(MissingProfileModulesError) as caught:
        resolve_analyzer_profile("node-atproto", builtin_metadata)
    assert caught.value.missing_module_names == ("node-service", "atproto")
    assert caught.value.profile_version == "1.0"
    assert "node-atproto@1.0" in str(caught.value)


def test_missing_base_is_an_error_even_when_all_optional_layers_exist(full_metadata):
    incomplete = [metadata for metadata in full_metadata if metadata.name != "config"]
    with pytest.raises(MissingProfileModulesError, match="config"):
        resolve_analyzer_profile("node-atproto", incomplete)


@pytest.mark.parametrize("name", ["unknown", "node-atproto@2.0", "Node-ATProto", ""])
def test_unknown_names_and_versions_fail_clearly(name, full_metadata):
    with pytest.raises(AnalyzerProfileError, match="Unknown analyzer profile"):
        resolve_analyzer_profile(name, full_metadata)


@pytest.mark.parametrize("name", PROFILE_MODULES)
def test_profile_conflicts_with_bare_explicit_modules(name, full_metadata):
    with pytest.raises(AnalyzerProfileError, match="cannot be combined with explicit --module"):
        resolve_analyzer_profile(name, full_metadata, explicit_modules=["config"])
    assert resolve_analyzer_profile(name, full_metadata, explicit_modules=[])


def test_serialization_is_deterministic_and_accepts_metadata_mappings(full_metadata):
    payload = analyzer_profile_inventory(full_metadata)
    from_mappings = analyzer_profile_inventory(item.model_dump() for item in reversed(full_metadata))
    assert payload == from_mappings
    assert json.dumps(payload, sort_keys=True) == json.dumps(from_mappings, sort_keys=True)
    assert payload["schema_version"] == ANALYZER_PROFILES_SCHEMA_VERSION
    selection = resolve_analyzer_profile("node-atproto", full_metadata)
    assert json.loads(json.dumps(selection.as_dict()))["profile_version"] == "1.0"


def test_effective_experimental_and_opt_in_flags_come_from_supplied_inventory(full_metadata):
    changed = [
        item.model_copy(update={"experimental": False, "enabled_by_default": True})
        if item.name == "node-service" else item for item in full_metadata
    ]
    selection = resolve_analyzer_profile("node-atproto", changed)
    assert selection.experimental_module_names == ("atproto", "node-atproto")
    assert selection.opt_in_module_names == ("atproto",)
    inventory = _profile(analyzer_profile_inventory(changed), "node-atproto")
    assert inventory["experimental_module_names"] == ["node-service", "atproto", "node-atproto"]
    assert inventory["installed_experimental_module_names"] == ["atproto", "node-atproto"]


def test_duplicate_inventory_names_fail_instead_of_silently_changing_implementation(full_metadata):
    duplicate = [*full_metadata, full_metadata[0]]
    with pytest.raises(AnalyzerProfileError, match="effective, deduplicated inventory"):
        analyzer_profile_inventory(duplicate)
    with pytest.raises(AnalyzerProfileError, match="Duplicate installed analyzer name"):
        resolve_analyzer_profile("automatic", duplicate)


def test_runtime_detection_still_gates_explicit_opt_in_modules(monkeypatch, tmp_path, full_metadata):
    class FakeAnalyzer:
        def __init__(self, metadata):
            self.metadata = metadata
            self.name = metadata.name

        def detect(self, root):
            assert root == tmp_path.resolve()
            return self.name != "atproto"

    registered = [FakeAnalyzer(metadata) for metadata in full_metadata]
    monkeypatch.setattr(analyzers, "get_registered_analyzers", lambda: registered)
    profile = resolve_analyzer_profile("node-atproto", full_metadata)
    explicit = [item for item in registered if item.name in profile.module_names]
    actual = analyzers.resolve_run_analyzers(tmp_path, analyzers=explicit)
    assert [item.name for item in actual] == [
        "javascript-web", "node-service", "config", "default", "node-atproto",
    ]
    automatic = analyzers.resolve_run_analyzers(tmp_path)
    assert "node-service" not in {item.name for item in automatic}
    # Bare -m remains an exact list, with no profile expansion at runtime.
    bare = analyzers.resolve_run_analyzers(tmp_path, analyzers=[next(item for item in registered if item.name == "node-service")])
    assert [item.name for item in bare] == ["node-service"]


def test_runtime_priority_and_name_order_are_not_profile_membership_order(monkeypatch, tmp_path, full_metadata):
    class FakeAnalyzer:
        def __init__(self, metadata):
            self.metadata = metadata
            self.name = metadata.name

        def detect(self, root):
            return True

    changed = [item.model_copy(update={"priority": 1}) if item.name == "node-atproto" else item for item in full_metadata]
    profile = resolve_analyzer_profile("node-atproto", changed)
    registered = [FakeAnalyzer(metadata) for metadata in changed if metadata.name in profile.module_names]
    monkeypatch.setattr(analyzers, "get_registered_analyzers", lambda: registered)
    actual = analyzers.resolve_run_analyzers(tmp_path, analyzers=registered)
    assert profile.module_names[-1] == "node-atproto"
    assert profile.candidate_module_names == tuple(item.name for item in actual)
    assert profile.candidate_module_names[0] == "node-atproto"
