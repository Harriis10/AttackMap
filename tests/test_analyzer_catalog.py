from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from attackmap import analyzers as registry
from attackmap.analyzer_catalog import get_analyzer_catalog
from attackmap.analyzer_contracts import AnalyzerMetadata, AnalyzerResult
from attackmap.plugins_lock import OFFICIAL_PLUGINS


class _Distribution:
    def __init__(self, name: str, direct_url: object = None) -> None:
        self.name = name
        self.version = "2.3.4"
        self.direct_url = direct_url

    def read_text(self, name: str) -> str | None:
        assert name == "direct_url.json"
        return json.dumps(self.direct_url) if self.direct_url is not None else None


class _EntryPoint:
    def __init__(self, name: str, loaded: object, *, package: str = "third-party", direct_url: object = None) -> None:
        self.name = name
        self.value = "example.plugin:Analyzer"
        self.dist = _Distribution(package, direct_url)
        self.loaded = loaded
        self.loads = 0

    def load(self) -> object:
        self.loads += 1
        if isinstance(self.loaded, Exception):
            raise self.loaded
        return self.loaded


class _EntryPoints:
    def __init__(self, candidates: list[_EntryPoint]) -> None:
        self.candidates = candidates
        self.selections = 0

    def select(self, *, group: str) -> list[_EntryPoint]:
        assert group == registry.ANALYZER_ENTRYPOINT_GROUP
        self.selections += 1
        return self.candidates


class _Plugin:
    def __init__(self, name: str, priority: int = 20, *, enabled_by_default: bool = False) -> None:
        self.name = name
        self.metadata = AnalyzerMetadata(name=name, priority=priority, enabled_by_default=enabled_by_default)

    def detect(self, root: Path) -> bool:
        raise AssertionError("Discovery must not evaluate repository applicability")

    def analyze(self, root: Path) -> AnalyzerResult:
        raise AssertionError("Discovery must not execute an analyzer")


def _install(monkeypatch: pytest.MonkeyPatch, *points: _EntryPoint) -> _EntryPoints:
    monkeypatch.delenv(registry.TRUSTED_ONLY_ENV, raising=False)
    entry_points = _EntryPoints(list(points))
    monkeypatch.setattr(registry, "entry_points", lambda: entry_points)
    return entry_points


def _plugin_rows(payload: dict) -> list[dict]:
    return [row for row in payload["candidates"] if row["origin"] == "plugin"]


def test_catalog_retains_all_three_php_collisions_and_builtin_precedence(monkeypatch) -> None:
    names = ["php-web", "php-laminas", "omeka-s"]
    points = [_EntryPoint(name, _Plugin(name, priority=0), package=f"attackmap-analyzer-{name}") for name in names]
    discovery = _install(monkeypatch, *points)

    snapshot = get_analyzer_catalog()
    payload = snapshot.to_dict()

    assert discovery.selections == 1
    assert [point.loads for point in points] == [1, 1, 1]
    assert len(snapshot.analyzers) == 9
    assert len(payload["candidates"]) == 12
    winners = {row["name"]: row for row in payload["candidates"] if row["status"] == "effective"}
    for row in _plugin_rows(payload):
        winner = winners[row["name"]]
        assert row["status"] == "shadowed"
        assert row["shadowed_by"] == winner["candidate_id"]
        assert row["metadata"]["priority"] == 0
        assert winner["origin"] == "builtin"
        assert winner["implementation"]["module"] == "attackmap.ecosystem_php"
        assert winner["provenance"]["declared_pin"] is None
        assert row["provenance"]["declared_pin"]["package"] == row["package"]["name"]


def test_snapshot_metadata_matches_effective_run_order_and_loads_once(monkeypatch) -> None:
    early = _EntryPoint("zz-alias", _Plugin("early", priority=0))
    tie = _EntryPoint("aa-alias", _Plugin("aaa-tie", priority=20))
    discovery = _install(monkeypatch, early, tie)

    snapshot = get_analyzer_catalog()
    payload = snapshot.to_dict()

    expected = sorted([*registry.get_builtin_repository_analyzers(), early.loaded, tie.loaded], key=registry._run_order_key)
    assert [item.name for item in snapshot.analyzers] == [item.name for item in expected]
    assert [item.model_dump() for item in snapshot.metadata] == [registry.get_analyzer_metadata(item).model_dump() for item in expected]
    assert payload["effective_order"][:2] == ["early", "aaa-tie"]
    assert payload["scope"] == "installed_discovery"
    assert payload["policy"] == {"registry_precedence": "builtin_first_seen_name", "run_order": ["priority", "name"], "trusted_only": False}
    assert discovery.selections == 1 and early.loads == tie.loads == 1
    assert not any("executed" in row or "applicable" in row for row in payload["candidates"])
    assert _plugin_rows(payload)[0]["metadata"]["enabled_by_default"] is False
    # Consumers may retain or annotate their JSON without mutating the snapshot.
    payload["candidates"].clear()
    assert len(snapshot.to_dict()["candidates"]) == 11


def test_plugin_name_collision_uses_entry_point_order_before_priority(monkeypatch) -> None:
    first = _EntryPoint("a-alias", _Plugin("same-name", priority=200), package="first-package")
    second = _EntryPoint("z-alias", _Plugin("same-name", priority=0), package="second-package")
    _install(monkeypatch, second, first)

    snapshot = get_analyzer_catalog()
    rows = _plugin_rows(snapshot.to_dict())

    assert [(row["package"]["name"], row["status"]) for row in rows] == [("first-package", "effective"), ("second-package", "shadowed")]
    assert rows[1]["shadowed_by"] == rows[0]["candidate_id"]
    assert snapshot.analyzers[-1] is first.loaded


def test_trusted_only_records_third_party_without_loading_it(monkeypatch) -> None:
    third_party = _EntryPoint("external", _Plugin("external"))
    official = _EntryPoint("python", _Plugin("python"), package="attackmap-analyzer-python")
    _install(monkeypatch, third_party, official)
    monkeypatch.setenv(registry.TRUSTED_ONLY_ENV, "1")

    payload = get_analyzer_catalog().to_dict()
    rows = {row["name"]: row for row in _plugin_rows(payload)}

    assert third_party.loads == 0 and official.loads == 1
    assert rows["external"]["status"] == "skipped_policy"
    assert rows["external"]["metadata"] is None
    assert rows["external"]["official_package"] is False
    assert rows["python"]["status"] == "effective"
    assert rows["python"]["official_package"] is True
    assert payload["policy"]["trusted_only"] is True


def test_third_party_is_effective_under_existing_default_policy(monkeypatch) -> None:
    point = _EntryPoint("external", _Plugin("external"))
    _install(monkeypatch, point)

    row = _plugin_rows(get_analyzer_catalog().to_dict())[0]

    assert row["status"] == "effective"
    assert row["official_package"] is False
    assert row["package"] == {"name": "third-party", "version": "2.3.4"}
    assert row["entry_point"] == {"name": "external", "group": registry.ANALYZER_ENTRYPOINT_GROUP, "value": "example.plugin:Analyzer"}


def test_discovery_keeps_named_load_initialization_metadata_and_contract_errors(monkeypatch) -> None:
    class BrokenInitialization:
        def __init__(self) -> None:
            raise RuntimeError("secret initialization detail")

    class BrokenMetadata:
        name = "bad-meta"
        metadata = {"name": "INVALID NAME"}

        def analyze(self, root):
            return None

    class BrokenContract:
        name = "bad-contract"
        metadata = AnalyzerMetadata(name="bad-contract")
        analyze = None

    points = [
        _EntryPoint("load", ImportError("secret load detail")),
        _EntryPoint("init", BrokenInitialization),
        _EntryPoint("metadata", BrokenMetadata()),
        _EntryPoint("contract", BrokenContract()),
        _EntryPoint("good", _Plugin("good")),
    ]
    _install(monkeypatch, *points)

    payload = get_analyzer_catalog().to_dict()
    rows = {row["entry_point"]["name"]: row for row in _plugin_rows(payload)}

    assert {name: row["status"] for name, row in rows.items()} == {
        "load": "load_error", "init": "initialization_error", "metadata": "metadata_error", "contract": "contract_error", "good": "effective",
    }
    assert rows["load"]["error"] == {"stage": "load", "error_type": "ImportError"}
    assert rows["init"]["error"] == {"stage": "initialization", "error_type": "RuntimeError"}
    assert rows["metadata"]["error"]["error_type"] == "ValidationError"
    assert "secret load detail" not in json.dumps(payload)
    assert "secret initialization detail" not in json.dumps(payload)
    assert payload["discovery_errors"] == []
    assert payload["effective_order"].count("good") == 1
    assert [point.loads for point in points] == [1] * 5


def test_entry_point_enumeration_failure_is_not_reported_as_empty_discovery(monkeypatch) -> None:
    def broken_entry_points():
        raise OSError("secret directory")

    monkeypatch.setattr(registry, "entry_points", broken_entry_points)

    snapshot = get_analyzer_catalog()

    assert len(snapshot.analyzers) == 9
    assert snapshot.to_dict()["discovery_errors"] == [{"stage": "entry_points", "error_type": "OSError"}]
    assert "secret directory" not in json.dumps(snapshot.to_dict())
    # Existing callers retain their error semantics unless they request a catalog.
    with pytest.raises(OSError, match="secret directory"):
        registry.discover_installed_analyzers()


@pytest.mark.parametrize("source_kind", ["wheel", "archive", "directory", "missing"])
def test_distribution_path_or_wheel_hash_does_not_verify_declared_git_pin(monkeypatch, source_kind) -> None:
    lock = next(item for item in OFFICIAL_PLUGINS if item["package"] == "attackmap-analyzer-python")
    direct = {
        "wheel": {"url": f"file:///builds/{lock['git_sha']}.whl", "archive_info": {"hashes": {"sha256": "a" * 64}}},
        "archive": {"url": f"file:///builds/{lock['git_sha']}.zip", "archive_info": {}},
        "directory": {"url": f"file:///builds/{lock['git_sha']}", "dir_info": {"editable": True}},
        "missing": None,
    }[source_kind]
    _install(monkeypatch, _EntryPoint("python", _Plugin("python"), package=lock["package"], direct_url=direct))

    provenance = _plugin_rows(get_analyzer_catalog().to_dict())[0]["provenance"]

    assert provenance["declared_pin"] == lock
    assert provenance["pin_status"] == "unverified"
    assert provenance["content_verified"] is False
    assert provenance["installed_source"]["kind"] == ("distribution_metadata_only" if source_kind == "missing" else source_kind)


@pytest.mark.parametrize("matching_commit,matching_repo", [(True, True), (False, True), (True, False)])
def test_vcs_metadata_comparison_never_claims_content_attestation(monkeypatch, matching_commit, matching_repo) -> None:
    lock = next(item for item in OFFICIAL_PLUGINS if item["package"] == "attackmap-analyzer-python")
    direct = {
        "url": f"https://github.com/mlaify/{lock['repo'] if matching_repo else 'other-repo'}.git",
        "vcs_info": {"vcs": "git", "commit_id": lock["git_sha"] if matching_commit else "0" * 40, "requested_revision": "main"},
    }
    _install(monkeypatch, _EntryPoint("python", _Plugin("python"), package=lock["package"], direct_url=direct))

    provenance = _plugin_rows(get_analyzer_catalog().to_dict())[0]["provenance"]

    assert provenance["pin_status"] == ("matches_installed_vcs_metadata" if matching_commit and matching_repo else "differs_from_installed_vcs_metadata")
    assert provenance["content_verified"] is False
    assert provenance["installed_source"]["commit_id"] == direct["vcs_info"]["commit_id"]


def test_malformed_direct_url_is_named_without_hiding_effective_plugin(monkeypatch) -> None:
    point = _EntryPoint("external", _Plugin("external"))
    point.dist.read_text = lambda name: "not JSON with secret text"
    _install(monkeypatch, point)

    row = _plugin_rows(get_analyzer_catalog().to_dict())[0]

    assert row["status"] == "effective"
    assert row["provenance"]["errors"] == [{"stage": "provenance_metadata", "error_type": "JSONDecodeError"}]
    assert "secret" not in json.dumps(row)


def test_direct_url_credentials_and_query_are_not_exposed(monkeypatch) -> None:
    direct = {"url": "https://user:secret@example.test/package.whl?token=secret#secret", "archive_info": {}}
    _install(monkeypatch, _EntryPoint("external", _Plugin("external"), direct_url=direct))

    row = _plugin_rows(get_analyzer_catalog().to_dict())[0]

    assert row["provenance"]["installed_source"]["url"] == "https://example.test/package.whl"
    assert "secret" not in json.dumps(row)


def test_observed_source_hash_is_bounded_to_class_source_file(monkeypatch, tmp_path) -> None:
    source = tmp_path / "observed.py"
    source.write_text("# observed class source\n", encoding="utf-8")
    monkeypatch.setattr("attackmap.analyzer_catalog.inspect.getsourcefile", lambda cls: str(source))
    _install(monkeypatch)

    first = get_analyzer_catalog().to_dict()["candidates"][0]["implementation"]
    source.write_text("# changed class source\n", encoding="utf-8")
    second = get_analyzer_catalog().to_dict()["candidates"][0]["implementation"]

    assert first["source_status"] == second["source_status"] == "observed_file"
    assert second["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert first["source_sha256"] != second["source_sha256"]


def test_unavailable_source_does_not_invent_frozen_provenance(monkeypatch) -> None:
    monkeypatch.setattr("attackmap.analyzer_catalog.inspect.getsourcefile", lambda cls: None)
    _install(monkeypatch)

    row = get_analyzer_catalog().to_dict()["candidates"][0]

    assert row["implementation"]["source_sha256"] is None
    assert row["implementation"]["source_status"] == "unavailable"
    assert row["provenance"]["content_verified"] is False


def test_undiscovered_official_packages_are_distinct_from_failed_entry_points(monkeypatch) -> None:
    point = _EntryPoint("python", ImportError(), package="attackmap-analyzer-python")
    _install(monkeypatch, point)

    payload = get_analyzer_catalog().to_dict()

    assert "attackmap-analyzer-python" not in payload["undiscovered_official_packages"]
    assert "attackmap-analyzer-go" in payload["undiscovered_official_packages"]
    assert _plugin_rows(payload)[0]["status"] == "load_error"


def test_legacy_entry_point_mapping_still_supports_catalog(monkeypatch) -> None:
    point = _EntryPoint("external", _Plugin("external"))
    monkeypatch.delenv(registry.TRUSTED_ONLY_ENV, raising=False)
    monkeypatch.setattr(registry, "entry_points", lambda: {registry.ANALYZER_ENTRYPOINT_GROUP: [point]})

    assert _plugin_rows(get_analyzer_catalog().to_dict())[0]["status"] == "effective"
    assert point.loads == 1
