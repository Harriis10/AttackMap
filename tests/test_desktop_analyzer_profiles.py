"""A versioned native profile reaches the same offline selection and ledger path."""
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from attackmap import analyzers, scan_service
from attackmap.cli import app
from attackmap.desktop_capabilities import build_capabilities, preflight_capabilities, validate_desktop_request
from attackmap.run_contract import RunRequest, ScanOptionsV15


def payload(tmp_path, profile="php-laminas-omeka@1.0", schema="1.5"):
    return dict(schema_version=schema, kind="request", run_id="profile-test", repository_id="repo",
                generation=1, revision=0, repository_path=str(tmp_path), output_path=str(tmp_path / "out"),
                modules=[], options={"analyzer_profile": profile})


@pytest.mark.parametrize("schema", ["1.0", "1.1", "1.2", "1.3", "1.4"])
def test_old_schemas_reject_profile_instead_of_ignoring_it(tmp_path, schema):
    with pytest.raises(ValueError, match="unsupported or malformed"):
        validate_desktop_request(payload(tmp_path, schema=schema))


@pytest.mark.parametrize("profile", ["python", "", "python@2.0\n", "python@1.0 --install", 5])
def test_profile_requires_bounded_qualified_identity(tmp_path, profile):
    with pytest.raises(ValueError):
        validate_desktop_request(payload(tmp_path, profile))


def test_explicit_modules_cannot_override_named_profile(tmp_path):
    raw = payload(tmp_path) | {"modules": ["config"]}
    with pytest.raises(ValidationError, match="cannot be combined"):
        RunRequest.model_validate(raw)


def test_profile_reaches_application_and_pipeline_once(tmp_path, monkeypatch):
    registry_calls, pipeline_calls = [], []
    def registry():
        registry_calls.append(True)
        return analyzers.get_builtin_repository_analyzers()
    monkeypatch.setattr(analyzers, "get_registered_analyzers", registry)
    def run(request, selected):
        pipeline_calls.append(scan_service._analyze_options(request, tmp_path, request.output, selected))
        return scan_service.RunSummary(exit_code=0)
    monkeypatch.setattr(scan_service, "_run_single_repo", run)
    request = scan_service.scan_request_from_run(validate_desktop_request(payload(tmp_path)))
    assert scan_service.execute_scan_request(request).exit_code == 0
    assert len(registry_calls) == 1
    assert pipeline_calls[0].analyzer_profile_id == "php-laminas-omeka@1.0"
    assert [a.name for a in pipeline_calls[0].analyzers] == ["php-web", "config", "php-laminas", "default", "omeka-s"]


def test_automatic_keeps_discovery_at_pipeline(tmp_path, monkeypatch):
    def forbidden():
        pytest.fail("Automatic was eagerly discovered")
    monkeypatch.setattr(analyzers, "get_registered_analyzers", forbidden)
    monkeypatch.setattr(scan_service, "_run_single_repo", lambda request, selected:
                        scan_service.RunSummary(exit_code=0) if selected is None else pytest.fail("not automatic"))
    request = scan_service.scan_request_from_run(validate_desktop_request(payload(tmp_path, "automatic@1.0")))
    assert scan_service.execute_scan_request(request).exit_code == 0


@pytest.mark.parametrize("profile", ["python@1.0", "php-laminas-omeka@99.0"])
def test_missing_or_unknown_never_runs_or_installs(tmp_path, monkeypatch, profile):
    monkeypatch.setattr(analyzers, "get_registered_analyzers", analyzers.get_builtin_repository_analyzers)
    monkeypatch.setattr(analyzers, "install_analyzer_module", lambda *a, **kw: pytest.fail("install"))
    monkeypatch.setattr(scan_service, "_run_single_repo", lambda *a: pytest.fail("scan"))
    request = scan_service.scan_request_from_run(validate_desktop_request(payload(tmp_path, profile)))
    with pytest.raises(scan_service.ScanRequestError):
        scan_service.execute_scan_request(request)


def test_preflight_binds_profile_membership_and_availability(tmp_path):
    caps = build_capabilities(app, metadata=[a.metadata for a in analyzers.get_builtin_repository_analyzers()])
    raw = payload(tmp_path)
    assert preflight_capabilities(caps, request=raw)["supported"]
    assert not preflight_capabilities(caps, request=payload(tmp_path, "python@1.0"))["supported"]
    php = next(p for p in caps["analyzer_profiles"]["profiles"] if p["name"] == "php-laminas-omeka")
    php["module_names"] = ["php-laminas"]
    assert not preflight_capabilities(caps, request=raw)["supported"]


def test_profile_fleet_worker_keeps_profile_identity(tmp_path):
    request = scan_service.ScanRequest(repo_paths=[tmp_path], output=tmp_path / "out",
                                      analyzer_profile_id="php-laminas-omeka@1.0")
    argv = scan_service._run_fleet_repo_argv(request, tmp_path, tmp_path / "child", ["php-laminas"])
    assert argv[argv.index("--analyzer-profile") + 1] == request.analyzer_profile_id
    assert "--module" not in argv


def test_schema15_keeps_advanced_options(tmp_path):
    raw = payload(tmp_path)
    raw["options"]["provider"] = {"enable_ai": True, "provider": "openai", "mode": "hunt_verify", "jury_votes": 3}
    request = validate_desktop_request(raw)
    assert isinstance(request.options, ScanOptionsV15)
    assert request.options.provider.mode == "hunt_verify"


def test_mismatched_runtime_metadata_name_is_typed_failure(tmp_path, monkeypatch):
    registered = analyzers.get_builtin_repository_analyzers()
    original = next(a for a in registered if a.name == "php-web")
    mismatched = SimpleNamespace(name="different-runtime-name", metadata=original.metadata)
    registered = [mismatched if a is original else a for a in registered]
    monkeypatch.setattr(analyzers, "get_registered_analyzers", lambda: registered)
    request = scan_service.scan_request_from_run(validate_desktop_request(payload(tmp_path)))
    with pytest.raises(scan_service.ScanRequestError, match="runtime names"):
        scan_service.execute_scan_request(request)
    from typer.testing import CliRunner
    response = CliRunner().invoke(app, ["analyze", str(tmp_path), "-o", str(tmp_path / "cli"), "--analyzer-profile", "php-laminas-omeka"])
    assert response.exit_code == 2
    assert "runtime names" in response.output
