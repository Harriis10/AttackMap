"""Profile dispatch preserves exact -m semantics and never enters installation."""
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from attackmap import analyzers
from attackmap.cli import app


@pytest.fixture
def dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(analyzers, "get_registered_analyzers", analyzers.get_builtin_repository_analyzers)

    def execute(request):
        calls.append(request)
        return SimpleNamespace(exit_code=0)

    def forbidden(*args, **kwargs):
        pytest.fail("Profile attempted installation or interactive confirmation")

    monkeypatch.setattr("attackmap.cli.execute_scan_request", execute)
    monkeypatch.setattr("attackmap.cli.install_analyzer_module", forbidden)
    monkeypatch.setattr(analyzers, "install_analyzer_module", forbidden)
    monkeypatch.setattr("typer.confirm", forbidden)
    return calls


def invoke(tmp_path, *args, fleet=False):
    repos = [str(tmp_path)]
    if fleet:
        second = tmp_path / "second"
        second.mkdir()
        repos.append(str(second))
    return CliRunner().invoke(app, ["analyze", *repos, "-o", str(tmp_path / "out"),
                                    "--no-progress", *args])


@pytest.mark.parametrize("fleet", [False, True])
def test_php_profile_expands_base_and_overlay_layers(tmp_path, dispatch, fleet):
    result = invoke(tmp_path, "--analyzer-profile", "php-laminas-omeka", fleet=fleet)
    assert result.exit_code == 0, result.output
    assert len(dispatch) == 1
    assert [a.name for a in dispatch[0].analyzers] == [
        "php-web", "config", "php-laminas", "default", "omeka-s",
    ]
    assert len(dispatch[0].repo_paths) == (2 if fleet else 1)
    assert "php-laminas-omeka@1.0" in result.output
    assert "Experimental modules selected: php-laminas, omeka-s." in result.output


@pytest.mark.parametrize("args", [[], ["--analyzer-profile", "automatic"]])
def test_default_and_automatic_keep_pipeline_default_selection(tmp_path, dispatch, args):
    result = invoke(tmp_path, *args)
    assert result.exit_code == 0, result.output
    assert dispatch[0].analyzers is None


def test_automatic_does_not_discover_twice(tmp_path, dispatch, monkeypatch):
    def forbidden():
        pytest.fail("Automatic profile performed discovery before the pipeline")

    monkeypatch.setattr(analyzers, "get_registered_analyzers", forbidden)
    result = invoke(tmp_path, "--analyzer-profile", "automatic@1.0")
    assert result.exit_code == 0, result.output
    assert dispatch[0].analyzers is None


def test_bare_module_remains_exact_selection(tmp_path, dispatch):
    result = invoke(tmp_path, "-m", "php-laminas")
    assert result.exit_code == 0, result.output
    assert [a.name for a in dispatch[0].analyzers] == ["php-laminas"]


@pytest.mark.parametrize("profile,missing", [
    ("node-atproto", "node-service"), ("python", "python"), ("typo", "typo"),
])
def test_missing_or_unknown_profile_fails_before_dispatch(tmp_path, dispatch, profile, missing):
    result = invoke(tmp_path, "--analyzer-profile", profile)
    assert result.exit_code == 2, result.output
    assert missing in result.output
    assert not dispatch


@pytest.mark.parametrize("args", [["-m", "config"], ["--install-missing"]])
@pytest.mark.parametrize("profile", ["automatic", "php-laminas-omeka"])
def test_conflicting_selection_fails_without_prompt(tmp_path, dispatch, args, profile):
    result = invoke(tmp_path, "--analyzer-profile", profile, *args)
    assert result.exit_code == 2, result.output
    assert "cannot be combined" in result.output
    assert not dispatch
