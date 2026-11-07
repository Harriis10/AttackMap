"""Windows release pipeline: build definition consistency.

These tests guard the P1 follow-up to consolidate the Windows build into a
single authoritative PyInstaller spec and keep the batch wrapper thin.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SPEC = PROJECT_ROOT / "installer" / "attackmap.spec"
BATCH = PROJECT_ROOT / "installer" / "build-installer.bat"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


@pytest.mark.skipif(not SPEC.exists(), reason="PyInstaller spec not present")
def test_spec_exists() -> None:
    assert SPEC.is_file()


@pytest.mark.skipif(not BATCH.exists(), reason="Build batch not present")
def test_build_batch_uses_spec() -> None:
    text = BATCH.read_text(encoding="utf-8")
    assert "attackmap.spec" in text, "build-installer.bat should delegate to attackmap.spec"
    assert "--collect-all" not in text, "analyzer collection should live in the spec"
    assert "--hidden-import" not in text, "hidden imports should live in the spec"


def _analyzer_module_names_from_pyproject() -> set[str]:
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    in_all = False
    names: set[str] = set()
    for line in pyproject.splitlines():
        stripped = line.strip()
        if stripped == "all = [":
            in_all = True
            continue
        if in_all:
            if stripped == "]":
                break
            # Lines look like: "attackmap-analyzer-python @ git+..."
            # or the legacy typo "attack-map-analyzer-omeka-s @ ...".
            match = re.search(r"analyzer-([-a-z0-9]+)\s*@", stripped)
            if match:
                suffix = match.group(1).replace("-", "_")
                names.add(f"attackmap_analyzer_{suffix}")
    return names


@pytest.mark.skipif(not SPEC.exists(), reason="PyInstaller spec not present")
def test_spec_collects_all_analyzer_plugins() -> None:
    expected = _analyzer_module_names_from_pyproject()
    assert expected, "could not parse analyzer packages from pyproject.toml"

    source = SPEC.read_text(encoding="utf-8")
    tree = ast.parse(source)

    pkg_list: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "ANALYZER_PKGS":
                    pkg_list = [elt.value for elt in node.value.elts if isinstance(elt, ast.Constant)]
                    break

    missing = expected - set(pkg_list)
    extra = set(pkg_list) - expected
    assert not missing, f"spec missing collect_all for analyzers: {missing}"
    assert not extra, f"spec has unexpected analyzer entries: {extra}"


@pytest.mark.skipif(not SPEC.exists(), reason="PyInstaller spec not present")
def test_spec_includes_required_hiddenimports() -> None:
    required = {
        "attackmap.cli",
        "attackmap.analyzers",
        "attackmap.ui",
        "attackmap.ui.launch",
        "attackmap.ui.server",
        "attackmap.ui.runner",
        "attackmap.ui.config",
        "attackmap.ui.report",
        "attackmap.ui.output",
        "attackmap.ui.secrets",
        "attackmap.ui.watch",
        "attackmap.ui.suppress_write",
        "attackmap.ui.spawn",
    }
    source = SPEC.read_text(encoding="utf-8")
    missing = {name for name in required if name not in source}
    assert not missing, f"spec missing hiddenimports: {missing}"


@pytest.mark.skipif(not SPEC.exists(), reason="PyInstaller spec not present")
def test_spec_includes_required_data_files() -> None:
    source = SPEC.read_text(encoding="utf-8")
    for needle in [
        "attackmap/ui/web",
        "attackmap/ui/fixtures",
        "taint_sinks.yaml",
    ]:
        assert needle in source, f"spec missing data file: {needle}"


CI_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
SMOKE_TESTS = PROJECT_ROOT / "installer" / "smoke-tests.ps1"


@pytest.mark.skipif(not CI_WORKFLOW.exists(), reason="CI workflow not present")
def test_ci_includes_windows_build_job() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "windows-build" in text, "CI workflow missing windows-build job"
    assert "build-installer.bat" in text, "CI workflow does not run the Windows build"
    assert "smoke-tests.ps1" in text, "CI workflow does not run frozen smoke tests"


@pytest.mark.skipif(not SMOKE_TESTS.exists(), reason="Smoke tests script not present")
def test_smoke_tests_script_references_exe() -> None:
    text = SMOKE_TESTS.read_text(encoding="utf-8")
    assert "attackmap.exe" in text, "smoke tests should exercise attackmap.exe"
    assert "--version" in text
    assert "capabilities" in text
    assert "modules" in text
    assert "analyze" in text
