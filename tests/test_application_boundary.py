"""The application service and engine use neutral request/error contracts."""
import ast
from pathlib import Path

import pytest

from attackmap.application_errors import AnalysisConfigurationError, AnalysisExit
from attackmap.pipeline import AnalyzeOptions, run_scan
from attackmap.scan_service import ScanRequest, execute_scan_request


@pytest.mark.parametrize("name", ["scan_service.py", "pipeline.py", "application_errors.py"])
def test_core_service_has_no_presentation_import(name):
    path = Path(__file__).resolve().parents[1] / "src" / "attackmap" / name
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
    assert not any(module.split(".")[0] in {"typer", "click", "ui", "desktop_worker"}
                   for module in modules)


# --- Mechanical import-boundary matrix (C15) -------------------------------
# Roadmap C15: the shared application service accepts typed requests and
# returns typed results without importing Typer or desktop modules;
# presentation translates requests and renders results; analyzer modules do
# not import report rendering or scoring policy. The checks below resolve
# every import (module- and function-level, absolute and relative, including
# ``from package import name`` aliases) so a boundary crossing anywhere in a
# file is caught, not just at the top of it.

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "attackmap"
SERVICE_LAYER_MODULES = ["pipeline", "scan_service", "run_contract", "application_errors"]
ANALYZER_SURFACE_SEEDS = ["analyzers", "analyzer", "analyzer_contracts", "sdk"]
FORBIDDEN_FOR_ANALYZER_SURFACE = {
    # report rendering
    "attackmap.report", "attackmap.md", "attackmap.review_json", "attackmap.defensive_review",
    # scoring policy / ranking
    "attackmap.threat_model", "attackmap.triage",
}


def _module_name_of(path: Path) -> str:
    relative = path.relative_to(PACKAGE_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return "attackmap." + ".".join(parts)


def _module_file(name: str) -> Path | None:
    if not name.startswith("attackmap."):
        return None
    relative = Path(*name[len("attackmap."):].split("."))
    for candidate in (PACKAGE_ROOT / relative).with_suffix(".py"), PACKAGE_ROOT / relative / "__init__.py":
        if candidate.exists():
            return candidate
    return None


def _resolved_imports(path: Path) -> set[str]:
    """Absolute module names referenced by any import statement in ``path``."""
    module_name = _module_name_of(path)
    package = module_name.rsplit(".", 1)[0] if path.name != "__init__.py" else module_name
    resolved: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            resolved.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                parts = package.split(".")
                parts = parts[: len(parts) - (node.level - 1)]
                base = ".".join(filter(None, [*parts, node.module or ""]))
            resolved.add(base)
            resolved.update(f"{base}.{alias.name}" for alias in node.names)
    return resolved


def _imports_module(imports: set[str], forbidden: str) -> bool:
    return any(name == forbidden or name.startswith(forbidden + ".") for name in imports)


@pytest.mark.parametrize("name", SERVICE_LAYER_MODULES)
def test_service_layer_import_matrix_keeps_requests_and_results_neutral(name):
    path = PACKAGE_ROOT / f"{name}.py"
    imports = _resolved_imports(path)
    presentation = sorted(
        target for target in (*imports,)
        if _imports_module({target}, "typer") or _imports_module({target}, "click")
        or _imports_module({target}, "attackmap.ui") or _imports_module({target}, "attackmap.desktop_worker")
        or _imports_module({target}, "attackmap.desktop_actions") or _imports_module({target}, "attackmap.desktop_provider"))
    assert not presentation, (
        f"{name} is shared application service; Typer/Click/UI/desktop modules "
        f"belong to presentation adapters: {presentation}")


def test_analyzer_surface_import_matrix_excludes_rendering_and_scoring_policy():
    """The analyzer-facing surface (analyzers.py and its first-party closure,
    including the plugin SDK) never imports report rendering or scoring policy;
    rendering and ranking stay in core pipeline/presentation layers."""
    surface: dict[str, set[str]] = {}
    pending = list(ANALYZER_SURFACE_SEEDS)
    while pending:
        module = pending.pop()
        if module in surface:
            continue
        path = _module_file(f"attackmap.{module}")
        assert path is not None, f"analyzer surface seed {module!r} has no source file"
        surface[module] = _resolved_imports(path)
        for name in surface[module]:
            if name.startswith("attackmap.") and _module_file(name) and name not in surface:
                pending.append(name[len("attackmap."):])
    violations = sorted(
        (module, forbidden)
        for module, imports in surface.items()
        for forbidden in FORBIDDEN_FOR_ANALYZER_SURFACE
        if _imports_module(imports, forbidden))
    assert not violations, (
        "Analyzer-facing modules must not import report rendering or scoring "
        f"policy (move the dependency toward presentation instead): {violations}")


def test_presentation_adapters_translate_while_the_service_stays_neutral():
    """The two client adapters (CLI and desktop worker) import the typed
    service layer to translate requests; the reverse direction is forbidden by
    the service-layer matrix above. The desktop adapter's end-to-end legs are
    covered by tests/test_desktop_worker.py and the broker tests in
    tests/test_diagnostic_adapters.py. A macOS adapter does not exist yet
    (no darwin/macos module under src/attackmap as of this check)."""
    adapters = {
        "cli.py": {"attackmap.scan_service", "attackmap.pipeline"},
        "desktop_worker.py": {"attackmap.run_contract", "attackmap.pipeline"},
        "ui/contract_adapter.py": {"attackmap.run_contract"},
    }
    for adapter, expected in adapters.items():
        path = PACKAGE_ROOT / adapter
        assert path.exists(), f"missing presentation adapter {path}"
        imports = _resolved_imports(path)
        assert any(_imports_module(imports, service) for service in expected), (
            f"{adapter} must translate through the typed service layer {sorted(expected)}")


def test_invalid_configuration_is_neutral(tmp_path):
    with pytest.raises(AnalysisConfigurationError, match="requires --baseline"):
        run_scan(AnalyzeOptions(repo_path=tmp_path, output=tmp_path / "reports",
                                fail_on_new_high=True))


def test_controlled_engine_exit_translates_to_application_result(tmp_path, monkeypatch):
    def stop(_options):
        raise AnalysisExit(2)
    monkeypatch.setattr("attackmap.scan_service.run_scan", stop)
    result = execute_scan_request(ScanRequest(repo_paths=[tmp_path], output=tmp_path / "reports"))
    assert result.exit_code == 2 and result.report_path is None

@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows junction semantics')
def test_atomic_service_rejects_junction_before_output_marking_or_engine(tmp_path, monkeypatch):
    import os
    import subprocess
    from attackmap.scan_service import ScanRequestError
    target = tmp_path / 'outside'
    target.mkdir()
    junction = tmp_path / 'junction'
    result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(target)], capture_output=True)
    if result.returncode:
        pytest.skip('Junction creation unavailable')
    monkeypatch.setattr('attackmap.scan_service._run_single_repo', lambda *_: pytest.fail('engine must not start'))
    try:
        with pytest.raises(ScanRequestError):
            execute_scan_request(ScanRequest(repo_paths=[tmp_path], output=junction / 'reports'))
        assert list(target.iterdir()) == []
    finally:
        os.rmdir(junction)


def test_atomic_service_creates_normal_marked_output(tmp_path, monkeypatch):
    from attackmap.scan_service import RunSummary
    output = tmp_path / 'new' / 'reports'
    def engine(request, analyzers):
        assert output.is_dir()
        assert (output / '.attackmap-output').is_file()
        return RunSummary(exit_code=0)
    monkeypatch.setattr('attackmap.scan_service._run_single_repo', engine)
    assert execute_scan_request(ScanRequest(repo_paths=[tmp_path], output=output)).exit_code == 0
