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
