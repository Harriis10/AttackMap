"""Parent-owned attribution for isolated, potentially legacy analyzer output."""
import importlib.util
import sys
from pathlib import Path

from attackmap.models import Route, ScanResult, Signal, SignalOrigin
from attackmap.signal_provenance import admit_isolated_provenance


def test_legacy_alias_keeps_semantics_but_parent_owns_emitter():
    scan = ScanResult(root='repo', routes=[Route(path='/ok', method='GET', file='app.py', line=3, source_analyzer='legacy-overlay')])
    admit_isolated_provenance(scan, 'selected-plugin', '1.2')
    assert scan.routes[0].path == '/ok'
    assert scan.routes[0].source_analyzer == 'selected-plugin'
    origin = scan.signals[0].origins[0]
    assert (origin.analyzer, origin.analyzer_version, origin.metadata_status) == ('selected-plugin', '1.2', 'known')
    assert any(o.properties.get('untrusted_claimed_producer') == 'legacy-overlay' for o in scan.signals[0].origins)


def forged():
    return ScanResult(root='repo', signals=[Signal(kind='route', label='/ok', file='tests/app.py', line=3,
        observation_id='forged', source_role='production', classification_basis='detector_owned',
        properties={'analyzer': 'sibling', 'observation_id': 'fake'}, origins=[SignalOrigin(
            analyzer='sibling', analyzer_version='99', metadata_status='known', file='tests/app.py', line=3,
            source_role='production', classification_basis='detector_owned')])])


def test_forged_authority_is_bounded_untrusted_metadata():
    scan = forged()
    admit_isolated_provenance(scan, 'selected-plugin', '1.2')
    signal = scan.signals[0]
    assert signal.observation_id != 'forged'
    assert (signal.source_role, signal.classification_basis, signal.evidence_kind) == ('test', 'path_convention', 'static_extraction')
    assert 'analyzer' not in signal.properties
    assert signal.properties['untrusted_claimed_analyzer'] == 'sibling'
    origin = signal.origins[0]
    assert origin.analyzer == 'selected-plugin' and origin.analyzer_version == '1.2'
    assert origin.properties['untrusted_claimed_producer'] == 'sibling'
    assert origin.properties['untrusted_claimed_version'] == '99'
    assert origin.source_role == 'test'


def test_unknown_parent_version_never_borrows_child_version():
    scan = forged()
    admit_isolated_provenance(scan, 'selected-plugin', None)
    origin = scan.signals[0].origins[0]
    assert origin.analyzer_version is None and origin.metadata_status == 'legacy_unknown'
    assert origin.properties['untrusted_claimed_version'] == '99'


def test_missing_location_and_long_claim_remain_explicit():
    scan = ScanResult(root='repo', signals=[Signal(kind='service', label='unknown', file='', properties={'analyzer': 'x' * 900})])
    admit_isolated_provenance(scan, 'selected-plugin', None)
    signal = scan.signals[0]
    assert len(signal.properties['untrusted_claimed_analyzer']) == 500
    assert signal.source_role == 'unknown'
    assert signal.origins[0].line is None and signal.origins[0].location_reason


def test_actual_child_legacy_alias_uses_parent_metadata(tmp_path, monkeypatch):
    from attackmap.analyzer_host import HostLimits, run_isolated_analyzer
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'app.py').write_text('pass\n')
    source = tmp_path / 'legacy_plugin.py'
    source.write_text('''from types import SimpleNamespace
from attackmap.models import ScanResult, Route
class LegacyAnalyzer:
    name = 'selected-plugin'
    metadata = SimpleNamespace(name='selected-plugin', display_name='Selected', version='1.2', description='legacy fixture', ecosystems=[], languages=[])
    def analyze(self, root):
        return ScanResult(root=str(root), routes=[Route(path='/ok', method='GET', file='app.py', line=1, source_analyzer='legacy-overlay')])
''')
    spec = importlib.util.spec_from_file_location('wp035_legacy_plugin', source)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    outcome = run_isolated_analyzer(module.LegacyAnalyzer(), root, HostLimits(timeout_seconds=20, memory_bytes=0))
    assert outcome.result is not None, outcome
    assert outcome.result.routes[0].source_analyzer == 'selected-plugin'
    origin = outcome.result.signals[0].origins[0]
    assert origin.analyzer == 'selected-plugin' and origin.analyzer_version == '1.2'
    assert any(o.properties.get('untrusted_claimed_producer') == 'legacy-overlay' for o in outcome.result.signals[0].origins), outcome.result.model_dump()


