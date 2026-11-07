from itertools import permutations

from attackmap.analyzers import merge_analyzer_results
from attackmap.models import Route, ScanResult


def _scan(auth, analyzer, files=None):
    return ScanResult(root='.', files_scanned=2,scanned_files=files,
                      routes=[Route(path='/account',method='GET',file='app.py',auth=auth,source_analyzer=analyzer)])


def test_merge_owns_deep_copies_and_preserves_original_auth():
    unknown, protected = _scan('unknown','base'), _scan('required','framework')
    result = merge_analyzer_results([unknown,protected])
    assert unknown.routes[0].auth == 'unknown'
    assert result.routes[0].auth == 'required'
    result.routes[0].guards.append('later')
    assert unknown.routes[0].guards == [] and protected.routes[0].guards == []


def test_normalized_conflicts_and_origins_are_permutation_invariant():
    inputs = [_scan('required','a'),_scan('anonymous','b'),_scan('required','c')]
    outputs = [merge_analyzer_results(order).all_signals() for order in permutations(inputs)]
    expected = [signal.model_dump() for signal in outputs[0]]
    assert all([signal.model_dump() for signal in output] == expected for output in outputs)
    signal = outputs[0][0]
    assert signal.observation_id.startswith('obs-')
    assert {origin.analyzer for origin in signal.origins} == {'a','b','c'}
    assert signal.conflicts[0].field == 'auth'
    assert signal.conflicts[0].values == ['anonymous','required']
    assert len(outputs[0]) == 1
    assert all(origin.location_reason for origin in signal.origins)


def test_known_coverage_is_unique_and_unknown_coverage_is_explicit():
    known = merge_analyzer_results([_scan('required','a',['app.py','x.py']),_scan('required','b',['app.py','y.py'])])
    assert known.files_scanned == 3
    assert known.scanned_files == ['app.py','x.py','y.py']
    mixed = merge_analyzer_results([_scan('required','a',['app.py']),_scan('required','b')])
    assert mixed.scanned_files is None
    assert mixed.files_scanned == 4
    assert any('Unique-file coverage unavailable' in limitation for limitation in mixed.limitations)


def test_legacy_origin_unknown_and_json_roundtrip_retains_provenance():
    merged = merge_analyzer_results([_scan('unknown',None)])
    signal = merged.all_signals()[0]
    assert signal.origins[0].metadata_status == 'legacy_unknown'
    assert signal.origins[0].analyzer_version is None
    reopened = ScanResult.model_validate_json(merged.model_dump_json())
    assert reopened.all_signals() == merged.all_signals()


def test_remerge_preserves_conflicts_without_adding_synthetic_origin():
    merged = merge_analyzer_results([_scan('required','a'),_scan('anonymous','b')])
    again = merge_analyzer_results([merged,merged])
    assert again.all_signals() == merged.all_signals()



def test_distinct_secret_locations_and_outbound_methods_are_not_collapsed():
    from attackmap.models import SecretHint, ExternalCall
    source = ScanResult(root='.',secret_hints=[SecretHint(name='AKIA...',file='app.py',line=1),SecretHint(name='AKIA...',file='app.py',line=2)],external_calls=[ExternalCall(target='https://api',file='app.py',method='GET'),ExternalCall(target='https://api',file='app.py',method='POST')])
    signals = merge_analyzer_results([source]).all_signals()
    assert len(signals) == 4
    assert len({signal.observation_id for signal in signals}) == 4
