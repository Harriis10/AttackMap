"""Synthetic packaging safety; these fake bytes never execute a runtime."""
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

import pytest

SPEC = importlib.util.spec_from_file_location('portable_preview', Path(__file__).parents[1] / 'tools/package_native_portable_preview.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


@pytest.fixture
def inputs(tmp_path):
    native, engine = tmp_path / 'native', tmp_path / 'engine'
    native.mkdir(); engine.mkdir()
    for name in ('AttackMap.NativeSpike.exe','AttackMap.NativeSpike.dll','coreclr.dll','hostfxr.dll',
                 'hostpolicy.dll','Microsoft.ui.xaml.dll','AttackMap.NativeSpike.deps.json',
                 'AttackMap.NativeSpike.runtimeconfig.json'):
        (native / name).write_bytes(('fake-native:' + name).encode())
    (native / 'capture-smoke.json').write_bytes(b'not shipped')
    (native / 'AttackMap.NativeSpike.pdb').write_bytes(b'not shipped')
    (engine / '_internal').mkdir()
    for name in ('attackmap.exe','_internal/python313.dll','_internal/base_library.zip','_internal/extra.pyd'):
        (engine / name).write_bytes(('fake-engine:' + name).encode())
    np, ep, rp = (tmp_path / name for name in ('native.json','engine.json','runtime.json'))
    np.write_text(json.dumps({'artifacts':{name:{'bytes':(native/name).stat().st_size,
                  'sha256':builder.digest(native/name)} for name in ('AttackMap.NativeSpike.exe','AttackMap.NativeSpike.dll')}}))
    ep.write_text(json.dumps({'exe_sha256':builder.digest(engine/'attackmap.exe'),
                  'payload_files':[{'path':name,**row} for name,row in builder.inventory(engine).items()]}))
    rp.write_text(json.dumps({'failure':None,'result':{'passed':True}}))
    return [native,np,engine,ep,rp,tmp_path/'new-package']


def test_complete_archive_preserves_runtime_sidecars_and_case(inputs):
    result = builder.package(*inputs)
    with zipfile.ZipFile(result['zip']) as archive:
        names = set(archive.namelist())
        assert 'AttackMap-Windows/Microsoft.ui.xaml.dll' in names
        assert 'AttackMap-Windows/engine/_internal/extra.pyd' in names
        assert 'AttackMap-Windows/Spustit-AttackMap.bat' in names
        assert not any('smoke' in name or name.endswith('.pdb') for name in names)
        manifest = json.loads(archive.read('AttackMap-Windows/portable-manifest.json'))
        assert manifest['runtime']['external_python_required'] is False and manifest['release_candidate'] is False
        assert manifest['schema_version'] == 1 and manifest['kind'] == 'portable-development-preview'
        assert manifest['runtime']['engine'] == 'engine/attackmap.exe'
        assert manifest['native_build'] == 'integrated-20261021-l'
        launcher = archive.read('AttackMap-Windows/Spustit-AttackMap.bat').decode('ascii')
        assert 'cd /d "%~dp0"\r\n' in launcher
        assert launcher.index('cd /d "%~dp0"') < launcher.index('start "" "%~dp0AttackMap.NativeSpike.exe"')
        readme = archive.read('AttackMap-Windows/CTETE-ME.txt').decode('utf-8')
        assert manifest['startup_engine_selection'] == 'saved_engine_or_bundle'
        assert 'v Scan options zvolte mistni' in readme
        assert 'automaticky vybere mistni' not in readme
    assert hashlib.sha256(Path(result['zip']).read_bytes()).hexdigest() == result['zip_sha256']


def test_native_build_identity_comes_from_supplied_proof(inputs):
    proof_path = inputs[1]
    proof = json.loads(proof_path.read_text())
    proof['build_id'] = 'portable-startup-fix-20261022'
    proof_path.write_text(json.dumps(proof))
    result = builder.package(*inputs)
    with zipfile.ZipFile(result['zip']) as archive:
        manifest = json.loads(archive.read('AttackMap-Windows/portable-manifest.json'))
        assert manifest['native_build'] == proof['build_id']
        assert json.loads(archive.read('AttackMap-Windows/provenance/native-build.json')) == proof


@pytest.mark.parametrize('normal,explicit,override,automatic', [
    (True, False, False, True),
    (False, False, False, False),
    (True, True, False, False),
    (True, False, True, False),
    (True, None, False, False),
    (True, False, None, False),
])
def test_startup_advice_requires_normal_startup_proof(inputs, normal, explicit, override, automatic):
    proof_path = inputs[4]
    proof_path.write_text(json.dumps({'failure': None, 'result': {
        'passed': True, 'normalStartupBranch': normal,
        'explicitEngineArgument': explicit, 'settingsOverride': override}}))
    result = builder.package(*inputs)
    with zipfile.ZipFile(result['zip']) as archive:
        manifest = json.loads(archive.read('AttackMap-Windows/portable-manifest.json'))
        readme = archive.read('AttackMap-Windows/CTETE-ME.txt').decode('utf-8').replace('\r\n', '\n')
        assert manifest['startup_engine_selection'] == (
            'bundled_on_portable_startup' if automatic else 'saved_engine_or_bundle')
        assert ('pres BAT i primo pres EXE se automaticky vybere mistni' in readme) is automatic
        assert ('globalni nastaveni se\nneprepisuje' in readme) is automatic
        assert ('v Scan options zvolte mistni' in readme) is not automatic


@pytest.mark.parametrize('kind', ['native','engine','sidecar','extra','runtime-proof'])
def test_bad_input_is_refused_before_any_output(inputs, kind):
    native, _np, engine, _ep, rp, output = inputs
    if kind == 'native':
        (native/'AttackMap.NativeSpike.dll').write_bytes(b'changed')
    elif kind == 'engine':
        (engine/'attackmap.exe').write_bytes(b'changed')
    elif kind == 'sidecar':
        (engine/'_internal/base_library.zip').unlink()
    elif kind == 'extra':
        (engine/'unexpected.py').write_bytes(b'changed')
    else:
        rp.write_text(json.dumps({'failure':'interrupted','result':None}))
    with pytest.raises(ValueError):
        builder.package(*inputs)
    assert not output.exists() and not output.with_suffix('.zip').exists()


def test_existing_output_and_zip_are_preserved(inputs):
    target = inputs[-1].with_suffix('.zip')
    target.write_bytes(b'user archive')
    with pytest.raises(ValueError, match='existing artifacts'):
        builder.package(*inputs)
    assert target.read_bytes() == b'user archive'


def test_output_inside_source_is_refused(inputs):
    inputs[-1] = inputs[0] / 'nested-output'
    with pytest.raises(ValueError, match='outside'):
        builder.package(*inputs)
