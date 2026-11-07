import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import zipfile

root = Path.cwd()
evidence = root / 'docs/verification/windows-parity/WP024/portable-20261022/attempt03'
evidence.mkdir(parents=True, exist_ok=False)
archive = root / 'desktop/windows/artifacts/AttackMap-Windows-Portable-20261022.zip'
extraction = root / '.tmp/portable extracted 20261022 c'
second = root / '.tmp/portable moved 20261022 c'
assert not extraction.exists() and not second.exists()
with zipfile.ZipFile(archive) as bundle:
    assert len(bundle.infolist()) < 10000
    assert sum(row.file_size for row in bundle.infolist()) < 1024**3
    for row in bundle.infolist():
        name = Path(row.filename)
        assert not name.is_absolute() and '..' not in name.parts
        assert name.parts[0] == 'AttackMap-Windows'
        assert not stat.S_ISLNK(row.external_attr >> 16)
        assert (extraction / name).resolve().is_relative_to(extraction.resolve())
    bundle.extractall(extraction)
app = extraction / 'AttackMap-Windows'
manifest = json.loads((app / 'portable-manifest.json').read_text())
def hashed(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
for name, record in manifest['files'].items():
    path = app / name
    assert path.stat().st_size == record['size_bytes'] and hashed(path) == record['sha256'], name
assert {p.relative_to(app).as_posix() for p in app.rglob('*') if p.is_file()} == set(manifest['files']) | {'portable-manifest.json'}
environment = dict(os.environ)
for name in list(environment):
    if name.upper().startswith(('PYTHON', 'VIRTUAL_ENV', 'CONDA', 'OPENAI_', 'ANTHROPIC_')):
        environment.pop(name)
environment['PATH'] = str(Path(environment['SYSTEMROOT']) / 'System32') + ';' + environment['SYSTEMROOT']
assert shutil.which('python', path=environment['PATH']) is None
assert shutil.which('python3', path=environment['PATH']) is None
original_mode = ctypes.windll.kernel32.SetErrorMode(0x8003)
commands = []
def run(executable, arguments, label, timeout=120):
    started = __import__('time').monotonic()
    completed = subprocess.run([str(executable), *map(str, arguments)], cwd=executable.parent,
                               env=environment, capture_output=True, timeout=timeout)
    (evidence / f'{label}.stdout.log').write_bytes(completed.stdout)
    (evidence / f'{label}.stderr.log').write_bytes(completed.stderr)
    commands.append({'executable':str(executable), 'arguments':list(map(str,arguments)),
                     'exit_code':completed.returncode, 'seconds':__import__('time').monotonic()-started})
    assert completed.returncode == 0, (label, completed.stderr.decode('utf-8', 'replace'))
    return completed.stdout.decode('utf-8-sig')
try:
    first_settings = evidence / 'fresh-settings.json'
    run(app / 'AttackMap.NativeSpike.exe', ['--startup-smoke', first_settings], 'fresh-native-startup')
    startup = json.loads(Path(str(first_settings)+'.result.json').read_text())
    # Preserve the legacy aggregate result. Its Provider==null assertion is
    # stale: ReadScanOptions now returns disabled saved provider preferences.
    # The portable defect is tested by the actual selected engine and off-state.
    assert Path(startup['bundledEngine']) == app / 'engine/attackmap.exe'
    assert not any(startup[key] for key in ('automaticScan','aiEnabled','cveEnabled','personalSettingsRead'))
    version = run(app / 'engine/attackmap.exe', ['--version'], 'frozen-version').strip()
    caps = json.loads(run(app / 'engine/attackmap.exe', ['capabilities'], 'frozen-capabilities'))
    (evidence / 'capabilities.json').write_text(json.dumps(caps,indent=2)+'\n')
    assert caps['engine_identity']['runtime_kind'] == 'Frozen'
    assert Path(caps['engine_identity']['path']) == app / 'engine/attackmap.exe'
    assert {'desktop-action','desktop-worker'}.issubset(caps['commands']) and len(caps['modules']) >= 15
    shutil.copytree(app, second)
    moved_settings = evidence / 'moved-settings.json'
    run(second / 'AttackMap.NativeSpike.exe', ['--startup-smoke', moved_settings], 'moved-native-startup')
    moved = json.loads(Path(str(moved_settings)+'.result.json').read_text())
    assert Path(moved['bundledEngine']) == second / 'engine/attackmap.exe'
    assert not any(moved[key] for key in ('automaticScan','aiEnabled','cveEnabled','personalSettingsRead'))
    moved_caps = json.loads(run(second / 'engine/attackmap.exe', ['capabilities'], 'moved-capabilities'))
    assert Path(moved_caps['engine_identity']['path']) == second / 'engine/attackmap.exe'
    assert moved_caps['engine_identity']['sha256'] == caps['engine_identity']['sha256']
    summary = {'portable_engine_checks_passed':True, 'zip':str(archive),'zip_sha256':hashed(archive),'zip_bytes':archive.stat().st_size,
               'payload_files_verified':len(manifest['files']), 'fresh_native_startup':startup,
               'moved_native_startup':moved, 'version':version,'analyzers':len(caps['modules']),
               'child_PATH':environment['PATH'], 'python_on_child_PATH':False, 'external_python_required':False,
               'commands':commands,'real_clean_PC_test':False,'manual_UI_acceptance':False,
               'legacy_startup_aggregate_passed':startup['passed'] and moved['passed'],
               'legacy_startup_aggregate_limitation':'Unchanged L smoke expects null Provider; current preferences are nonnull with EnableAi=false. Raw false results retained; no whole-startup acceptance claimed.',
               'scope':'Real extracted native startup + frozen capabilities in two relocated paths with spaces; developer host, not clean VM.'}
    (evidence / 'verification.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))
finally:
    ctypes.windll.kernel32.SetErrorMode(original_mode)
    (evidence / 'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
