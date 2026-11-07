"""Package an explicitly pinned native/engine development pair for transfer.

This is not the current-source RequiredBundled release-candidate builder. It
preserves the independently captured inputs and never manufactures release proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
from pathlib import Path
import zipfile


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(folder: Path, *, native: bool = False) -> dict[str, dict]:
    if not folder.is_dir():
        raise ValueError(f'Missing payload directory: {folder}')
    for parent in (folder, *folder.parents):
        if parent.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError(f'Redirected payload path: {parent}')
    result = {}
    folded = set()
    for path in sorted(folder.rglob('*')):
        if path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError(f'Redirected payload entry: {path}')
        if not path.is_file():
            continue
        relative = path.relative_to(folder).as_posix()
        if native and (path.suffix.lower() in {'.pdb', '.log'} or 'smoke' in path.name.lower()
                       or path.name in {'settings.json', 'recent-repositories.json'}):
            continue
        if relative.casefold() in folded:
            raise ValueError(f'Duplicate Windows payload name: {relative}')
        folded.add(relative.casefold())
        result[relative] = {'size_bytes': path.stat().st_size, 'sha256': digest(path)}
    return result


def package(native: Path, native_proof: Path, engine: Path, engine_proof: Path,
            runtime_proof: Path, output: Path) -> dict:
    native, engine = native.resolve(), engine.resolve()
    output = output.absolute()
    if output.exists() or output.with_suffix('.zip').exists():
        raise ValueError('Choose a new output directory and ZIP name; existing artifacts are preserved.')
    for source in (native, engine):
        if output.resolve().is_relative_to(source):
            raise ValueError('Output must be outside both input payloads.')
    native_bytes = inventory(native, native=True)
    engine_bytes = inventory(engine)
    nproof = json.loads(native_proof.read_text(encoding='utf-8-sig'))
    eproof = json.loads(engine_proof.read_text(encoding='utf-8-sig'))
    rproof = json.loads(runtime_proof.read_text(encoding='utf-8-sig'))
    for name in ('AttackMap.NativeSpike.exe', 'AttackMap.NativeSpike.dll'):
        expected = nproof['artifacts'][name]
        if native_bytes.get(name) != {'size_bytes': expected['bytes'], 'sha256': expected['sha256']}:
            raise ValueError(f'Native build fingerprint mismatch: {name}')
    for name in ('coreclr.dll', 'hostfxr.dll', 'hostpolicy.dll', 'Microsoft.UI.Xaml.dll',
                 'AttackMap.NativeSpike.deps.json', 'AttackMap.NativeSpike.runtimeconfig.json'):
        if name.casefold() not in {key.casefold() for key in native_bytes}:
            raise ValueError(f'Incomplete native runtime: {name}')
    expected_engine = {}
    for row in eproof['payload_files']:
        name = row['path']
        if name in expected_engine or Path(name).is_absolute() or '..' in Path(name).parts or '\\' in name:
            raise ValueError('Invalid frozen payload inventory')
        expected_engine[name] = {key: row[key] for key in ('size_bytes', 'sha256')}
    if engine_bytes != expected_engine or engine_bytes.get('attackmap.exe', {}).get('sha256') != eproof['exe_sha256']:
        raise ValueError('Frozen engine payload differs from its immutable build proof')
    for name in ('_internal/python313.dll', '_internal/base_library.zip'):
        if name not in engine_bytes:
            raise ValueError(f'Incomplete embedded Python runtime: {name}')
    if rproof.get('failure') is not None or not rproof.get('result', {}).get('passed'):
        raise ValueError('The explicit native/engine pair requires completed runtime proof')
    startup_proof = rproof['result']
    automatic_bundle = (startup_proof.get('normalStartupBranch') is True
                        and startup_proof.get('explicitEngineArgument') is False
                        and startup_proof.get('settingsOverride') is False)
    startup_advice = ('''Pri spusteni pres BAT i primo pres EXE se automaticky vybere mistni
engine/attackmap.exe z teto rozbalene slozky. Starsi globalni nastaveni se
neprepisuje; ostatni ulozene volby zustavaji zachovany. Pozdeji lze v Scan
options vybrat jiny engine.''' if automatic_bundle else '''Pokud uz na PC mate starsi nastaveni, v Scan options zvolte mistni
engine/attackmap.exe z teto rozbalene slozky. Puvodni nastaveni se neprepisuje.''')
    output.mkdir(parents=True)
    app = output / 'AttackMap-Windows'
    app.mkdir()
    for source, files, target in ((native, native_bytes, app), (engine, engine_bytes, app / 'engine')):
        for relative, expected in files.items():
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, destination)
            if destination.stat().st_size != expected['size_bytes'] or digest(destination) != expected['sha256']:
                raise ValueError(f'Copied payload changed: {relative}')
    if inventory(native, native=True) != native_bytes or inventory(engine) != engine_bytes:
        raise ValueError('Input payload changed during copying')
    provenance = app / 'provenance'
    provenance.mkdir()
    for source, name in ((native_proof, 'native-build.json'), (engine_proof, 'engine-build.json'),
                         (runtime_proof, 'pair-runtime.json')):
        shutil.copyfile(source, provenance / name)
    (app / 'Spustit-AttackMap.bat').write_bytes(b'''@echo off\r
setlocal\r
cd /d "%~dp0"\r
if not exist "%~dp0engine\\attackmap.exe" (\r
  echo Chybi engine. Rozbalte cely ZIP vcetne vsech podslozek.\r
  pause\r
  exit /b 1\r
)\r
if not exist "%~dp0coreclr.dll" (\r
  echo Chybi knihovny aplikace. Rozbalte cely ZIP.\r
  pause\r
  exit /b 1\r
)\r
start "" "%~dp0AttackMap.NativeSpike.exe"\r
''')
    (app / 'CTETE-ME.txt').write_text('''AttackMap pro Windows 10/11 x64 (Windows 10 build 19041 nebo novejsi)

1. Preneste cely ZIP na druhy pocitac.
2. Rozbalte cely ZIP do libovolne slozky. Nespoustejte aplikaci uvnitr ZIPu.
3. Ve slozce AttackMap-Windows spustte Spustit-AttackMap.bat nebo AttackMap.NativeSpike.exe.

Samostatna instalace Pythonu ani .NET neni pro tento balicek potreba.
Zachovejte vsechny soubory a podslozky, vcetne engine a engine/_internal.
Samotne EXE bez ostatnich souboru neni prenosna aplikace.

{startup_advice}
Volitelne AI funkce potrebuji vlastni nakonfigurovany endpoint/model.

Jde o nepodepsany vyvojovy nahled plneho UI s jeho otestovanym zmrazenym
enginem B-J. Identitu sestaveni uvadi portable-manifest.json. Neni to
finalni release ani doklad dokonceni roadmapy.
'''.format(startup_advice=startup_advice), encoding='utf-8')
    manifest = {
        'schema_version': 1, 'kind': 'portable-development-preview', 'release_candidate': False,
        'native_build': nproof.get('build_id', 'integrated-20261021-l'), 'engine_build': 'fresh-B-J-20261021-01',
        'startup_engine_selection': 'bundled_on_portable_startup' if automatic_bundle else 'saved_engine_or_bundle',
        'minimum_windows': '10.0.19041.0', 'architecture': 'x64',
        'runtime': {'dotnet_self_contained': True, 'python_embedded': True,
                    'engine': 'engine/attackmap.exe', 'external_python_required': False},
        'limitations': ['Separately captured, previously runtime-tested snapshots; not current-source release acceptance.',
                        'Clean Windows VM/second physical PC qualification remains separate.'],
        'files': inventory(app),
    }
    (app / 'portable-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    archive = output.with_suffix('.zip')
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in sorted(app.rglob('*')):
            if path.is_file():
                bundle.write(path, path.relative_to(output).as_posix())
    checksum = digest(archive)
    archive.with_suffix('.zip.sha256').write_text(f'{checksum}  {archive.name}\n', encoding='ascii')
    return {'directory': str(app), 'zip': str(archive), 'zip_sha256': checksum,
            'zip_bytes': archive.stat().st_size, 'native_files': len(native_bytes), 'engine_files': len(engine_bytes)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('native', 'native-proof', 'engine', 'engine-proof', 'runtime-proof', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(args.native, args.native_proof, args.engine, args.engine_proof,
                             args.runtime_proof, args.output), indent=2))
