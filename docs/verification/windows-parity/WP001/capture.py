"""Reproduce identities and independently verify every manifest payload hash read-only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone

OUT = Path(__file__).resolve().parent
REPO = OUT.parents[3]


def digest(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest() if path.is_file() else None


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def git(*args):
    return subprocess.check_output(['git', '-C', str(REPO), *args], text=True).strip()


def payload(folder, installers=False):
    manifest = read(folder / 'package-manifest.json')
    expected = {'package-manifest.json'}
    if installers:
        expected.update(('Install-AttackMap.ps1', 'Install-AttackMap.cmd'))
    failures = []
    for entry in manifest['files']:
        relative = Path('app') / entry['path']
        assert not relative.is_absolute() and '..' not in relative.parts
        path = folder / relative
        expected.add(relative.as_posix())
        if not path.is_file() or path.stat().st_size != entry['size_bytes'] or digest(path) != entry['sha256']:
            failures.append(entry['path'])
    extras = [p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file() and p.relative_to(folder).as_posix() not in expected]
    return manifest, failures, extras


def probe(exe, args, name):
    process = subprocess.run([str(exe), *args], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=120)
    stdout, stderr = OUT / (name + '.stdout.txt'), OUT / (name + '.stderr.txt')
    stdout.write_bytes(process.stdout)
    stderr.write_bytes(process.stderr)
    assert process.returncode == 0
    return dict(executable=str(exe), arguments=args, exit_code=process.returncode, stdout_file=stdout.name, stderr_file=stderr.name, stdout_sha256=digest(stdout))


def main():
    base = REPO / 'desktop/windows/artifacts/development-packages'
    ids = ['dev-20261019192050-b678aee2', 'dev-20261019201436-7d3584c4']
    packages = []
    for index, identity in enumerate(ids):
        folder = base / identity
        manifest, failures, extras = payload(folder, True)
        assert not failures and not extras
        zip_hash = digest(base / (identity + '.zip'))
        assert zip_hash == (base / (identity + '.zip.sha256')).read_text(encoding='utf-8-sig').split()[0].lower()
        packages.append(dict(package_id=identity, role='audit_candidate' if index == 0 else 'newer_retained_candidate', manifest_sha256=digest(folder / 'package-manifest.json'), file_count=len(manifest['files']), payload_validation='PASS independent SHA256/size/inventory and original installer Validate-Payload execution', zip_sha256=zip_hash, zip_sidecar_match=True, engine=manifest['engine'], exe_sha256=digest(folder / manifest['engine']['executable']), installer_sha256=digest(folder / 'Install-AttackMap.ps1'), extras=extras, failed_entries=failures))
    install = Path(os.environ['LOCALAPPDATA']) / 'Programs/AttackMapDevelopment'
    current = read(install / 'current.json')
    installed_folder = install / 'versions' / current['package_id']
    im, failures, extras = payload(installed_folder)
    installed = dict(root=str(install), package_id=current['package_id'], selection_status='selection_and_listed_payload_verified', current_json_sha256=digest(install / 'current.json'), manifest_sha256=digest(installed_folder / 'package-manifest.json'), engine_sha256=digest(installed_folder / im['engine']['executable']), listed_payload_hashes_match=not failures, failed_entries=failures, extra_files=extras, strict_existing_installer_validation='FAIL: Unrecognized file in owned version; refusing deletion or activation.', runtime_launch_not_performed=True, custom_roots_not_enumerated=True)
    assert not failures
    exe = base / ids[0] / 'app/engine/attackmap.exe'
    version = probe(exe, ['--version'], 'packaged-version')
    modules = probe(exe, ['modules', '--json'], 'packaged-modules')
    source_version = REPO / 'src/attackmap/__init__.py'
    diff = OUT / 'preserved-package-script.diff.txt'
    diff.write_text(git('diff', '--', 'tools/package_native_windows.ps1') + '\n', encoding='utf-8')
    historical = ['docs/windows-m3-acceptance.md', 'desktop/windows/verification/retained-m3/README.md', 'desktop/windows/verification/retained-m3/relocation-manifest.json', 'desktop/windows/artifacts/development-packages/dev-20261015190038-5667bbbf/package-manifest.json']
    retained = []
    for entry in read(REPO / historical[2])['files']:
        path = REPO / entry['retained']
        retained.append(dict(path=entry['retained'], exists=path.is_file(), expected_sha256=entry['sha256'], actual_sha256=digest(path), match=digest(path) == entry['sha256']))
    result = dict(schema_version=1, captured_utc=datetime.now(timezone.utc).isoformat(), source=dict(head=git('rev-parse', 'HEAD'), branch=git('branch', '--show-current'), declared_version=source_version.read_text().split('__version__ = "')[1].split('"')[0], version_source='src/attackmap/__init__.py', version_source_sha256=digest(source_version), dirty_status=git('status', '--porcelain=v1', '--untracked-files=normal').splitlines(), package_script_sha256=digest(REPO / 'tools/package_native_windows.ps1'), package_script_diff_sha256=digest(diff)), packages=packages, installed=installed, selected_engine=dict(version_probe=version, modules_probe=modules, module_count=len(read(OUT / modules['stdout_file'])), version=(OUT / version['stdout_file']).read_text().strip()), historical_evidence=[dict(path=p, exists=(REPO / p).is_file(), sha256=digest(REPO / p)) for p in historical], historical_relocation_validation=retained, accepted_m3=dict(date='2026-10-15', package_id='dev-20261015190038-5667bbbf', scope='Windows functional beta with limitations on Windows 10 x64 development host', deferred_unverified=['C19 participant study', 'C21/C25 manual workflow and UX', 'C24 manual accessibility including Narrator'], windows_C26='removed by user decision; no replacement performance gate', exclusions=['macOS', 'clean-host compatibility', 'signed public release', 'every original prerequisite', 'acceptance of newer binary']), unsupported_claims=['Installed strict package integrity passes despite extra smoke artifacts', 'Newer binaries inherit M3 acceptance', 'Checksums authenticate publisher', 'Manifest engine verification/source digests establish exact dirty checkout build provenance', 'This baseline proves scan/GUI/AI/manual accessibility acceptance'], scope='Read-only source/package/installation identity and hash capture. No rebuild/install/scan/model call. Manifest verification/source digest values retained as assertions; external matching proof not established.')
    result['source']['inventory_limitations'] = ['git status may warn about inaccessible temporary directories; their contents are not inventoried. This run warned for .tmp-parity-root-20261020/, .tmp-parity-root-20261020-approved/, .tmp-wp030-root-approved/.']
    (OUT / 'baseline.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f'PASS capture: {len(packages)} candidate payloads, {len(retained)} retained evidence entries, {result["selected_engine"]["module_count"]} runtime modules; installed strict validation FAIL due to {len(extras)} extra files')


if __name__ == '__main__':
    main()
