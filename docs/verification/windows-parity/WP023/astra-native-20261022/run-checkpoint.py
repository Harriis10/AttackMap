"""WP023 bounded native regression evidence. Default prepares only; --run executes."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
HISTORY = ROOT / 'docs/verification/windows-parity/WP023/native-consumers-20261021-j-b/aggregate.json'
CONSOLE = [row['project'] + '.Tests' for row in json.loads(HISTORY.read_text())['projects']]
CONTROLLED = {'EngineSession.Tests': ('ControlledFakeBroker', 9),
              'DesktopActionRunner.Tests': ('ControlledFakeBroker', 8),
              'NativeFaultComposition.Tests': ('NativeFaultBroker', 14)}
DEFERRED = {
    'FrozenRunner.Tests': 'Fresh source-bound frozen engine required; integrator gate.',
    'FrozenCancellation.Tests': 'Fresh frozen engine and exclusive runtime slot required; original 50 cycles/2000 files preserved.',
    'ProtectedProviderStore.Tests': 'Fresh frozen engine plus real Windows DPAPI/Python integration; separate isolated settings gate.',
    'ProviderRoundtrip.Tests': 'Real Python provider configuration/broker processes; separate integration gate.',
    'ReportExport.Tests': 'Runs installed Edge/Chrome headless PDF export; separate browser process gate, not pure consumer fixture.',
}
DOTNET = str(ROOT / '.tools/dotnet/dotnet.exe')
ENV = dict(os.environ, DOTNET_ROOT=str(ROOT / '.tools/dotnet'),
           DOTNET_CLI_HOME=str(ROOT / '.tools/dotnet-home'),
           NUGET_PACKAGES=str(ROOT / '.tools/nuget-packages'),
           DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1',
           MSBUILDDISABLENODEREUSE='1', TEMP=str(OUT / 'temp'), TMP=str(OUT / 'temp'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def snapshot():
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--', 'desktop/windows',
        'src', 'tests', 'tools', 'installer', 'pyproject.toml', 'uv.lock'], cwd=ROOT).decode().split('\0')
    # Preserve ignored fixture/metadata inputs present in the preceding checkpoint.
    previous = json.loads((HISTORY.parent / 'inputs-before.json').read_text())
    paths = set(paths) | set(previous)
    return {p: sha(ROOT / p) for p in sorted(paths) if p and (ROOT / p).is_file()}


def project(name):
    return str(ROOT / 'desktop/windows' / name / (name + '.csproj'))


def build(name):
    return [DOTNET, 'build', project(name), '--no-restore', '-p:NuGetAudit=false',
            '-p:UseSharedCompilation=false', '-nodeReuse:false']


def executable(name):
    return ROOT / 'desktop/windows' / name / 'bin/Debug/net8.0' / (name + '.exe')


def prepare():
    inventory = sorted(p.name for p in (ROOT / 'desktop/windows').glob('*.Tests') if p.is_dir())
    assert set(inventory) == set(CONSOLE) | set(CONTROLLED) | set(DEFERRED), 'Unclassified test project'
    plan = []
    for name in CONSOLE + ['ControlledFakeBroker', 'NativeFaultBroker'] + list(CONTROLLED):
        plan.append({'label': 'build-' + name, 'command': build(name)})
        if name in CONSOLE:
            plan.append({'label': name, 'command': [str(executable(name))]})
    for name, (broker, count) in CONTROLLED.items():
        plan.append({'label': name, 'command': [str(executable(name)),
                     str(OUT / 'staged-brokers' / broker / 'attackmap.exe'),
                     str(OUT / (name + '-proof.json'))], 'expected_cases': count})
    save('plan.json', {'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
        'console_projects': CONSOLE, 'controlled_projects': CONTROLLED,
        'deferred_projects': DEFERRED, 'all_test_projects': inventory, 'commands': plan,
        'environment_overrides': {k: ENV[k] for k in ['DOTNET_ROOT', 'DOTNET_CLI_HOME', 'NUGET_PACKAGES',
            'DOTNET_CLI_TELEMETRY_OPTOUT', 'DOTNET_NOLOGO', 'MSBUILDDISABLENODEREUSE', 'TEMP', 'TMP']},
        'restore_if_missing': [DOTNET, 'restore', '<project>', '--source', str(OUT / 'empty-feed'),
                              '--ignore-failed-sources', '-p:NuGetAudit=false'],
        'scope': '26 native console/owned-filesystem suites plus 3 controlled fake-broker suites; no GUI/provider/frozen acceptance.'})
    save('inputs-prepared.json', snapshot())
    print('Prepared 26 console suites, 3 controlled suites, 5 explicit separate integration gates; no build/test launched.')


def execute():
    if (OUT / 'commands.json').exists():
        raise RuntimeError('Evidence already exists; do not overwrite a run')
    sys.path.insert(0, str(ROOT / 'src'))
    from attackmap.execution.windows import WindowsProcessJob
    for directory in ['temp', 'empty-feed', 'staged-brokers']:
        (OUT / directory).mkdir(exist_ok=False)
    inputs = snapshot()
    save('inputs-before.json', inputs)
    save('source-identity.json', {'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
        'tracked_status': subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT).decode(),
        'dotnet_sha256': sha(Path(DOTNET)), 'python': sys.executable, 'python_sha256': sha(Path(sys.executable)),
        'runner_sha256': sha(Path(__file__)), 'input_count': len(inputs)})
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.SetErrorMode.argtypes = [ctypes.c_uint]
    kernel.SetErrorMode.restype = ctypes.c_uint
    old_mode = kernel.SetErrorMode(0x8003)
    records, suites = [], []

    def run(label, command, timeout=300):
        job, process, attached = WindowsProcessJob(), None, False
        record = {'label': label, 'command': command, 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        started = time.monotonic()
        try:
            with (OUT / (label + '.stdout.txt')).open('xb') as stdout, (OUT / (label + '.stderr.txt')).open('xb') as stderr:
                process = subprocess.Popen(command, cwd=ROOT, env=ENV, stdout=stdout, stderr=stderr, creationflags=4)
                record['pid'] = process.pid
                save('active-command.json', record)
                job.attach_and_resume(process)
                attached = True
                record['timed_out'] = False
                try:
                    record['exit_code'] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record['timed_out'] = True
                    job.terminate()
                    record['exit_code'] = process.wait(timeout=20)
                deadline = time.monotonic() + 15
                while job.active() and time.monotonic() < deadline:
                    time.sleep(.05)
                record['owned_job_empty_before_close'] = job.active() == 0
                if not record['owned_job_empty_before_close']:
                    job.terminate()
            if record['exit_code'] or record['timed_out'] or not record['owned_job_empty_before_close']:
                raise RuntimeError('Command failed: ' + label)
        finally:
            if process is not None and process.poll() is None:
                job.terminate() if attached else process.kill()
                process.wait(timeout=20)
            job.close()
            record['seconds'] = round(time.monotonic() - started, 3)
            for kind in ['stdout', 'stderr']:
                path = OUT / (label + '.' + kind + '.txt')
                if path.exists():
                    record[kind + '_sha256'] = sha(path)
            records.append(record)
            save('commands.json', records)
            print(json.dumps(record), flush=True)

    failure = None
    try:
        run('dotnet-version', [DOTNET, '--version'])
        for name in CONSOLE + ['ControlledFakeBroker', 'NativeFaultBroker'] + list(CONTROLLED):
            if not (Path(project(name)).parent / 'obj/project.assets.json').is_file():
                run('restore-' + name, [DOTNET, 'restore', project(name), '--source', str(OUT / 'empty-feed'),
                                       '--ignore-failed-sources', '-p:NuGetAudit=false'])
            run('build-' + name, build(name))
            if name in CONSOLE:
                run(name, [str(executable(name))])
                content = (OUT / (name + '.stdout.txt')).read_text(encoding='utf-8', errors='replace')
                evidence = [line for line in content.splitlines() if re.search(r'\b(?:checks?\s+passed|PASS\s+\d+|\d+\s+.*checks?.*PASS)', line, re.I)]
                if not evidence:
                    raise RuntimeError('No explicit assertion count: ' + name)
                line = evidence[-1]
                match = re.search(r'\bPASS\s+(\d+)|\b(\d+)\s+(?:[\w/-]+\s+)*checks?', line, re.I)
                if not match:
                    raise RuntimeError('Cannot parse explicit assertion count: ' + line)
                suites.append({'project': name, 'kind': 'console_fixture_or_owned_filesystem',
                    'assertion_count': int(next(g for g in match.groups() if g)), 'count_evidence': line,
                    'executable_sha256': sha(executable(name)), 'passed': True})
                save('suite-results.json', suites)
        for name in ['ControlledFakeBroker', 'NativeFaultBroker']:
            destination = OUT / 'staged-brokers' / name
            destination.mkdir()
            for path in executable(name).parent.iterdir():
                if path.is_file():
                    if path.is_symlink():
                        raise RuntimeError('Redirected broker payload')
                    shutil.copy2(path, destination / path.name)
            shutil.copy2(executable(name), destination / 'attackmap.exe')
        save('staged-broker-payloads.json', {p.relative_to(OUT).as_posix(): sha(p)
             for p in (OUT / 'staged-brokers').rglob('*') if p.is_file()})
        for name, (broker, expected) in CONTROLLED.items():
            proof = OUT / (name + '-proof.json')
            run(name, [str(executable(name)), str(OUT / 'staged-brokers' / broker / 'attackmap.exe'), str(proof)])
            data = json.loads(proof.read_text(encoding='utf-8-sig'))
            cases = data['results']
            if len(cases) != expected or not all(case['passed'] for case in cases) or data.get('gaps'):
                raise RuntimeError('Controlled proof failed or case count changed: ' + name)
            suites.append({'project': name, 'kind': 'controlled_fake_broker', 'case_count': len(cases),
                           'proof_sha256': sha(proof), 'executable_sha256': sha(executable(name)), 'passed': True})
            save('suite-results.json', suites)
    except BaseException as error:
        failure = repr(error)
        raise
    finally:
        kernel.SetErrorMode(old_mode)
        after = snapshot()
        save('inputs-after.json', after)
        changed = sorted(p for p in inputs.keys() | after.keys() if inputs.get(p) != after.get(p))
        save('summary.json', {'failure': failure, 'input_count': len(inputs), 'changed_inputs': changed,
            'suite_count': len(suites), 'console_assertions': sum(s.get('assertion_count', 0) for s in suites),
            'controlled_cases': sum(s.get('case_count', 0) for s in suites),
            'passed': failure is None and not changed and len(suites) == 29,
            'scope': 'Console fixture/owned filesystem plus controlled fake brokers only. No GUI, live provider, real engine, manual or release acceptance.',
            'deferred_projects': DEFERRED})


if __name__ == '__main__':
    execute() if '--run' in sys.argv else prepare()
