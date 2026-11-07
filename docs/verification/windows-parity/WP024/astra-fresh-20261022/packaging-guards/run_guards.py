"""Owned synthetic packaging guard evidence; execute only with --run."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path.cwd().resolve()
OUT = Path(__file__).resolve().parent
FIXTURES = OUT / 'fixtures'
PWSH = Path('C:/Program Files/PowerShell/7/pwsh.exe')
COMMAND = [str(PWSH), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
           str(ROOT / 'tools/test_native_windows_package.ps1'), '-TestRoot', str(FIXTURES)]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def save(name, value):
    with (OUT / name).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')

def snapshot():
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--', 'src', 'tests',
        'tools', 'installer', 'pyproject.toml'], cwd=ROOT).decode().split('\0')
    return {p: sha(ROOT / p) for p in paths if p and (ROOT / p).is_file()}

if not OUT.is_relative_to(ROOT / 'docs/verification/windows-parity/WP024/astra-fresh-20261022'):
    raise RuntimeError('Unexpected evidence destination')
if FIXTURES.exists() or FIXTURES.is_symlink():
    raise RuntimeError('Synthetic TestRoot must not exist')
for path in (OUT, *OUT.parents):
    if path.is_symlink() or getattr(path.stat(), 'st_file_attributes', 0) & 0x400:
        raise RuntimeError('Redirected evidence parent')

if '--run' not in sys.argv:
    print(json.dumps({'prepared_command': COMMAND, 'tests_executed': False}))
    raise SystemExit(0)

before = snapshot()
save('source-before.json', before)
save('command.json', {'command': COMMAND, 'cwd': str(ROOT), 'python': sys.executable,
    'python_sha256': sha(Path(sys.executable)), 'pwsh_sha256': sha(PWSH),
    'runner_sha256': sha(Path(__file__)), 'scope': 'Synthetic packaging/installer guards only; no production executable, GUI or provider'})
env = dict(os.environ)
for key, relative in [('TEMP', 'temp'), ('TMP', 'temp'), ('LOCALAPPDATA', 'profile/Local'),
                      ('APPDATA', 'profile/Roaming'), ('USERPROFILE', 'profile')]:
    destination = OUT / relative
    destination.mkdir(parents=True, exist_ok=True)
    env[key] = str(destination)
sys.path.insert(0, str(ROOT / 'src'))
from attackmap.execution.windows import WindowsProcessJob
job, process, attached = WindowsProcessJob(), None, False
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.SetErrorMode.argtypes = [ctypes.c_uint]
kernel.SetErrorMode.restype = ctypes.c_uint
old_mode = kernel.SetErrorMode(0x8003)
result = {'started_utc': datetime.now(timezone.utc).isoformat(), 'timed_out': False}
started = time.perf_counter()
try:
    with (OUT / 'stdout.log').open('xb') as stdout, (OUT / 'stderr.log').open('xb') as stderr:
        process = subprocess.Popen(COMMAND, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                   creationflags=4)
        result['pid'] = process.pid
        save('started.json', result)
        job.attach_and_resume(process)
        attached = True
        try:
            result['exit_code'] = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            result['timed_out'] = True
            job.terminate()
            result['exit_code'] = process.wait(timeout=20)
        deadline = time.monotonic() + 15
        while job.active() and time.monotonic() < deadline:
            time.sleep(0.05)
        result['owned_job_empty_before_close'] = job.active() == 0
        if not result['owned_job_empty_before_close']:
            job.terminate()
finally:
    if process is not None and process.poll() is None:
        job.terminate() if attached else process.kill()
        process.wait(timeout=20)
    job.close()
    kernel.SetErrorMode(old_mode)
    after = snapshot()
    save('source-after.json', after)
    result.update(finished_utc=datetime.now(timezone.utc).isoformat(),
                  elapsed_seconds=time.perf_counter()-started, source_equal=before == after,
                  changed_paths=[p for p in sorted(before.keys() | after.keys()) if before.get(p) != after.get(p)])
    save('result.json', result)
print(json.dumps(result), flush=True)
raise SystemExit(0 if result.get('exit_code') == 0 and not result['timed_out']
                 and result.get('owned_job_empty_before_close') and result['source_equal'] else 1)
