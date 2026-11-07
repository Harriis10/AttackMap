import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone

repo = Path.cwd().resolve()
out = repo / 'docs/verification/windows-parity/WP023/astra-python-20261022/unrestricted-attempt-02'
out.mkdir(exist_ok=False)
base = repo / '.tmp-wp023-astra-python-20261022-02'
if base.exists():
    raise RuntimeError(f'Fresh basetemp required: {base}')

def git(*args):
    return subprocess.check_output(['git', *args], cwd=repo).decode('utf-8', errors='replace').strip()

def hashes():
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--', 'src', 'tests', 'installer', 'tools', 'pyproject.toml', 'setup.cfg', 'pytest.ini', 'conftest.py'], cwd=repo).decode().split('\0')
    return {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in paths if p and (repo / p).is_file()}

def write(name, value):
    (out / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')

before = hashes()
write('source-before.json', {'head': git('rev-parse', 'HEAD'), 'tracked_status': git('status', '--porcelain', '--untracked-files=no'), 'hashes': before})
write('runtime.json', {'python': sys.version, 'executable': sys.executable, 'executable_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(), 'platform': platform.platform(), 'packages': sorted([{'name': d.metadata['Name'], 'version': d.version} for d in importlib.metadata.distributions()], key=lambda d: d['name'].lower()), 'test_environment': {k: os.environ.get(k) for k in ['PYTEST_ADDOPTS', 'PYTHONPATH', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD']}})
command = [sys.executable, '-m', 'pytest', 'tests', '-q', '--basetemp', str(base), '--junitxml', str(out / 'pytest-junit.xml')]
started = datetime.now(timezone.utc).isoformat()
write('command.json', {'command': command, 'cwd': str(repo), 'started_utc': started, 'coverage_reductions': [], 'timeout_or_timing_overrides': []})
print(f'START {started}: {command}', flush=True)
start = time.perf_counter()
with (out / 'pytest-stdout.log').open('wb') as stdout, (out / 'pytest-stderr.log').open('wb') as stderr:
    completed = subprocess.run(command, cwd=repo, stdout=stdout, stderr=stderr)
elapsed = time.perf_counter() - start
after = hashes()
write('source-after.json', {'head': git('rev-parse', 'HEAD'), 'tracked_status': git('status', '--porcelain', '--untracked-files=no'), 'hashes': after})
result = {'exit_code': completed.returncode, 'elapsed_seconds': elapsed, 'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(), 'source_equal': before == after, 'changed_paths': [p for p in sorted(set(before) | set(after)) if before.get(p) != after.get(p)]}
write('result.json', result)
print(json.dumps(result), flush=True)
sys.exit(completed.returncode)
