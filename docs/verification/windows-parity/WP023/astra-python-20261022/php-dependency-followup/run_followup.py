"""Execute only after the integration owner releases the native heavy slot."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone

repo = Path.cwd().resolve()
out = Path(__file__).resolve().parent
preparation = json.loads((out / 'preparation.json').read_text())
if (out / 'result.json').exists() or (repo / '.tmp-wp023-astra-php-20261022-01').exists():
    raise RuntimeError('Use a fresh evidence and basetemp path; never overwrite a run.')

def source_hashes():
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--', 'src', 'tests/test_analyzers.py', 'pyproject.toml'], cwd=repo).decode().split('\0')
    return {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in paths if p and (repo / p).is_file()}

before = source_hashes()
(out / 'source-before.json').write_text(json.dumps(before, indent=2) + '\n')
started = datetime.now(timezone.utc).isoformat()
start = time.perf_counter()
with (out / 'pytest-stdout.log').open('wb') as stdout, (out / 'pytest-stderr.log').open('wb') as stderr:
    completed = subprocess.run(preparation['command'], cwd=repo, stdout=stdout, stderr=stderr)
elapsed = time.perf_counter() - start
after = source_hashes()
(out / 'source-after.json').write_text(json.dumps(after, indent=2) + '\n')
result = {'exit_code': completed.returncode, 'elapsed_seconds': elapsed, 'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(), 'source_equal': before == after, 'scope': preparation['scope']}
(out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
sys.exit(completed.returncode)
