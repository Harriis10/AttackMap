"""Bounded frozen CLI proof; never executes the inert fixture application code."""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
WORK = ROOT / '.tmp/wp039-python-20261023'
PROFILE_NAMES = {'python', 'python-web', 'config', 'python-service', 'default'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def hashes(folder):
    return {path.relative_to(folder).as_posix(): sha(path)
            for path in sorted(folder.rglob('*')) if path.is_file()}


def prepare():
    upstream = json.loads((OUT / 'upstream-route-fixtures.json').read_text())
    alias = Path(upstream['fastapi-import-alias']['root'])
    assert hashes(alias) == upstream['fastapi-import-alias']['sha256']
    tests = ROOT / 'tests/test_python_route_prefixes.py'
    tree = ast.parse(tests.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'test_mutual_cycle_and_descendant_retain_local_prefixes')
    base = next(node.value.value for node in function.body
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant))
    cyclic_source = 'from fastapi import FastAPI, APIRouter\n' + base + '''
app = FastAPI()
@a.get("/item")
def first(): return {}
@b.get("/item")
def second(): return {}
@c.get("/item")
def third(): return {}
'''
    cyclic = WORK / 'python-mounts-frozen-fixtures/cyclic-prefix'
    cyclic.mkdir(parents=True, exist_ok=True)
    target = cyclic / 'main.py'
    if target.exists():
        assert target.read_bytes() == cyclic_source.encode('utf-8')
    else:
        target.write_bytes(cyclic_source.encode('utf-8'))
    specs = {
        'fastapi-bound-siblings': (WORK / 'python-mounts-fixtures/fastapi-siblings',
                                 {'/private/item': 'required', '/public/item': 'unknown'},
                                 ['fastapi_router_mount:/api/private']),
        'flask-bound-siblings': (WORK / 'python-mounts-fixtures/flask-siblings',
                               {'/v1/item': 'required', '/public/item': 'unknown'},
                               ['flask_blueprint_mount:/api']),
        'alias-mount-control': (alias, {'/v1/users': 'unknown'}, ['fastapi_router_mount:/api/v1']),
        'shadowed-known-decorator': (WORK / 'python-mounts-profile-fixtures/shadowed-known-route-decorator',
                                     {'/public': 'unknown'}, []),
        'foreign-custom-decorator': (WORK / 'python-mounts-profile-fixtures/foreign-custom-decorator-collision',
                                     {'/public': 'unknown'}, []),
        'constant-credential': (WORK / 'mount-independent/constant-credential', {'/public': 'unknown'}, []),
        'mixed-repeated-mount': (WORK / 'python-mounts-fixtures/fastapi-mixed-mounts',
                                 {'/items/item': 'unknown'},
                                 ['fastapi_router_mount:/private/items', 'fastapi_router_mount:/public/items']),
        'cyclic-prefix': (cyclic, {'/a/item': 'unknown', '/b/item': 'unknown', '/c/item': 'unknown'}, []),
    }
    cases = {}
    for name, (fixture, expected, hints) in specs.items():
        assert fixture.is_dir()
        cases[name] = {'fixture': str(fixture), 'sha256': hashes(fixture),
                       'expected_paths_auth': expected, 'expected_mount_hints': hints}
    data = {'scope': 'Frozen python@1.0 merged static extraction, no AI or fixture runtime execution',
            'cyclic_fixture_scope': 'Unsupported cyclic configuration derived from retained unit specimen; termination/local-prefix test, no valid app runtime claim',
            'cycle_unit_source': {'path': str(tests), 'sha256': sha(tests)}, 'cases': cases}
    path = OUT / 'python-mounts-frozen-fixtures.json'
    if path.exists():
        assert json.loads(path.read_text()) == data
    else:
        save(path, data)
    return data


def collect(folder, output, case, expected_engine_sha, engine):
    process = json.loads((folder / 'process.json').read_text())
    assert process['exit_code'] == 0 and process['exited'] and not process['timed_out']
    assert process['owned_job_assigned'] and process['owned_tree_cleanup_verified']
    manifest = json.loads((output / 'artifact-manifest.json').read_text())
    assert manifest['exit_state']['status'] == 'succeeded'
    generation = output / manifest['generation_id']
    report_path = generation / 'attackmap-report.json'
    run_path = generation / 'run-manifest.json'
    report = json.loads(report_path.read_text())
    run = json.loads(run_path.read_text())
    scan = report['scan']
    assert sha(output / 'attackmap-report.json') == sha(report_path)
    assert sha(output / 'run-manifest.json') == sha(run_path)
    ledger = scan['analyzer_run_ledger']
    assert ledger == run['analyzer_run_ledger']
    assert ledger['schema_version'] == '1.1' and ledger['profile_id'] == 'python@1.0'
    assert ledger['resolution_complete'] and ledger['execution_complete']
    entries = {entry['name']: entry for entry in ledger['entries']}
    assert PROFILE_NAMES <= entries.keys()
    assert {name for name, entry in entries.items() if entry['selection'] == 'selected'} <= PROFILE_NAMES
    assert all(entries[name]['execution'] in {'succeeded', 'skipped'} for name in PROFILE_NAMES)
    assert scan['analyzer_errors'] == [] and not run.get('llm_usage')
    for expected_path, auth in case['expected_paths_auth'].items():
        found = [route for route in scan['routes'] if route['path'] == expected_path]
        assert found and all(route['auth'] == auth for route in found), (expected_path, auth, found)
        if auth == 'unknown':
            assert all(not route['guards'] for route in found), found
    hints = {hint['hint'] for hint in scan['framework_hints']}
    assert set(case['expected_mount_hints']) <= hints
    assert 'flask_blueprint_mount:/api/v1' not in hints
    assert hashes(Path(case['fixture'])) == case['sha256'], 'fixture changed'
    assert sha(engine) == expected_engine_sha, 'engine changed'
    return {'passed': True, 'process': process, 'output': str(output), 'generation': str(generation),
            'routes': scan['routes'], 'framework_hints': scan['framework_hints'], 'limitations': scan['limitations'],
            'report_sha256': sha(report_path), 'run_manifest_sha256': sha(run_path),
            'artifact_manifest_sha256': sha(output / 'artifact-manifest.json'),
            'report_run_ledger_equal': True, 'ledger': ledger, 'fixture_hashes_unchanged': True}


def run(args):
    data = prepare()
    engine = args.engine.resolve()
    assert engine.is_file() and sha(engine) == args.engine_sha256
    spec = importlib.util.spec_from_file_location('mount_bounded_jobs', OUT / 'verify_python_batch.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    results = {}
    for name, case in data['cases'].items():
        fixture = Path(case['fixture'])
        assert hashes(fixture) == case['sha256']
        label = f'python-mounts-frozen-{args.run_id}-{name}'
        output = WORK / f'python-mounts-frozen-output-{args.run_id}' / name
        assert not output.exists() and not output.resolve().is_relative_to(fixture.resolve())
        command = [engine, 'analyze', fixture, '--analyzer-profile', 'python@1.0',
                   '--format', 'json', '--no-progress', '--output', output]
        print(json.dumps({'case': name, 'state': 'starting', 'timeout_seconds': 90}), flush=True)
        try:
            folder = helper.run(label, command, timeout=90)
            result = collect(folder, output, case, args.engine_sha256, engine)
        except Exception as error:
            result = {'passed': False, 'error': str(error), 'output': str(output), 'log_folder': str(OUT / label)}
        results[name] = result
        save(OUT / label / 'verification.json', result)
        print(json.dumps({'case': name, 'passed': result['passed'], 'error': result.get('error')}), flush=True)
    summary = {'passed': all(row['passed'] for row in results.values()), 'scope': data['scope'],
               'engine': str(engine), 'engine_sha256': sha(engine), 'fixtures_manifest_sha256': sha(OUT / 'python-mounts-frozen-fixtures.json'),
               'cases': results, 'limits': ['Cross-file mounted URLs remain hints rather than new canonical Route objects.',
               'Unsupported cyclic configuration proves bounded static termination only.',
               'External plugin route completeness and unrelated raw Django duplicates remain open.',
               'The frozen executable hash is attested; root separately qualifies complete package/native release inputs.']}
    path = OUT / f'python-mounts-frozen-{args.run_id}.json'
    assert not path.exists()
    save(path, summary)
    print(json.dumps({'summary': str(path), 'passed': summary['passed'], 'case_count': len(results)}), flush=True)
    if not summary['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--engine', type=Path)
    parser.add_argument('--engine-sha256')
    parser.add_argument('--run-id', default='final')
    args = parser.parse_args()
    if args.prepare:
        print(json.dumps({'prepared': len(prepare()['cases'])}))
    else:
        assert args.engine and args.engine_sha256
        run(args)
