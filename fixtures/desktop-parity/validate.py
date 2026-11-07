"""Read-only parity validation. Run from any directory with project dependencies."""
from pathlib import Path
import hashlib
import json
import sys
import jsonschema

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from attackmap.run_contract import parse_run_message, import_legacy_report, accepts_update

HERE = Path(__file__).resolve().parent
checks = []
def check(value, label):
    if not value:
        raise AssertionError(label)
    checks.append(label)

manifest = json.loads((HERE / 'manifest.json').read_text(encoding='utf-8'))
for entry in manifest['entries']:
    path = ROOT / entry['id']
    check(hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'], 'sha256:' + entry['id'])
    check(path.stat().st_size == entry['size_bytes'], 'size:' + entry['id'])
    if 'expected' in entry:
        value = json.loads(path.read_text(encoding='utf-8'))
        for key, expected in entry['expected'].items():
            check(len(value[key]) == expected['count'] and [r.get('id') for r in value[key]] == expected['ids_in_source_order'], 'ordered rows:' + entry['id'] + ':' + key)
for path in sorted(HERE.glob('request-*.json')) + sorted((HERE / 'providers').glob('*.json')) + sorted(HERE.glob('terminal-*.json')):
    payload = json.loads(path.read_text(encoding='utf-8'))
    if 'unsupported' in path.name:
        try:
            parse_run_message(payload)
        except ValueError:
            checks.append('future major rejected')
        else:
            raise AssertionError('future major accepted')
    else:
        check(parse_run_message(payload).model_dump() == payload, 'model round-trip:' + path.name)
        schema_name = 'run-request.schema.json' if payload['kind'] == 'request' else 'run-terminal.schema.json'
        jsonschema.validate(payload, json.loads((ROOT / 'schemas' / schema_name).read_text(encoding='utf-8')))
        checks.append('JSON schema:' + path.name)
events = [parse_run_message(p) for p in json.loads((HERE / 'events.json').read_text(encoding='utf-8'))]
check(accepts_update(events[0],events[1]) and accepts_update(events[1],events[2]), 'forward events accepted')
check(not accepts_update(events[1],events[0]) and not accepts_update(events[1],events[1]), 'stale and duplicate rejected')
check(not accepts_update(events[2],events[1].model_copy(update={'revision':5})), 'cancelling regression rejected')
for field, value in [('run_id','synthetic-other'),('repository_id','synthetic-repo-b'),('generation',2)]:
    check(not accepts_update(events[0],events[1].model_copy(update={field:value})), 'cross identity rejected:' + field)
terminal = parse_run_message(json.loads((HERE / 'terminal-completed-failed.json').read_text(encoding='utf-8')))
check(not accepts_update(terminal, events[1].model_copy(update={'revision':9})), 'terminal regression rejected')
for event in events:
    jsonschema.validate(event.model_dump(), json.loads((ROOT / 'schemas' / 'run-progress.schema.json').read_text(encoding='utf-8')))
    checks.append('progress JSON schema:' + event.state)
for name in ('report-empty.json','report-missing-sections.json'):
    terminal, payload = import_legacy_report(json.loads((HERE / name).read_text(encoding='utf-8')),run_id='synthetic-import',repository_id='synthetic-repo-a',generation=1)
    check(terminal.artifact_readiness == 'unavailable' and terminal.policy_outcome == 'not_evaluated', 'legacy unverified:' + name)
features = json.loads((HERE / 'feature-map.json').read_text(encoding='utf-8'))
check((HERE / 'report-nonempty-legacy.json').read_bytes() == (ROOT / 'tests/fixtures/ui/juice-shop-report.json').read_bytes(), 'nonempty legacy copy byte identical to maintained source')
expected_reports = json.loads((HERE / 'report-expectations.json').read_text(encoding='utf-8'))['reports']
for name, expected in expected_reports.items():
    report = json.loads((HERE / name).read_text(encoding='utf-8'))
    for dotted, section in expected['sections'].items():
        value = report
        present = True
        for key in dotted.split('.'):
            if key not in value:
                present = False
                break
            value = value[key]
        check(present == (section['state'] == 'present'), 'section presence:' + name + ':' + dotted)
        if present:
            check(len(value) == section['count'] and value == section['rows_in_source_order'], 'exact ordered section:' + name + ':' + dotted)
            check([[r.get(k) for k in section['identity_fields']] for r in value] == section['source_keys_in_order'], 'source identities:' + name + ':' + dotted)
    ai = expected['ai']['defensive_review_llm']
    check(('defensive_review_llm' in report) == (ai['state'] == 'present'), 'AI section presence:' + name)
    if ai['state'] == 'present':
        check(report['defensive_review_llm'] == ai['value'], 'AI text exact:' + name)
check([f['id'] for f in features] == [f'F{i:02}' for i in range(1,27)], 'all 26 features mapped')
for feature in features:
    check(bool(feature['procedure']) and bool(feature['owner_task']), 'explicit procedure:' + feature['id'])
print(json.dumps({'status':'PASS','checks':len(checks),'scope':'Synthetic Python contract/hash checks only','limitations':['No live provider calls, native UI, C# or Swift execution','Future WP004/WP014/WP018 contract additions require new versioned fixtures and consumer evidence']},indent=2))
