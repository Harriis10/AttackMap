"""Rebuild synthetic portable contract fixtures; never calls providers or scans."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from attackmap.run_contract import RunRequest, RunProgress, RunTerminal

HERE = Path(__file__).resolve().parent

def write(name, value):
    path = HERE / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

base = dict(run_id='synthetic-run-a1', repository_id='synthetic-repo-a', generation=1, revision=0)
request = RunRequest(**base, repository_path='C:/synthetic/team-a/sample', output_path='C:/synthetic/reports/a')
write('request-current.json', request.model_dump())
write('request-previous.json', request.model_copy(update={'schema_version': '1.0'}).model_dump())
write('request-unsupported-major.json', request.model_copy(update={'schema_version': '99.0'}).model_dump())
sentinel = request.model_dump()
sentinel['options'].update(recall=True, strict_analyzers=True, no_suppress=True, cve=True, secrets_history=17, timeout_seconds=743)
sentinel['options']['provider'].update(enable_ai=True, max_calls=11, timeout_seconds=719, output_token_limit=12345)
sentinel['modules'] = ['synthetic-language', 'synthetic-overlay']
write('request-sentinels.json', RunRequest.model_validate(sentinel).model_dump())
for provider in ('openai', 'claude'):
    for enabled in (False, True):
        value = request.model_dump()
        value['options']['provider'].update(provider=provider, enable_ai=enabled)
        write(f'providers/{provider}-{str(enabled).lower()}.json', RunRequest.model_validate(value).model_dump())
events = []
for revision, state, stage, done, total in [(1,'queued','',None,None),(2,'running','analyzers',1,4),(3,'cancelling','analyzers',2,4)]:
    events.append(RunProgress(**(base | {'revision': revision}), state=state, stage=stage, completed_units=done, total_units=total).model_dump())
write('events.json', events)
for state, policy, ready in [('completed','passed','ready'),('completed','failed','ready'),('failed','not_evaluated','unavailable'),('cancelled','not_evaluated','unavailable')]:
    execution = {'completed':'succeeded','failed':'failed','cancelled':'cancelled'}[state]
    write(f'terminal-{state}-{policy}.json', RunTerminal(**(base | {'revision':4}), state=state, execution_outcome=execution, policy_outcome=policy, artifact_readiness=ready, limitations=['SYNTHETIC contract scenario; no scan executed.']).model_dump())
write('identities.json', [base, base | {'run_id':'synthetic-run-a2','generation':2}, base | {'run_id':'synthetic-run-b1','repository_id':'synthetic-repo-b'}])
write('identity-paths.json', {'synthetic-repo-a':'C:/synthetic/team-a/sample','synthetic-repo-b':'C:/synthetic/team-b/sample'})
write('report-empty.json', {'scan':{'root':'C:/synthetic/team-a/sample','files_scanned':0,'scanned_files':[], 'limitations':['SYNTHETIC empty report; no runtime coverage claim.'],'analyzer_errors':[]},'findings':[], 'suppressed_findings':[], 'attack_paths':[], 'exploitability':[]})
write('report-missing-sections.json', {'scan':{'root':'C:/synthetic/team-a/sample','limitations':['SYNTHETIC missing optional sections; unknown, not zero.']},'findings':[]})
# Preserve the maintained UI corpus exactly; this is legacy display data, not a
# newly executed scan or a claim that every row satisfies current core models.
source = ROOT / 'tests/fixtures/ui/juice-shop-report.json'
(HERE / 'report-nonempty-legacy.json').write_bytes(source.read_bytes())
nonempty = json.loads(source.read_text(encoding='utf-8'))
partial = json.loads(source.read_text(encoding='utf-8'))
partial['scan']['limitations'] = ['SYNTHETIC partial projection of maintained UI fixture; dependency/CVE section unavailable.']
partial['scan'].pop('dependencies')
partial['scan'].pop('vulnerabilities')
write('report-partial-legacy.json', partial)
section_keys = {'findings':['id'], 'suppressed_findings':['id'], 'attack_paths':['name'], 'attack_surfaces':['method','route','file'], 'exploitability':['subject'], 'scan.routes':['method','path','file','line'], 'scan.secret_hints':['name','kind','file','line'], 'scan.dependencies':['ecosystem','name','version'], 'scan.taint_chains':['sink_kind','file','line'], 'scan.vulnerabilities':[], 'scan.workflow_issues':[], 'scan.analyzer_errors':[]}
def resolve(value, dotted):
    for key in dotted.split('.'):
        value = value[key]
    return value
expectations = {}
for name in ('report-nonempty-legacy.json','report-partial-legacy.json','report-empty.json','report-missing-sections.json'):
    report = json.loads((HERE / name).read_text(encoding='utf-8'))
    sections = {}
    for dotted, keys in section_keys.items():
        try:
            rows = resolve(report,dotted)
        except KeyError:
            sections[dotted] = {'state':'missing'}
            continue
        sections[dotted] = {'state':'present','count':len(rows),'identity_fields':keys,'source_keys_in_order':[[r.get(k) for k in keys] for r in rows], 'rows_in_source_order':rows}
    expectations[name] = {'sections':sections,'ai':{'defensive_review_llm': {'state':'present','value':report['defensive_review_llm']} if 'defensive_review_llm' in report else {'state':'missing'}, 'provider_metadata':{'state':'missing'}, 'live_response_claim':False}}
write('report-expectations.json', {'provenance':'Byte copy and explicitly limited projection of maintained UI fixture; rows without IDs use source fields, never fabricated IDs.', 'reports':expectations})
references = ['fixtures/desktop-workflows/current.json','fixtures/desktop-workflows/previous.json','fixtures/desktop-workflows/partial-coverage.json','fixtures/desktop-workflows/suppressed.json','fixtures/desktop-workflows/expected.json','fixtures/desktop-workflows/suppressions.yaml','fixtures/run-contract/faults/duplicate-reordered.json','fixtures/run-contract/faults/cancelling-regression.json','tests/fixtures/ui/juice-shop-report.json']
entries = []
paths = sorted(p for p in HERE.rglob('*.json') if p.name != 'manifest.json') + [ROOT / p for p in references]
for path in paths:
    value = json.loads(path.read_text(encoding='utf-8')) if path.suffix == '.json' else None
    entry = {'id':path.relative_to(ROOT).as_posix(), 'sha256':hashlib.sha256(path.read_bytes()).hexdigest(), 'size_bytes':path.stat().st_size}
    if isinstance(value, dict) and isinstance(value.get('findings'), list):
        entry['expected'] = {key:{'count':len(value[key]), 'ids_in_source_order':[r.get('id') for r in value[key]]} for key in ('findings','suppressed_findings','attack_paths','exploitability') if isinstance(value.get(key),list)}
    entries.append(entry)
write('manifest.json', {'contract':'desktop-parity/v1','status':'CURRENT_BOUNDARY_FROZEN_2026-10-20','synthetic':True,'entries':entries})
print(f'Prepared {len(entries)} hash-bound fixture entries')
