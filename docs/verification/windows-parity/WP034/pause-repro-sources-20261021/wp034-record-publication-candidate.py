import hashlib,json,statistics
from pathlib import Path

root=Path('C:/Projects/INPROGRESS/AttackMap');case=Path('C:/tmp/attackmap-wp034/publication-candidate-20261021-01');baseline=Path('C:/tmp/attackmap-wp034/10k-20261021-02/source')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def tree(path):return {p.relative_to(path).as_posix():sha(p) for p in path.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
a,b=tree(baseline),tree(case/'source');changed=[p for p in sorted(a.keys()|b.keys()) if a.get(p)!=b.get(p)]
assert changed==['src/attackmap/report.py','src/attackmap/safe_fs.py']
runs=json.loads((case/'campaign-runs.json').read_text());assert all(r['exit_code']==0 and r['cleanup_verified'] and not r['abort'] for r in runs)
timing=[json.loads((case/f"{r['number']}-{r['label']}-result.json").read_text())|{'owned_job_lifetime_peak_commit_bytes':r['peak_owned_job_commit_bytes']} for r in runs if r['label']!='checks']
stats={name:{key:statistics.median(r[key] for r in timing if r['implementation']==name) for key in ('cpu_seconds','wall_seconds','owned_job_lifetime_peak_commit_bytes')} for name in ('baseline','candidate')}
artifacts=[root/'.tmp/wp034-publication-prototype.py',root/'.tmp/wp034-publication-candidate.diff',case/'source-delta.json',case/'campaign-runs.json',case/'checks-result.json']+[case/f"{r['number']}-{r['label']}-result.json" for r in runs if r['label']!='checks']
evidence={'status':'BYTE_AND_FAILURE_CHECKS_PASS_MEMORY_CPU_TRADEOFF_NOT_PRODUCTION_OR_C35_ACCEPTANCE','session':41096,
 'command':"$env:PYTHONPATH='C:/tmp/attackmap-wp034/10k-20261021-02/source/src'; $env:PYTHONDONTWRITEBYTECODE='1'; & ./.tools/wp024-freeze-venv/Scripts/python.exe .tmp/wp034-publication-prototype.py",
 'baseline_source':str(baseline),'owned_candidate_source':str(case/'source'),'source_file_count':len(a),'changed_files':changed,'source_delta':json.loads((case/'source-delta.json').read_text()),
 'checks':json.loads((case/'checks-result.json').read_text()),'runs':runs,'serialization_only_results':timing,'medians_separate_wall_cpu_and_job_peak':stats,
 'input':{'path':'C:/tmp/attackmap-wp034/1000-profile-20261021-01/reports/attackmap-report.json','bytes':36895649,'sha256':timing[0]['input_sha256']},
 'artifacts':{str(p):sha(p) for p in artifacts},
 'runtime_json_encoder':{'path':'C:/Program Files/Python313/Lib/json/encoder.py','sha256':sha(Path('C:/Program Files/Python313/Lib/json/encoder.py')),
 'verified_behavior':'JSONEncoder.encode calls iterencode(o,_one_shot=True); this runtime selects c_make_encoder whenever _one_shot and accelerator exists, including indent=2. Candidate public iterencode defaults _one_shot=False and selects Python _make_iterencode. This code-path difference is verified; precise cost attribution was not profiled in this comparison.'},
 'interpretation':['Exact bytes matched all actual outputs and eight fixture goldens; ordinary writer flags/API unchanged, only shared internal target/open validation factored.',
 'Actual target symlink and directory escape symlink rejected on Windows; no skipped symlink fixture. Encoder/write/close/replace failures kept previous report bytes and a real published, checksum-valid prior generation pointer.',
 'Same-directory exclusive staging narrows per-report commit: replacement happens after encode and close. No fsync/durability guarantee, generation-pointer changes or blanket cleanup.',
 'Peak job values include startup and decoding retained input before timed serialization; no resettable OS stage high-water counter was available. before/after and lifetime counters are separately retained. This is not full pipeline peak.',
 'Candidate CPU regression is material (~18s vs2.2s here); do not integrate as a performance improvement or assume it resolves default600s exhaustion. Memory tradeoff needs review. No50k/100k inference.'],
 'review_boundaries':['A stricter follow-up should close the raw descriptor if os.fdopen itself raises before context ownership. Inject that failure before production; current injected write/close errors occur after wrapping.',
 'Replacing an existing report can change inode/file identity, links and destination-specific permissions/ACL relative to old truncate-in-place behavior. Generated staged reports normally start absent, but custom existing metadata equivalence is unproven and must be reviewed.',
 'write_reports dictionary construction/return expression is unchanged by the two-line call/import delta; this adapter tests serialization bytes and failure publication isolation, not a full write_reports/pipeline invocation.',
 'No canonical edits. Root reviews precise delta and tradeoff before any further owned prototype or persistent production integration.']}
out=root/'docs/verification/windows-parity/WP034/publication-copy-candidate-2026-10-21.json';out.write_text(json.dumps(evidence,indent=2)+'\n');print(json.dumps({'evidence':str(out),'changed':changed,'medians':stats},indent=2))
