import hashlib,json,subprocess,xml.etree.ElementTree as ET
from pathlib import Path
root=Path('C:/Projects/INPROGRESS/AttackMap');owned=Path('C:/tmp/attackmap-wp034/publication-heldtemp-candidate-20261021-02/source')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
paths=[root/'src/attackmap/safe_fs.py',root/'src/attackmap/report.py',root/'tests/test_report_json_writer.py']
for relative in ('src/attackmap/safe_fs.py','src/attackmap/report.py'):
    assert sha(root/relative)==sha(owned/relative)
xml=root/'.tmp/wp034-publication-tests-20261021-02.xml';tree=ET.parse(xml)
cases=list(tree.iter('testcase'));failures=[{'test':c.get('name'),'class':c.get('classname'),'details':n.text} for c in cases for n in c if n.tag in ('failure','error')]
skips=[{'test':c.get('name'),'reason':n.get('message')} for c in cases for n in c if n.tag=='skipped']
counts={name:len([c for c in cases if c.get('classname')==name]) for name in sorted({c.get('classname') for c in cases})}
diff=root/'.tmp/wp034-publication-canonical.diff';diff.write_bytes(subprocess.run(['git','diff','--','src/attackmap/safe_fs.py','src/attackmap/report.py'],cwd=root,capture_output=True,check=True).stdout)
cleanup=root/'.tmp/wp034-publication-process-cleanup.json'
cleanup_result=json.loads(cleanup.read_text(encoding='utf-8-sig'))
assert cleanup_result['MatchingOwnedProcesses']==0
paths.extend((xml,diff,cleanup))
payload={'status':'FOCUSED_PUBLICATION_CANONICAL_CHECKPOINT_PASS_NOT_C35' if not failures else 'FOCUSED_PUBLICATION_FAILURE_REQUIRES_REVIEW','session':48723,'source_frozen':not failures,
 'command':"$env:PYTHONPATH=Join-Path $PWD 'src'; $env:PYTHONDONTWRITEBYTECODE='1'; & ./.venv/Scripts/python.exe -m pytest tests/test_report_json_writer.py tests/test_report.py tests/test_safe_fs.py tests/test_output_format.py tests/test_artifact_manifest.py tests/test_artifact_publisher.py tests/test_diagnostics_export.py -q -p no:cacheprovider --basetemp .tmp/wp034-publication-tests-20261021-02 --junitxml .tmp/wp034-publication-tests-20261021-02.xml",
 'result':{'testcases':len(cases),'passed':len(cases)-len(failures)-len(skips),'failed_or_error':len(failures),'skipped':len(skips),'by_module':counts,'failures':failures,'skip_details':skips,'pytest_terminal_seconds':660.03,'exit_code':0},
 'owned_attempt_process_cleanup':cleanup_result,
 'initial_attempt':{'session':6030,'status':'INTERRUPTED_NOT_ACCEPTANCE','details':'Restricted-token run emitted fixture E markers before assertion results; interrupted. No full error stack or terminal test matrix retained, so exact fixture cause not asserted. Approved-access fresh-temp retry is authoritative.'},
 'reviewed_fifth_source_bytes_equal_canonical':True,'files':{str(p):sha(p) for p in paths},
 'contract':['Existing/symlink initial targets retain exact original C dumps+safe_write_text without TemporaryFile creation; original overwrite/error ordering and inode/security metadata preserved.',
 'New targets use section-C UTF8 encoding in held TemporaryFile; flush+seek before final shared checked EXCL open. No stage name reopen/manual cleanup, rename/replace/link/ACL API in helper.',
 'Encoding/stage write/flush/seek failures leave destination absent; final copy/fdopen/late temp-close failure may leave new partial/complete destination but prior authoritative generation remains valid. No per-file atomic rollback claim.',
 'Concurrent appeared regular/symlink/hardlink target deliberately refused; no fallback/retry/actor cleanup. New output parent must authorize report content; mode0600 is not a Windows DACL-private guarantee.'],
 'memory_evidence_limit':'Earlier isolated fourth/stage-copy prototypes suggested roughly21–23% lower whole-child lifetime job peak on retained36.9MB report, with CPU/IO tradeoff. Fifth/canonical held-temp variant has no retained-report benchmark yet. Potential only, not default pipeline/C35/<2GiB or50k/100k acceptance.',
 'unchanged':'Report dictionary construction/return/ordering, ordinary writer API, generation-level pointer/validation/checksum behavior, defaults/budgets/analyzer coverage. No full suite,36.9MBbenchmark, GUI/provider/build launched by this slice.'}
out=root/'docs/verification/windows-parity/WP034/publication-integration-2026-10-21.json';out.write_text(json.dumps(payload,indent=2)+'\n');print(json.dumps({'evidence':str(out),'result':payload['result']},indent=2))
