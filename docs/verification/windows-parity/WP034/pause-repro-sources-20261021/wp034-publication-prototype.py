"""Owned-copy report serialization prototype; no scanner invocation."""
import hashlib,importlib.util,json,os,shutil,subprocess,sys,time,difflib
from pathlib import Path

ROOT=Path('C:/Projects/INPROGRESS/AttackMap')
SOURCE=Path('C:/tmp/attackmap-wp034/10k-20261021-02/source')
CASE=Path('C:/tmp/attackmap-wp034/publication-candidate-20261021-01')
INPUT=Path('C:/tmp/attackmap-wp034/1000-profile-20261021-01/reports/attackmap-report.json')
HELPER='''

def safe_write_json_report(out_dir: str | Path, path: str | Path, value: object) -> None:
    """Commit one complete report after successful encode/close; not a durability guarantee."""
    import json
    import uuid

    out, target = Path(out_dir), Path(path)
    _check_output_target(out, target)
    stage = target.with_name(f".{target.name}-{uuid.uuid4().hex}.tmp")
    owned = False
    try:
        fd = _open_output_fd(out, stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0))
        owned = True
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            pending, size = [], 0
            for chunk in json.JSONEncoder(indent=2).iterencode(value):
                if size + len(chunk) >= 65536:
                    handle.write("".join(pending))
                    pending, size = [], 0
                if len(chunk) >= 65536:
                    handle.write(chunk)
                else:
                    pending.append(chunk)
                    size += len(chunk)
            handle.write("".join(pending))
            handle.write("\\n")
        _check_output_target(out, stage)
        _check_output_target(out, target)
        os.replace(stage, target)
        owned = False
    finally:
        if owned:
            stage.unlink(missing_ok=True)
'''

def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load_safe():
    spec=importlib.util.spec_from_file_location('owned_safe_fs',CASE/'source/src/attackmap/safe_fs.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def checks():
    from unittest.mock import patch
    safe=load_safe();out=CASE/'checks';out.mkdir();target=out/'report.json'
    values=[None,{},[],{'z':1,'a':2},{'nested':[True,False,None,{},[],{'x':'line\n\t"\\é😀'}]},
            {1:'int',None:'none',False:'bool'}, {'f':[-0.0,1e-30,float('inf'),float('-inf'),float('nan')]},
            {'long':'x'*200000,'end':'retained'}]
    for value in values:
        safe.safe_write_json_report(out,target,value)
        assert target.read_bytes()==(json.dumps(value,indent=2)+'\n').encode('utf-8')
    # A real valid prior generation/pointer is independent of the failing new report.
    from attackmap.artifact_manifest import SECTION_ORDER,SCHEMA_VERSION,ARTIFACT_TYPE
    from attackmap.artifact_publisher import publish_generation,current_generation,validate_generation,CURRENT_POINTER
    base=out/'published';old=base/'prior';old.mkdir(parents=True)
    entries=[]
    for key,name,role in SECTION_ORDER:
        p=old/name;p.write_text(json.dumps({'root':'owned'} if key=='scan' else [])+'\n')
        entries.append({'name':key,'path':name,'role':role,'format':'json','checksum':sha(p)})
    for name,value in [('attackmap-report.json',{'scan':{'root':'owned'}}),('run-manifest.json',{'stages':[]})]:
        p=old/name;p.write_text(json.dumps(value)+'\n');entries.append({'name':name,'path':name,'role':'compatibility','format':'json','checksum':sha(p)})
    dump(old/'artifact-manifest.json',{'schema_version':SCHEMA_VERSION,'artifact_type':ARTIFACT_TYPE,'generation_id':'prior','engine_version':'test','created_at':'2026-10-21','run_identity':{'repo_root':'owned','repo_name':'owned','analyzers':[]},'exit_state':{'exit_code':0,'status':'succeeded'},'sections':entries,'compatibility_exports':[]})
    publish_generation(base,'prior');pointer=(base/CURRENT_POINTER).read_bytes()
    target.write_bytes(b'previous-report\n');previous=target.read_bytes();faults=[]
    def preserved(name,operation):
        try:operation()
        except (TypeError,OSError):pass
        else:raise AssertionError('Expected failure: '+name)
        assert target.read_bytes()==previous and (base/CURRENT_POINTER).read_bytes()==pointer
        assert current_generation(base)==old;validate_generation(old)
        assert not list(out.glob('.report.json-*.tmp'));faults.append(name)
    preserved('encoder',lambda:safe.safe_write_json_report(out,target,{'good':1,'bad':object()}))
    fdopen=safe.os.fdopen
    class FaultFile:
        def __init__(self,*args,close_failure=False,**kwargs):self.handle=fdopen(*args,**kwargs);self.close_failure=close_failure
        def __enter__(self):return self
        def write(self,value):
            if not self.close_failure:raise OSError('injected write failure')
            return self.handle.write(value)
        def __exit__(self,*args):
            self.handle.close()
            if self.close_failure:raise OSError('injected close failure')
    with patch.object(safe.os,'fdopen',lambda *a,**k:FaultFile(*a,**k)):
        preserved('write',lambda:safe.safe_write_json_report(out,target,{'value':1}))
    with patch.object(safe.os,'fdopen',lambda *a,**k:FaultFile(*a,close_failure=True,**k)):
        preserved('close',lambda:safe.safe_write_json_report(out,target,{'value':1}))
    with patch.object(safe.os,'replace',side_effect=OSError('injected replace failure')):
        preserved('replace',lambda:safe.safe_write_json_report(out,target,{'value':1}))
    outside=CASE/'outside.json';outside.write_bytes(b'outside')
    try:safe.safe_write_json_report(out,outside,{})
    except safe.UnsafePathError:pass
    else:raise AssertionError('escape allowed')
    assert outside.read_bytes()==b'outside'
    symlinks={}
    for name,link,destination,is_dir in [('target',out/'link.json',outside,False),('directory',out/'linked',CASE,True)]:
        try:link.symlink_to(destination,target_is_directory=is_dir)
        except OSError as error:symlinks[name]={'skipped':str(error)};continue
        try:
            try:safe.safe_write_json_report(out,link if not is_dir else link/'outside.json',{})
            except safe.UnsafePathError:symlinks[name]='rejected'
            else:raise AssertionError('symlink allowed')
        finally:link.unlink()
    assert outside.read_bytes()==b'outside'
    # Existing ordinary writer's output/exception behavior remains available.
    safe.safe_write_text(out,target,'ordinary\n');assert target.read_bytes()==b'ordinary\n'
    dump(CASE/'checks-result.json',{'byte_golden_cases':len(values),'failures_preserve_report_and_valid_current_generation':faults,'outside_path_rejected':True,'symlink_results':symlinks,'ordinary_writer_bytes':True})

def worker(label,number):
    safe=load_safe();value=json.loads(INPUT.read_bytes());before=safe_memory()
    output=CASE/f'{number}-{label}.json';start=time.perf_counter();cpu=time.process_time()
    if label=='baseline':safe.safe_write_text(CASE,output,json.dumps(value,indent=2)+'\n')
    else:safe.safe_write_json_report(CASE,output,value)
    timing={'wall_seconds':time.perf_counter()-start,'cpu_seconds':time.process_time()-cpu}
    assert sha(output)==sha(INPUT)
    dump(CASE/f'{number}-{label}-result.json',{'implementation':label,'input_sha256':sha(INPUT),'output_sha256':sha(output),'output_bytes':output.stat().st_size,'before_serialization_memory':before,'after_serialization_memory':safe_memory(),**timing})

def safe_memory():
    spec=importlib.util.spec_from_file_location('campaign_memory',SOURCE/'tools/measure_memory_admission.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.memory()

def main():
    if len(sys.argv)>1:
        if sys.argv[1]=='checks':checks()
        else:worker(sys.argv[1],int(sys.argv[2]))
        return 0
    CASE.mkdir();shutil.copytree(SOURCE,CASE/'source',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    path=CASE/'source/src/attackmap/safe_fs.py';text=path.read_text()
    beginning=text.index('    out = Path(out_dir)',text.index('def safe_write_text('));flags=text.index('    flags = os.O_WRONLY',beginning);opening=text.index('    try:\n        fd = os.open',flags);with_at=text.index('    with os.fdopen(fd, "w"',opening)
    validation=text[beginning:flags]
    validation=validation.replace('    out = Path(out_dir)\n    target = Path(path)\n','')
    opened=text[opening:with_at].replace('        fd = os.open(target, flags, 0o644)','        return os.open(target, flags, 0o644)')
    support='def _check_output_target(out: Path, target: Path) -> None:\n'+validation+'\n\ndef _open_output_fd(out: Path, target: Path, flags: int) -> int:\n    _check_output_target(out, target)\n'+opened+'\n\n'
    start=text.index('def safe_write_text(')
    text=text[:start]+support+text[start:beginning]+'    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)\n    fd = _open_output_fd(Path(out_dir), Path(path), flags)\n'+text[with_at:]+HELPER
    path.write_text(text)
    report=CASE/'source/src/attackmap/report.py';text=report.read_text();text=text.replace('from .safe_fs import ensure_output_dir, safe_write_text','from .safe_fs import ensure_output_dir, safe_write_text, safe_write_json_report').replace('write("attackmap-report.json", json.dumps(json_report, indent=2) + "\\n")','safe_write_json_report(out, out / "attackmap-report.json", json_report)');report.write_text(text)
    delta=[];diff=''
    for rel in ('src/attackmap/safe_fs.py','src/attackmap/report.py'):
        a,b=SOURCE/rel,CASE/'source'/rel;delta.append({'path':rel,'baseline_sha256':sha(a),'candidate_sha256':sha(b)})
        diff+=''.join(difflib.unified_diff(a.read_text().splitlines(True),b.read_text().splitlines(True),fromfile='sealed-source2/'+rel,tofile='owned-candidate/'+rel))
    (ROOT/'.tmp/wp034-publication-candidate.diff').write_text(diff);dump(CASE/'source-delta.json',delta)
    spec=importlib.util.spec_from_file_location('campaign',SOURCE/'tools/measure_memory_admission.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    from attackmap.execution.windows import WindowsProcessJob
    from attackmap.analyzer_host import _query_job_peak_memory
    runs=[]
    for number,label in enumerate(('checks','baseline','candidate','candidate','baseline')):
        job=WindowsProcessJob();handles={};started=time.monotonic();peak=0;abort=None
        with (CASE/f'{number}-{label}.stdout').open('x') as out,(CASE/f'{number}-{label}.stderr').open('x') as err:
            process=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),label,str(number)],cwd=SOURCE,stdout=out,stderr=err,creationflags=4)
            try:
                job.attach_and_resume(process)
                while process.poll() is None:
                    row=module.sample_owned_tree(job,handles);peak=max(peak,_query_job_peak_memory(job.handle))
                    if max(peak,row['private_bytes'],row['working_set_bytes'])>=3*1024**3 or time.monotonic()-started>1200:
                        abort='safety_bound';job.terminate();break
                    time.sleep(.05)
                code=process.wait(timeout=15);peak=max(peak,_query_job_peak_memory(job.handle))
            finally:
                if process.poll() is None:job.terminate();process.wait(timeout=15)
                until=time.monotonic()+15
                while job.active() and time.monotonic()<until:time.sleep(.05)
                cleanup=job.active()==0
                if not cleanup:job.terminate()
                for h in handles.values():job._kernel.CloseHandle(h)
                job.close()
        runs.append({'label':label,'number':number,'exit_code':code,'abort':abort,'cleanup_verified':cleanup,'peak_owned_job_commit_bytes':peak,'whole_child_wall_seconds':time.monotonic()-started})
        dump(CASE/'campaign-runs.json',runs)
        if code or abort or not cleanup:return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
