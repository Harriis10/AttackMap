"""Owned-copy report serialization prototype; no scanner invocation."""
import hashlib,importlib.util,json,os,shutil,subprocess,sys,time,difflib
from pathlib import Path

ROOT=Path('C:/Projects/INPROGRESS/AttackMap')
SOURCE=Path('C:/tmp/attackmap-wp034/10k-20261021-02/source')
CASE=Path('C:/tmp/attackmap-wp034/publication-heldtemp-candidate-20261021-01')
INPUT=Path('C:/tmp/attackmap-wp034/1000-profile-20261021-01/reports/attackmap-report.json')
HELPER='\n\ndef safe_write_json_report(out_dir: str | Path, path: str | Path, value: object) -> None:\n    """Encode to a held temporary, then exclusively create a new report destination."""\n    import json\n    import tempfile\n\n    out, target = Path(out_dir), Path(path)\n    if target.exists() or target.is_symlink():\n        safe_write_text(out, target, json.dumps(value, indent=2) + "\\n")\n        return\n    _check_output_target(out, target)\n    with tempfile.TemporaryFile(mode="w+b", dir=target.parent, prefix=".report-stage-") as stage:\n        def emit(text):\n            stage.write(text.encode("utf-8"))\n        if type(value) is dict and all(type(key) is str for key in value):\n            if not value:\n                emit("{}")\n            else:\n                emit("{\\n")\n                first = True\n                for key, section in value.items():\n                    if not first:\n                        emit(",\\n")\n                    first = False\n                    emit("  " + json.dumps(key) + ": ")\n                    text = json.dumps(section, indent=2)\n                    emit(text.replace("\\n", "\\n  "))\n                    del text\n                emit("\\n}")\n        else:\n            emit(json.dumps(value, indent=2))\n        emit("\\n")\n        stage.flush()\n        stage.seek(0)\n        _check_output_target(out, target)\n        if target.exists() or target.is_symlink():\n            raise FileExistsError(f"report destination appeared during encoding: {target}")\n        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)\n        target_fd = _open_output_fd(out, target, flags)\n        try:\n            destination = os.fdopen(target_fd, "wb")\n        except BaseException:\n            try:\n                os.close(target_fd)\n            except OSError:\n                pass\n            raise\n        with destination:\n            while chunk := stage.read(65536):\n                destination.write(chunk)\n'

def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load_safe():
    spec=importlib.util.spec_from_file_location('owned_safe_fs',CASE/'source/src/attackmap/safe_fs.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def checks():
    from unittest.mock import patch
    from types import SimpleNamespace
    import uuid,ctypes,tempfile
    safe=load_safe();out=CASE/'checks';out.mkdir();target=out/'report.json'
    values=[None,{},[],{'z':1,'a':2},{'nested':[True,False,None,{},[],{'x':'line\n\t"\\é😀'}]},
            {1:'int',None:'none',False:'bool'},{'f':[-0.0,1e-30,float('inf'),float('-inf'),float('nan')]},{'long':'x'*200000,'end':'retained'}]
    for value in values:
        target.unlink(missing_ok=True)
        safe.safe_write_json_report(out,target,value)
        assert target.read_bytes()==(json.dumps(value,indent=2)+'\n').encode('utf-8')
    from attackmap.artifact_manifest import SECTION_ORDER,SCHEMA_VERSION,ARTIFACT_TYPE
    from attackmap.artifact_publisher import publish_generation,current_generation,validate_generation,CURRENT_POINTER
    base=out/'published';old=base/'prior';old.mkdir(parents=True);entries=[]
    for key,name,role in SECTION_ORDER:
        p=old/name;p.write_text(json.dumps({'root':'owned'} if key=='scan' else [])+'\n')
        entries.append({'name':key,'path':name,'role':role,'format':'json','checksum':sha(p)})
    for name,value in [('attackmap-report.json',{'scan':{'root':'owned'}}),('run-manifest.json',{'stages':[]})]:
        p=old/name;p.write_text(json.dumps(value)+'\n');entries.append({'name':name,'path':name,'role':'compatibility','format':'json','checksum':sha(p)})
    dump(old/'artifact-manifest.json',{'schema_version':SCHEMA_VERSION,'artifact_type':ARTIFACT_TYPE,'generation_id':'prior','engine_version':'test','created_at':'2026-10-21','run_identity':{'repo_root':'owned','repo_name':'owned','analyzers':[]},'exit_state':{'exit_code':0,'status':'succeeded'},'sections':entries,'compatibility_exports':[]})
    publish_generation(base,'prior');pointer=(base/CURRENT_POINTER).read_bytes()
    def prior_ok():
        assert (base/CURRENT_POINTER).read_bytes()==pointer and current_generation(base)==old
        validate_generation(old)
    def no_stages():assert not list(out.glob('.report-stage-*'))
    # Read-only owner/group/DACL snapshot, no ACL changes or writer ACL API.
    def security(path):
        from ctypes import wintypes
        api=ctypes.WinDLL('advapi32',use_last_error=True).GetFileSecurityW
        api.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)];api.restype=wintypes.BOOL
        size=wintypes.DWORD();api(str(path),7,None,0,ctypes.byref(size));buffer=ctypes.create_string_buffer(size.value)
        if not api(str(path),7,buffer,len(buffer),ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        return hashlib.sha256(buffer.raw[:size.value]).hexdigest()
    target.write_bytes(b'existing');inode=target.stat().st_ino;acl=security(target)
    with patch.object(tempfile,'TemporaryFile',side_effect=AssertionError('existing path created a stage')):
        safe.safe_write_json_report(out,target,{'existing':'exact legacy'})
        assert target.read_bytes()==(json.dumps({'existing':'exact legacy'},indent=2)+'\n').encode()
        previous=target.read_bytes()
        try:safe.safe_write_json_report(out,target,{'bad':object()})
        except TypeError:pass
        else:raise AssertionError('encoder failure missing')
        assert target.read_bytes()==previous
    assert target.stat().st_ino==inode and security(target)==acl;no_stages();prior_ok()
    fdopen=safe.os.fdopen
    class FaultFile:
        def __init__(self,handle,phase):self.handle=handle;self.phase=phase
        def __enter__(self):return self
        def __exit__(self,*args):
            self.handle.close()
            if self.phase=='stage_close':raise OSError('stage close fault')
        def read(self,size):
            if self.phase=='copy_read':raise OSError('copy read fault')
            return self.handle.read(size)
        def write(self,value):
            if self.phase in ('stage_write','copy_write','legacy_write'):
                if self.phase!='stage_write':self.handle.write(value[:5]);self.handle.flush()
                raise OSError('write fault')
            return self.handle.write(value)
    def wrapper(phase):
        def wrap(fd,mode,*a,**k):
            if phase=='stage_fdopen' and mode=='w':raise OSError('stage fdopen fault')
            handle=fdopen(fd,mode,*a,**k)
            return FaultFile(handle,phase) if mode=={'stage_write':'w','stage_close':'w','copy_read':'rb','copy_write':'wb','legacy_write':'w'}.get(phase) else handle
        return wrap
    # Existing-target write fault remains the exact legacy partial-write behavior.
    with patch.object(tempfile,'TemporaryFile',side_effect=AssertionError('existing path staged')),patch.object(safe.os,'fdopen',wrapper('legacy_write')):
        try:safe.safe_write_json_report(out,target,{'existing':'failure'})
        except OSError:pass
        else:raise AssertionError('legacy write fault missing')
    assert len(target.read_bytes())==5 and target.stat().st_ino==inode and security(target)==acl;no_stages();prior_ok()
    real_temp=tempfile.TemporaryFile
    class TempFault:
        def __init__(self,handle,phase):self.handle=handle;self.phase=phase
        @property
        def name(self):raise AssertionError('writer accessed temp.name')
        def __enter__(self):self.handle.__enter__();return self
        def __exit__(self,*args):
            result=self.handle.__exit__(*args)
            if self.phase=='temp_close':raise OSError('temporary close failure')
            return result
        def write(self,value):
            if self.phase=='stage_write':raise OSError('stage write failure')
            return self.handle.write(value)
        def flush(self):
            if self.phase=='stage_flush':raise OSError('stage flush failure')
            return self.handle.flush()
        def seek(self,where):
            if self.phase=='stage_seek':raise OSError('stage seek failure')
            return self.handle.seek(where)
        def read(self,size):
            if self.phase=='copy_read':raise OSError('copy read failure')
            return self.handle.read(size)
    faults=[]
    for phase in ('encoder','stage_write','stage_flush','stage_seek','copy_read','copy_write','target_fdopen','temp_close'):
        target.unlink(missing_ok=True)
        value={'good':1,'bad':object()} if phase=='encoder' else {'new':'complete stage'}
        def fdwrapped(fd,mode,*a,**k):
            if phase=='target_fdopen' and mode=='wb':raise OSError('target fdopen failure')
            handle=fdopen(fd,mode,*a,**k)
            return FaultFile(handle,'copy_write') if phase=='copy_write' and mode=='wb' else handle
        with patch.object(tempfile,'TemporaryFile',lambda *a,**k:TempFault(real_temp(*a,**k),phase)),patch.object(safe.os,'fdopen',fdwrapped):
            try:safe.safe_write_json_report(out,target,value)
            except (TypeError,OSError):pass
            else:raise AssertionError('missing fault '+phase)
        pretarget=phase in ('encoder','stage_write','stage_flush','stage_seek')
        assert not target.exists() if pretarget else target.exists()
        count=target.stat().st_size if target.exists() else None
        faults.append({'phase':phase,'target_exists':target.exists(),'new_target_bytes':count})
        no_stages();prior_ok()
    target.unlink(missing_ok=True)
    # Spy wrapper makes any name access an error; no application unlink is allowed.
    with patch.object(tempfile,'TemporaryFile',lambda *a,**k:TempFault(real_temp(*a,**k),'none')),patch.object(safe.os,'unlink',side_effect=AssertionError('application unlinked temp path')):
        safe.safe_write_json_report(out,target,{'held':'original bytes'})
    assert target.read_bytes()==(json.dumps({'held':'original bytes'},indent=2)+'\n').encode();target.unlink();no_stages();prior_ok()
    substitutions=[]
    # Test code may inspect the name; application writer never does.
    for kind in ('regular','hardlink'):
        target.unlink(missing_ok=True);moved=out/f'moved-original-{kind}.tmp';actor=out/f'foreign-{kind}.json';actor.write_bytes(b'foreign must survive')
        observations={}
        class SwapTemp(TempFault):
            def seek(self,where):
                result=self.handle.seek(where);name=Path(self.handle.name);observations['original_name']=str(name)
                try:name.rename(moved)
                except OSError as error:
                    observations.update(mutation_allowed=False,error_type=type(error).__name__,winerror=error.winerror);return result
                if kind=='regular':name.write_bytes(b'foreign must survive')
                else:os.link(actor,name)
                observations.update(mutation_allowed=True,foreign_path=str(name));return result
        with patch.object(tempfile,'TemporaryFile',lambda *a,**k:SwapTemp(real_temp(*a,**k),'none')):
            safe.safe_write_json_report(out,target,{'held':'original bytes'})
        assert target.read_bytes()==(json.dumps({'held':'original bytes'},indent=2)+'\n').encode()
        if observations.get('mutation_allowed'):
            foreign=Path(observations['foreign_path']);assert foreign.read_bytes()==b'foreign must survive';observations['foreign_preserved']=True
            foreign.unlink()
        if moved.exists():moved.unlink()
        assert actor.read_bytes()==b'foreign must survive';substitutions.append({'kind':kind,**observations});no_stages();prior_ok()
    outside=CASE/'outside.json';outside.write_bytes(b'outside');symlinks={}
    for label,link,destination,is_dir in [('target',target,outside,False),('directory',out/'linked',CASE,True)]:
        try:link.symlink_to(destination,target_is_directory=is_dir)
        except OSError as error:symlinks[label]={'skipped':str(error)};continue
        try:
            with patch.object(tempfile,'TemporaryFile',side_effect=AssertionError('symlink initial target staged')) if label=='target' else patch.object(uuid,'uuid4',wraps=uuid.uuid4):
                try:safe.safe_write_json_report(out,link if not is_dir else link/'outside.json',{})
                except safe.UnsafePathError:symlinks[label]='rejected'
                else:raise AssertionError('symlink allowed')
        finally:link.unlink()
    try:safe.safe_write_json_report(out,outside,{})
    except safe.UnsafePathError:pass
    else:raise AssertionError('outside target allowed')
    assert outside.read_bytes()==b'outside'
    races=[];original_check=safe._check_output_target;original_open=safe._open_output_fd
    for when in ('before_final_recheck','after_final_recheck_before_open'):
        for kind in ('regular','symlink','hardlink'):
            target.unlink(missing_ok=True);actor=out/f'actor-{when}-{kind}.json';actor.write_bytes(b'actor-owned')
            count=0;created=False
            def appear():
                nonlocal created
                if kind=='regular':target.write_bytes(b'actor-owned')
                elif kind=='symlink':target.symlink_to(actor)
                else:os.link(actor,target)
                created=True
            def checked(o,t):
                nonlocal count
                if Path(t)==target:
                    count+=1
                    if when=='before_final_recheck' and count==2:appear()
                return original_check(o,t)
            def opened(o,t,flags):
                if Path(t)==target and when=='after_final_recheck_before_open':appear()
                return original_open(o,t,flags)
            with patch.object(safe,'_check_output_target',checked),patch.object(safe,'_open_output_fd',opened):
                try:safe.safe_write_json_report(out,target,{'new':'must not overwrite actor'})
                except (FileExistsError,safe.UnsafePathError) as error:failure=type(error).__name__
                else:raise AssertionError('race overwrote actor')
            assert created and target.read_bytes()==b'actor-owned' and actor.read_bytes()==b'actor-owned'
            races.append({'when':when,'kind':kind,'failure':failure,'actor_preserved':True})
            no_stages();prior_ok();target.unlink()
    dump(CASE/'checks-result.json',{'byte_golden_cases_new_targets':len(values),'existing_target_no_stage_sentinel':True,'existing_file_id_unchanged':inode,'existing_owner_group_dacl_sha256_unchanged':acl,'existing_write_failure_legacy_partial_bytes':5,'new_target_failure_phases':faults,'no_temp_name_access_or_application_unlink':True,'held_descriptor_substitution_attempts':substitutions,'outside_path_rejected':True,'actual_symlink_results':symlinks,'concurrent_target_races':races,'prior_generation_valid_all_checks':True,'permission_assumption':'New target/stage inherit authorized output parent; no ACL equality for temporary versus concurrently created target claimed.'})

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
    (ROOT/'.tmp/wp034-publication-heldtemp-candidate.diff').write_text(diff);dump(CASE/'source-delta.json',delta)
    spec=importlib.util.spec_from_file_location('campaign',SOURCE/'tools/measure_memory_admission.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    from attackmap.execution.windows import WindowsProcessJob
    from attackmap.analyzer_host import _query_job_peak_memory
    runs=[]
    for number,label in enumerate(('checks',)):
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
