"""Pure main-thread normalization of hash-bound actual published signals."""
import cProfile
import gc
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import tracemalloc

SOURCE=Path('C:/tmp/attackmap-wp034/10k-20261021-02/source')
INPUT=Path('C:/tmp/attackmap-wp034/1000-profile-20261021-01/reports/scan.json')
CASE=Path('C:/tmp/attackmap-wp034/normalization-micro-20261021-01')

def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def worker():
    from attackmap.models import ScanResult
    from attackmap.signal_provenance import merge_normalized_signals,normalized_view
    assert threading.active_count()==1
    raw=INPUT.read_bytes();input_hash=hashlib.sha256(raw).hexdigest()
    scan=ScanResult.model_validate_json(raw);del raw
    before=scan.model_dump(mode='json');before_hash=digest(before)
    signals=scan.signals
    assert len(signals)==6000
    results=[]
    for name,call in [('merge_normalized_signals',lambda:merge_normalized_signals(signals)),
                      ('normalized_view_stored_branch',lambda:normalized_view(scan,signals))]:
        assert threading.active_count()==1
        gc.collect();tracemalloc.start(12);initial=tracemalloc.take_snapshot()
        profile=cProfile.Profile();cpu=time.process_time();start=time.monotonic()
        output=profile.runcall(call)
        seconds=time.monotonic()-start;cpu_seconds=time.process_time()-cpu
        current,peak=tracemalloc.get_traced_memory();after=tracemalloc.take_snapshot()
        profile.dump_stats(str(CASE/(name+'.pstats')))
        after.dump(str(CASE/(name+'.allocations')))
        allocation=[{'traceback':str(item.traceback),'size_diff':item.size_diff,'count_diff':item.count_diff} for item in after.compare_to(initial,'lineno')[:20]]
        tracemalloc.stop()
        output_dump=[item.model_dump(mode='json') for item in output]
        output_hash=digest(output_dump)
        assert digest(scan.model_dump(mode='json'))==before_hash
        # Actual data mutation probes: output-owned dictionaries/origins must not alias input.
        output[0].properties['__wp034_output_probe__']='yes'
        if output[0].origins:output[0].origins[0].properties['__wp034_origin_probe__']='yes'
        assert digest(scan.model_dump(mode='json'))==before_hash
        results.append({'function':name,'wall_seconds':seconds,'cpu_seconds':cpu_seconds,'output_signals':len(output),'output_sha256':output_hash,
                        'input_unchanged':True,'output_mutation_isolated':True,'tracemalloc_current_bytes':current,'tracemalloc_peak_bytes':peak,'allocation_diff':allocation,'threads_before_after':1})
        del output,output_dump,initial,after,profile;gc.collect()
    assert INPUT.is_file() and hashlib.sha256(INPUT.read_bytes()).hexdigest()==input_hash
    assert threading.active_count()==1
    write(CASE/'worker-result.json',{'diagnostic_only':True,'input':str(INPUT),'input_sha256':input_hash,'input_bytes':INPUT.stat().st_size,
          'validated_input_sha256':before_hash,'normalized_signal_count':len(signals),'origin_count':sum(len(s.origins) for s in signals),
          'conflict_count':sum(len(s.conflicts) for s in signals),'cases':results,'limitation':'Stored normalized branch only; tracemalloc+cProfile overhead, no standalone performance/C35 claim. New synthesis/conflict coverage requires focused tests before any patch.'})

def main():
    if len(sys.argv)>1:worker();return
    assert os.environ.get('PYTHONDONTWRITEBYTECODE')=='1'
    CASE.mkdir()
    source_manifest={name:hashlib.sha256((SOURCE/'src/attackmap'/name).read_bytes()).hexdigest() for name in ['models.py','signal_provenance.py']}
    write(CASE/'source-input-identity.json',{'source':str(SOURCE),'files':source_manifest,'input_sha256':hashlib.sha256(INPUT.read_bytes()).hexdigest()})
    spec=importlib.util.spec_from_file_location('campaign',SOURCE/'tools/measure_memory_admission.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    from attackmap.execution.windows import WindowsProcessJob
    from attackmap.analyzer_host import _query_job_peak_memory
    job=WindowsProcessJob();handles={};peak=0;abort=None;started=time.monotonic()
    command=[sys.executable,str(Path(__file__).resolve()),'--worker']
    with (CASE/'stdout.log').open('x') as out,(CASE/'stderr.log').open('x') as err:
        process=subprocess.Popen(command,cwd=SOURCE,stdout=out,stderr=err,creationflags=4)
        try:
            job.attach_and_resume(process)
            while process.poll() is None:
                row=module.sample_owned_tree(job,handles);peak=max(peak,_query_job_peak_memory(job.handle))
                memory=max(peak,row['private_bytes'],row['working_set_bytes'])>=3*1024**3
                if memory or time.monotonic()-started>1200:abort='memory' if memory else 'timeout';job.terminate();break
                time.sleep(.05)
            code=process.wait(timeout=15);peak=max(peak,_query_job_peak_memory(job.handle))
        finally:
            if process.poll() is None:job.terminate();process.wait(timeout=15)
            end=time.monotonic()+15
            while job.active() and time.monotonic()<end:time.sleep(.05)
            cleanup=job.active()==0
            if not cleanup:job.terminate()
            for handle in handles.values():job._kernel.CloseHandle(handle)
            job.close()
    stable=all(hashlib.sha256((SOURCE/'src/attackmap'/name).read_bytes()).hexdigest()==value for name,value in source_manifest.items())
    write(CASE/'campaign-result.json',{'diagnostic_only':True,'exit_code':code,'abort':abort,'cleanup_verified':cleanup,'peak_owned_job_commit_bytes':peak,'source_stable':stable,'command':command,'wall_seconds':time.monotonic()-started})
    print(CASE)
    return code

if __name__=='__main__':raise SystemExit(main())
