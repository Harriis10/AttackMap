from pathlib import Path
import ast, bisect, hashlib, json, sys, time
ROOT=Path.cwd()
sys.path.insert(0,str(ROOT/'src'))
from attackmap import taint_flow
from attackmap.scanner import scan_repo
ns={}
prototype=(ROOT/'.tmp/wp023-enclosing-prototype-20261021-01/source/attackmap/taint_flow.py').read_text(encoding='utf-8')
tree=ast.parse(prototype)
fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_enclosing_segments')
import heapq
ns['heapq']=heapq
exec(compile(ast.Module(body=[fn],type_ignores=[]),'prototype','exec'),ns)
root=ROOT/'.tmp/wp023-perf-profile-20261021-01/many_matches'
outputs=[]; records=[]
for mode in ('linear','indexed'):
    if mode=='indexed':
        original_init=taint_flow._PyFlow.__init__
        def init(self,content):
            original_init(self,content)
            self._segments=ns['_enclosing_segments'](self.funcs)
        def enclosing(self,line):
            starts,winners=self._segments
            pos=bisect.bisect_right(starts,line)-1
            return winners[pos] if pos>=0 else None
        taint_flow._PyFlow.__init__=init
        taint_flow._PyFlow._enclosing=enclosing
    start=time.perf_counter(); cpu=time.process_time()
    scan=scan_repo(root)
    data=scan.model_dump(mode='json')
    encoded=json.dumps(data,sort_keys=True,separators=(',',':')).encode()
    records.append(dict(mode=mode,wall_seconds=time.perf_counter()-start,cpu_seconds=time.process_time()-cpu,routes=len(scan.routes),external_calls=len(scan.external_calls),sha256=hashlib.sha256(encoded).hexdigest()))
    outputs.append(data)
assert outputs[0]==outputs[1], 'Full ScanResult differential mismatch'
record=dict(equal_full_scan_result=True,records=records,limit='one real6000-route fixture, no profile; no large stress or broad gate')
(ROOT/'docs/verification/windows-parity/WP023/resume-scanner-20261022/differential-6000.json').write_text(json.dumps(record,indent=2))
print(json.dumps(record,indent=2))
