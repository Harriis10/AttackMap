"""Owned prototype differential checks; no canonical edits."""
import ast,bisect,json,random,sys,time
from pathlib import Path
import pytest
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'source'))
from attackmap import taint_flow
assert Path(taint_flow.__file__).resolve().is_relative_to(HERE/'source')

def old(funcs,line):
    best=None;best_start=-1
    for start,end,node in funcs:
        if start<=line<=end and start>best_start:best,best_start=node,start
    return best

def indexed(funcs):
    starts,nodes=taint_flow._enclosing_segments(funcs)
    def get(line):
        i=bisect.bisect_right(starts,line)-1
        return nodes[i] if i>=0 else None
    return get

def test_empty_and_outside():
    assert indexed([])(-1) is None
    node=ast.Pass();get=indexed([(2,4,node)])
    assert [get(n) for n in (1,2,3,4,5)]==[None,node,node,node,None]

def test_equal_start_first_eligible_and_overlapping():
    a,b,c,d=[ast.Pass() for _ in range(4)]
    funcs=[(2,4,a),(2,10,b),(3,7,c),(6,8,d),(-1,99,ast.Pass()),(30,29,ast.Pass())]
    get=indexed(funcs)
    for line in range(-5,110):assert get(line) is old(funcs,line)
    assert get(2) is a and get(9) is b

def test_deterministic_random_overlapping_nested_every_line():
    rng=random.Random(3533)
    for _ in range(250):
        funcs=[]
        for _ in range(rng.randrange(0,65)):
            start=rng.randrange(-3,80);end=start+rng.randrange(-2,40)
            funcs.append((start,end,ast.Pass()))
        rng.shuffle(funcs);get=indexed(funcs)
        for line in range(-5,125):assert get(line) is old(funcs,line)

def test_async_decorator_nested_ast_every_line():
    source='''@decorate
async def outer():
    @decorate
    def inner():
        return 1
    return inner()

def sibling():
    return 2
'''
    flow=taint_flow._PyFlow(source)
    for line in range(-3,20):assert flow._enclosing(line) is old(flow.funcs,line)
    assert flow._enclosing(1).name=='outer'
    assert flow._enclosing(3).name=='inner'

def test_original_actual_6000_fixture_retains_all_routes():
    from attackmap.scanner import scan_repo
    root=HERE.parent/'wp023-perf-profile-20261021-01/many_matches'
    assert root.is_dir()
    wall=time.perf_counter();cpu=time.process_time();scan=scan_repo(root)
    assert len(scan.routes)==6000 and scan.files_scanned==1
    assert {r.path for r in scan.routes}=={f'/r{i}' for i in range(6000)}
    assert len(scan.external_calls)==6000
    record={'routes':len(scan.routes),'external_calls':len(scan.external_calls),'files_scanned':scan.files_scanned,'wall_seconds':time.perf_counter()-wall,'process_seconds':time.process_time()-cpu,'scope':'owned prototype, concurrent native QA; no qualified speed claim'}
    (HERE.parents[1]/'docs/verification/windows-parity/WP023/python-enclosing-prototype-20261021-01.json').write_text(json.dumps(record,indent=2))
