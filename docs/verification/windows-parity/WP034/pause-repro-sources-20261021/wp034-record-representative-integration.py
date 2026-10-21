import ast,hashlib,json,subprocess
from pathlib import Path
root=Path('C:/Projects/INPROGRESS/AttackMap');source=root/'src/attackmap/signal_provenance.py';test=root/'tests/test_signal_representative_copy.py';owned=Path('C:/tmp/attackmap-wp034/normalization-candidate-20261021-01/source/src/attackmap/signal_provenance.py')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
current=ast.parse(source.read_text(encoding='utf-8'));candidate=ast.parse(owned.read_text(encoding='utf-8'))
helper=lambda tree:next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_copy_merge_representative')
assert ast.dump(helper(current))==ast.dump(helper(candidate))
head_text=subprocess.run(['git','show','HEAD:src/attackmap/signal_provenance.py'],cwd=root,capture_output=True,check=True).stdout.decode('utf-8')
current.body.remove(helper(current));changed=0
class Restore(ast.NodeTransformer):
    def visit_Call(self,node):
        global changed
        if isinstance(node.func,ast.Name) and node.func.id=='_copy_merge_representative':
            changed+=1;return ast.parse('ordered[0].model_copy(deep=True)',mode='eval').body
        return self.generic_visit(node)
Restore().visit(current);assert changed==1 and ast.dump(current)==ast.dump(ast.parse(head_text))
diff=subprocess.run(['git','diff','--','src/attackmap/signal_provenance.py'],cwd=root,capture_output=True,check=True).stdout
delta=root/'.tmp/wp034-representative-canonical.diff';delta.write_bytes(diff)
command1="$env:PYTHONPATH=Join-Path $PWD 'src'; $env:PYTHONDONTWRITEBYTECODE='1'; & ./.venv/Scripts/python.exe -m pytest tests/test_signal_representative_copy.py tests/test_merge_signal_provenance.py tests/test_source_classification.py tests/test_merge.py -q --basetemp .tmp/wp034-representative-tests-20261021-01"
command2="$env:PYTHONPATH=Join-Path $PWD 'src'; $env:PYTHONDONTWRITEBYTECODE='1'; & ./.venv/Scripts/python.exe -m pytest tests/test_signal_representative_copy.py -q -o cache_dir=.tmp/wp034-representative-pytest-cache --basetemp .tmp/wp034-representative-tests-20261021-02 --junitxml .tmp/wp034-representative-tests-final.xml"
payload={'status':'FOCUSED_REPRESENTATIVE_COPY_CANONICAL_CHECKPOINT_PASS_NOT_C35','source_frozen':True,'files':{str(p):sha(p) for p in (source,test,delta,root/'.tmp/wp034-representative-tests-final.xml')},
 'delta':'16-line reviewed guarded helper plus one representative call replacement; all other module AST identical to HEAD. No sorting/origin validation/model construction/scoring/budget/coverage changes. report.py/safe_fs untouched by this slice.',
 'reviewed_helper_ast_equals_owned_candidate':True,'other_module_ast_identical_to_head':True,
 'checks':[{'session':69307,'command':command1,'exit_code':1,'passed':49,'failed':6,'details':'All32 existing merge/provenance/classification checks passed, plus16 new matrix cases and sibling case. Six new fallback test fixtures omitted required Signal.file, failing at construction before helper. Only test factory fixed, source unchanged. Global pytest cache ACL warnings; original output retained in tool result, no separate file log.'},
 {'session':50804,'command':command2,'exit_code':0,'passed':23,'seconds':3.49,'details':'All new cases PASS:16 matrix cases internally compare all8 JSON exclusion combinations and recursive fields_sets/IDs/order/origins/conflicts plus bidirectional mutation; sibling-origin isolation;6 direct guarded fallback cases with deep=True observation. One task-cache ACL write warning, not a failed test.'}],
 'fallback_cases':['Signal subclass with extra/private/nested state','Exact Signal with injected extra state','Exact Signal with injected private state','Unexpected mutable __dict__ field','Properties dict subclass','Mutable properties value'],
 'prior_measurement':'Owned normalization-copy-candidate-2026-10-21.json proves actual6000-signal equivalence and CPU diagnostic; not rerun here and not a full-pipeline performance/C35 claim.',
 'limits':['55 distinct focused checks passed across two runs:32 existing in first run,23 new after fixture correction. Do not present the initial combined run as all-pass.',
 'Only canonical signal_provenance.py and new focused test file changed. Immutable source/fixture/campaign evidence untouched. No full suite, pipeline scan, GUI, provider, publication patch or larger campaign.']}
out=root/'docs/verification/windows-parity/WP034/representative-copy-integration-2026-10-21.json';out.write_text(json.dumps(payload,indent=2)+'\n');print(out)
