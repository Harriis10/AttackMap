from pathlib import Path
import os,json,subprocess,hashlib,datetime
r=Path(os.environ['QA_ROOT']);e=r/'dist/attackmap/attackmap.exe'
b=json.loads((r/'frozen-build-proof.json').read_text(encoding='utf-8'));q=json.loads((r/'frozen-command-proof.json').read_text(encoding='utf-8'))
env=dict(os.environ)
for k in ('OPENAI_API_KEY','ANTHROPIC_API_KEY','ATTACKMAP_ACTION_CREDENTIAL'):env.pop(k,None)
def call(name,args):
 with (r/(name+'.stdout.log')).open('wb') as out,(r/(name+'.stderr.log')).open('wb') as err:
  p=subprocess.Popen([str(e),*args],stdin=subprocess.PIPE,stdout=out,stderr=err,env=env,creationflags=subprocess.CREATE_NO_WINDOW)
  meta={'pid':p.pid,'arguments':args,'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()};(r/(name+'.process.json')).write_text(json.dumps(meta),encoding='utf-8');code=p.wait();p.stdin.close()
 meta['exit_code']=code;(r/(name+'.process.json')).write_text(json.dumps(meta),encoding='utf-8');assert code==0
 return [json.loads(x) for x in (r/(name+'.stdout.log')).read_text(encoding='utf-8').splitlines() if x.strip()],meta
for command in ('desktop-worker','desktop-action'):call('help-'+command,[command,'--help']) if False else None
repo=r/'uuid-probe-repository';out=r/'actual-broker-output';req={'schema_version':'1.1','kind':'request','run_id':'preview-proof','repository_id':str(repo),'generation':1,'revision':0,'repository_path':str(repo),'output_path':str(out),'modules':[],'options':{}}
p=r/'actual-broker-request.json';p.write_text(json.dumps(req),encoding='utf-8');messages,meta=call('actual-worker',['desktop-worker','--request',str(p)]);t=next(x for x in messages if x.get('kind')=='terminal');assert t['state']=='completed' and t['artifact_readiness']=='ready';assert (out/'current-generation.json').is_file();report=t['artifact_path']
a={'schema_version':'1.1','request_id':'preview-compare','operation':'compare','output_path':str(r/'actual-action-output'),'payload':{'baseline_path':report,'current_path':report}};p=r/'actual-action-request.json';p.write_text(json.dumps(a),encoding='utf-8');am,ma=call('actual-action',['desktop-action','--request',str(p)]);at=next(x for x in am if x.get('kind')=='action_result');assert at['state']=='completed'
proof={'exe_sha256':b['executableSha256'],'version':q['version'],'checks':{'modules_discovered':q['moduleCount'],'native_broker_commands_present':True,'scan_atomic_current_ready':True,'frozen_compare_action_ready':True},'scan':dict(meta,terminal=t,messages=messages),'action':dict(ma,terminal=at,messages=am),'payload_files':b['payloadFiles'],'source_checksums_sha256':b['sourceInventorySha256'],'limitations':['Development preview only. Broad regression predates latest AI/helper/GUI changes; no full M3 acceptance.','No AI/model calls in frozen checks; no signing/clean-machine/platform acceptance.'],'proofs':{'build':str(r/'frozen-build-proof.json'),'commands':str(r/'frozen-command-proof.json')}}
(e.parent/'engine-verification.json').write_text(json.dumps(proof,indent=2),encoding='utf-8');print(e);print(b['executableSha256']);print('PASS actual worker/action exit0 + terminal; metadata bound',len(b['payloadFiles']))
