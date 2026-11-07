"""Prepared QA only: execution requires root's explicit --release flag/package path."""
import argparse,datetime,hashlib,json,os,pathlib,subprocess,sys,threading,time,uuid
BASE=pathlib.Path(__file__).resolve().parent
ROOT=BASE.parents[1]
sys.path.insert(0,str(ROOT/'src'))
import attackmap
from attackmap.run_contract import RunRequest,RunProgress,RunTerminal
assert pathlib.Path(attackmap.__file__).resolve().is_relative_to(ROOT/'src')
def write(name,value):
 (BASE/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
 return h.hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--engine',type=pathlib.Path,required=True);ap.add_argument('--release',action='store_true');ap.add_argument('--server-log',type=pathlib.Path);args=ap.parse_args()
 if not args.release:raise SystemExit('Prepared only: root must explicitly release this single run.')
 engine=args.engine.resolve(strict=True);assert engine.name.lower()=='attackmap.exe'
 assert not (BASE/'launch.json').exists(),'Never retry this owned workflow automatically'
 repo=pathlib.Path('C:/tmp/juice-shop').resolve(strict=True);out=BASE/'output';out.mkdir();run_id=uuid.uuid4().hex
 request={'schema_version':'1.1','kind':'request','run_id':run_id,'repository_id':str(repo),'generation':1,'revision':0,'repository_path':str(repo),'output_path':str(out),'modules':[],'options':{'recall':False,'strict_analyzers':False,'no_suppress':False,'cve':False,'secrets_history':0,'timeout_seconds':600,'provider':{'enable_ai':True,'provider':'openai','endpoint':'http://127.0.0.1:1234/v1','model':'cyberstag-security-26b-a4b-v1','max_calls':8,'timeout_seconds':600,'output_token_limit':32000}}}
 RunRequest.model_validate(request);write('request.json',request)
 env=os.environ.copy();removed=['OPENAI_API_KEY','ANTHROPIC_API_KEY','ANTHROPIC_AUTH_TOKEN','OPENAI_BASE_URL','ANTHROPIC_BASE_URL','OPENAI_ORG_ID','OPENAI_PROJECT_ID','ATTACKMAP_ACTION_CREDENTIAL']
 for key in removed:env.pop(key,None)
 env['LOCALAPPDATA']=str(BASE/'isolated-localappdata')
 p=subprocess.Popen([str(engine),'desktop-worker','--request',str(BASE/'request.json')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
 started=time.monotonic();write('launch.json',{'pid':p.pid,'windows_popen_handle':int(p._handle),'engine':str(engine),'engine_sha256':sha(engine),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'removed_environment_keys':removed,'localappdata_isolated':env['LOCALAPPDATA'],'personal_provider_io':'No provider action or restore; loopback path returns dummy key before credential loading','live_import':attackmap.__file__})
 errors=[];events=[]
 def drain(stream,name,parse):
  total=0
  with (BASE/name).open('wb') as f:
   while line:=stream.readline(1048577):
    total+=len(line)
    if total<=16*1024*1024:f.write(line);f.flush()
    else:errors.append(name+' capture truncated at16MiB')
    if parse:
     try:
      event=json.loads(line.decode('utf-8',errors='strict'));events.append(event)
      if event.get('kind')=='progress':RunProgress.model_validate(event)
      elif event.get('kind')=='terminal':RunTerminal.model_validate(event)
      assert event['run_id']==run_id and event['repository_id']==str(repo) and event['generation']==1
     except Exception as e:errors.append(type(e).__name__+' protocol validation failure')
 threads=[threading.Thread(target=drain,args=(p.stdout,'protocol.jsonl',True)),threading.Thread(target=drain,args=(p.stderr,'stderr.log',False))]
 for t in threads:t.start()
 # Observational threshold only. Never close stdin/cancel/kill/restart at600s.
 noted=False
 while p.poll() is None:
  if time.monotonic()-started>=600 and not noted:
   write('observational-timeout.json',{'pid':p.pid,'popen_handle':int(p._handle),'action':'none; original process remains owned and stdin open','elapsed_seconds':time.monotonic()-started});noted=True
  time.sleep(.25)
 code=p.wait()
 for t in threads:t.join()
 p.stdin.close()
 from attackmap.artifact_publisher import validate_generation
 validation={}
 try:
  manifest=validate_generation(out/run_id);validation={'status':'validated by current core API','manifest':manifest}
 except Exception as e:validation={'status':'failed','error_type':type(e).__name__}
 files=[{'path':str(x.relative_to(out)),'sha256':sha(x),'bytes':x.stat().st_size} for x in out.rglob('*') if x.is_file()]
 terminals=[x for x in events if x.get('kind')=='terminal']
 assert code==0 and len(terminals)==1 and terminals[0]['state']=='completed' and terminals[0]['artifact_readiness']=='ready'
 published=pathlib.Path(terminals[0]['artifact_path']).resolve(strict=True)
 assert published.parent== (out/run_id).resolve(strict=True)
 assert validation['status']=='validated by current core API'
 md=published.parent/'defensive-review-llm.md';meta_path=published.parent/'defensive-review-llm.meta.json'
 prose=md.read_text(encoding='utf-8');meta=json.loads(meta_path.read_text(encoding='utf-8'));reference=meta['reference_validation']
 assert reference['reference_validity'] in {'valid','invalid','missing'}
 assert reference['scope']=='selected_prompt_producer_evidence_ids' and reference['claim_support']=='not_assessed'
 assert reference['source_location_validation'] in {'unvalidated','not_assessed'}
 notice='> Evidence reference check: '+reference['reference_validity']+'. Claim support and source-location validity are not assessed.'
 assert notice in prose
 if reference['invalid_references']:assert 'Unresolved evidence IDs are present' in prose
 if reference['unresolved_source_references']:assert 'Source file/line references are unresolved' in prose
 write('reference-validation-proof.json',{'published_report':str(published),'markdown':str(md),'markdown_sha256':sha(md),'metadata_sha256':sha(meta_path),'reference_validation':reference,'notice_present':True,'claim_support':'not_assessed','scope':'Exact terminal-published generation, not latestglob. This verifies persisted reference semantics/notice, not claim truth.'})
 ai=[md]
 revisions=[x['revision'] for x in events];terminals=[x for x in events if x.get('kind')=='terminal']
 logproof={'status':'unavailable; no server log path supplied; no HTTP capture inferred'}
 if args.server_log:
  with args.server_log.open('rb') as f:f.seek(max(0,args.server_log.stat().st_size-262144));tail=f.read(262144)
  (BASE/'server-log-tail.txt').write_bytes(tail);logproof={'status':'provided existing server log bounded tail; may include other activity, not exclusive HTTP attribution','source':str(args.server_log),'captured_bytes':len(tail),'sha256':sha(BASE/'server-log-tail.txt')}
 write('result.json',{'exit_code':code,'seconds':time.monotonic()-started,'protocol_errors':errors,'revisions_strictly_increasing':all(b>a for a,b in zip(revisions,revisions[1:])),'terminal_events':terminals,'generation_validation':validation,'artifacts':files,'ai_final_reports':[{'path':str(x),'sha256':sha(x),'characters':len(x.read_text(encoding='utf-8'))}for x in ai],'server_log':logproof,'limitations':['Real bundled broker workflow, not native button interaction','No direct HTTP interception or exclusive server attribution unless actual supplied logs prove it','AI report presence is not semantic correctness or runtime vulnerability confirmation']})
 print(str(BASE/'result.json'),flush=True)
if __name__=='__main__':main()
