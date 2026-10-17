from pathlib import Path
import ast,json,hashlib
base=Path(__file__).resolve().parent;root=base.parents[1];source=base/'source'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
inventory=json.loads((base/'source-checksums.json').read_text(encoding="utf-8"))
snapshot_changed=[name for name,h in inventory.items() if not (source/name).exists() or digest(source/name)!=h]
live_changed=[name for name,h in inventory.items() if not (root/name).exists() or digest(root/name)!=h]
assert not snapshot_changed,snapshot_changed
rows=[]
def walk(value):
 if isinstance(value,(tuple,list)):
  if len(value)>2 and isinstance(value[0],str) and (value[0]=='attackmap' or value[0].startswith('attackmap.')) and isinstance(value[1],str) and value[1].endswith('.py'):rows.append(value[:3])
  for item in value:walk(item)
walk(ast.literal_eval((base/'build/attackmap/Analysis-00.toc').read_text(encoding="utf-8")))
required={'attackmap.diagnostics','attackmap.models','attackmap.pipeline','attackmap.artifact_publisher','attackmap.scan_service','attackmap.desktop_worker','attackmap.cli'}
assert required <= {row[0] for row in rows}
outside=[row for row in rows if not Path(row[1]).resolve().is_relative_to((source/'src/attackmap').resolve())]
assert not outside,outside
exit_data=json.loads((base/'build-exit.json').read_text(encoding="utf-8"));assert exit_data['exit_code']==0
payload=[{'path':str(p.relative_to(base/'dist/attackmap')).replace('\\','/'),'size_bytes':p.stat().st_size,'sha256':digest(p)} for p in sorted((base/'dist/attackmap').rglob('*')) if p.is_file()]
proof={'scope':'Windows beta citation/reopen integration immutable snapshot frozen engine, not final package/platform acceptance','buildExitCode':0,'buildSeconds':exit_data['seconds'],'sourceFiles':len(inventory),'boundSnapshotInputsUnchanged':True,'liveSourceDifferencesAtVerification':live_changed,'coreModuleCount':len(rows),'coreOrigins':rows,'coreOutsideSnapshot':outside,'payloadFiles':payload,'executableSha256':digest(base/'dist/attackmap/attackmap.exe'),'sourceInventorySha256':digest(base/'source-checksums.json'),'buildLogSha256':digest(base/'build.log'),'metadataWriter':'No engine-verification.json; sole metadata/package owner root/atomic'}
(base/'frozen-build-proof.json').write_text(json.dumps(proof,indent=2), encoding="utf-8")
assert not live_changed,live_changed
print('PASS bound snapshot/live hashes and every core TOC snapshot origin',len(rows))
