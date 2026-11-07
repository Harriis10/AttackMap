from pathlib import Path
import shutil,json,hashlib,sys,datetime
base=Path(__file__).resolve().parent;root=base.parents[1];source=base/'source'
assert sys.argv[1:]==['--root-released'],'Wait for root stable-source release'
assert not source.exists(),'Never overwrite an immutable snapshot'
ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.egg-info')
shutil.copytree(root/'src/attackmap',source/'src/attackmap',ignore=ignore)
shutil.copytree(root/'src/attackmap.egg-info',source/'src/attackmap.egg-info')
(source/'installer').mkdir()
for name in ('entry.py','attackmap.spec'):shutil.copy2(root/'installer'/name,source/'installer'/name)
shutil.copytree(root/'schemas',source/'schemas')
shutil.copytree(root/'fixtures/diagnostics',source/'fixtures/diagnostics')
shutil.copy2(root/'pyproject.toml',source/'pyproject.toml')
inventory={str(p.relative_to(source)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source.rglob('*')) if p.is_file()}
assert 'src/attackmap/diagnostics.py' in inventory
assert 'schemas/diagnostic-context.schema.json' in inventory
(base/'source-checksums.json').write_text(json.dumps(inventory,indent=2), encoding="utf-8")
(base/'snapshot-proof.json').write_text(json.dumps({'scope':'Current stable dirty workspace, not clean checkout','preparedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':len(inventory),'schemaFixtureInputs':'Copied for QA/provenance; installer spec determines actual runtime bundled assets'},indent=2), encoding="utf-8")
print(base,len(inventory))
