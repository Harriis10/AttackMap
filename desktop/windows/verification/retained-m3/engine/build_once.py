from pathlib import Path
import subprocess,os,json,time,datetime,sys
assert sys.argv[1:] == ['--root-released'], 'Do not build before explicit root release'
base=Path(__file__).resolve().parent;root=base.parents[1];source=base/'source'
python=root/'.pytest_cache/m3-frozen-engine/venv/Scripts/python.exe'
assert not (base/'build-handle.json').exists(), 'One build attempt per owned root; preserve existing handle'
assert (base/'source-checksums.json').is_file(), 'Prepare immutable snapshot first'
env=dict(os.environ,PYTHONPATH=str(source/'src'),PYINSTALLER_CONFIG_DIR=str(base/'ownedcache'),PYTHONDONTWRITEBYTECODE='1')
assertion="import pathlib,attackmap,PyInstaller,sys; assert pathlib.Path(attackmap.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve()); print(sys.version,PyInstaller.__version__,attackmap.__file__)"
check_argv=[str(python),'-c',assertion,str(source)]
check_metadata={'argv':check_argv,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
with (base/'environment.log').open('wb') as stdout_log,(base/'environment.stderr.log').open('wb') as stderr_log:
 check=subprocess.Popen(check_argv,cwd=source,env=env,stdout=stdout_log,stderr=stderr_log)
 check_metadata['pid']=check.pid
 (base/'environment-handle.json').write_text(json.dumps(check_metadata,indent=2),encoding='utf-8')
 check_code=check.wait()
check_metadata.update(exit_code=check_code,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
(base/'environment-handle.json').write_text(json.dumps(check_metadata,indent=2),encoding='utf-8')
assert check_code==0,check_code
argv=[str(python),'-m','PyInstaller',str(source/'installer/attackmap.spec'),'--noconfirm','--distpath',str(base/'dist'),'--workpath',str(base/'build')]
start=time.monotonic()
with (base/'build.log').open('wb') as log:
 process=subprocess.Popen(argv,cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT)
 (base/'build-handle.json').write_text(json.dumps({'pid':process.pid,'argv':argv,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2), encoding="utf-8")
 code=process.wait()
(base/'build-exit.json').write_text(json.dumps({'exit_code':code,'seconds':time.monotonic()-start}), encoding="utf-8")
print(base,code,flush=True)
raise SystemExit(code)
