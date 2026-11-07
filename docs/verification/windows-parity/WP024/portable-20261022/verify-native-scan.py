import ctypes
import json
import os
from pathlib import Path
import subprocess
import time

root=Path.cwd()
app=root/'.tmp/portable extracted 20261022 c/AttackMap-Windows'
proof=root/'docs/verification/windows-parity/WP024/portable-20261022/native-scan'
proof.mkdir(exist_ok=False)
env=dict(os.environ)
for key in list(env):
    if key.upper().startswith(('PYTHON','VIRTUAL_ENV','CONDA','OPENAI_','ANTHROPIC_')):
        env.pop(key)
env['PATH']=env['SYSTEMROOT']+'\\System32;'+env['SYSTEMROOT']
arguments=[str(app/'AttackMap.NativeSpike.exe'),'--parity-smoke',
           str(root/'desktop/windows/verification/retained-m3/live/output/da6b4d5767534bcd859d83b68fab8a7c/attackmap-report.json'),
           str(proof),'--engine',str(app/'engine/attackmap.exe'),'--native-scan','--repository','C:\\tmp\\juice-shop']
old=ctypes.windll.kernel32.SetErrorMode(0x8003)
started=time.monotonic()
try:
    process=subprocess.Popen(arguments,cwd=app,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    (proof/'process-started.json').write_text(json.dumps({'pid':process.pid,'arguments':arguments,'PATH':env['PATH']},indent=2)+'\n')
    try:
        stdout,stderr=process.communicate(timeout=900)
    except subprocess.TimeoutExpired:
        subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True)
        stdout,stderr=process.communicate(timeout=15)
        raise
    finally:
        if process.poll() is None:
            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True)
            process.wait(timeout=15)
    (proof/'stdout.log').write_bytes(stdout)
    (proof/'stderr.log').write_bytes(stderr)
    summary={'exit_code':process.returncode,'seconds':time.monotonic()-started,'pid':process.pid,'exited':True}
    (proof/'process.json').write_text(json.dumps(summary,indent=2)+'\n')
    result=json.loads((proof/'parity-smoke.json').read_text())
    assert process.returncode==0 and result['failure'] is None
    assert result['result']['passed'] and result['result']['scanCompleted']
    assert result['result']['progressState']=='completed' and result['result']['capabilitiesChecked']
    print(json.dumps({'passed':True,**summary,'run':result['result']['run'],'report':result['result']['report'],
                      'reportHash':result['result']['reportHash'],'ai_requests':False,'python_on_PATH':False},indent=2))
finally:
    ctypes.windll.kernel32.SetErrorMode(old)
