import ctypes
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RESUME = '--remaining-with-staged-brokers' in sys.argv
OUT = ROOT / ('docs/verification/windows-parity/WP023/controlled-processes-20261021-k-b' if RESUME else 'docs/verification/windows-parity/WP023/controlled-processes-20261021-k')
OUT.mkdir(exist_ok=False)
(OUT / 'runner-source.py').write_bytes(Path(__file__).read_bytes())
(OUT / 'empty-feed').mkdir()
sys.path.insert(0, str(ROOT / 'src'))
from attackmap.execution.windows import WindowsProcessJob

projects = ['ControlledFakeBroker', 'NativeFaultBroker', 'EngineSession.Tests', 'DesktopActionRunner.Tests', 'NativeFaultComposition.Tests']
inputs = {}
for name in projects:
    project = ROOT / 'desktop/windows' / name / (name + '.csproj')
    paths = [project, *project.parent.glob('*.cs')]
    paths.extend((project.parent / item.attrib['Include']).resolve() for item in ET.parse(project).iter('Compile'))
    for path in paths:
        inputs[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()

def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')

save('inputs-before.json', inputs)
environment = dict(os.environ, DOTNET_ROOT=str(ROOT / '.tools/dotnet'),
    DOTNET_CLI_HOME=str(ROOT / '.tools/dotnet-home'), NUGET_PACKAGES=str(ROOT / '.tools/nuget-packages'),
    DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.SetErrorMode.argtypes = [ctypes.c_uint]
kernel.SetErrorMode.restype = ctypes.c_uint
oldmode = kernel.SetErrorMode(0x8003)
records = []

def run(label, command, timeout):
    started = time.monotonic()
    job = WindowsProcessJob()
    process = None
    attached = False
    timed_out = False
    cleanup = False
    try:
        with (OUT / (label + '.stdout.txt')).open('wb') as stdout, (OUT / (label + '.stderr.txt')).open('wb') as stderr:
            process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr, creationflags=4)
            save(label + '-started.json', dict(pid=process.pid, command=command))
            try:
                job.attach_and_resume(process)
                attached = True
            except Exception:
                # The exact owned child is still suspended if assignment failed.
                process.kill()
                process.wait(timeout=20)
                raise
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                job.terminate()
                code = process.wait(timeout=20)
            deadline = time.monotonic() + 15
            while job.active() and time.monotonic() < deadline:
                time.sleep(.05)
            cleanup = job.active() == 0
            if not cleanup:
                job.terminate()
        record = dict(label=label, command=command, pid=process.pid, exit_code=code,
            timeout=timed_out, owned_job_empty_before_close=cleanup, seconds=time.monotonic()-started)
        records.append(record)
        save('commands.json', records)
        print(json.dumps(record), flush=True)
        if code or timed_out or not cleanup:
            raise RuntimeError('Controlled checkpoint command failed: ' + label)
    finally:
        if process is not None and process.poll() is None:
            if attached:
                job.terminate()
            else:
                process.kill()
            process.wait(timeout=20)
        job.close()

failure = None
try:
    dotnet = str(ROOT / '.tools/dotnet/dotnet.exe')
    for name in ([] if RESUME else projects):
        project = ROOT / 'desktop/windows' / name / (name + '.csproj')
        if not (project.parent / 'obj/project.assets.json').is_file():
            run('restore-' + name, [dotnet, 'restore', str(project), '--source', str(OUT / 'empty-feed'), '--ignore-failed-sources', '-p:NuGetAudit=false'], 180)
        run('build-' + name, [dotnet, 'build', str(project), '--no-restore', '-p:NuGetAudit=false', '-p:UseSharedCompilation=false'], 300)
    controlled = ROOT / 'desktop/windows/ControlledFakeBroker/bin/Debug/net8.0/ControlledFakeBroker.exe'
    fault = ROOT / 'desktop/windows/NativeFaultBroker/bin/Debug/net8.0/NativeFaultBroker.exe'
    if RESUME:
        staged = []
        for source in (controlled, fault):
            directory = OUT / 'staged-brokers' / source.stem
            directory.mkdir(parents=True)
            for entry in source.parent.iterdir():
                if entry.is_file():
                    if entry.is_symlink():
                        raise RuntimeError('Unexpected redirected owned broker payload')
                    shutil.copy2(entry, directory / entry.name)
            renamed = directory / 'attackmap.exe'
            shutil.copy2(source, renamed)
            staged.append(renamed)
        controlled, fault = staged
        save('staged-broker-payloads.json', {path.relative_to(OUT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (OUT / 'staged-brokers').rglob('*') if path.is_file()})
    steps = [('DesktopActionRunner.Tests', controlled), ('NativeFaultComposition.Tests', fault)]
    if not RESUME:
        steps.insert(0, ('EngineSession.Tests', controlled))
    for name, broker in steps:
        executable = ROOT / 'desktop/windows' / name / 'bin/Debug/net8.0' / (name + '.exe')
        run(name, [str(executable), str(broker), str(OUT / (name + '-proof.json'))], 300)
except Exception as error:
    failure = repr(error)
    raise
finally:
    kernel.SetErrorMode(oldmode)
    after = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}
    save('inputs-after.json', after)
    save('summary.json', dict(failure=failure, input_count=len(inputs), inputs_unchanged=after == inputs,
        process_local_error_mode='0x8003 inherited by owned children; no machine WER setting changed',
        scope='Controlled fake-broker protocol/process tests only; no real scanner/provider/GUI proof. Outer owned-job cleanup does not substitute for production runner assertions.',
        commands=records))
