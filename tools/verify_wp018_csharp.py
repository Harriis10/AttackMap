"""Launch the real headless C# fleet consumer in an owned Windows Job."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

from verify_wp018_native import ROOT, WindowsJob, census, descendants, require, save, inherited_error_mode

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--engine", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
require(not args.output.exists(), "Use fresh evidence")
args.output.mkdir(parents=True)
environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1",
                   DOTNET_ROOT=str(ROOT / ".tools/dotnet"))
argv = [str(ROOT / ".tools/dotnet/dotnet.exe"),
        str(ROOT / "desktop/windows/FleetWorkspace.Tests/bin/Release/net8.0/FleetWorkspace.Tests.dll"),
        "--real-engine", str(args.engine.resolve()), "--output", str(args.output.resolve() / "consumer")]
job = WindowsJob()
process = None
observed = {}
try:
    with (args.output / "stdout.log").open("wb") as stdout, (args.output / "stderr.log").open("wb") as stderr:
        with inherited_error_mode():
            process = subprocess.Popen(argv, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr,
                                       stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW | 4)
        save(args.output / "started.json", dict(pid=process.pid, argv=argv, suspended_before_job_assignment=True))
        job.assign(process)
        job.resume(process)
        deadline = time.monotonic() + 230
        while process.poll() is None and time.monotonic() < deadline:
            for row in descendants(census(), process.pid):
                observed[row["pid"]] = row
            time.sleep(0.1)
        require(process.poll() is not None, "Actual CSharp consumer timed out")
        limit = time.monotonic() + 5
        while job.active() and time.monotonic() < limit:
            time.sleep(0.05)
        natural = job.active()
        post = census()
        save(args.output / "process.json", dict(exit_code=process.returncode, natural_job_active=natural,
             observed=list(observed.values()), post_exit_census=post))
        require(process.returncode == 0 and natural == 0, "Consumer failed or descendants survived")
        require(len(observed) >= 3 and not (observed.keys() & {row["pid"] for row in post}), "OS process proof incomplete")
        print("PASS actual CSharp consumer and natural owned Job0")
finally:
    job.cleanup()
    job.close()
    if process is not None:
        process.wait(timeout=10)
