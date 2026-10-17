"""Fresh frozen command and tiny synthetic UUID publication proof; no network."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from uuid import UUID
from datetime import datetime, timezone
import jsonschema

root = Path(__file__).resolve().parent
executable = root / "dist/attackmap/attackmap.exe"
environment = dict(os.environ, PYTHONUTF8="0", PYTHONIOENCODING="cp1250")
for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
            "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "ATTACKMAP_ACTION_CREDENTIAL"):
    environment.pop(key, None)

command_index = 0

def command(arguments):
    global command_index
    command_index += 1
    prefix = root / ("command-" + str(command_index).zfill(3))
    stdout_path = prefix.with_suffix(".stdout.log")
    stderr_path = prefix.with_suffix(".stderr.log")
    proof_path = prefix.with_suffix(".process.json")
    metadata = {"arguments": arguments, "executable": str(executable),
                "startedUtc": datetime.now(timezone.utc).isoformat(),
                "stdoutPath": str(stdout_path), "stderrPath": str(stderr_path)}
    with stdout_path.open("wb") as stdout_log, stderr_path.open("wb") as stderr_log:
        process = subprocess.Popen([str(executable), *arguments], stdout=stdout_log, stderr=stderr_log,
                                   env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
        metadata["pid"] = process.pid
        proof_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        (root / "qa-current-process.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        # The parent retains Popen's original OS handle; outer execution yields while this waits.
        code = process.wait()
    metadata.update(exitCode=code, finishedUtc=datetime.now(timezone.utc).isoformat())
    proof_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    assert code == 0, (arguments, code, str(stderr_path))
    return stdout_path.read_bytes().decode("utf-8", errors="strict")

help_text = command(["analyze", "--help"])
assert "--ai-max-calls" in help_text and "--ai-output-tokens" in help_text
assert "--ai-timeout-seconds" in help_text
modules = json.loads(command(["modules", "--json"]))
assert len(modules) == 19
repository = root / "uuid-probe-repository"
repository.mkdir()
(repository / "app.py").write_text("print('synthetic UUID publication probe')\n", encoding="utf-8")
output = root / "uuid-probe-output"
before_scan = datetime.now(timezone.utc)
command(["analyze", str(repository), "--output", str(output), "--format", "json"])
manifest = json.loads((output / "artifact-manifest.json").read_text(encoding="utf-8"))
run_manifest=json.loads((output/"run-manifest.json").read_text(encoding="utf-8"))
timing=run_manifest["scan_timing"]
started=datetime.fromisoformat(timing["started_at"]);finished=datetime.fromisoformat(timing["finished_at"])
assert started.utcoffset().total_seconds()==finished.utcoffset().total_seconds()==0
assert before_scan <= started <= finished <= datetime.now(timezone.utc)
assert timing["clock"]=="engine_utc" and timing["outcome"]=="completed"
assert timing["scope"]=="analysis_pipeline_before_publication"
context_schema=json.loads((root/"source/schemas/diagnostic-context.schema.json").read_text(encoding="utf-8"))
context=run_manifest["diagnostic_context"]
jsonschema.validate(context,context_schema)
assert context["context_version"]=="1.0" and context["outcome"]=="completed"
assert context["coverage"]["accepted_file_count"] is not None or context["coverage"]["status"] in {"partial","unknown"}
assert "other limits remain unknown" in context["resource_events"]["scope_notice"]
assert any(stage["stage_id"]=="publication" and stage["duration_milliseconds"] >= 0 for stage in context["stages"])
generation_id = manifest["generation_id"]
suffix = generation_id.split("-")[-1]
assert len(suffix) == 32 and UUID(hex=suffix).version == 4
proof = {
    "scope": "Frozen final command compatibility; redirected pipes forced cp1250 and PYTHONUTF8=0",
    "executable": str(executable),
    "executableSha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
    "version": command(["--version"]).strip(),
    "moduleCount": len(modules),
    "checks": {"forcedCp1250HelpExitZero": True, "redirectedOutputStrictUtf8": True,
               "wholeScanAiFlagsPresent": True, "moduleDiscovery19": True,
               "generatedRunIdFullUuid4": True},
    "diagnosticContextSchemaValid":True, "diagnosticContext":context,
    "generatedRunId": generation_id, "scanTiming":timing, "scanTimingActualUtcOrderedCompleted":True,
    "limits": ["No packaging, signing, clean-machine or UI acceptance claim", "No AI/model request"]
}
(root / "frozen-command-proof.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
print("PASS final frozen version, 19 modules, UTF-8 redirected help under forced cp1250")
