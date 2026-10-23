"""Preflight, or explicitly run, the full native shell's five local AI journeys.

No process or HTTP request starts without --run. A manifest pin is mandatory for
--run; package byte consistency is separate from WP024 same-source acceptance.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time
import urllib.request
import uuid

try:
    from . import verify_wp017_live as gate
    from . import generate_release_lock as release_lock_tool
except ImportError:
    import verify_wp017_live as gate
    import generate_release_lock as release_lock_tool

REPOSITORY = Path(r"C:\tmp\juice-shop")
APP_NAME = "AttackMap.NativeSpike.exe"
REQUIRED_FILES = {
    APP_NAME, "AttackMap.NativeSpike.dll", "AttackMap.NativeSpike.deps.json",
    "AttackMap.NativeSpike.runtimeconfig.json", "coreclr.dll", "hostfxr.dll",
    "hostpolicy.dll", "Microsoft.UI.Xaml.dll", "engine/attackmap.exe",
    "engine/_internal/python313.dll", "engine/_internal/base_library.zip",
    "provenance/native-build.json", "provenance/engine-build.json", "provenance/pair-runtime.json",
}
ACCEPTANCE = dict(accepted_wp017=False, accepted_manual_ui=False,
                  accepted_same_source=False, accepted_release=False, accepted_clean_host=False)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(path):
    return {"path": str(path), "sha256": sha(path)}


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON property: " + key)
        result[key] = value
    return result


def read(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object)
    require(isinstance(value, dict), "JSON object required: " + str(path))
    return value


def safe_component(part):
    require(part not in ("", ".", "..") and not part.endswith((" ", ".")), "Unsafe path component")
    require(not any(ord(c) < 32 or c in '<>:"|?*' for c in part), "Unsafe path character")
    require(not re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", part.split(".")[0], re.I), "Reserved Windows path")


def no_link(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
            "Links/reparse points rejected: " + str(path))
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "Special file rejected: " + str(path))


def local_path(value):
    value = str(value)
    require(not value.startswith(("\\\\", "//")), "UNC/device/network paths rejected")
    path = Path(value)
    require(path.is_absolute(), "Absolute local path required: " + value)
    for part in value.replace("\\", "/").split("/"):
        if part and part != path.anchor.replace("\\", "/").strip("/"):
            safe_component(part)
    if os.name == "nt":
        require(ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == 3, "Fixed local drive required")
    for entry in (path, *path.parents):
        if entry.exists() or entry.is_symlink():
            no_link(entry)
    return path


def relative_name(name):
    require(isinstance(name, str) and "\\" not in name and not name.startswith("/"), "Unsafe manifest path")
    for part in name.split("/"):
        safe_component(part)
    require(PurePosixPath(name).as_posix() == name, "Noncanonical manifest path")
    return name


def production_inventory(manifest, lock_path):
    require(manifest.get("profile") == "RequiredBundled" and manifest.get("architecture") == "win-x64",
            "RequiredBundled win-x64 package required")
    require(bool(re.fullmatch(r"dev-[0-9]{14}-[a-f0-9]{8}", str(manifest.get("package_id", "")))),
            "Invalid production package ID")
    runtime, engine = manifest.get("native_runtime", {}), manifest.get("engine", {})
    require(runtime.get("dotnet_self_contained") is True and runtime.get("windows_app_sdk_self_contained") is True
            and engine.get("bundled") is True and engine.get("runtime_kind") == "Frozen"
            and engine.get("executable") == "app/engine/attackmap.exe", "Complete bundled native/engine runtime required")
    require(lock_path is not None, "RequiredBundled preflight requires --release-lock")
    lock_path = local_path(lock_path)
    lock_record = record(lock_path)
    require(lock_record["sha256"] == engine.get("release_lock_sha256"), "Package release-lock hash mismatch")
    lock = read(lock_path)
    current = release_lock_tool.release_inputs(Path(__file__).resolve().parents[1])
    for key in ("source_checksums_sha256", "release_inputs_sha256", "analyzer_requirements_sha256"):
        require(bool(re.fullmatch(r"[a-f0-9]{64}", str(engine.get(key, ""))))
                and current[key] == lock.get(key) == engine[key], "Stale package/source lock: " + key)
    for tool in ("python", "pyinstaller", "dotnet_sdk"):
        version = lock.get("toolchain", {}).get(tool, {}).get("version")
        require(isinstance(version, str) and version not in ("", "unknown"), "Unknown release toolchain: " + tool)
    require(record(lock_path) == lock_record, "Release lock changed during validation")
    expected = {}
    for key, prefix in (("files", "app/"), ("deployment_files", "")):
        rows = manifest.get(key)
        require(isinstance(rows, list) and bool(rows), "Missing production " + key)
        for row in rows:
            require(isinstance(row, dict), "Malformed production inventory row")
            name = prefix + relative_name(row.get("path"))
            require(name not in expected, "Duplicate production inventory entry")
            expected[name] = {field: row.get(field) for field in ("size_bytes", "sha256")}
    runtime_files = {"app/" + name for name in REQUIRED_FILES if not name.startswith("provenance/")}
    require({name.casefold() for name in runtime_files} <= {name.casefold() for name in expected},
            "Incomplete production payload inventory")
    require({row["path"] for row in manifest["deployment_files"]} == {"Install-AttackMap.ps1", "Install-AttackMap.cmd"},
            "Unexpected production deployment inventory")
    return expected, lock_record


def package_identity(app, pin=None, release_lock=None):
    app = local_path(app)
    require(app.name == APP_NAME and app.is_file(), "--app must select the full " + APP_NAME)
    folder = app.parent
    portable = folder / "portable-manifest.json"
    production = folder.parent / "package-manifest.json"
    require(not (portable.exists() and production.exists()), "Ambiguous package manifests")
    is_production = not portable.exists() and production.exists() and folder.name == "app"
    manifest_path = production if is_production else portable
    if is_production:
        folder = folder.parent
    local_path(manifest_path)
    fingerprint = sha(manifest_path)
    if pin is not None:
        require(bool(re.fullmatch(r"[a-f0-9]{64}", pin)), "Invalid --manifest-sha256")
        require(fingerprint == pin, "Package manifest differs from the reviewed pin")
    manifest = read(manifest_path)
    require(manifest.get("schema_version") == 1, "Unsupported package manifest")
    lock_record = None
    if is_production:
        expected, lock_record = production_inventory(manifest, release_lock)
    else:
        require(manifest.get("architecture") == "x64", "Unsupported portable manifest")
        runtime = manifest.get("runtime", {})
        require(runtime.get("dotnet_self_contained") is True and runtime.get("python_embedded") is True
                and runtime.get("external_python_required") is False and runtime.get("engine") == "engine/attackmap.exe",
                "Complete bundled native/engine runtime required")
        expected = manifest.get("files")
        require(isinstance(expected, dict) and {name.casefold() for name in REQUIRED_FILES} <= {name.casefold() for name in expected},
                "Incomplete portable payload inventory")
    folded = set()
    directories = set()
    for name, wanted in expected.items():
        relative_name(name)
        require(name != manifest_path.name and name.casefold() not in folded, "Duplicate/self-referential manifest name")
        folded.add(name.casefold())
        require(isinstance(wanted, dict) and type(wanted.get("size_bytes")) is int and wanted["size_bytes"] >= 0
                and bool(re.fullmatch(r"[a-f0-9]{64}", str(wanted.get("sha256", "")))), "Malformed payload fingerprint")
        directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != ".")
    actual = set()
    # os.walk never follows links; inspect each entry before descending.
    for root, dirs, files in os.walk(folder, followlinks=False):
        for name in dirs + files:
            path = Path(root) / name
            no_link(path)
            relative = path.relative_to(folder).as_posix()
            if path.is_dir():
                require(relative in directories, "Unexpected portable directory: " + relative)
            elif relative != manifest_path.name:
                require(relative in expected, "Unexpected portable file: " + relative)
                require(path.stat().st_nlink == 1, "Hard-linked payload rejected: " + relative)
                wanted = expected[relative]
                require(path.stat().st_size == wanted["size_bytes"] and sha(path) == wanted["sha256"], "Payload tamper: " + relative)
                actual.add(relative)
    require(actual == expected.keys(), "Missing portable payload files")
    require(sha(manifest_path) == fingerprint, "Portable manifest changed during inventory")
    return dict(passed=True, scope="Complete pinned package byte consistency; source lock consistency when RequiredBundled; acceptance separate",
                package_id=manifest["package_id"] if is_production else "sha256:" + fingerprint,
                manifest=record(manifest_path), files_verified=len(actual), release_lock=lock_record,
                kind=manifest.get("kind"), native_build=manifest.get("native_build"), engine_build=manifest.get("engine_build"),
                identities={name: record(app.parent / name) for name in (APP_NAME, "AttackMap.NativeSpike.dll", "engine/attackmap.exe")},
                **ACCEPTANCE)


def timeout_budget(provider=900, scan=1200, process=1500):
    require(type(provider) is int and 1 <= provider <= 7200, "Provider timeout must be 1..7200 whole seconds")
    require(type(scan) is int and 1 <= scan <= 86400, "Scan timeout must be 1..86400 whole seconds")
    require(type(process) is int and 1 <= process <= 10800, "Process timeout must be 1..10800 whole seconds")
    require(provider <= 3600 or gate.ENDPOINT == "http://127.0.0.1:1234/v1",
            "Extended AI allowance requires the fixed loopback endpoint")
    require(provider <= scan < process, "Timeouts require provider <= scan < process")
    return dict(provider_timeout_seconds=provider, scan_timeout_seconds=scan, harness_timeout_seconds=process)


def plan_timeouts(plan):
    return timeout_budget(plan["provider_budget_seconds"], plan["native_scan_timeout_seconds"], plan["process_timeout_seconds"])


def preflight(app, seed, output, mode="all", manifest_sha256=None, release_lock=None,
              *, provider_timeout=900, scan_timeout=1200, process_timeout=1500):
    timeouts = timeout_budget(provider_timeout, scan_timeout, process_timeout)
    app, seed, output = local_path(app), local_path(seed), local_path(output)
    repository = local_path(REPOSITORY)
    require(seed.is_file() and isinstance(read(seed).get("scan"), dict), "Seed must be an existing report JSON with scan")
    require(repository.is_dir(), "Target repository unavailable: " + str(repository))
    require(not output.exists() and output.parent.is_dir(), "Use a new output directory under an existing parent; stale proof roots rejected")
    package = package_identity(app, manifest_sha256, release_lock)
    for source in (Path(package["manifest"]["path"]).parent, seed.parent, repository):
        require(not output.is_relative_to(source) and not source.is_relative_to(output), "Output must be separate from package, seed and repository")
    require(mode == "all" or mode in gate.MODES, "Unsupported AI mode")
    return dict(passed=True, stage="preflight-only", provider_requests_started=0, processes_started=0,
                app=str(app), engine=str(app.parent / "engine/attackmap.exe"), seed=record(seed), output=str(output),
                repository=str(repository), modes=list(gate.MODES) if mode == "all" else [mode],
                endpoint=gate.ENDPOINT, model=gate.MODEL, provider_budget_seconds=timeouts["provider_timeout_seconds"], max_calls=8,
                output_token_limit=32000, native_scan_timeout_seconds=timeouts["scan_timeout_seconds"],
                process_timeout_seconds=timeouts["harness_timeout_seconds"],
                package=package, **ACCEPTANCE)


def child_environment(folder, ambient=None):
    # An allowlist drops Python, remote-provider, endpoint, proxy and QA overrides.
    ambient = {key.upper(): value for key, value in (os.environ if ambient is None else ambient).items()}
    keys = {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "COMPUTERNAME", "USERNAME", "USERDOMAIN",
            "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROGRAMFILES", "PROGRAMFILES(X86)",
            "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "PROGRAMDATA"}
    result = {key: value for key, value in ambient.items() if key in keys}
    system = local_path(result.get("SYSTEMROOT", ""))
    require(system.is_dir() and (system / "System32").is_dir(), "Windows system directory unavailable")
    result["PATH"] = str(system / "System32") + ";" + str(system)
    for key, name in (("APPDATA", "profile/AppData/Roaming"), ("LOCALAPPDATA", "profile/AppData/Local"), ("USERPROFILE", "profile"), ("TEMP", "temp"), ("TMP", "temp")):
        target = folder / name
        target.mkdir(parents=True, exist_ok=True)
        result[key] = str(target)
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redirect rejected; only the fixed loopback endpoint is authorized")


def check_local_model(folder):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    url = gate.ENDPOINT + "/models"
    with opener.open(urllib.request.Request(url), timeout=15) as response:
        require(response.status == 200 and response.geturl() == url, "Unexpected model-list response")
        raw = response.read(2 * 1024 * 1024 + 1)
    require(len(raw) <= 2 * 1024 * 1024, "Model-list response too large")
    (folder / "models-response.json").write_bytes(raw)
    body = json.loads(raw)
    require(gate.MODEL in {row.get("id") for row in body.get("data", []) if isinstance(row, dict)}, "Exact local model is not listed")
    save(folder / "connection.json", dict(url=url, status=200, response=record(folder / "models-response.json"),
         selected_model_listed=True, model=gate.MODEL, completed_model_responses=0))


class WindowsJob:
    """Own one launched app and its descendants; never target process names."""
    def __init__(self):
        from ctypes import wintypes as w

        class Limits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", w.DWORD),
                        ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t), ("active_limit", w.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [("limits", Limits), ("io", ctypes.c_ulonglong * 6),
                        ("process_mem", ctypes.c_size_t), ("job_mem", ctypes.c_size_t),
                        ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        for name, args, result in (
            ("CreateJobObjectW", [ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            ("SetInformationJobObject", [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            ("AssignProcessToJobObject", [w.HANDLE, w.HANDLE], w.BOOL),
            ("TerminateJobObject", [w.HANDLE, w.UINT], w.BOOL),
            ("QueryInformationJobObject", [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p], w.BOOL),
            ("CloseHandle", [w.HANDLE], w.BOOL),
            ("CreateToolhelp32Snapshot", [w.DWORD, w.DWORD], w.HANDLE),
            ("Thread32First", [w.HANDLE, ctypes.c_void_p], w.BOOL),
            ("Thread32Next", [w.HANDLE, ctypes.c_void_p], w.BOOL),
            ("OpenThread", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            ("ResumeThread", [w.HANDLE], w.DWORD),
        ):
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.limits.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process):
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def resume(self, process):
        from ctypes import wintypes as w

        class ThreadEntry(ctypes.Structure):
            _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("thread_id", w.DWORD), ("owner_pid", w.DWORD),
                        ("base_priority", w.LONG), ("delta_priority", w.LONG), ("flags", w.DWORD)]

        snapshot = self.api.CreateToolhelp32Snapshot(4, 0)  # TH32CS_SNAPTHREAD
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            available = self.api.Thread32First(snapshot, ctypes.byref(entry))
            matches = []
            while available:
                if entry.owner_pid == process.pid:
                    matches.append(entry.thread_id)
                available = self.api.Thread32Next(snapshot, ctypes.byref(entry))
            require(len(matches) == 1, "Suspended app primary thread unavailable/ambiguous")
            thread = self.api.OpenThread(2, False, matches[0])  # THREAD_SUSPEND_RESUME
            if not thread:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                require(self.api.ResumeThread(thread) == 1, "Could not resume the owned app primary thread")
            finally:
                self.api.CloseHandle(thread)
        finally:
            self.api.CloseHandle(snapshot)

    def active(self):
        class Accounting(ctypes.Structure):
            _fields_ = [("times", ctypes.c_longlong * 4), ("faults", ctypes.c_ulong),
                        ("total", ctypes.c_ulong), ("active", ctypes.c_ulong), ("terminated", ctypes.c_ulong)]
        value = Accounting()
        if not self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(value), ctypes.sizeof(value), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return value.active

    def cleanup(self):
        if self.active() and not self.api.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        deadline = time.monotonic() + 10
        while self.active() and time.monotonic() < deadline:
            time.sleep(.05)
        require(self.active() == 0, "Owned job processes did not terminate")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


@contextmanager
def inherited_error_mode():
    """Suppress QA child crash/WER dialogs; restore the parent immediately."""
    from ctypes import wintypes as w
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.SetErrorMode.argtypes, api.SetErrorMode.restype = [w.UINT], w.UINT
    previous = api.SetErrorMode(0x8003)
    try:
        yield
    finally:
        api.SetErrorMode(previous)


def launch(arguments, folder, environment, timeout):
    started, child, assigned, timed_out, cleanup = time.monotonic(), None, False, False, False
    job = WindowsJob()
    try:
        with (folder / "stdout.log").open("xb") as out, (folder / "stderr.log").open("xb") as err:
            with inherited_error_mode():
                child = subprocess.Popen(arguments, cwd=Path(arguments[0]).parent, env=environment,
                                         stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                         creationflags=subprocess.CREATE_NO_WINDOW | 0x4)  # CREATE_SUSPENDED
            save(folder / "started.json", dict(pid=child.pid, arguments=arguments, utc=datetime.now(timezone.utc).isoformat(),
                 path=environment["PATH"], appdata=environment["APPDATA"], localappdata=environment["LOCALAPPDATA"],
                 suspended_before_job_assignment=True))
            job.assign(child)
            assigned = True
            job.resume(child)
            try:
                child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                raise
    finally:
        try:
            if assigned:
                job.cleanup()
                cleanup = True
            elif child is not None:
                # Assignment failure is never accepted. Kill only this owned PID tree.
                subprocess.run([str(Path(environment["SYSTEMROOT"]) / "System32/taskkill.exe"), "/PID", str(child.pid), "/T", "/F"],
                               capture_output=True, timeout=15, check=False)
            if child is not None:
                child.wait(timeout=15)
        finally:
            job.close()
            save(folder / "process.json", dict(pid=child.pid if child else None, exit_code=child.returncode if child else None,
                 exited=child is not None and child.poll() is not None, seconds=time.monotonic() - started,
                 timed_out=timed_out, timeout_seconds=timeout, owned_job_assigned=assigned, owned_tree_cleanup_verified=cleanup))
    require(child.returncode == 0 and cleanup, "Native app failed or owned cleanup unverified")


def bound_inside(path, root):
    path = local_path(path)
    require(path.is_relative_to(root) and path.is_file(), "Evidence path outside the fresh mode root: " + str(path))
    return path


def verify_timeout_evidence(plan, status, request, process):
    expected = plan_timeouts(plan)
    native = status.get("timeoutBudget")
    require(isinstance(native, dict) and native == expected and all(type(native[key]) is int for key in expected),
            "Native QA timeout proof differs from requested budgets; legacy/missing proof is not accepted")
    options = request.get("options", {})
    provider = options.get("provider", {})
    require(type(provider.get("timeout_seconds")) is int and provider["timeout_seconds"] == expected["provider_timeout_seconds"]
            and type(options.get("timeout_seconds")) is int and options["timeout_seconds"] == expected["scan_timeout_seconds"],
            "Emitted request timeouts differ from requested budgets")
    require(type(process.get("timeout_seconds")) is int and process["timeout_seconds"] == expected["harness_timeout_seconds"],
            "Actual launcher timeout differs from requested harness budget")
    return expected


def collect(plan, mode, folder, nonce):
    smoke_path = folder / "parity-smoke.json"
    smoke = read(smoke_path)
    require(smoke.get("failure") is None and isinstance(smoke.get("result"), dict), "Native smoke failed")
    status = smoke["result"]
    display = status.get("aiDisplay") or {}
    require(display.get("mode") == mode and display.get("state") == "completed", "Requested visible mode incomplete/fallback")
    report = bound_inside(status["report"], folder / "reports")
    require(report.name == "attackmap-report.json" and report.parent.name == status["run"] and sha(report) == status["reportHash"], "Selected report/generation mismatch")
    request_path = folder / "reports/native-request.json"
    request = read(request_path)
    process_path = folder / "process.json"
    timeouts = verify_timeout_evidence(plan, status, request, read(process_path))
    expected = dict(enable_ai=True, provider="openai", endpoint=gate.ENDPOINT, model=gate.MODEL, max_calls=8,
                    timeout_seconds=timeouts["provider_timeout_seconds"], output_token_limit=32000, mode=mode, speed="standard", backend="api")
    require(request.get("options", {}).get("provider") == expected, "Emitted local provider/budgets differ")
    require(request.get("run_id") == status["run"] and request.get("repository_path") == plan["repository"]
            and request.get("output_path") == str(folder / "reports") and request["options"].get("cve") is False, "Request run/repository/output/network mismatch")
    generation = report.parent
    artifact_manifest_path = bound_inside(generation / "artifact-manifest.json", folder)
    manifest = read(artifact_manifest_path)
    require(manifest.get("generation_id") == status["run"] and manifest.get("exit_state", {}).get("status") == "succeeded", "Unsuccessful/stale artifact manifest")
    rows = manifest.get("sections", []) + manifest.get("compatibility_exports", [])
    require(bool(rows), "Missing artifact inventory")
    verified = set()
    for row in rows:
        name = relative_name(row["path"])
        require("/" not in name and name not in verified, "Unsafe/duplicate generation artifact")
        path = bound_inside(generation / name, folder)
        require(path.stat().st_size == row["size_bytes"] and sha(path) == row["checksum"], "Generation artifact tamper: " + name)
        verified.add(name)
    artifact = bound_inside(display["artifact"], folder)
    exported = bound_inside(display["exportPath"], folder)
    require(artifact == generation / gate.MODES[mode] and exported == folder / gate.MODES[mode]
            and sha(artifact) == display["artifactSha256"], "Displayed/exported artifact identity mismatch")
    metadata = bound_inside(artifact.with_suffix(".meta.json"), folder)
    run_manifest = bound_inside(generation / "run-manifest.json", folder)
    require({report.name, artifact.name, metadata.name, run_manifest.name} <= verified, "Selected artifact/report/metadata absent from manifest")
    capture = bound_inside(folder / "AI-mode.png", folder)
    require(capture.stat().st_size > 8 and capture.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n", "Native Reports PNG missing/invalid")
    capture_metadata = display.get("capture") or {}
    require(capture_metadata.get("OutputPath") == str(capture) and capture_metadata.get("Sha256") == sha(capture),
            "Native capture metadata does not match the captured Reports bytes")
    audit_records = [record(bound_inside(path, folder / "http-audit")) for path in sorted((folder / "http-audit").rglob("http-audit.jsonl"))]
    observed = [json.loads(line) for audit in audit_records for line in Path(audit["path"]).read_text(encoding="utf-8").splitlines()]
    actual = sum(event.get("event") == "http_response_received" for event in observed)
    completed = sum(event.get("event") == "observation_complete" and event.get("completed") is True for event in observed)
    for event in observed:
        if event.get("event") == "observation_complete":
            require(event.get("completed") is True, "Partial/failed transport response cannot pass a mode")
        if event.get("event") == "http_response_received":
            require(type(event.get("status")) is int and 200 <= event["status"] < 300, "Failed/redirected provider HTTP response")
    evidence = dict(mode=mode, engine_kind="packaged", engine=record(Path(plan["engine"])),
        native=record(Path(plan["app"])), native_dll=record(Path(plan["app"]).with_suffix(".dll")),
        package_proof=record(Path(plan["output"]) / "package-verification.json"), package_id=plan["package"]["package_id"],
        smoke=record(smoke_path), request=record(request_path), process=record(process_path), timeout_budget=timeouts,
        preflight=record(Path(plan["output"]) / "preflight.json"),
        emitted_provider=expected, provider_pointer="/options/provider",
        provider_fields={**{key: key for key in ("endpoint", "model", "mode", "backend", "speed", "max_calls", "timeout_seconds")}, "max_output_tokens": "output_token_limit"},
        isolated_output=True, run_manifest=record(run_manifest), artifact_manifest=record(artifact_manifest_path),
        report=record(report), artifact=record(artifact), metadata=record(metadata), capture=record(capture), export=record(exported),
        displayed_mode=display["mode"], displayed_generation=status["run"], selected_report_sha256=status["reportHash"],
        provider_event_source="attackmap-httpx-audit", provider_audits=audit_records, audit_nonce=nonce,
        actual_http_requests=actual, completed_responses=completed)
    save(folder / "evidence.json", evidence)
    result = gate.verify(evidence, folder)
    result.update(artifact_manifest_files_verified=len(verified), package_id=plan["package"]["package_id"], **ACCEPTANCE)
    save(folder / "verification.json", result)
    require(result["passed"], "WP017 offline evidence gate: " + "; ".join(result["failures"]))
    return result


def run(plan, timeout=None):
    require(os.name == "nt", "Native execution requires Windows")
    timeouts = plan_timeouts(plan)
    require(timeout is None or (type(timeout) is int and timeout == timeouts["harness_timeout_seconds"]),
            "Run timeout override differs from preflight harness budget")
    timeout = timeouts["harness_timeout_seconds"]
    output = local_path(plan["output"])
    output.mkdir()  # Exclusive fresh root: never append to earlier proof.
    save(output / "preflight.json", plan)
    save(output / "package-verification.json", plan["package"])
    results = []
    try:
        for mode in plan["modes"]:
            lock_path = (plan["package"].get("release_lock") or {}).get("path")
            require(package_identity(plan["app"], plan["package"]["manifest"]["sha256"], lock_path) == plan["package"], "Package changed since preflight")
            require(record(Path(plan["seed"]["path"])) == plan["seed"], "Seed changed since preflight")
            folder = output / mode
            folder.mkdir()
            environment = child_environment(folder)
            (folder / "http-audit").mkdir()
            nonce = "wp017-" + mode + "-" + uuid.uuid4().hex
            environment.update(ATTACKMAP_QA_HTTP_AUDIT_DIR=str(folder / "http-audit"), ATTACKMAP_QA_HTTP_AUDIT_NONCE=nonce)
            save(folder / "inputs.json", dict(mode=mode, seed=plan["seed"], package_id=plan["package"]["package_id"],
                 identities=plan["package"]["identities"], endpoint=gate.ENDPOINT, model=gate.MODEL, audit_nonce=nonce,
                 repository=plan["repository"], timeout_budget=timeouts,
                 personal_settings_read=False, separate_python_on_child_path=False))
            check_local_model(folder)  # GET only; completion is proven separately from transport audits.
            arguments = [plan["app"], "--parity-smoke", plan["seed"]["path"], str(folder), "--engine", plan["engine"],
                         "--native-scan", "--repository", plan["repository"], "--ai-mode", mode,
                         "--qa-provider-timeout", str(timeouts["provider_timeout_seconds"]),
                         "--qa-scan-timeout", str(timeouts["scan_timeout_seconds"]),
                         "--qa-harness-timeout", str(timeouts["harness_timeout_seconds"])]
            launch(arguments, folder, environment, timeout)
            require(package_identity(plan["app"], plan["package"]["manifest"]["sha256"], lock_path) == plan["package"], "Package changed during native run")
            results.append(collect(plan, mode, folder, nonce))
        summary = dict(passed=True, scope="Pinned package full native shell local AI evidence consistency only",
                       modes=results, endpoint=gate.ENDPOINT, model=gate.MODEL, package_id=plan["package"]["package_id"],
                       timeout_budget=timeouts, **ACCEPTANCE)
        save(output / "summary.json", summary)
        return summary
    except BaseException as error:
        save(output / "failure.json", dict(passed=False, error=str(error), completed_modes=[row["mode"] for row in results], **ACCEPTANCE))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "seed", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", choices=("all", *gate.MODES), default="all")
    parser.add_argument("--manifest-sha256", help="Reviewed portable/package manifest pin; required with --run")
    parser.add_argument("--release-lock", help="RequiredBundled release-lock.json; checked against package and current sources")
    parser.add_argument("--run", action="store_true", help="Explicitly start sequential native scans and local HTTP")
    parser.add_argument("--provider-timeout", type=int, default=900, help="QA total AI allowance for the fixed loopback target, 1..7200 seconds (default 900)")
    parser.add_argument("--scan-timeout", type=int, default=1200, help="QA scan timeout in seconds, 1..86400 (default 1200)")
    parser.add_argument("--process-timeout", type=int, default=1500, help="Per-mode app wall timeout, at most 10800 seconds; provider <= scan < process (default 1500)")
    args = parser.parse_args(argv)
    try:
        require(not args.run or args.manifest_sha256 is not None, "--run requires the reviewed --manifest-sha256 pin")
        plan = preflight(args.app, args.seed, args.output, args.mode, args.manifest_sha256, args.release_lock,
                         provider_timeout=args.provider_timeout, scan_timeout=args.scan_timeout, process_timeout=args.process_timeout)
        result = run(plan) if args.run else plan
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(passed=False, error=str(error), **ACCEPTANCE), indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
