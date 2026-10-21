"""Optional isolated analyzer host (AM050 / criterion C36).

Runs ONE analyzer in a supervised subprocess so a crashing, hanging, noisy
or malformed-output analyzer cannot crash core or corrupt another
analyzer's output. Process and stream supervision are reused from
:mod:`attackmap.execution` (Windows Job Objects, verified timeouts,
bounded output retention); this module adds only the analyzer worker
protocol and limit classification.

Honest scope — what this is NOT:

* It is not a security sandbox. The worker runs with the same user, same
  filesystem and same network access as core. There is no syscall
  filtering, no filesystem restriction and no network restriction.
* A lockfile entry for an official analyzer pins a git commit; it is not
  cryptographic authenticity and not a sandbox either.

What is actually enforced (see docs/external-analyzers.md):

* Time — supervisor timeout kills the whole process tree (verified).
* Output size — the worker interposes on file descriptors 1/2 and counts
  every byte written by the analyzer (and its children); over the cap the
  worker is terminated. The parent additionally caps the result payload
  size before parsing. A deliberately evasive analyzer can re-dup its own
  descriptors and bypass the stream counter; the parent's bounded
  retention (a 50-line tail) keeps core memory safe regardless.
* Memory — on Windows the supervisor configures a job-wide commit cap before
  creating/assigning/resuming the child. Setup failure prevents launch.
  Other platforms remain functional with an explicit unenforced policy.

Every breach produces a named partial-coverage result: an
``analyzer_errors`` entry with a distinct error_type plus a
``limitations`` note, so a clean report is never mistaken for full
coverage. Sibling analyzers are unaffected (their results are collected
separately and merged by core's merge rules).

Default is OFF: analyzers run in-process (#220 already isolates
exceptions); the host is opt-in via ``analyze_repository(...,
isolated_analyzers=True)``.

Worker mode: ``python -m attackmap.analyzer_host --worker ...`` — kept
stdlib-only at module import so the child boots small.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path

# Named partial-coverage error types (analyzer_errors.error_type).
HOST_TIMEOUT = "AnalyzerHostTimeout"
HOST_OUTPUT_LIMIT = "AnalyzerHostOutputLimit"
HOST_MEMORY_LIMIT = "AnalyzerHostMemoryLimit"
HOST_CRASH = "AnalyzerHostCrash"
HOST_INVALID_OUTPUT = "AnalyzerHostInvalidOutput"
HOST_LAUNCH_FAILED = "AnalyzerHostLaunchFailed"
HOST_STUCK = "AnalyzerHostStuck"
HOST_INPUT_INVALID = "AnalyzerHostInputInvalid"

_STATUS_FILE = "status.json"
_RESULT_FILE = "result.json"
_STREAM_BREACH_FILE = "output-breach.json"

# Worker exit codes (the parent classifies from files, these are diagnostics).
_EXIT_STREAM_BREACH = 80
_EXIT_RESULT_TOO_LARGE = 81

_MESSAGE_MAX_CHARS = 500
_QUARANTINE_LOCK = threading.Lock()
_QUARANTINED_HOSTS: dict[object, Path] = {}


def _recover_quarantined_hosts() -> bool:
    with _QUARANTINE_LOCK:
        pending = list(_QUARANTINED_HOSTS.items())
    for supervisor, workdir in pending:
        if supervisor.wait(0) or supervisor.retry_cleanup():
            with _QUARANTINE_LOCK:
                _QUARANTINED_HOSTS.pop(supervisor, None)
            shutil.rmtree(workdir, ignore_errors=True)
    with _QUARANTINE_LOCK:
        return not _QUARANTINED_HOSTS


@dataclass(frozen=True)
class HostLimits:
    """Resource limits for one isolated analyzer run.

    ``memory_bytes``: ``None`` selects the platform default (1 GiB on
    Windows, unlimited elsewhere — only Windows Job Objects support the
    cap today). ``0`` explicitly disables the memory cap everywhere.
    """

    timeout_seconds: float = 300.0
    stream_bytes: int = 8 * 1024 * 1024
    result_bytes: int = 64 * 1024 * 1024
    memory_bytes: int | None = None

    def __post_init__(self):
        if self.memory_bytes is not None:
            from .execution.windows import validate_memory_limit
            validate_memory_limit(self.memory_bytes)

    def effective_memory_limit(self) -> int:
        if self.memory_bytes is not None:
            return self.memory_bytes
        return 1024**3 if os.name == "nt" else 0


@dataclass
class IsolatedOutcome:
    """One isolated run: either a validated result or a named failure."""

    analyzer: str
    result: object | None = None  # a validated ScanResult (typed loosely: stdlib-only module)
    error_type: str | None = None
    message: str = ""
    limitation: str | None = None
    exit_code: int | None = None
    resource_policy: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error_type is None


class AnalyzerHostError(RuntimeError):
    """Raised under ``strict=True`` when an isolated analyzer breached a limit."""


def _partial(name: str, error_type: str, reason: str, message: str, exit_code: int | None) -> IsolatedOutcome:
    limitation = (
        f"Analyzer '{name}' did not complete inside the isolated analyzer host ({reason}); "
        "its signals are missing from this scan (partial coverage)."
    )
    return IsolatedOutcome(
        analyzer=name, error_type=error_type, message=message[:_MESSAGE_MAX_CHARS],
        limitation=limitation, exit_code=exit_code,
    )


def _analyzer_name(analyzer: object) -> str:
    name = getattr(analyzer, "name", None)
    if isinstance(name, str) and name.strip():
        return name
    metadata = getattr(analyzer, "metadata", None)
    meta_name = getattr(metadata, "name", None)
    return meta_name if isinstance(meta_name, str) and meta_name else "unknown"


def _analyzer_load_spec(analyzer: object) -> dict[str, str | None]:
    """How a worker can reconstruct this analyzer in a subprocess.

    Entry-point name is preferred (registered plugins load exactly the way
    core loads them); module and file paths are fallbacks for objects the
    test fixtures construct directly.
    """
    entry_point = getattr(analyzer, "_attackmap_entry_point_name", None)
    if isinstance(entry_point, str) and entry_point:
        return {"entry_point": entry_point, "module": None, "file": None, "qualname": None}
    import inspect

    cls = type(analyzer)
    qualname = getattr(cls, "__qualname__", cls.__name__)
    module = sys.modules.get(getattr(cls, "__module__", ""))
    file = getattr(module, "__file__", None) if module is not None else None
    if not file:
        try:
            file = inspect.getfile(cls)
        except (TypeError, OSError):
            file = None
    return {
        "entry_point": None,
        "module": getattr(cls, "__module__", None) if module is not None else None,
        "file": file,
        "qualname": qualname,
    }


def run_isolated_analyzer(
    analyzer: object,
    root: str | Path,
    limits: HostLimits | None = None,
    *, index=None, bundle=None,
) -> IsolatedOutcome:
    """Run one analyzer in a supervised subprocess and classify the outcome.

    Returns either a validated ``ScanResult`` or a named partial-coverage
    failure; never raises for analyzer misbehavior (only for genuinely
    broken host preconditions, e.g. an analyzer that cannot be located for
    the worker — reported as ``AnalyzerHostLaunchFailed`` instead).
    """
    host_limits = limits if limits is not None else HostLimits()
    name = _analyzer_name(analyzer)
    if not _recover_quarantined_hosts():
        return _partial(name, HOST_STUCK, "previous host cleanup remains unverified",
                        "no new isolated worker admitted while an owned process tree is uncertain", None)
    spec = _analyzer_load_spec(analyzer)
    if not (spec.get("entry_point") or spec.get("module") or spec.get("file")):
        return _partial(name, HOST_LAUNCH_FAILED, "no loadable analyzer source", "cannot determine how to load the analyzer in a subprocess", None)

    from .index import RepoIndex, active_index_for
    from .snapshot_transport import SnapshotBundle, SnapshotInputError
    own_bundle = bundle is None
    try:
        if bundle is None:
            index = index if index is not None else active_index_for(root)
            index = index if index is not None else RepoIndex.build(root)
            if index.root != Path(root).resolve():
                raise SnapshotInputError("Captured index belongs to another repository")
            bundle = SnapshotBundle(index)
        if bundle.descriptor.root != str(Path(root).resolve()):
            raise SnapshotInputError("Sealed input belongs to another repository")
        expected = index.snapshot if index is not None else bundle.identity
        if (expected is None or bundle.descriptor.snapshot_id != expected.snapshot_id
                or bundle.descriptor.config_identity != expected.config_identity):
            raise SnapshotInputError("Sealed input does not match the selected capture/config")
        lease = bundle.acquire()
    except (SnapshotInputError, OSError) as exc:
        if own_bundle and bundle is not None:
            bundle.close()
        return _partial(name, HOST_INPUT_INVALID, "captured input admission failed", str(exc), None)

    workdir = None
    quarantined = False
    try:
        workdir = Path(tempfile.mkdtemp(prefix="attackmap-analyzer-host-"))
        argv = [
            sys.executable, "-m", "attackmap.analyzer_host", "--worker",
            "--repo", str(root),
            "--workdir", str(workdir),
            "--stream-bytes", str(host_limits.stream_bytes),
            "--result-bytes", str(host_limits.result_bytes),
            "--snapshot-descriptor", bundle.descriptor.dumps(),
        ]
        if spec.get("entry_point"):
            argv += ["--entry-point", str(spec["entry_point"])]
        if spec.get("module"):
            argv += ["--analyzer-module", str(spec["module"])]
        if spec.get("file"):
            argv += ["--analyzer-file", str(spec["file"])]
        if spec.get("qualname"):
            argv += ["--analyzer-attr", str(spec["qualname"])]

        from .execution import ProcessSupervisor

        supervisor = ProcessSupervisor()
        memory_limit = host_limits.effective_memory_limit()
        observed: dict[str, object] = {}

        def with_policy(outcome: IsolatedOutcome) -> IsolatedOutcome:
            outcome.resource_policy = dict(supervisor.memory_policy)
            outcome.resource_policy["observed_peak_job_memory_bytes"] = observed.get("peak_memory")
            outcome.resource_policy.update(input_policy="cooperating_sdk_sealed_snapshot",
                snapshot_id=bundle.descriptor.snapshot_id, config_identity=bundle.descriptor.config_identity,
                filesystem_restricted=False, network_restricted=False)
            if memory_limit and outcome.resource_policy.get("status") == "unsupported_on_platform":
                note = "Isolated analyzer host requested memory cap is UNENFORCED on this platform; filesystem/network access is unrestricted."
                if outcome.result is not None:
                    outcome.result.limitations.append(note)
                elif outcome.limitation:
                    outcome.limitation += " " + note
            return outcome

        def quarantine():
            nonlocal quarantined
            with _QUARANTINE_LOCK:
                _QUARANTINED_HOSTS[supervisor] = workdir
            quarantined = True

        def _on_done(code: int, tail: str) -> None:
            # Runs in the pump thread just before the job object is closed:
            # the last chance to query the job's peak memory footprint.
            try:
                observed["code"] = code
                observed["tail"] = tail
                observed["timed_out"] = supervisor.timed_out
                job = getattr(supervisor, "_job", None)  # private reuse: see module docstring
                observed["peak_memory"] = (_query_job_peak_memory(job.handle) or None) if job is not None else None
                observed["memory_policy"] = dict(supervisor.memory_policy)
            finally:
                lease.release()  # on_done runs only after verified owned-tree cleanup

        extra = {"job_memory_bytes": memory_limit} if memory_limit else {}
        if not supervisor.start(argv, timeout=host_limits.timeout_seconds, on_done=_on_done, **extra):
            if supervisor.running:
                quarantine()
                return with_policy(_partial(name, HOST_STUCK, "launch cleanup remains unverified", supervisor.stderr_tail, None))
            return with_policy(_partial(name, HOST_LAUNCH_FAILED, "worker launch failed", supervisor.stderr_tail, None))

        if not supervisor.wait(host_limits.timeout_seconds + 20):
            supervisor.request_cancel()
            if not supervisor.wait(10):
                quarantine()
                return with_policy(_partial(
                    name, HOST_STUCK, "worker termination could not be verified",
                    "supervisor could not verify process-tree termination", None,
                ))
        outcome = _classify(name, workdir, observed, memory_limit, host_limits.result_bytes)
        if outcome.result is not None:
            try:
                root_matches = Path(outcome.result.root).resolve() == Path(bundle.descriptor.root)
            except (OSError, ValueError):
                root_matches = False
            if not root_matches:
                return with_policy(_partial(name, HOST_INVALID_OUTPUT, "result root differs from captured input", "worker result root mismatch", outcome.exit_code))
            claimed = outcome.result.scan_snapshot
            if claimed is not None and claimed != bundle.identity:
                return with_policy(_partial(name, HOST_INVALID_OUTPUT, "result snapshot differs from captured input", "worker result snapshot/config mismatch", outcome.exit_code))
            outcome.result.scan_snapshot = bundle.identity
            from .analyzer_contracts import normalize_analyzer_metadata
            from .signal_provenance import admit_isolated_provenance
            version = None
            try:
                metadata = normalize_analyzer_metadata(getattr(analyzer, "metadata", None))
                if "version" in metadata.model_fields_set:
                    version = metadata.version
            except (TypeError, ValueError):
                pass  # metadata-free legacy direct callers retain an unknown version
            admit_isolated_provenance(outcome.result, name, version)
        return with_policy(outcome)
    finally:
        if not quarantined:
            lease.release()  # also covers a verified launch failure with no callback
            if workdir is not None:
                shutil.rmtree(workdir, ignore_errors=True)
        if own_bundle:
            bundle.close()


def _classify(name: str, workdir: Path, observed: dict[str, object], memory_limit: int, result_bytes_cap: int) -> IsolatedOutcome:
    from .redact import redact_text

    code = observed.get("code")
    code_int = code if isinstance(code, int) else None
    tail = observed.get("tail") or ""
    tail_text = tail if isinstance(tail, str) else ""
    peak = observed.get("peak_memory")
    peak_bytes = peak if isinstance(peak, int) and peak > 0 else None

    status = _read_json(workdir / _STATUS_FILE)
    stream_breach = _read_json(workdir / _STREAM_BREACH_FILE)

    def _redacted(message: str) -> str:
        redacted = redact_text(message)
        return (redacted or "")[:_MESSAGE_MAX_CHARS]

    if observed.get("timed_out"):
        return _partial(name, HOST_TIMEOUT, "exceeded the isolation time limit and was force-terminated",
                        _redacted(f"worker exceeded the isolation time limit{'; tail: ' + tail_text if tail_text else ''}"), code_int)
    if stream_breach is not None:
        return _partial(name, HOST_OUTPUT_LIMIT, "exceeded the stdout/stderr byte cap and was terminated",
                        _redacted(f"worker wrote more than the stream byte cap ({stream_breach.get('bytes', '?')} bytes)"), _EXIT_STREAM_BREACH)
    result_path = workdir / _RESULT_FILE
    if result_path.exists() and result_path.stat().st_size > result_bytes_cap:
        return _partial(name, HOST_OUTPUT_LIMIT, "result payload exceeded the byte cap",
                        f"serialized result exceeds the cap ({result_path.stat().st_size} bytes)", code_int)
    if isinstance(status, dict) and status.get("status") == "breach":
        return _partial(name, HOST_OUTPUT_LIMIT, "result payload exceeded the byte cap",
                        _redacted(str(status.get("message", "worker self-reported a result-size breach"))), code_int)

    # MemoryError is an observed worker report, not proof that a configured cap
    # caused it. Near-cap peaks alone must never turn a good result into failure.
    if isinstance(status, dict) and status.get("error_type") == "MemoryError":
        policy = observed.get("memory_policy") or {}
        enforced = policy.get("enforced_bytes", 0) if isinstance(policy, dict) else 0
        detail = (f"worker reported MemoryError; enforced job cap={enforced} bytes; "
                  f"observed peak={peak_bytes if peak_bytes is not None else 'unknown'}; cap causality is unverified")
        return _partial(name, HOST_MEMORY_LIMIT,
                        "worker reported a memory allocation failure",
                        _redacted(detail), code_int)
    if isinstance(status, dict) and status.get("status") == "error":
        error_type = str(status.get("error_type") or HOST_CRASH)
        message = f"{error_type}: {status.get('message', '')}"
        if error_type == "SnapshotInputError":
            return _partial(name, HOST_INPUT_INVALID, "captured input verification failed before plugin import",
                            _redacted(message), code_int)
        return _partial(name, HOST_CRASH, "worker exited after an analyzer exception",
                        _redacted(message), code_int)
    if code_int not in (0, None):
        return _partial(name, HOST_CRASH, "worker exited non-zero",
                        _redacted(f"exit code {code_int}{'; tail: ' + tail_text if tail_text else ''}"), code_int)

    if not result_path.exists():
        return _partial(name, HOST_INVALID_OUTPUT, "worker exited without a result",
                        "no result file was produced", code_int)
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _partial(name, HOST_INVALID_OUTPUT, "result was not valid JSON",
                        _redacted(f"result file unparseable: {exc}"), code_int)
    if not isinstance(payload, dict):
        return _partial(name, HOST_INVALID_OUTPUT, "result was not a JSON object",
                        f"result decoded to {type(payload).__name__}", code_int)
    from .models import ScanResult

    try:
        result = ScanResult.model_validate(payload)
    except Exception as exc:
        return _partial(name, HOST_INVALID_OUTPUT, "result did not validate as a ScanResult",
                        _redacted(f"ValidationError: {exc}"), code_int)
    return IsolatedOutcome(analyzer=name, result=result, exit_code=code_int)


def _read_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Windows Job Object memory cap (applied to the supervisor's own job — the
# struct mirrors execution/windows.py; flags preserve KILL_ON_JOB_CLOSE).
# ---------------------------------------------------------------------------

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x200
_JOB_EXTENDED_LIMIT_INFORMATION = 9


def _job_extended_limits_structs() -> "tuple[type, type]":
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                    ("flags", wintypes.DWORD), ("min_working", ctypes.c_size_t),
                    ("max_working", ctypes.c_size_t), ("active_limit", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                    ("scheduling", wintypes.DWORD)]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("basic", BasicLimits), ("io", ctypes.c_ulonglong * 6),
                    ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                    ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]
    return BasicLimits, ExtendedLimits


def _query_job_peak_memory(handle: int) -> int:
    import ctypes

    if os.name != "nt":
        return 0
    _, extended = _job_extended_limits_structs()
    value = extended()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    if not kernel.QueryInformationJobObject(handle, _JOB_EXTENDED_LIMIT_INFORMATION, ctypes.byref(value), ctypes.sizeof(value), None):
        return 0
    return int(value.peak_job_memory)


# ---------------------------------------------------------------------------
# Worker mode (runs inside the supervised subprocess).
# ---------------------------------------------------------------------------

def _write_json(path: Path, payload: dict[str, object]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, path)


def _install_stream_cap(cap_bytes: int, breach_path: Path) -> None:
    """Interpose on fds 1/2 and terminate the process over the byte cap.

    Every write through file descriptors 1 and 2 (including raw os.write
    and child processes that inherit them) flows through an internal pipe
    this pump counts. Over the cap the pump records a breach marker and
    exits the process immediately; the parent's ProcessSupervisor verifies
    process-tree cleanup afterwards. Not a sandbox: analyzer code can
    close or re-dup descriptors to evade the counter — the parent's bounded
    output retention keeps core memory safe in that case.
    """
    if cap_bytes <= 0:
        return
    saved_err = os.dup(2)
    read_fd, write_fd = os.pipe()
    os.dup2(write_fd, 1)
    os.dup2(write_fd, 2)
    os.close(write_fd)

    def _pump() -> None:
        total = 0
        try:
            while True:
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > cap_bytes:
                    _write_json(breach_path, {"status": "breach", "bytes": total})
                    os._exit(_EXIT_STREAM_BREACH)
                os.write(saved_err, chunk)
        except OSError:
            pass

    threading.Thread(target=_pump, daemon=True).start()


def _resolve_attr(owner: object, qualname: str | None) -> object:
    target = owner
    for part in (qualname or "").split("."):
        if not part:
            continue
        target = getattr(target, part)
    return target


def _load_analyzer(args: "argparse.Namespace") -> object:
    attempts: list[str] = []

    if args.entry_point:
        try:
            matches = [ep for ep in entry_points(group="attackmap.analyzers") if ep.name == args.entry_point]
            if not matches:
                raise ImportError(f"entry point {args.entry_point!r} not found")
            return matches[0].load()
        except Exception as exc:
            attempts.append(f"entry-point: {type(exc).__name__}: {exc}")

    if args.analyzer_module:
        try:
            module = importlib.import_module(args.analyzer_module)
            return _resolve_attr(module, args.analyzer_attr)
        except Exception as exc:
            attempts.append(f"module: {type(exc).__name__}: {exc}")

    if args.analyzer_file:
        try:
            spec = importlib.util.spec_from_file_location("attackmap_host_analyzer", args.analyzer_file)
            if spec is None or spec.loader is None:
                raise ImportError(f"cannot load {args.analyzer_file}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return _resolve_attr(module, args.analyzer_attr)
        except Exception as exc:
            attempts.append(f"file: {type(exc).__name__}: {exc}")

    raise RuntimeError("could not load analyzer in worker (" + "; ".join(attempts[-3:]) + ")")


def _worker_main(args: "argparse.Namespace") -> int:
    workdir = Path(args.workdir)
    repo = str(args.repo)
    _install_stream_cap(int(args.stream_bytes), workdir / _STREAM_BREACH_FILE)
    try:
        from .index import pinned_index_scope, install_process_snapshot
        from .snapshot_transport import SealedSnapshot, read_snapshot, SnapshotInputError
        descriptor = SealedSnapshot.loads(args.snapshot_descriptor)
        if descriptor.root != str(Path(repo).resolve()):
            raise SnapshotInputError("Worker root differs from sealed input")
        captured = read_snapshot(descriptor)
        install_process_snapshot(captured)
        with pinned_index_scope(captured):
            analyzer = _load_analyzer(args)
            if isinstance(analyzer, type):
                analyzer = analyzer()
            import inspect
            try:
                parameters = inspect.signature(analyzer.analyze).parameters
            except (TypeError, ValueError):
                parameters = {}  # legacy callables without an inspectable signature
            extra = {"index": captured} if "index" in parameters or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()) else {}
            result = analyzer.analyze(repo, **extra)  # type: ignore[attr-defined]
    except BaseException as exc:  # analyzer crashed; record and exit non-zero
        try:
            _write_json(workdir / _STATUS_FILE, {
                "status": "error",
                "error_type": type(exc).__name__,
                "message": str(exc)[:_MESSAGE_MAX_CHARS],
                "result_bytes": int(args.result_bytes),
            })
        except OSError:
            pass
        return 1

    if hasattr(result, "model_dump_json"):
        # Typed producer hints are intentionally excluded from wire models.
        # Preserve their legacy aliases in normalized origins before encoding;
        # the parent subsequently treats every such claim as untrusted.
        from .models import ScanResult
        if isinstance(result, ScanResult):
            result.signals = result.all_signals()
        payload_text = result.model_dump_json()
    elif isinstance(result, dict):
        payload = {"root": repo, **result}
        try:
            payload_text = json.dumps(payload)
        except (TypeError, ValueError) as exc:
            _write_json(workdir / _STATUS_FILE, {
                "status": "error", "error_type": "AnalyzerResultError",
                "message": f"dict result is not JSON-serializable: {exc}",
                "result_bytes": int(args.result_bytes),
            })
            return 1
    else:
        _write_json(workdir / _STATUS_FILE, {
            "status": "error", "error_type": "AnalyzerResultError",
            "message": f"analyze() returned {type(result).__name__}, expected ScanResult or dict",
            "result_bytes": int(args.result_bytes),
        })
        return 1

    data = payload_text.encode("utf-8")
    if len(data) > int(args.result_bytes):
        _write_json(workdir / _STATUS_FILE, {
            "status": "breach", "reason": "result_too_large", "bytes": len(data),
            "result_bytes": int(args.result_bytes),
        })
        return _EXIT_RESULT_TOO_LARGE

    tmp = workdir / (_RESULT_FILE + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, workdir / _RESULT_FILE)
    _write_json(workdir / _STATUS_FILE, {"status": "ok", "result_bytes": int(args.result_bytes)})
    return 0


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="attackmap.analyzer_host")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--stream-bytes", type=int, default=0)
    parser.add_argument("--result-bytes", type=int, default=0)
    parser.add_argument("--entry-point")
    parser.add_argument("--analyzer-module")
    parser.add_argument("--analyzer-file")
    parser.add_argument("--analyzer-attr")
    parser.add_argument("--snapshot-descriptor", required=True)
    args = parser.parse_args(argv)
    if not args.worker:
        parser.error("--worker is required (this module is the isolated analyzer host worker)")
    return _worker_main(args)


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
