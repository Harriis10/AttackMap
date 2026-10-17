"""Desktop transport broker: typed stdout events, cancel/EOF on stdin."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import TextIO

from .run_contract import RunProgress, RunRequest, RunTerminal


def serve(request: RunRequest, *, control: TextIO, events: TextIO) -> int:
    from .artifact_publisher import diagnostic_context_from_generation, generation_dir, publish_generation, validate_generation, write_diagnostic
    from .diagnostics import unknown_diagnostic
    from .execution import ProcessSupervisor

    lock = threading.RLock()
    finished = threading.Event()
    cancelled = threading.Event()
    revision = request.revision
    terminal_sent = False
    completing = False
    supervisor = ProcessSupervisor()
    output_base = Path(request.output_path).absolute()
    output = generation_dir(output_base, request.run_id)
    from .safe_fs import ensure_output_dir
    ensure_output_dir(output, mark=True)
    identity = dict(run_id=request.run_id, repository_id=request.repository_id,
                    generation=request.generation)

    def diagnostic(state: str, error: str | None = None) -> None:
        context = diagnostic_context_from_generation(output_base, request.run_id, outcome=state)
        write_diagnostic(output_base, request.run_id, state=state, error=error,
                         context=context or unknown_diagnostic("worker", outcome=state))

    def emit(payload: dict) -> None:
        nonlocal revision
        with lock:
            revision += 1
            payload["revision"] = revision
            try:
                events.write(json.dumps(payload, ensure_ascii=True) + "\n")
                events.flush()
            except (BrokenPipeError, OSError):
                cancelled.set()
                supervisor.request_cancel()

    def progress(event: dict) -> None:
        with lock:
            if terminal_sent or completing or event.get("event") == "done":
                return
            total, done = event.get("total"), event.get("done")
            bounded = (type(total) is int and total > 0 and type(done) is int
                       and 0 <= done <= total)
            message = RunProgress(**identity, revision=revision,
                state="cancelling" if cancelled.is_set() else "running",
                stage=str(event.get("label") or event.get("current") or "Analysis"),
                completed_units=done if bounded else None,
                total_units=total if bounded else None)
            emit(message.model_dump(mode="json"))

    def complete(code: int, _tail: str = "") -> None:
        nonlocal terminal_sent, completing
        with lock:
            if terminal_sent or completing:
                return
            completing = True
        state = "cancelled" if cancelled.is_set() else "failed" if code else "completed"
        artifact_path = None
        error = "Analysis exceeded the configured time limit." if getattr(supervisor, "timed_out", False) else None
        policy = "not_evaluated"
        try:
            if state != "cancelled":
                try:
                    manifest = validate_generation(output)
                except (OSError, ValueError):
                    if state == "completed":
                        raise
                    manifest = None
                exit_state = manifest["exit_state"] if manifest else {}
                if manifest:
                    expected_root = os.path.normcase(str(Path(request.repository_path).resolve()))
                    actual_root = manifest["run_identity"].get("repo_root", "")
                    report = json.loads((output / "attackmap-report.json").read_text(encoding="utf-8"))
                    roots = (actual_root, report["scan"]["root"])
                    if any(os.path.normcase(str(Path(root).resolve())) != expected_root for root in roots):
                        raise ValueError("Worker repository identity mismatch")
                # A policy rejection is a completed analysis, established by
                # validated artifacts rather than an ambiguous process code.
                if manifest and exit_state.get("exit_code") != code:
                    raise ValueError("Worker exit state mismatch")
                if exit_state.get("status") == "policy_failed":
                    state = "completed"
                    policy = "failed"
            if state == "completed":
                published = publish_generation(output_base, request.run_id, cancelled=cancelled.is_set)
                artifact_path = str(published / "attackmap-report.json")
                from .retention import retain_after_publish
                retain_after_publish(output_base)
            else:
                diagnostic(state, error)
        except Exception:
            state = "cancelled" if cancelled.is_set() else "failed"
            policy = "not_evaluated"
            error = "Result publication failed; previous results were preserved."
            try:
                diagnostic(state, error)
            except (OSError, ValueError):
                pass
        with lock:
            terminal_sent = True
            terminal = RunTerminal(**identity, revision=revision, state=state,
                execution_outcome={"completed": "succeeded", "failed": "failed", "cancelled": "cancelled"}[state],
                policy_outcome=policy, error=error,
                artifact_readiness="ready" if artifact_path else "unavailable")
            payload = terminal.model_dump(mode="json")
            if artifact_path:
                payload["artifact_path"] = artifact_path
            emit(payload)
            finished.set()

    prepared = output / "desktop-request.json"
    prepared.write_text(request.model_copy(update={"output_path": str(output)}).model_dump_json(), encoding="utf-8")
    prefix = ([sys.executable, "desktop-worker"] if getattr(sys, "frozen", False)
              else [sys.executable, "-m", "attackmap.desktop_worker"])
    argv = [*prefix, "--engine", "--request", str(prepared)]
    env = dict(os.environ)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY",
                 "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID"):
        env.pop(name, None)
    provider = request.options.provider
    if provider.enable_ai:
        from .ui.secrets import child_llm_env
        env.update(child_llm_env(provider.provider, provider.endpoint, allow_environment=False))
        if provider.provider == "claude" and provider.endpoint:
            env["ANTHROPIC_BASE_URL"] = provider.endpoint
    emit(RunProgress(**identity, revision=revision, state="queued").model_dump(mode="json"))
    if not supervisor.start(argv, env=env, on_progress=progress, on_done=complete,
                            timeout=request.options.timeout_seconds):
        complete(1)
        return 1

    def controls() -> None:
        # Avoid holding a buffered stdin lock in a daemon during interpreter exit.
        try:
            descriptor = control.fileno()
        except (AttributeError, OSError, ValueError):
            descriptor = None

        def read_line() -> str:
            if descriptor is None:
                return control.readline(65)
            data = bytearray()
            while len(data) <= 64:
                try:
                    value = os.read(descriptor, 1)
                except OSError:
                    return ""
                if not value or value == b"\n":
                    return data.decode("utf-8", errors="replace")
                data.extend(value)
            return "cancel"

        while not finished.is_set():
            line = read_line()
            if not line or line.strip() == "cancel":
                with lock:
                    if terminal_sent:
                        return
                    cancelled.set()
                    emit(RunProgress(**identity, revision=revision, state="cancelling").model_dump(mode="json"))
                    supervisor.request_cancel()
                return

    threading.Thread(target=controls, daemon=True).start()
    finished.wait()
    return 0


def run_request_file(path: Path, *, engine: bool = False) -> int:
    request = None
    stage_id = "request_validation"
    stage_started = time.perf_counter()
    try:
        if path.stat().st_size > 1_000_000:
            raise ValueError("Request exceeds size limit")
        request = RunRequest.model_validate(json.loads(path.read_text(encoding="utf-8")))
        if not Path(request.repository_path).is_dir():
            raise ValueError("Repository directory does not exist")
        if engine:
            from .pipeline import AnalyzeOptions, run_scan
            from .analyzers import select_requested_analyzers
            stage_id = "select_analyzers"
            stage_started = time.perf_counter()
            selected = select_requested_analyzers(request.modules, auto_install=False) if request.modules else None
            stage_id = "worker"
            stage_started = time.perf_counter()
            from .ai_budget import AiBudget, budget_scope
            provider = request.options.provider
            ledger = AiBudget(max_calls=provider.max_calls, max_seconds=provider.timeout_seconds,
                              output_token_limit=provider.output_token_limit)
            with budget_scope(ledger):
                state = run_scan(AnalyzeOptions(repo_path=Path(request.repository_path),
                output=Path(request.output_path), output_format="all", atomic_output=False,
                run_id=request.run_id, progress_format="json", analyzers=selected,
                recall=request.options.recall, strict_analyzers=request.options.strict_analyzers,
                no_suppress=request.options.no_suppress, cve=request.options.cve,
                secrets_history=request.options.secrets_history,
                llm=provider.enable_ai, llm_provider=provider.provider, llm_model=provider.model,
                llm_backend="api",
                echo=lambda *args, **kwargs: None))
            return state.exit_code
        return serve(request, control=sys.stdin, events=sys.stdout)
    except (OSError, ValueError):
        stage_duration = round((time.perf_counter() - stage_started) * 1000)
        error = "Invalid desktop scan request; verify paths and schema compatibility."
        if request is not None:
            from .artifact_publisher import write_diagnostic
            from .diagnostics import startup_diagnostic
            try:
                write_diagnostic(Path(request.output_path).absolute(), request.run_id,
                                 state="failed", error=error,
                                 context=startup_diagnostic(stage_id,
                                     duration_milliseconds=stage_duration,
                                     requested_analyzers=request.modules))
            except (OSError, ValueError):
                pass
        if request is not None and not engine:
            terminal = RunTerminal(run_id=request.run_id, repository_id=request.repository_id,
                generation=request.generation, revision=request.revision + 1,
                state="failed", execution_outcome="failed", error=error)
            print(terminal.model_dump_json(), flush=True)
        print(error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--engine", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    raise SystemExit(run_request_file(arguments.request, engine=arguments.engine))
