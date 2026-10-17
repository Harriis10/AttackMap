"""Bounded desktop action transport; semantic policies stay in core services."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import threading

from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from .safe_fs import ensure_output_dir, safe_write_text

MAX_RESULT_BYTES = 64 * 1024 * 1024


class ActionRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    schema_version: Literal["1.1"] = "1.1"
    request_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    operation: Literal["compare", "suppression_preview", "suppression_apply", "suppression_undo", "suppression_recover",
                       "provider_save", "provider_check",
                       "pin_generation", "unpin_generation", "diagnostics_preview", "diagnostics_export"]
    output_path: str = Field(min_length=1)
    payload: dict


def execute_action(request: ActionRequest) -> dict:
    payload = request.payload
    if request.operation == "compare":
        from .comparison import compare_report_files
        return compare_report_files(Path(payload["baseline_path"]), Path(payload["current_path"]))
    if request.operation.startswith("suppression_"):
        from .suppression_actions import execute_suppression_action
        return execute_suppression_action(request.operation, payload)
    if request.operation in {"pin_generation", "unpin_generation"}:
        from .retention import pin_generation, unpin_generation
        action = pin_generation if request.operation == "pin_generation" else unpin_generation
        return {"pinned": sorted(action(Path(payload["output_base"]), payload["run_id"]))}
    if request.operation in {"diagnostics_preview", "diagnostics_export"}:
        from .diagnostics_export import collect_diagnostic_export, export_diagnostics
        max_generations = payload.get("max_generations", 50)
        if request.operation == "diagnostics_preview":
            return collect_diagnostic_export(Path(payload["output_base"]), max_generations=max_generations)
        payload_out, target = export_diagnostics(Path(payload["output_base"]), Path(payload["target_path"]),
                                                 max_generations=max_generations)
        return {"written": str(target), "preview": payload_out}
    from .desktop_provider import execute_provider_action
    return execute_provider_action(request.operation, payload)


def _result_path(request: ActionRequest) -> Path:
    folder = ensure_output_dir(Path(request.output_path).absolute(), mark=True)
    return folder / f"{request.request_id}.result.json"


def run_action_file(path: Path, *, engine: bool = False, expected_sha256: str | None = None) -> int:
    request = None
    try:
        with path.open("rb") as stream:
            request_bytes = stream.read(4 * 1024 * 1024 + 1)
        if len(request_bytes) > 4 * 1024 * 1024:
            raise ValueError("Action request exceeds size limit")
        if expected_sha256 is not None and hashlib.sha256(request_bytes).hexdigest() != expected_sha256:
            raise ValueError("Action request changed before execution")
        request = ActionRequest.model_validate_json(request_bytes)
        target = _result_path(request)
        if target.exists():
            raise ValueError("Action ID already used")
        if engine:
            result = execute_action(request)
            raw = json.dumps({"schema_version": "1.1", "request_id": request.request_id,
                              "operation": request.operation, "result": result}, ensure_ascii=True)
            if len(raw.encode("utf-8")) > MAX_RESULT_BYTES:
                raise ValueError("Action result exceeds size limit")
            safe_write_text(target.parent, target, raw)
            return 0
        # Persistent admission survives failures and uncertain side effects. Only
        # the outer broker claims it; the checksum-bound child shares its ID.
        admission = target.with_name(f"{request.request_id}.admitted.json")
        descriptor = os.open(admission, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(json.dumps({"schema_version": "1.1", "request_id": request.request_id,
                                     "operation": request.operation}))
            stream.flush()
            os.fsync(stream.fileno())
        prepared = target.with_name(f"{request.request_id}.request.json")
        if prepared.exists():
            raise ValueError("Action request identity already used")
        snapshot = request.model_dump_json()
        safe_write_text(prepared.parent, prepared, snapshot)
        return _serve(request, prepared, target, hashlib.sha256(snapshot.encode("utf-8")).hexdigest())
    except Exception:
        # Payloads may contain local suppression snapshots or transient secrets.
        # Never print exception text, request contents, or provider output here.
        if request is not None and not engine:
            print(json.dumps({"schema_version": "1.1", "kind": "action_result",
                              "request_id": request.request_id, "operation": request.operation,
                              "state": "failed", "error": "Desktop action failed; verify the selected inputs."}), flush=True)
        print("Desktop action failed; verify the selected inputs.", file=sys.stderr)
        return 1


def _serve(request: ActionRequest, path: Path, target: Path, checksum: str) -> int:
    from .execution import ProcessSupervisor
    supervisor = ProcessSupervisor()
    finished = threading.Event()
    cancelled = threading.Event()
    prefix = ([sys.executable, "desktop-action"] if getattr(sys, "frozen", False)
              else [sys.executable, "-m", "attackmap.desktop_actions"])
    env = dict(os.environ)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY",
                 "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID"):
        env.pop(name, None)
    if not request.operation.startswith("provider_"):
        env.pop("ATTACKMAP_ACTION_CREDENTIAL", None)

    def complete(code: int, _tail: str = "") -> None:
        state = "cancelled" if cancelled.is_set() else "failed" if code else "completed"
        message = {"schema_version": "1.1", "kind": "action_result",
                   "request_id": request.request_id, "operation": request.operation, "state": state}
        try:
            if state == "completed":
                if target.stat().st_size > MAX_RESULT_BYTES:
                    raise ValueError("Action result exceeds size limit")
                raw = target.read_bytes()
                result = json.loads(raw)
                if (result.get("request_id") != request.request_id
                        or result.get("operation") != request.operation or result.get("schema_version") != "1.1"):
                    raise ValueError("Action result identity mismatch")
                message.update(result_path=str(target), sha256=hashlib.sha256(raw).hexdigest())
            else:
                message["error"] = "Action cancelled." if state == "cancelled" else "Desktop action failed; inputs were not accepted."
        except Exception:
            message.update(state="failed", error="Desktop action result failed validation.")
        try:
            print(json.dumps(message, ensure_ascii=True), flush=True)
        finally:
            finished.set()

    if not supervisor.start([*prefix, "--engine", "--request", str(path.absolute()), "--expected-sha256", checksum],
                            env=env, on_done=complete, timeout=60):
        if not finished.is_set():
            complete(1)
        return 1

    def controls() -> None:
        try:
            descriptor = sys.stdin.fileno()
            data = bytearray()
            while not finished.is_set():
                value = os.read(descriptor, 1)
                if not value or value == b"\n" or len(data) >= 64:
                    if not value or data.strip() == b"cancel" or len(data) >= 64:
                        cancelled.set()
                        supervisor.request_cancel()
                        return
                    data.clear()
                else:
                    data.extend(value)
        except (OSError, ValueError):
            if not finished.is_set():
                cancelled.set()
                supervisor.request_cancel()

    threading.Thread(target=controls, daemon=True).start()
    finished.wait()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--engine", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--expected-sha256", help=argparse.SUPPRESS)
    args = parser.parse_args()
    raise SystemExit(run_action_file(args.request, engine=args.engine, expected_sha256=args.expected_sha256))
