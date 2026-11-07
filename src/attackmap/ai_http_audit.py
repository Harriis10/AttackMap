"""Explicit, local QA observation of own nonstreaming OpenAI Responses calls.

No audit is enabled by default. This is a locally trusted observer, not a
cryptographic attestation by the provider. Request bodies/headers are never saved.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid
from datetime import datetime, timezone

ENDPOINT = "http://127.0.0.1:1234/v1"
MODEL = "cyberstag-security-26b-a4b-v1"
DIRECTORY_ENV = "ATTACKMAP_QA_HTTP_AUDIT_DIR"
NONCE_ENV = "ATTACKMAP_QA_HTTP_AUDIT_NONCE"
MAX_BODY = 2 * 1024 * 1024
MAX_EVENTS = 512
MAX_LOG_BYTES = 1024 * 1024


class AuditConfigurationError(ValueError):
    pass


def _local_directory(value: str) -> Path:
    path = Path(value)
    if (not path.is_absolute() or value.startswith(("\\\\", "//"))
            or any(ord(c) < 32 for c in value)
            or any(part in (".", "..") or part.endswith((" ", ".")) for part in value.replace("\\", "/").split("/") if part)):
        raise AuditConfigurationError("QA audit requires an existing absolute local directory")
    if os.name == "nt" and ":" in value[2:]:
        raise AuditConfigurationError("QA audit directory aliases are unsupported")
    if os.name == "nt":
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == 4:
            raise AuditConfigurationError("QA audit requires a local drive")
    try:
        for ancestor in (path, *path.parents):
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise AuditConfigurationError("QA audit directory must not contain links or reparse points")
    except OSError:
        raise AuditConfigurationError("QA audit directory unavailable") from None
    return path


def _safe_id(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) else None


def _output_text(payload: dict) -> str:
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    parts = []
    for item in payload.get("output", []) if isinstance(payload.get("output"), list) else []:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []) if isinstance(item.get("content"), list) else []:
            if isinstance(content, dict) and content.get("type") == "output_text" and isinstance(content.get("text"), str):
                parts.append(content["text"])
    return "\n".join(parts).strip()


class _Observer:
    def __init__(self, directory: Path, nonce: str):
        self.nonce = nonce
        self.lock = threading.RLock()
        self.pending = {}
        self.sequence = 0
        self.log_bytes = 0
        self.failed = False
        # Every client owns a new directory and exclusive files. Never append to
        # an unrelated log, even if the caller reuses its outer QA directory.
        self.directory = directory / f"wp017-{nonce}-{os.getpid()}-{uuid.uuid4().hex}"
        try:
            self.directory.mkdir()
            self.log = self.directory / "http-audit.jsonl"
            with self.log.open("xb"):
                pass
            self._write("audit_started", endpoint=ENDPOINT, model=MODEL)
        except OSError:
            raise AuditConfigurationError("QA audit output could not be created") from None

    def _write(self, event, **fields):
        with self.lock:
            if self.failed:
                raise AuditConfigurationError("QA audit is incomplete")
            self.sequence += 1
            record = dict(schema_version="1.0", event=event, sequence=self.sequence,
                          nonce=self.nonce, pid=os.getpid(), utc=datetime.now(timezone.utc).isoformat(),
                          monotonic_ns=time.monotonic_ns(), **fields)
            data = (json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
            if self.sequence > MAX_EVENTS or self.log_bytes + len(data) > MAX_LOG_BYTES:
                self.failed = True
                raise AuditConfigurationError("QA audit capacity exceeded")
            try:
                with self.log.open("ab") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                self.log_bytes += len(data)
            except OSError:
                self.failed = True
                raise AuditConfigurationError("QA audit write failed") from None

    def request(self, request):
        # Read only the SDK's already materialized JSON to reject a wrong model
        # or streaming request before dispatch. No body or field is persisted.
        if str(request.url) != ENDPOINT + "/responses" or request.method != "POST":
            raise AuditConfigurationError("QA audit permits only local Responses requests")
        try:
            payload = json.loads(request.content)
        except (ValueError, UnicodeError, RuntimeError):
            raise AuditConfigurationError("QA audit requires a nonstreaming JSON request") from None
        if not isinstance(payload, dict) or payload.get("model") != MODEL or payload.get("stream", False) is not False:
            raise AuditConfigurationError("QA audit model or streaming configuration mismatch")
        with self.lock:
            attempt = uuid.uuid4().hex
            self._write("attempted_dispatch", attempt_id=attempt, method=request.method,
                        path="/v1/responses", origin="http://127.0.0.1:1234", model=MODEL)
            self.pending[id(request)] = attempt

    def response(self, response):
        with self.lock:
            attempt = self.pending.pop(id(response.request), None)
        if attempt is None:
            return
        try:
            self._write("http_response_received", attempt_id=attempt, method=response.request.method,
                        path="/v1/responses", status=response.status_code,
                        provider_request_id=_safe_id(response.headers.get("x-request-id")))
            # Current Responses calls are nonstreaming. SDK sees these same
            # cached bytes; no request, header, response or retry is replaced.
            body = response.read()
            fields = dict(attempt_id=attempt, body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body),
                          status=response.status_code, parse_status="unknown", completed=False,
                          model=None, provider_response_id=None, output_sha256=None, output_bytes=0, output_file=None)
            if len(body) <= MAX_BODY:
                try:
                    payload = json.loads(body)
                    if isinstance(payload, dict):
                        text = _output_text(payload)
                        fields.update(parse_status="json", model=MODEL if payload.get("model") == MODEL else "unexpected",
                                      provider_response_id=_safe_id(payload.get("id")),
                                      completed=200 <= response.status_code < 300 and payload.get("status") == "completed"
                                      and payload.get("model") == MODEL and bool(text))
                        if fields["completed"]:
                            generated = text.encode("utf-8")
                            name = f"output-{attempt}.utf8"
                            with (self.directory / name).open("xb") as stream:
                                stream.write(generated)
                                stream.flush()
                                os.fsync(stream.fileno())
                            fields.update(output_sha256=hashlib.sha256(generated).hexdigest(), output_bytes=len(generated), output_file=name)
                except (ValueError, UnicodeError):
                    pass
            self._write("observation_complete", **fields)
        except (OSError, AuditConfigurationError):
            # Explicit QA audit failure must not replace a real provider reply.
            # The unmatched/missing observation_complete makes proof fail closed.
            self.failed = True


def client_audit_options(base_url: str | None) -> dict:
    directory = os.environ.get(DIRECTORY_ENV)
    if not directory:
        return {}
    nonce = os.environ.get(NONCE_ENV, "")
    if base_url != ENDPOINT or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", nonce):
        raise AuditConfigurationError("QA audit requires its exact local endpoint and explicit run nonce")
    observer = _Observer(_local_directory(directory), nonce)
    return {"event_hooks": {"request": [observer.request], "response": [observer.response]}}
