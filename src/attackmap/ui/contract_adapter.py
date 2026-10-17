"""Explicit Windows snapshot adapter, not a worker-native run protocol."""
from __future__ import annotations

import threading
from typing import Any

from ..run_contract import (
    SUPPORTED_SCHEMA_VERSIONS, RunProgress, RunTerminal, accepts_update,
)


class LegacyRunContractAdapter:
    """Assign session-local identity/revisions to locked LoopbackApp snapshots.

    Callers must pass the real lifecycle state because the legacy status string
    conflates cancellation and failure. No process exit-code interpretation or
    artifact-integrity inference happens here.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._generations: dict[tuple[str, str], int] = {}
        self._messages: dict[tuple[str, str], RunProgress | RunTerminal] = {}

    def snapshot(self, snapshot: dict[str, Any], *, run_state: str | None = None) -> dict[str, Any] | None:
        with self._lock:
            return self._snapshot(snapshot, run_state=run_state)

    def _snapshot(self, snapshot: dict[str, Any], *, run_state: str | None) -> dict[str, Any] | None:
        run_id, repository_id = snapshot.get("runId"), snapshot.get("repositoryKey")
        if not isinstance(run_id, str) or not run_id or not isinstance(repository_id, str) or not repository_id:
            return None
        state = run_state if run_state is not None else snapshot.get("status")
        state = {"done": "completed", "succeeded": "completed"}.get(state, state)
        if state == "idle":
            return None
        if state not in {"queued", "running", "cancelling", "completed", "failed", "cancelled"}:
            raise ValueError(f"Unsupported Windows run state: {state!r}")
        identity = (repository_id, run_id)
        generation = self._generations.setdefault(identity, len(self._generations) + 1)
        previous = self._messages.get(identity)
        common = dict(run_id=run_id, repository_id=repository_id, generation=generation,
                      revision=previous.revision if previous else 0)
        if state in {"queued", "running", "cancelling"}:
            progress = snapshot.get("progress")
            progress = progress if isinstance(progress, dict) else {}
            label = progress.get("label", "")
            # Stage/done events do not establish a bounded whole-run total.
            done, total = progress.get("done"), progress.get("total")
            bounded = (progress.get("event") in {"begin", "advance"}
                       and type(total) is int and total >= 0
                       and type(done) is int and 0 <= done <= total)
            message = RunProgress(**common, state=state, stage=label if isinstance(label, str) else "",
                                  completed_units=done if bounded else None,
                                  total_units=total if bounded else None)
        else:
            error = snapshot.get("error")
            message = RunTerminal(
                **common, state=state,
                execution_outcome={"completed":"succeeded", "failed":"failed", "cancelled":"cancelled"}[state],
                error=error if isinstance(error, str) else None,
                limitations=["Windows legacy snapshot adapter; revisions are session-local; policy outcome and artifact integrity are unverified."],
            )
        if previous is not None and previous.model_dump() != message.model_dump():
            message = message.model_copy(update={"revision": previous.revision + 1})
            if not accepts_update(previous, message):
                message = previous
        self._messages[identity] = message
        return {
            "scope": "windows-legacy-adapter",
            "supportedSchemaVersions": list(SUPPORTED_SCHEMA_VERSIONS),
            "legacyGeneration": snapshot.get("reportGeneration") if snapshot.get("reportRepositoryKey") == repository_id else None,
            "message": message.model_dump(mode="json"),
        }
