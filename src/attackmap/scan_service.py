"""Shared scan orchestration used by the CLI and the GUI worker.

This module deliberately does not depend on Typer/Click for its core logic;
adapters in ``attackmap.cli`` and ``attackmap.ui.server`` convert between
application-specific I/O and the neutral ``ScanRequest`` / ``RunSummary`` contract.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from .application_errors import AnalysisAborted, AnalysisConfigurationError, AnalysisExit, emit_text

from .analyzers import MissingAnalyzersError, select_requested_analyzers
from .anomalies import route_auth_signals
from .contracts import DeploymentAliases, link_contracts
from .crossrepo import (
    find_cross_boundary_flows,
    find_cross_repo_anomalies,
    find_trust_gaps,
)
from .fleet import (
    FleetRepoResult,
    FleetScan,
    fleet_repo_ids,
    fleet_summary_json,
    render_fleet_graph_mermaid,
    render_fleet_summary,
)
from .fleet_admission import (FleetAdmissionError, FleetMemoryLedger, FleetMemoryPolicy,
                              current_reservation, reservation_scope, unverified_fleet_cleanup)
from .models import AttackPath, Finding, ScanResult
from .pipeline import AnalyzeOptions, ScanAiLimits, run_scan
from .run_contract import RunRequest
from .safe_fs import UnsafePathError, ensure_output_dir, safe_write_text


class ScanRequestError(Exception):
    """Validation or configuration error raised before any repository is scanned."""


@dataclass
class ScanRequest:
    """Neutral scan request consumed by ``execute_scan_request``."""

    repo_paths: list[Path]
    output: Path
    output_format: str = "all"
    modules: list[str] = field(default_factory=list)
    analyzers: list | None = None
    analyzer_profile_id: str | None = None
    install_missing: bool = False
    recall: bool = False
    cve: bool = False
    no_suppress: bool = False
    suppress_file: str | None = None
    suppress_from_ref: str | None = None
    allow_pr_suppressions: bool = False
    strict_suppressions: bool = False
    strict_analyzers: bool = False
    isolated_analyzers: bool = False
    # C34/AM048: activate the per-file incremental cache (default off).
    incremental: bool = False
    time_budget_seconds: int | None = None
    progress_format: str = "auto"
    no_progress: bool = False
    secrets_history: int = 0
    run_id: str | None = None
    baseline: str | None = None
    diff_output: str | None = None
    fail_on_new_high: bool = False
    fail_on_new_suppression: bool = False
    pr_comment: str | None = None
    llm: bool = False
    llm_provider: str = "claude"
    llm_model: str | None = None
    llm_effort: str | None = None
    llm_backend: str = "auto"
    llm_speed: str = "standard"
    desktop_ai_mode: str | None = None
    hunt: bool = False
    verify: bool = False
    verify_votes: int = 3
    hunt_lenses: int = 1
    hunt_rounds: int = 1
    hunt_budget: int = 0
    remediate: bool = False
    triage: bool = False
    ai_limits: ScanAiLimits = field(default_factory=ScanAiLimits)
    echo: Callable[..., None] = field(default=emit_text)
    cancel_check: Callable[[], bool] | None = None
    max_workers: int = 1
    fleet_result: Path | None = None
    atomic_output: bool = True
    # Optional desktop fleet transport; ordinary CLI requests retain their path.
    fleet_supervised: bool = False
    fleet_timeout_seconds: int = 600
    fleet_child_run_ids: dict[str, str] = field(default_factory=dict)
    fleet_event: Callable[[dict], None] | None = None
    fleet_finished: Callable[[Path, FleetScan], None] | None = None
    # Opt-in only until current-scope working peaks qualify a measured default.
    fleet_memory_policy: FleetMemoryPolicy | None = None
    # Explicit deployment alias declarations for cross-repo link resolution
    # (C28): positive host→repo mappings; never inferred by similarity.
    deployment_aliases: DeploymentAliases | None = None
    # Append new options after legacy fields to preserve positional callers.
    # Optional aggregate captured-input limit; distinct from working-set memory.
    fleet_input_byte_budget: int | None = None


@dataclass
class RunSummary:
    """Terminal result of ``execute_scan_request``."""

    exit_code: int
    report_path: Path | None = None
    fleet_summary_path: Path | None = None
    error: str | None = None


def scan_request_from_run(request: RunRequest, *, echo: Callable[..., None] = emit_text) -> ScanRequest:
    """Translate the versioned single-repository contract without orchestration policy."""
    options = request.options
    provider = options.provider
    from .desktop_ai import service_ai_options
    ai = service_ai_options(provider)
    extended = {name: getattr(options, name, None if name in {"baseline", "suppress_file", "time_budget_seconds"} else False)
                for name in ("baseline", "suppress_file", "fail_on_new_high", "fail_on_new_suppression",
                             "strict_suppressions", "isolated_analyzers", "time_budget_seconds")}
    return ScanRequest(repo_paths=[Path(request.repository_path)], output=Path(request.output_path),
        output_format="all", modules=list(request.modules), install_missing=False,
        analyzer_profile_id=getattr(options, "analyzer_profile", None),
        recall=options.recall, cve=options.cve, no_suppress=options.no_suppress,
        strict_analyzers=options.strict_analyzers, secrets_history=options.secrets_history,
        run_id=request.run_id, progress_format="json", atomic_output=False,
        **ai, ai_limits=ScanAiLimits(max_calls=provider.max_calls,
            timeout_seconds=provider.timeout_seconds, output_token_limit=provider.output_token_limit),
        echo=echo, **extended)


def _fleet_incompatible_flags(request: ScanRequest) -> list[str]:
    active: list[str] = []
    if request.baseline is not None:
        active.append("--baseline")
    if request.diff_output is not None:
        active.append("--diff-output")
    if request.fail_on_new_high:
        active.append("--fail-on-new-high")
    if request.fail_on_new_suppression:
        active.append("--fail-on-new-suppression")
    if request.pr_comment is not None:
        active.append("--pr-comment")
    if request.llm:
        active.append("--llm")
    if request.hunt:
        active.append("--hunt")
    if request.remediate:
        active.append("--remediate")
    if request.triage:
        active.append("--triage")
    if request.secrets_history > 0:
        active.append("--secrets-history")
    return active


def _analyze_options(
    request: ScanRequest,
    repo_path: Path,
    output: Path,
    analyzers: list | None,
) -> AnalyzeOptions:
    # Explicit False from a desktop request must override inherited CLI env.
    extra: dict[str, Any] = {"incremental": request.incremental}
    return AnalyzeOptions(
        repo_path=repo_path,
        output=output,
        output_format=request.output_format,
        atomic_output=request.atomic_output,
        analyzers=analyzers,
        analyzer_profile_id=request.analyzer_profile_id,
        recall=request.recall,
        cve=request.cve,
        no_suppress=request.no_suppress,
        suppress_file=request.suppress_file,
        suppress_from_ref=request.suppress_from_ref,
        allow_pr_suppressions=request.allow_pr_suppressions,
        strict_suppressions=request.strict_suppressions,
        strict_analyzers=request.strict_analyzers,
        isolated_analyzers=request.isolated_analyzers,
        progress_format=request.progress_format,
        no_progress=request.no_progress,
        secrets_history=request.secrets_history,
        baseline=request.baseline,
        diff_output=request.diff_output,
        fail_on_new_high=request.fail_on_new_high,
        fail_on_new_suppression=request.fail_on_new_suppression,
        pr_comment=request.pr_comment,
        llm=request.llm,
        llm_provider=request.llm_provider,
        llm_model=request.llm_model,
        llm_effort=request.llm_effort,
        llm_backend=request.llm_backend,
        llm_speed=request.llm_speed,
        desktop_ai_mode=request.desktop_ai_mode,
        hunt=request.hunt,
        verify=request.verify,
        verify_votes=request.verify_votes,
        hunt_lenses=request.hunt_lenses,
        hunt_rounds=request.hunt_rounds,
        hunt_budget=request.hunt_budget,
        remediate=request.remediate,
        triage=request.triage,
        ai_limits=request.ai_limits,
        time_budget_seconds=request.time_budget_seconds,
        run_id=request.run_id,
        echo=request.echo,
        **extra,
    )


def _write_artifact(path: Path, text: str) -> None:
    path = Path(path)
    try:
        safe_write_text(ensure_output_dir(path.parent), path, text)
    except UnsafePathError as exc:
        raise ScanRequestError(str(exc)) from exc


def _run_single_repo(request: ScanRequest, analyzers: list | None) -> RunSummary:
    repo_path = request.repo_paths[0]
    try:
        state = run_scan(_analyze_options(request, repo_path, request.output, analyzers))
    except AnalysisConfigurationError as exc:
        if request.fleet_result is not None:
            _write_artifact(request.fleet_result, json.dumps({
                "error_kind": "configuration", "error": str(exc),
            }))
        raise ScanRequestError(str(exc)) from exc
    except AnalysisExit as exc:
        return RunSummary(exit_code=exc.exit_code if exc.exit_code is not None else 1)
    except AnalysisAborted as exc:
        return RunSummary(exit_code=1, error=f"aborted: {exc}")
    except UnsafePathError as exc:
        raise ScanRequestError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface as failed scan
        return RunSummary(exit_code=1, error=f"{type(exc).__name__}: {exc}")

    if request.fleet_result is not None and state.exit_code == 0:
        assert state.scan is not None
        payload = {
            "scan": state.scan.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in state.findings],
            "attack_paths": [p.model_dump(mode="json") for p in state.paths],
            "suppressed_count": len(state.suppressed),
        }
        _write_artifact(request.fleet_result, json.dumps(payload, ensure_ascii=False))

    report_root = Path(request.output)
    if request.atomic_output:
        from .artifact_publisher import current_generation
        published = current_generation(report_root)
        if published is None:
            return RunSummary(exit_code=state.exit_code, report_path=None,
                              error="Published result is unavailable or failed integrity validation.")
        report_root = published
    candidate = report_root / "attackmap-report.json"
    report_path: Path | None = candidate if candidate.is_file() else None
    return RunSummary(
        exit_code=state.exit_code,
        report_path=report_path,
        error=None,
    )


class _FleetRepoError(Exception):
    """Raised when a single repository in a fleet scan fails."""

    def __init__(self, repo_id: str, root: str, message: str, error_type: str = "fleet_worker_failed") -> None:
        super().__init__(message)
        self.repo_id = repo_id
        self.root = root
        self.message = message
        self.error_type = error_type


def _effective_max_workers(request: ScanRequest) -> int:
    """Return the bounded worker count for fleet subprocess parallelism."""
    if request.max_workers <= 1:
        return 1
    requested = request.max_workers
    env_cap = os.environ.get("ATTACKMAP_FLEET_MAX_WORKERS")
    if env_cap:
        try:
            cap = int(env_cap)
        except ValueError as exc:
            raise ScanRequestError(
                f"ATTACKMAP_FLEET_MAX_WORKERS must be an integer, got {env_cap!r}"
            ) from exc
        if cap < 1:
            cap = 1
        requested = min(requested, cap)
    # Never spawn more workers than repositories; a single worker is the
    # serial fallback and avoids the ThreadPoolExecutor overhead.
    return max(1, min(requested, len(request.repo_paths)))


def _analyzer_names(analyzers: list | None) -> list[str]:
    """Resolve a list of analyzer objects or module names to slugs."""
    if analyzers is None:
        return []
    names: list[str] = []
    for analyzer in analyzers:
        name = getattr(analyzer, "name", None)
        if not name and hasattr(analyzer, "metadata"):
            name = analyzer.metadata.name
        if name:
            names.append(name)
    return names


def _run_fleet_repo_argv(
    request: ScanRequest,
    repo_path: Path,
    repo_out: Path,
    analyzer_names: list[str],
) -> list[str]:
    """Build the CLI argv for a per-repo subprocess worker."""
    prefix = (
        [sys.executable] if getattr(sys, "frozen", False)
        else [sys.executable, "-m", "attackmap"]
    )
    argv: list[str] = [
        *prefix,
        "analyze",
        str(repo_path),
        "--output",
        str(repo_out),
    ]
    argv.extend(["--format", request.output_format])
    argv.extend(["--ai-max-calls", str(request.ai_limits.max_calls),
                 "--ai-output-tokens", str(request.ai_limits.output_token_limit),
                 "--ai-timeout-seconds", str(request.ai_limits.timeout_seconds)])
    if request.run_id is not None:
        argv.extend(["--run-id", request.run_id])
    if request.analyzer_profile_id is not None:
        argv.extend(["--analyzer-profile", request.analyzer_profile_id])
    else:
        for name in analyzer_names:
            argv.extend(["--module", name])
        for module in request.modules:
            argv.extend(["--module", module])
    if request.install_missing:
        argv.append("--install-missing")
    if request.recall:
        argv.append("--recall")
    if request.cve:
        argv.append("--cve")
    if request.no_suppress:
        argv.append("--no-suppress")
    if request.suppress_file is not None:
        argv.extend(["--suppress-file", request.suppress_file])
    if request.suppress_from_ref is not None:
        argv.extend(["--suppress-from-ref", request.suppress_from_ref])
    if request.allow_pr_suppressions:
        argv.append("--allow-pr-suppressions")
    if request.strict_suppressions:
        argv.append("--strict-suppressions")
    if request.strict_analyzers:
        argv.append("--strict-analyzers")
    if request.isolated_analyzers:
        argv.append("--isolated-analyzers")
    if request.fleet_supervised and request.time_budget_seconds is not None:
        argv.extend(["--time-budget-seconds", str(request.time_budget_seconds)])
    if request.incremental:
        # The worker re-parses the flag and sets ATTACKMAP_INCREMENTAL itself,
        # so the subprocess scan activates the per-file cache (C34/AM048).
        argv.append("--incremental")
    if request.no_progress:
        argv.append("--no-progress")
    elif request.progress_format != "auto":
        argv.extend(["--progress-format", request.progress_format])
    return argv


def _read_fleet_payload(report_path: Path, max_bytes: int | None = None):
    if max_bytes is None:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    else:
        with report_path.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise FleetAdmissionError("fleet_result_bytes", "Worker result exceeds its explicitly reserved payload limit")
        data = json.loads(raw)
    return data


def _load_repo_scan(report_path: Path, *, max_bytes: int | None = None,
                    index_byte_budget: int | None = None) -> tuple[ScanResult, list[Finding], list[AttackPath], int]:
    """Load a single repo's result from its worker-written JSON report."""
    data = _read_fleet_payload(report_path, max_bytes)
    # The canonical report wraps the scan under "scan"; fall back to treating
    # the top-level object as the scan for compact fixtures / test reports.
    scan_data = data.get("scan", data)
    if index_byte_budget is not None:
        snapshot = scan_data.get("scan_snapshot")
        config = snapshot.get("index_config") if isinstance(snapshot, dict) else None
        size = snapshot.get("total_size") if isinstance(snapshot, dict) else None
        if (type(size) is not int or not 0 <= size <= index_byte_budget
                or not isinstance(config, dict) or type(config.get("index_byte_budget")) is not int
                or config["index_byte_budget"] != index_byte_budget):
            raise FleetAdmissionError("fleet_input_budget_unverified",
                "Worker result does not bind captured input bytes to its assigned quota")
    scan = ScanResult.model_validate(scan_data)
    findings = [Finding.model_validate(f) for f in data.get("findings", [])]
    attack_paths = [AttackPath.model_validate(p) for p in data.get("attack_paths", [])]
    suppressed_count = data.get("suppressed_count", len(data.get("suppressed_findings", [])))
    return scan, findings, attack_paths, suppressed_count


def _run_supervised_worker(
    argv: list[str], cancel_check: Callable[[], bool] | None = None,
    *, on_progress: Callable[[dict], None] | None = None, timeout: int = 600,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Wait for a bounded-output worker, including verified cancellation cleanup."""
    from .execution import ProcessSupervisor

    def terminal(code: int, tail: str, *, verified: bool = True):
        outcome = subprocess.CompletedProcess(argv, code, "", tail)
        outcome.cleanup_verified = verified
        return outcome

    if cancel_check is not None and cancel_check():
        return terminal(130, "Worker cancelled before launch.")
    supervisor = ProcessSupervisor()
    reservation = current_reservation()
    result: list[subprocess.CompletedProcess[str]] = []

    def complete(code: int, tail: str) -> None:
        if reservation is not None:
            reservation.ledger.verified_cleanup(reservation)
        result.append(terminal(130 if supervisor.cancelled else code, tail))

    extra = {"on_progress": on_progress} if on_progress is not None else {}
    if env is not None:
        extra["env"] = env
    started = supervisor.start(argv, on_done=complete, timeout=timeout, **extra)
    if not started and not supervisor.running:
        return result[0] if result else terminal(1, supervisor.stderr_tail)
    cleanup_deadline: float | None = None
    try:
        while not supervisor.wait(0.1):
            if cancel_check is not None and cancel_check():
                supervisor.request_cancel()
                cleanup_deadline = cleanup_deadline or time.monotonic() + 15
            if getattr(supervisor, "timed_out", False):
                cleanup_deadline = cleanup_deadline or time.monotonic() + 15
            if current_reservation() is not None and ("termination could not be verified" in getattr(supervisor, "stderr_tail", "") or (
                cleanup_deadline is not None and time.monotonic() >= cleanup_deadline
            )):
                # Preserve ownership across this return. A late verified callback
                # releases the quarantine; future completion alone cannot do so.
                reservation.ledger.settle(reservation, cleanup_verified=False, keep_result=False)
                return terminal(1, "Worker process-tree cleanup could not be verified; admission remains occupied.", verified=False)
    except BaseException:
        supervisor.request_cancel()
        # Do not let an interrupted caller abandon its owned process tree.
        while not supervisor.wait(0.1):
            pass
        raise
    return result[0]


def _run_fleet_repo_worker(
    request: ScanRequest,
    repo_id: str,
    repo_path: Path,
    output_root: Path,
    analyzer_names: list[str],
    *, index_byte_budget: int | None = None,
) -> FleetRepoResult:
    """Run one repository in a subprocess and load its JSON report."""
    repo_out = output_root / repo_id
    if repo_id in request.fleet_child_run_ids:
        request = replace(request, run_id=request.fleet_child_run_ids[repo_id])
    argv = _run_fleet_repo_argv(request, repo_path, repo_out, analyzer_names)
    worker_options = {}
    if index_byte_budget is not None:
        try:
            inherited_limit = int(os.environ.get("ATTACKMAP_INDEX_BYTE_BUDGET", "0") or "0")
        except ValueError as exc:
            raise ScanRequestError("ATTACKMAP_INDEX_BYTE_BUDGET must be an integer") from exc
        if inherited_limit > 0:
            index_byte_budget = min(index_byte_budget, inherited_limit)
        # Never change process-global environment while siblings are launching.
        worker_options["env"] = {**os.environ, "ATTACKMAP_INDEX_BYTE_BUDGET": str(index_byte_budget)}
    # Interchange lives outside report/source directories and is removed even
    # when a child fails. Presentation format never controls this payload.
    with tempfile.TemporaryDirectory(prefix="attackmap-fleet-") as worker_dir:
        result_path = Path(worker_dir) / "result.json"
        argv.extend(["--fleet-result", str(result_path)])
        reservation = current_reservation()
        if reservation is not None:
            reservation.process_cleanup_verified = False
        if request.fleet_event is not None:
            request.fleet_event({"repo_id": repo_id, "state": "running"})
            completed = _run_supervised_worker(argv, cancel_check=request.cancel_check,
                on_progress=lambda event: request.fleet_event({"repo_id": repo_id,
                    "state": "running", "progress": event}),
                timeout=request.fleet_timeout_seconds, **worker_options)
        else:
            completed = _run_supervised_worker(argv, cancel_check=request.cancel_check,
                                               timeout=request.fleet_timeout_seconds, **worker_options)
        if reservation is not None:
            reservation.process_cleanup_verified = getattr(completed, "cleanup_verified", False) is True
            if not reservation.process_cleanup_verified:
                raise FleetAdmissionError("fleet_cleanup_unknown", "Worker termination unverified; reservation retained")
        if completed.returncode != 0:
            # A usage error applies to the request; policy/analysis failures
            # remain per-repository failures even when their exit code is 2.
            if result_path.is_file():
                try:
                    failure = _read_fleet_payload(result_path,
                        reservation.estimate.result_bytes_limit if reservation is not None else None)
                except FleetAdmissionError:
                    raise
                except (ValueError, OSError):
                    failure = None
                if isinstance(failure, dict) and failure.get("error_kind") == "configuration":
                    raise ScanRequestError(f"{repo_id}: {failure.get('error', 'invalid request')}")
            stderr = completed.stderr.strip()[-500:] if completed.stderr else ""
            raise _FleetRepoError(
                repo_id, str(repo_path),
                f"subprocess exited {completed.returncode}{f' - {stderr}' if stderr else ''}",
            )
        try:
            scan, findings, attack_paths, suppressed_count = _load_repo_scan(result_path,
                **({"max_bytes": reservation.estimate.result_bytes_limit} if reservation is not None else {}),
                **({"index_byte_budget": index_byte_budget} if index_byte_budget is not None else {}))
        except FleetAdmissionError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface parse/load errors as a repo failure
            raise _FleetRepoError(
                repo_id, str(repo_path), f"failed to load report: {type(exc).__name__}: {exc}"
            ) from exc

    return FleetRepoResult(
        repo_id=repo_id,
        root=str(repo_path),
        report_dir=str(repo_out.resolve()),
        scan=scan,
        findings=findings,
        attack_paths=attack_paths,
        suppressed_count=suppressed_count,
    )


def _run_fleet_serial(
    request: ScanRequest,
    analyzers: list | None,
    fleet: FleetScan,
    output_root: Path,
) -> None:
    """Sequential per-repo scan used when max_workers == 1."""
    for repo_id, repo_path in zip(fleet_repo_ids(request.repo_paths), request.repo_paths):
        if request.cancel_check is not None and request.cancel_check():
            break
        request.echo("")
        request.echo(f"── {repo_id}  ({repo_path}) ──")
        try:
            repo_out = output_root / repo_id
            state = run_scan(_analyze_options(request, repo_path, repo_out, analyzers))
            if state.exit_code != 0:
                raise RuntimeError(f"scan exited with code {state.exit_code}")
            assert state.scan is not None
            fleet.results.append(
                FleetRepoResult(
                    repo_id=repo_id,
                    root=str(repo_path),
                    report_dir=str(repo_out.resolve()),
                    scan=state.scan,
                    findings=state.findings,
                    attack_paths=state.paths,
                    suppressed_count=len(state.suppressed),
                )
            )
        except AnalysisConfigurationError as exc:
            raise ScanRequestError(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 — one bad repo must not sink the fleet (#217)
            message = f"{type(exc).__name__}: {exc}"
            request.echo(f"Error: {repo_id} failed and was skipped — {message}", err=True)
            fleet.failed.append({"repo_id": repo_id, "root": str(repo_path), "error": message})


def _fleet_input_quotas(total: int | None, repo_ids: list[str]) -> dict[str, int] | None:
    if total is None:
        return None
    if type(total) is not int or total <= 0:
        raise ScanRequestError("Fleet input byte budget must be a positive integer")
    if not repo_ids:
        return {}
    share, remainder = divmod(total, len(repo_ids))
    # Reserve every quota for the whole run. Completion, failure and cancellation
    # do not redistribute it, so scheduling cannot alter source acceptance.
    return {repo_id: share + int(index < remainder) for index, repo_id in enumerate(repo_ids)}


def _run_fleet_parallel(
    request: ScanRequest,
    analyzer_names: list[str],
    fleet: FleetScan,
    output_root: Path,
) -> dict:
    """Bounded pool of per-repo subprocess workers."""
    max_workers = _effective_max_workers(request)
    repo_ids = fleet_repo_ids(request.repo_paths)
    input_quotas = _fleet_input_quotas(request.fleet_input_byte_budget, repo_ids)
    pending: list[tuple[str, Path]] = [
        (repo_id, repo_path) for repo_id, repo_path in zip(repo_ids, request.repo_paths)
    ]
    ledger = FleetMemoryLedger(request.fleet_memory_policy) if request.fleet_memory_policy is not None else None

    request.echo("")
    request.echo(f"Fleet: scanning {len(pending)} repositories with {max_workers} worker(s)...")

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="fleet-") as executor:
        futures: dict[Any, tuple[str, Path]] = {}
        remaining = deque(pending)

        def admission_failure(repo_id: str, repo_path: Path, exc: FleetAdmissionError):
            fleet.failed.append({"repo_id": repo_id, "root": str(repo_path),
                                 "error": str(exc), "error_type": exc.kind})
            request.echo(f"Error: {repo_id} not admitted — {exc}", err=True)
            if request.fleet_event is not None:
                request.fleet_event({"repo_id": repo_id, "state": "failed", "error_type": exc.kind})

        def reserved_worker(repo_id: str, repo_path: Path, reservation):
            keep_result = False
            try:
                with reservation_scope(reservation):
                    if request.cancel_check is not None and request.cancel_check():
                        raise FleetAdmissionError("fleet_admission_cancelled", "Child cancelled before dispatch")
                    result = _run_fleet_repo_worker(request, repo_id, repo_path, output_root, analyzer_names,
                        **({"index_byte_budget": input_quotas[repo_id]} if input_quotas is not None else {}))
                    keep_result = True
                    return result
            finally:
                if reservation is not None:
                    ledger.settle(reservation, cleanup_verified=reservation.process_cleanup_verified,
                                  keep_result=keep_result)

        def admit() -> bool:
            if request.cancel_check is not None and request.cancel_check():
                if ledger is not None:
                    ledger.cancel()
                while remaining:
                    repo_id, repo_path = remaining.popleft()
                    admission_failure(repo_id, repo_path, FleetAdmissionError(
                        "fleet_admission_cancelled", "Repository not started because fleet was cancelled"))
                return False
            while remaining:
                repo_id, repo_path = remaining[0]
                try:
                    if input_quotas is not None and input_quotas[repo_id] == 0:
                        raise FleetAdmissionError("fleet_input_capacity",
                            "Repository not started because its aggregate input quota is zero bytes")
                    reservation = ledger.reserve(repo_id) if ledger is not None else None
                except FleetAdmissionError as exc:
                    remaining.popleft()
                    admission_failure(repo_id, repo_path, exc)
                    continue
                if ledger is not None and reservation is None:
                    return False  # live workers may free capacity; keep input order
                remaining.popleft()
                try:
                    future = executor.submit(reserved_worker, repo_id, repo_path, reservation)
                except BaseException:
                    if reservation is not None:
                        ledger.settle(reservation, cleanup_verified=True, keep_result=False)
                    raise
                futures[future] = (repo_id, repo_path)
                return True
            return False

        for _ in range(max_workers):
            if not admit():
                break
        while futures:
            completed, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in completed:
                repo_id, repo_path = futures.pop(future)
                try:
                    result = future.result()
                    fleet.results.append(result)
                    if request.fleet_event is not None:
                        request.fleet_event({"repo_id": repo_id, "state": "completed"})
                    request.echo(f"  done {repo_id}  ({repo_path})")
                except ScanRequestError:
                    raise
                except _FleetRepoError as exc:
                    request.echo(
                        f"Error: {exc.repo_id} failed and was skipped - {exc.message}",
                        err=True,
                    )
                    fleet.failed.append(
                        {"repo_id": exc.repo_id, "root": exc.root, "error": exc.message,
                         "error_type": exc.error_type}
                    )
                    if request.fleet_event is not None:
                        request.fleet_event({"repo_id": repo_id, "state": "failed"})
                except FleetAdmissionError as exc:
                    admission_failure(repo_id, repo_path, exc)
                except Exception as exc:  # noqa: BLE001 — worker bugs must not sink the fleet
                    message = f"{type(exc).__name__}: {exc}"
                    request.echo(
                        f"Error: {repo_id} failed and was skipped - {message}", err=True
                    )
                    fleet.failed.append(
                        {"repo_id": repo_id, "root": str(repo_path), "error": message}
                    )
                    if request.fleet_event is not None:
                        request.fleet_event({"repo_id": repo_id, "state": "failed"})
            while len(futures) < max_workers and admit():
                pass

    # Completion order must not change normalized fleet output.
    order = {repo_id: index for index, repo_id in enumerate(repo_ids)}
    fleet.results.sort(key=lambda result: order[result.repo_id])
    fleet.failed.sort(key=lambda failure: order[failure["repo_id"]])
    admission = ledger.snapshot() if ledger is not None else {
        "policy": "count_only", "memory_qualification": "unknown", "os_enforced": False,
        "limitation": "Worker count and deadlines do not bound fleet or retained-parent memory"}
    admission.update(worker_limit=max_workers, hard_worker_timeout_seconds=request.fleet_timeout_seconds)
    if input_quotas is not None:
        admission["input_bytes"] = {
            "policy": "fixed_per_repository_quotas", "total_bytes": request.fleet_input_byte_budget,
            "allocated_bytes": sum(input_quotas.values()), "repository_quotas": input_quotas,
            "verified_captured_bytes": sum(result.scan.scan_snapshot.total_size for result in fleet.results),
            "capture_status": "partial" if fleet.failed or any(
                event.category == "index_bytes" for result in fleet.results
                for event in result.scan.resource_limit_events) else "within_quotas",
            "limitation": "Captured input bytes do not bound worker or retained-parent working-set memory",
        }
    return admission


def _effective_deployment_aliases(
    request: ScanRequest,
) -> tuple[DeploymentAliases | None, list[str]]:
    """Resolve the fleet's deployment-seam declarations (C28).

    Precedence is simple: config-file extraction (k8s manifests, compose
    files, nginx upstream configs across the fleet's repos) provides the base,
    and CLI declarations override config entries with the same key — an
    operator flag beats a file. If the two sources claim conflicting
    topologies for one host (e.g. a CLI host alias vs a config proxy), the CLI
    positive set alone is used: it is authoritative and was validated at parse
    time. Unresolved proxy/protocol evidence survives either path: a positive alias
    cannot establish host-wide routing that the extractor could not model.
    Returns the effective aliases (``None`` when nothing declares anything)
    plus user-facing notes about skipped or conflicting extractions.
    """
    from .config_scanner import extract_deployment_aliases

    extracted, notes = extract_deployment_aliases(request.repo_paths)
    cli = request.deployment_aliases
    if cli is None:
        if not any((extracted.hosts, extracted.host_ports, extracted.dns_suffixes,
                    extracted.service_ports, extracted.service_protocols, extracted.proxies,
                    extracted.scoped_services, extracted.scoped_proxies,
                    extracted.unresolved_proxies, extracted.unresolved_service_protocols)):
            return None, notes
        return extracted, notes

    unresolved = tuple(sorted(set(extracted.unresolved_proxies) | set(cli.unresolved_proxies)))
    unresolved_protocols = tuple(sorted(set(extracted.unresolved_service_protocols)
                                       | set(cli.unresolved_service_protocols)))
    scoped_overrides = (set(cli.hosts) | set(cli.proxies) | set(cli.scoped_proxies)
                        | {binding.rpartition(":")[0] for binding in cli.host_ports})

    def overridden(key: str) -> bool:
        # A CLI re-declaration must not keep the config file's provenance.
        return (
            (key.startswith("hosts:") and key[len("hosts:"):] in cli.hosts)
            or (key.startswith("host_ports:") and key[len("host_ports:"):] in cli.host_ports)
            or (key.startswith("proxies:") and key[len("proxies:"):] in cli.proxies)
            or (key.startswith("scoped_proxies:") and key[len("scoped_proxies:"):] in scoped_overrides)
            or (key.startswith("scoped_services:") and key[len("scoped_services:"):] in cli.scoped_services)
            or any(key.startswith(f"service_ports:{name}:") for name in cli.service_ports)
            or any(key.startswith(f"service_protocols:{name}:") for name in cli.service_protocols)
        )

    def merged_declaration_sources(include_config: bool) -> dict:
        sources = {key: value for key, value in extracted.declaration_sources.items()
                   if include_config and not overridden(key)}
        sources.update(cli.declaration_sources)
        for name in unresolved_protocols:
            key = f"unresolved_service_protocols:{name}"
            retained = set(extracted.declaration_sources.get(key, ())) | set(sources.get(key, ()))
            if retained:
                sources[key] = tuple(sorted(retained, key=lambda source: (
                    source.repository_root, source.file, source.line or 0)))
        return sources

    try:
        merged = DeploymentAliases(
            hosts={**extracted.hosts, **cli.hosts},
            host_ports={**extracted.host_ports, **cli.host_ports},
            dns_suffixes=tuple(extracted.dns_suffixes)
            + tuple(s for s in cli.dns_suffixes if s not in extracted.dns_suffixes),
            proxies={**extracted.proxies, **cli.proxies},
            service_ports={**extracted.service_ports, **cli.service_ports},
            service_protocols={**extracted.service_protocols, **cli.service_protocols},
            source_files={
                **{key: path for key, path in extracted.source_files.items() if not overridden(key)},
                **cli.source_files,
            },
            declaration_sources=merged_declaration_sources(include_config=True),
            unresolved_proxies=unresolved,
            scoped_services={**extracted.scoped_services, **cli.scoped_services},
            scoped_proxies={**{host: scope for host, scope in extracted.scoped_proxies.items()
                              if host not in scoped_overrides}, **cli.scoped_proxies},
            unresolved_service_protocols=unresolved_protocols,
        )
    except ValueError as exc:
        notes.append(
            "config-extracted declarations conflicted with CLI declarations "
            f"({exc}); using CLI declarations only; retaining unresolved proxy/protocol evidence"
        )
        negative_keys = {f"unresolved_service_protocols:{name}" for name in unresolved_protocols}
        negative_sources = {key: value for key, value in extracted.source_files.items()
                            if key in negative_keys}
        return replace(cli, unresolved_proxies=unresolved,
                       unresolved_service_protocols=unresolved_protocols,
                       source_files={**cli.source_files, **negative_sources},
                       declaration_sources=merged_declaration_sources(include_config=False)), notes
    return merged, notes


def _finalize_fleet(request: ScanRequest, fleet: FleetScan, output_root: Path) -> RunSummary:
    repo_scans = [(r.repo_id, r.scan) for r in fleet.results]
    aliases, alias_notes = _effective_deployment_aliases(request)
    for note in alias_notes:
        request.echo(f"Config extraction: {note}")
    fleet.links = link_contracts(repo_scans, aliases=aliases)
    fleet.cross_boundary = find_cross_boundary_flows(fleet.links, repo_scans)
    auth_by_repo = {r.repo_id: route_auth_signals(r.scan, r.root) for r in fleet.results}
    fleet.trust_gaps = find_trust_gaps(fleet.links, repo_scans, auth_by_repo)
    fleet.cross_repo_anomalies = find_cross_repo_anomalies(repo_scans, auth_by_repo)

    emit_markdown = request.output_format in {"all", "markdown"}
    if emit_markdown:
        _write_artifact(output_root / "fleet-summary.md", render_fleet_summary(fleet) + "\n")
        _write_artifact(
            output_root / "fleet-graph.md",
            render_fleet_graph_mermaid(fleet) + "\n",
        )
    if request.output_format in {"all", "json"}:
        _write_artifact(
            output_root / "fleet-summary.json",
            json.dumps(fleet_summary_json(fleet), indent=2) + "\n",
        )
    summary_name = "fleet-summary.md" if emit_markdown else "fleet-summary.json"
    request.echo("")
    request.echo(
        f"Fleet: {fleet.repo_count} repositories, {fleet.total_findings()} finding(s), "
        f"{len(fleet.links)} cross-repo link(s), "
        f"{len(fleet.cross_boundary)} cross-boundary + {len(fleet.trust_gaps)} trust-gap + "
        f"{len(fleet.cross_repo_anomalies)} anomaly (all speculative). "
        f"Summary written to: {(output_root / summary_name).resolve()}"
    )
    if fleet.failed:
        request.echo(
            f"{len(fleet.failed)} repository scan(s) failed: "
            f"{', '.join(f['repo_id'] for f in fleet.failed)}",
            err=True,
        )

    return RunSummary(
        exit_code=1 if fleet.failed else 0,
        fleet_summary_path=output_root / summary_name,
        error=None,
    )


def _run_fleet_generation(request: ScanRequest, analyzers: list | None) -> RunSummary:
    if unverified_fleet_cleanup():
        raise ScanRequestError("Previous fleet process-tree cleanup remains unverified; no new fleet can start")
    output_root = Path(request.output)
    incompatible = _fleet_incompatible_flags(request)
    if incompatible:
        raise ScanRequestError(
            f"{', '.join(sorted(incompatible))} not yet supported in multi-repo mode — "
            "run one repository at a time for these (fleet-aware wiring lands in #146b+)."
        )

    fleet = FleetScan()
    fleet_started = time.perf_counter()
    # The parent may itself be staged by a desktop caller, but child results
    # always need independently verified, manifest-bound generations.
    child_request = replace(request, atomic_output=True)
    if (_effective_max_workers(request) == 1 and not request.fleet_supervised
            and request.fleet_memory_policy is None and request.fleet_input_byte_budget is None):
        _run_fleet_serial(child_request, analyzers, fleet, output_root)
        admission = {"policy": "in_process_serial", "memory_qualification": "unknown", "os_enforced": False,
                     "limitation": "No current-scope measured memory reservation or hard worker deadline"}
    else:
        admission = _run_fleet_parallel(child_request, _analyzer_names(analyzers), fleet, output_root)
    fleet_duration = (time.perf_counter() - fleet_started) * 1000

    from .diagnostics import fleet_diagnostic
    from .safe_fs import safe_write_text
    cancelled = bool(request.cancel_check and request.cancel_check())
    completed = {result.repo_id: result for result in fleet.results}
    failed = {result["repo_id"] for result in fleet.failed}
    context = fleet_diagnostic(
        duration_milliseconds=round(fleet_duration),
        outcome="cancelled" if cancelled else "failed" if failed else "completed",
        requested_count=len(request.repo_paths),
        children=[{"index": index,
                   "outcome": "completed" if repo_id in completed else "failed" if repo_id in failed else "unknown",
                   "scan": completed[repo_id].scan if repo_id in completed else None}
                  for index, repo_id in enumerate(fleet_repo_ids(request.repo_paths))],
    )
    safe_write_text(output_root, output_root / "run-manifest.json", json.dumps({
        "stages": [{"name": "fleet", "milliseconds": round(fleet_duration, 3)}],
        "diagnostic_context": context.model_dump(mode="json"),
        "fleet_resource_admission": admission,
    }) + "\n")

    summary = _finalize_fleet(replace(request, output_format="all"), fleet, output_root)
    if request.fleet_finished is not None:
        request.fleet_finished(output_root, fleet)
    summary.fleet_summary_path = output_root / (
        "fleet-summary.json" if request.output_format == "json" else "fleet-summary.md")
    if not summary.exit_code and not (request.cancel_check and request.cancel_check()):
        from . import __version__
        from .artifact_publisher import write_fleet_manifest
        write_fleet_manifest(output_root, output_root.name, engine_version=__version__,
                             repo_roots=[str(path.resolve()) for path in request.repo_paths])
    return summary


def _run_fleet(request: ScanRequest, analyzers: list | None) -> RunSummary:
    if not request.atomic_output:
        return _run_fleet_generation(request, analyzers)
    from .artifact_manifest import make_run_id
    from .artifact_publisher import (
        diagnostic_context_from_generation, export_compatibility, generation_dir, publish_generation, write_diagnostic,
    )
    from .diagnostics import unknown_diagnostic
    base = Path(request.output)
    run_id = request.run_id or make_run_id()
    stage = generation_dir(base, run_id)
    ensure_output_dir(stage, mark=True)
    staged = replace(request, output=stage, run_id=run_id, atomic_output=False)
    def diagnostic(state: str) -> None:
        context = diagnostic_context_from_generation(base, run_id, outcome=state)
        write_diagnostic(base, run_id, state=state,
                         context=context or unknown_diagnostic("fleet", outcome=state))
    try:
        summary = _run_fleet_generation(staged, analyzers)
        cancelled = bool(request.cancel_check and request.cancel_check())
        if summary.exit_code or cancelled:
            diagnostic("cancelled" if cancelled else "failed")
            if cancelled:
                summary.exit_code = 130
            return summary
        publish_generation(base, run_id, cancelled=request.cancel_check)
    except InterruptedError:
        diagnostic("cancelled")
        summary.exit_code = 130
        return summary
    except BaseException as exc:
        try:
            diagnostic("cancelled" if isinstance(exc, KeyboardInterrupt) else "failed")
        except (OSError, ValueError):
            pass
        raise
    try:
        export_compatibility(base, stage, output_format=request.output_format)
    except (OSError, ValueError):
        request.echo("Warning: flat fleet export failed; the published generation remains available.", err=True)
    from .retention import retain_after_publish
    retain_after_publish(base, echo=request.echo)
    summary.fleet_summary_path = stage / (
        "fleet-summary.json" if request.output_format == "json" else "fleet-summary.md")
    return summary


def execute_scan_request(request: ScanRequest) -> RunSummary:
    """Run one repository or a fleet according to *request*.

    Raises ``ScanRequestError`` for configuration problems. Returns a
    ``RunSummary`` for normal termination (the exit code may be non-zero).
    """
    validation_started = time.perf_counter()
    if not request.repo_paths:
        validation_duration = round((time.perf_counter() - validation_started) * 1000)
        if request.atomic_output:
            from .artifact_manifest import make_run_id
            from .artifact_publisher import write_diagnostic
            from .diagnostics import startup_diagnostic
            try:
                write_diagnostic(request.output, request.run_id or make_run_id(), state="failed",
                    error="Request configuration unavailable.",
                    context=startup_diagnostic("request_validation",
                        duration_milliseconds=validation_duration))
            except (OSError, ValueError):
                pass  # Diagnostic storage cannot mask the typed request error.
        raise ScanRequestError("At least one repository path is required.")

    if request.fleet_input_byte_budget is not None:
        _fleet_input_quotas(request.fleet_input_byte_budget, fleet_repo_ids(request.repo_paths))
        if len(request.repo_paths) < 2:
            raise ScanRequestError("Fleet input byte budget requires at least two repository paths")

    try:
        if request.atomic_output:
            from .artifact_publisher import prepare_output_root
            prepare_output_root(request.output)
        else:
            ensure_output_dir(request.output, mark=True)
    except UnsafePathError as exc:
        raise ScanRequestError(str(exc)) from exc

    selection_started = time.perf_counter()
    try:
        analyzers = request.analyzers
        if request.analyzer_profile_id is not None:
            from .analyzer_profiles import get_analyzer_profiles, resolve_analyzer_profile
            from .analyzers import get_registered_analyzers, get_analyzer_metadata
            if request.modules or request.install_missing:
                raise ValueError("Analyzer profiles cannot be combined with explicit modules or installation")
            definition = next((p for p in get_analyzer_profiles()
                               if request.analyzer_profile_id in (p.name, p.qualified_name)), None)
            if definition is None:
                raise ValueError("Unknown analyzer profile")
            request.analyzer_profile_id = definition.qualified_name
            if definition.selection_mode == "automatic":
                if analyzers is not None:
                    raise ValueError("Automatic profile cannot override an explicit analyzer list")
            else:
                registered = analyzers if analyzers is not None else get_registered_analyzers()
                metadata = [get_analyzer_metadata(a) for a in registered]
                if any(a.name != meta.name for a, meta in zip(registered, metadata)):
                    raise ValueError("Analyzer runtime names do not match their declared metadata; profile unavailable.")
                selection = resolve_analyzer_profile(definition.qualified_name, metadata)
                by_name = {a.name: a for a in registered}
                analyzers = [by_name[name] for name in selection.module_names]
        if analyzers is None and request.modules:
            analyzers = select_requested_analyzers(
                request.modules,
                auto_install=request.install_missing,
            )
    except (MissingAnalyzersError, ValueError) as exc:
        selection_duration = round((time.perf_counter() - selection_started) * 1000)
        if request.atomic_output:
            from .artifact_manifest import make_run_id
            from .artifact_publisher import write_diagnostic
            from .diagnostics import startup_diagnostic
            try:
                write_diagnostic(request.output, request.run_id or make_run_id(), state="failed",
                                 error="Requested analyzer configuration unavailable.",
                                 context=startup_diagnostic("select_analyzers",
                                     duration_milliseconds=selection_duration,
                                     requested_analyzers=request.modules))
            except (OSError, ValueError):
                pass  # Preserve the typed configuration failure if diagnostics cannot be written.
        raise ScanRequestError(str(exc)) from exc

    if len(request.repo_paths) == 1:
        return _run_single_repo(request, analyzers)
    return _run_fleet(request, analyzers)
