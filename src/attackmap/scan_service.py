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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import typer

from .analyzers import MissingAnalyzersError, select_requested_analyzers
from .anomalies import route_auth_signals
from .contracts import link_contracts
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
from .models import AttackPath, Finding, ScanResult
from .pipeline import AnalyzeOptions, run_scan
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
    install_missing: bool = False
    recall: bool = False
    cve: bool = False
    no_suppress: bool = False
    suppress_file: str | None = None
    suppress_from_ref: str | None = None
    allow_pr_suppressions: bool = False
    strict_suppressions: bool = False
    strict_analyzers: bool = False
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
    hunt: bool = False
    verify: bool = False
    verify_votes: int = 3
    hunt_lenses: int = 1
    hunt_rounds: int = 1
    hunt_budget: int = 0
    remediate: bool = False
    triage: bool = False
    echo: Callable[..., None] = field(default=typer.echo)
    cancel_check: Callable[[], bool] | None = None
    max_workers: int = 1


@dataclass
class RunSummary:
    """Terminal result of ``execute_scan_request``."""

    exit_code: int
    report_path: Path | None = None
    fleet_summary_path: Path | None = None
    error: str | None = None


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
    return AnalyzeOptions(
        repo_path=repo_path,
        output=output,
        output_format=request.output_format,
        analyzers=analyzers,
        recall=request.recall,
        cve=request.cve,
        no_suppress=request.no_suppress,
        suppress_file=request.suppress_file,
        suppress_from_ref=request.suppress_from_ref,
        allow_pr_suppressions=request.allow_pr_suppressions,
        strict_suppressions=request.strict_suppressions,
        strict_analyzers=request.strict_analyzers,
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
        hunt=request.hunt,
        verify=request.verify,
        verify_votes=request.verify_votes,
        hunt_lenses=request.hunt_lenses,
        hunt_rounds=request.hunt_rounds,
        hunt_budget=request.hunt_budget,
        remediate=request.remediate,
        triage=request.triage,
        run_id=request.run_id,
        echo=request.echo,
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
    except typer.BadParameter as exc:
        raise ScanRequestError(str(exc)) from exc
    except typer.Exit as exc:
        return RunSummary(exit_code=exc.exit_code if exc.exit_code is not None else 1)
    except typer.Abort as exc:
        return RunSummary(exit_code=1, error=f"aborted: {exc}")
    except Exception as exc:  # noqa: BLE001 — surface as failed scan
        return RunSummary(exit_code=1, error=f"{type(exc).__name__}: {exc}")

    candidate = Path(request.output) / "attackmap-report.json"
    report_path: Path | None = candidate if candidate.is_file() else None
    return RunSummary(
        exit_code=state.exit_code,
        report_path=report_path,
        error=None,
    )


class _FleetRepoError(Exception):
    """Raised when a single repository in a fleet scan fails."""

    def __init__(self, repo_id: str, root: str, message: str) -> None:
        super().__init__(message)
        self.repo_id = repo_id
        self.root = root
        self.message = message


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
    argv: list[str] = [
        sys.executable,
        "-m",
        "attackmap",
        "analyze",
        str(repo_path),
        "--output",
        str(repo_out),
    ]
    argv.extend(["--format", request.output_format])
    if request.run_id is not None:
        argv.extend(["--run-id", request.run_id])
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
    if request.no_progress:
        argv.append("--no-progress")
    elif request.progress_format != "auto":
        argv.extend(["--progress-format", request.progress_format])
    return argv


def _load_repo_scan(repo_out: Path) -> tuple[ScanResult, list[Finding], list[AttackPath], int]:
    """Load a single repo's result from its worker-written JSON report."""
    report_path = repo_out / "attackmap-report.json"
    if not report_path.is_file():
        raise FileNotFoundError(f"missing report: {report_path}")
    data = json.loads(report_path.read_text(encoding="utf-8"))
    # The canonical report wraps the scan under "scan"; fall back to treating
    # the top-level object as the scan for compact fixtures / test reports.
    scan_data = data.get("scan", data)
    scan = ScanResult.model_validate(scan_data)
    findings = [Finding.model_validate(f) for f in data.get("findings", [])]
    attack_paths = [AttackPath.model_validate(p) for p in data.get("attack_paths", [])]
    suppressed_count = len(data.get("suppressed_findings", []))
    return scan, findings, attack_paths, suppressed_count


def _run_fleet_repo_worker(
    request: ScanRequest,
    repo_id: str,
    repo_path: Path,
    output_root: Path,
    analyzer_names: list[str],
) -> FleetRepoResult:
    """Run one repository in a subprocess and load its JSON report."""
    repo_out = output_root / repo_id
    argv = _run_fleet_repo_argv(request, repo_path, repo_out, analyzer_names)
    completed = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()[-500:] if completed.stderr else ""
        raise _FleetRepoError(
            repo_id,
            str(repo_path),
            f"subprocess exited {completed.returncode}{f' - {stderr}' if stderr else ''}",
        )
    try:
        scan, findings, attack_paths, suppressed_count = _load_repo_scan(repo_out)
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
        request.echo("")
        request.echo(f"── {repo_id}  ({repo_path}) ──")
        try:
            repo_out = output_root / repo_id
            state = run_scan(_analyze_options(request, repo_path, repo_out, analyzers))
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
        except typer.BadParameter as exc:
            raise ScanRequestError(str(exc)) from exc
        except typer.Exit as exc:
            # Usage / policy errors (e.g. --strict-suppressions) should fail the
            # whole fleet rather than be silently swallowed per repo.
            raise ScanRequestError(
                f"{repo_id}: scan exited with code {exc.exit_code}"
            ) from exc
        except typer.Abort as exc:
            raise ScanRequestError(f"{repo_id}: aborted") from exc
        except Exception as exc:  # noqa: BLE001 — one bad repo must not sink the fleet (#217)
            message = f"{type(exc).__name__}: {exc}"
            request.echo(f"Error: {repo_id} failed and was skipped — {message}", err=True)
            fleet.failed.append({"repo_id": repo_id, "root": str(repo_path), "error": message})


def _run_fleet_parallel(
    request: ScanRequest,
    analyzer_names: list[str],
    fleet: FleetScan,
    output_root: Path,
) -> None:
    """Bounded pool of per-repo subprocess workers."""
    max_workers = _effective_max_workers(request)
    repo_ids = fleet_repo_ids(request.repo_paths)
    pending: list[tuple[str, Path]] = [
        (repo_id, repo_path) for repo_id, repo_path in zip(repo_ids, request.repo_paths)
    ]

    request.echo("")
    request.echo(f"Fleet: scanning {len(pending)} repositories with {max_workers} worker(s)...")

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="fleet-") as executor:
        futures: dict[Any, tuple[str, Path]] = {}
        for repo_id, repo_path in pending:
            if request.cancel_check is not None and request.cancel_check():
                # Drain already-submitted work; cancel_check is checked again as
                # results arrive below.
                break
            future = executor.submit(
                _run_fleet_repo_worker,
                request,
                repo_id,
                repo_path,
                output_root,
                analyzer_names,
            )
            futures[future] = (repo_id, repo_path)

        for future in as_completed(futures):
            repo_id, repo_path = futures[future]
            if request.cancel_check is not None and request.cancel_check():
                continue
            try:
                result = future.result()
                fleet.results.append(result)
                request.echo(f"  done {repo_id}  ({repo_path})")
            except _FleetRepoError as exc:
                request.echo(
                    f"Error: {exc.repo_id} failed and was skipped - {exc.message}",
                    err=True,
                )
                fleet.failed.append(
                    {"repo_id": exc.repo_id, "root": exc.root, "error": exc.message}
                )
            except Exception as exc:  # noqa: BLE001 — worker bugs must not sink the fleet
                message = f"{type(exc).__name__}: {exc}"
                request.echo(
                    f"Error: {repo_id} failed and was skipped - {message}", err=True
                )
                fleet.failed.append(
                    {"repo_id": repo_id, "root": str(repo_path), "error": message}
                )


def _finalize_fleet(request: ScanRequest, fleet: FleetScan, output_root: Path) -> RunSummary:
    repo_scans = [(r.repo_id, r.scan) for r in fleet.results]
    fleet.links = link_contracts(repo_scans)
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


def _run_fleet(request: ScanRequest, analyzers: list | None) -> RunSummary:
    output_root = Path(request.output)
    incompatible = _fleet_incompatible_flags(request)
    if incompatible:
        raise ScanRequestError(
            f"{', '.join(sorted(incompatible))} not yet supported in multi-repo mode — "
            "run one repository at a time for these (fleet-aware wiring lands in #146b+)."
        )

    fleet = FleetScan()
    if _effective_max_workers(request) == 1:
        _run_fleet_serial(request, analyzers, fleet, output_root)
    else:
        _run_fleet_parallel(request, _analyzer_names(analyzers), fleet, output_root)

    return _finalize_fleet(request, fleet, output_root)


def execute_scan_request(request: ScanRequest) -> RunSummary:
    """Run one repository or a fleet according to *request*.

    Raises ``ScanRequestError`` for configuration problems. Returns a
    ``RunSummary`` for normal termination (the exit code may be non-zero).
    """
    if not request.repo_paths:
        raise ScanRequestError("At least one repository path is required.")

    try:
        ensure_output_dir(request.output, mark=True)
    except UnsafePathError as exc:
        raise ScanRequestError(str(exc)) from exc

    try:
        analyzers = request.analyzers
        if analyzers is None and request.modules:
            analyzers = select_requested_analyzers(
                request.modules,
                auto_install=request.install_missing,
            )
    except (MissingAnalyzersError, ValueError) as exc:
        raise ScanRequestError(str(exc)) from exc

    if len(request.repo_paths) == 1:
        return _run_single_repo(request, analyzers)
    return _run_fleet(request, analyzers)
