from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

import typer

from .analyzers import (
    TRUSTED_ONLY_ENV,
    MissingAnalyzersError,
    analyzer_install_command,
    get_available_modules,
    get_available_repository_modules,
    install_analyzer_module,
    select_requested_analyzers,
)
from .progress import PROGRESS_PROTOCOL_VERSION
from .scan_service import ScanRequest, ScanRequestError, execute_scan_request
from .review_prompts import HUNT_LENSES
from . import __version__
from .safe_fs import UnsafePathError, ensure_output_dir, safe_write_text
from .report import OUTPUT_FORMATS
from .suggest import detect_ecosystems

app = typer.Typer(help="AttackMap: understand your system and map your attack surface.")


def _select_modules(module: list[str], install_missing: bool) -> list:
    """Resolve `-m` names (#237). Only official, lock-pinned plugins can be
    installed by name, and only with --install-missing or an interactive
    confirmation; otherwise the exact pinned pip command is printed."""
    try:
        return select_requested_analyzers(module, auto_install=False)
    except MissingAnalyzersError as exc:
        commands = [shlex.join(analyzer_install_command(name)) for name in exc.missing]
        interactive = sys.stdin.isatty() and sys.stderr.isatty()
        if install_missing or (
            interactive
            and typer.confirm(
                "Install missing official analyzer(s) at their pinned commits?\n  "
                + "\n  ".join(commands),
                default=False,
                err=True,
            )
        ):
            try:
                return select_requested_analyzers(module, auto_install=True)
            except ValueError as install_exc:
                raise typer.BadParameter(str(install_exc)) from install_exc
        raise typer.BadParameter(
            f"{exc} Install with:\n  " + "\n  ".join(commands) + "\nor re-run with --install-missing."
        ) from exc
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _ensure_output_dir(path: Path, *, mark: bool = False) -> Path:
    try:
        return ensure_output_dir(path, mark=mark)
    except UnsafePathError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc


def _write_text(path: Path, text: str) -> None:
    """Write a CLI artifact without following symlinks (#228)."""
    path = Path(path)
    try:
        safe_write_text(ensure_output_dir(path.parent), path, text)
    except UnsafePathError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"attackmap {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the AttackMap version and exit.",
    ),
) -> None:
    """AttackMap: understand your system and map your attack surface."""

PROGRESS_FORMATS = ("auto", "tty", "json", "none")
LLM_PROVIDERS = ("claude", "openai")
LLM_SPEEDS = ("standard", "fast")
LLM_EFFORTS = ("low", "medium", "high", "xhigh", "max")
LLM_BACKENDS = ("auto", "api", "cli")


def _given(ctx: typer.Context, name: str) -> bool:
    """True when the user passed the option (not just its default)."""
    source = ctx.get_parameter_source(name)
    return source is not None and source.name not in {"DEFAULT", "DEFAULT_MAP"}


def _validate_analyze_options(
    ctx: typer.Context,
    *,
    progress_format: str,
    output_format: str,
    llm_provider: str,
    llm_speed: str,
    llm_effort: str | None,
    llm_backend: str,
    hunt: bool,
    verify: bool,
    verify_votes: int,
    hunt_lenses: int,
    hunt_rounds: int,
    hunt_budget: int,
    baseline: str | None,
    diff_output: str | None,
    secrets_history: int = 0,
) -> None:
    """Reject bad values and orphaned flags before any scanning starts (#229).

    A typo in an LLM option used to surface only after the full scan, CVE
    lookup and report writing; flags whose parent option was missing were
    silently ignored with exit 0.
    """

    def _choice(flag: str, value: str | None, allowed: tuple[str, ...]) -> None:
        if value is not None and value not in allowed:
            raise typer.BadParameter(f"{flag} must be one of: {', '.join(allowed)} (got {value!r}).")

    _choice("--progress-format", progress_format, PROGRESS_FORMATS)
    _choice("--format", output_format, tuple(OUTPUT_FORMATS))
    _choice("--llm-provider", llm_provider, LLM_PROVIDERS)
    _choice("--llm-speed", llm_speed, LLM_SPEEDS)
    _choice("--llm-effort", llm_effort, LLM_EFFORTS)
    _choice("--llm-backend", llm_backend, LLM_BACKENDS)

    hunt_only = ("verify", "verify_votes", "hunt_lenses", "hunt_rounds", "hunt_budget")
    orphaned = [f"--{name.replace('_', '-')}" for name in hunt_only if _given(ctx, name)]
    if orphaned and not hunt:
        verb = "only applies" if len(orphaned) == 1 else "only apply"
        raise typer.BadParameter(f"{', '.join(orphaned)} {verb} with --hunt.")
    if _given(ctx, "diff_output") and diff_output is not None and baseline is None:
        raise typer.BadParameter("--diff-output requires --baseline to be set.")

    if not 0 <= secrets_history <= 5000:
        raise typer.BadParameter(f"--secrets-history must be between 0 (off) and 5000 commits (got {secrets_history}).")
    if verify_votes < 1:
        raise typer.BadParameter(f"--verify-votes must be at least 1 (got {verify_votes}).")
    if not 1 <= hunt_lenses <= len(HUNT_LENSES):
        raise typer.BadParameter(f"--hunt-lenses must be between 1 and {len(HUNT_LENSES)} (got {hunt_lenses}).")
    if hunt_rounds < 1:
        raise typer.BadParameter(f"--hunt-rounds must be at least 1 (got {hunt_rounds}).")
    if hunt_budget < 0:
        raise typer.BadParameter(f"--hunt-budget must be 0 (no cap) or more (got {hunt_budget}).")


def _run_fleet(
    repo_paths: list[Path],
    *,
    output: str,
    module: list[str] | None,
    recall: bool,
    cve: bool,
    no_suppress: bool,
    suppress_file: str | None,
    progress_format: str,
    no_progress: bool,
    fleet_incompatible: dict[str, bool],
    output_format: str = "all",
    install_missing: bool = False,
    suppress_from_ref: str | None = None,
    strict_analyzers: bool = False,
    max_workers: int = 1,
    **single_repo_kwargs: Any,
) -> None:
    """Multi-repo fleet scan adapter around the shared ``execute_scan_request``."""
    active_flags = [flag for flag, on in fleet_incompatible.items() if on]
    if active_flags:
        raise typer.BadParameter(
            f"{', '.join(sorted(active_flags))} not yet supported in multi-repo mode — "
            "run one repository at a time for these (fleet-aware wiring lands in #146b+)."
        )

    selected_analyzers = None
    if module:
        selected_analyzers = _select_modules(module, install_missing)

    request = ScanRequest(
        repo_paths=repo_paths,
        output=Path(output),
        output_format=output_format,
        analyzers=selected_analyzers,
        recall=recall,
        cve=cve,
        no_suppress=no_suppress,
        suppress_file=suppress_file,
        suppress_from_ref=suppress_from_ref,
        strict_analyzers=strict_analyzers,
        progress_format=progress_format,
        no_progress=no_progress,
        max_workers=max_workers,
        **single_repo_kwargs,
    )
    try:
        summary = execute_scan_request(request)
    except ScanRequestError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if summary.exit_code:
        raise typer.Exit(code=summary.exit_code)


@app.command()
def analyze(
    ctx: typer.Context,
    paths: list[str] | None = typer.Argument(
        None,
        help="Path(s) to the repository(ies) to analyze. Pass two or more for a "
        "cross-repo fleet scan (#146a): each is scanned into its own report "
        "subdirectory and a fleet summary is written alongside. Defaults to '.'.",
    ),
    output: str = typer.Option("reports", "--output", "-o", help="Directory for generated reports."),
    format: str = typer.Option(
        "all",
        "--format",
        help="Which report artifacts to write: 'all' (default), 'json' (machine-readable "
        "*.json + SARIF), or 'markdown' (human-readable *.md + Graphviz *.dot). Opt-in "
        "outputs (--baseline diff, --pr-comment, LLM passes) are always written.",
    ),
    module: list[str] | None = typer.Option(
        None,
        "--module",
        "-m",
        help="Analyzer module(s) to run. Repeat to select multiple. A missing official analyzer is installed (at its pinned commit) only with --install-missing or after an interactive confirmation.",
    ),
    install_missing: bool = typer.Option(
        False,
        "--install-missing",
        help="Install missing official analyzers named by --module, pinned to the commits in attackmap's plugin lock.",
    ),
    trusted_analyzers_only: bool = typer.Option(
        False,
        "--trusted-analyzers-only",
        help=f"Load only official AttackMap analyzer plugins; skip any other installed package that registers one (also via {TRUSTED_ONLY_ENV}=1).",
    ),
    llm: bool = typer.Option(
        False,
        "--llm",
        help="Generate a narrative defensive review by calling Claude with the evidence pack. Auth resolves automatically: ANTHROPIC_API_KEY → ANTHROPIC_AUTH_TOKEN → `claude` CLI (subscription auth). Force a backend with --llm-backend.",
    ),
    llm_provider: str = typer.Option(
        "claude",
        "--llm-provider",
        help="LLM provider for --llm/--hunt/--remediate: 'claude' (default, Anthropic) or 'openai' (OpenAI/Codex).",
    ),
    llm_model: str | None = typer.Option(
        None,
        "--llm-model",
        help="Model ID for --llm. Claude provider: e.g. claude-opus-4-8 (default), claude-fable-5, claude-sonnet-5, claude-opus-4-7. OpenAI provider: e.g. gpt-5-codex (default), gpt-5.5, gpt-5.4, gpt-5.4-mini — any model ID is passed through verbatim.",
    ),
    llm_effort: str | None = typer.Option(
        None,
        "--llm-effort",
        help="Effort for --llm: low|medium|high|xhigh|max. Defaults to high. For OpenAI, xhigh/max clamp to high (Responses API reasoning effort tops out at high).",
    ),
    llm_backend: str = typer.Option(
        "auto",
        "--llm-backend",
        help="Which backend --llm uses. Claude: 'auto' tries ANTHROPIC_API_KEY → ANTHROPIC_AUTH_TOKEN → `claude` CLI; 'api' forces the SDK; 'cli' forces the `claude` CLI. OpenAI: 'auto' tries OPENAI_API_KEY then the `codex` CLI; 'api' forces the OpenAI SDK; 'cli' forces `codex exec` (your `codex login` subscription).",
    ),
    llm_speed: str = typer.Option(
        "standard",
        "--llm-speed",
        help="LLM output speed: 'standard' (default) or 'fast'. Fast mode (~2.5x output speed, premium price) applies only to Opus 4.8/4.7 via the API backend; other models/backends fall back to standard.",
    ),
    hunt: bool = typer.Option(
        False,
        "--hunt",
        help="Vulnerability-hypothesis mode (#80): have Claude reason over the full evidence pack as a red-team analyst and propose ranked, human-verifiable exploit-chain HYPOTHESES (leads, not detections) to vulnerability-hypotheses.md. Uses the same LLM auth/backend as --llm.",
    ),
    verify: bool = typer.Option(
        False,
        "--verify",
        help="With --hunt: adjudicate each hypothesis against the actual source at cited locations — CONFIRMED / REFUTED / NEEDS HUMAN REVIEW (#hunt-verify). AttackMap feeds the code excerpts to the model.",
    ),
    verify_votes: int = typer.Option(
        3,
        "--verify-votes",
        help="With --hunt --verify: number of independent skeptic passes to adjudicate each hypothesis. A lead is CONFIRMED only on a strict majority (NEEDS_REVIEW only if a majority flags the evidence insufficient); ties/uncertainty are REFUTED (#147a). 1 = the classic single-pass verify.",
    ),
    hunt_lenses: int = typer.Option(
        1,
        "--hunt-lenses",
        help="With --hunt --verify: run N independent generation passes, each specialised in a distinct failure mode (auth-bypass, TOCTOU, IDOR, deserialization, SSRF, secret-misuse), then dedupe across them before verifying (#147b). 1 = a single generalist pass. Costs one extra LLM call per lens.",
    ),
    hunt_rounds: int = typer.Option(
        1,
        "--hunt-rounds",
        help="With --hunt --verify: loop generation for up to N rounds, accumulating new (deduped) leads while a completeness critic seeds each next round with untried angles; stops early once a round finds nothing new (#147c). 1 = a single round.",
    ),
    hunt_budget: int = typer.Option(
        0,
        "--hunt-budget",
        help="With --hunt-rounds: stop launching new hunting rounds once this many output tokens have been spent (0 = no budget cap). A guardrail on multi-round cost.",
    ),
    remediate: bool = typer.Option(
        False,
        "--remediate",
        help="Remediation mode (#106): have Claude propose concrete, review-first fixes per finding (suggested diffs / precise instructions, grounded in evidence) to remediation.md. Uses the same LLM auth/backend as --llm.",
    ),
    triage: bool = typer.Option(
        False,
        "--triage",
        help="Triage mode (#145): cluster, de-duplicate, and rank the EXISTING heuristic findings into a prioritized shortlist (citing real finding IDs) at triage.md. LLM-backed when available; degrades to a deterministic score-ordered fallback when no backend is present.",
    ),
    recall: bool = typer.Option(
        False,
        "--recall",
        help="Recall mode (#148a): widen taint discovery — deeper import-hop depth and surfacing reaches the default pass conservatively hides. The extra reach is marked SPECULATIVE and kept out of --fail-on-new-high; pair with --hunt --verify to adjudicate it. Off by default (higher recall, lower precision).",
    ),
    baseline: str | None = typer.Option(
        None,
        "--baseline",
        help="Path to a prior `attackmap-report.json`. When set, emit a diff (new/persisted/resolved) alongside the fresh report.",
    ),
    diff_output: str | None = typer.Option(
        None,
        "--diff-output",
        help="Path to write the Markdown diff. Defaults to <output>/attackmap-diff.md when --baseline is set.",
    ),
    fail_on_new_high: bool = typer.Option(
        False,
        "--fail-on-new-high",
        help="Exit non-zero if the diff introduces any new HIGH-severity findings. Requires --baseline.",
    ),
    suppress_from_ref: str | None = typer.Option(
        None,
        "--suppress-from-ref",
        help="Trust only suppressions that exist at this git ref (e.g. the PR's base branch). Suppress-file entries and inline directives added since are reported as pending and not applied.",
    ),
    allow_pr_suppressions: bool = typer.Option(
        False,
        "--allow-pr-suppressions",
        help="With --suppress-from-ref, apply suppressions added since the ref anyway (they are still listed).",
    ),
    strict_suppressions: bool = typer.Option(
        False,
        "--strict-suppressions",
        help="Exit 2 if any suppression has expired (past its `expires:` / `until=` date).",
    ),
    strict_analyzers: bool = typer.Option(
        False,
        "--strict-analyzers",
        help="Fail fast if any analyzer raises or returns an invalid result, instead of skipping it and listing it under analyzer_errors (for plugin development and CI).",
    ),
    fail_on_new_suppression: bool = typer.Option(
        False,
        "--fail-on-new-suppression",
        help="Exit non-zero if a finding active in the baseline is suppressed in this run (e.g. a suppression added by the PR). Requires --baseline.",
    ),
    secrets_history: int = typer.Option(
        0,
        "--secrets-history",
        help="Also scan the patches of the last N commits (all refs) for hard-coded secrets, reporting the introducing commit and whether each is still in HEAD. Off by default (0); capped at 5000 commits and 64 MB of patch text. Git runs with hooks, pagers, external diff and textconv disabled.",
    ),
    cve: bool = typer.Option(
        False,
        "--cve",
        help="Cross-reference SBOM entries against OSV.dev and surface vulnerable dependencies as findings. Cached under ~/.attackmap/cache/osv/ (24h TTL). Off by default because it does network I/O.",
    ),
    no_progress: bool = typer.Option(
        False,
        "--no-progress",
        help="Disable the live progress bar / ETA during scanning. Progress auto-disables when stderr isn't a terminal (CI, piped output).",
    ),
    progress_format: str = typer.Option(
        "auto",
        "--progress-format",
        help="Progress reporting: 'auto' (TTY bar when stderr is a terminal), 'tty' (always the bar), 'json' (newline-delimited JSON events on stderr, for GUI/tool front-ends), or 'none'. --no-progress is equivalent to 'none'.",
    ),
    pr_comment: str | None = typer.Option(
        None,
        "--pr-comment",
        help="Write a Markdown PR summary comment to this path (for the GitHub Action / bot to post). Includes the baseline diff and top exploitability when available.",
    ),
    no_suppress: bool = typer.Option(
        False,
        "--no-suppress",
        help="Ignore all suppressions — the .attackmap-suppress.yaml baseline and inline `attackmap:ignore` directives (#144). Use for a full, unfiltered audit.",
    ),
    suppress_file: str | None = typer.Option(
        None,
        "--suppress-file",
        help="Path to a suppression baseline, overriding auto-discovery of .attackmap-suppress.yaml at the repo root (#144).",
    ),
    run_id: str | None = typer.Option(
        None,
        "--run-id",
        help="Optional run identifier written into artifact-manifest.json. Useful for GUI/CI correlation.",
    ),
    fleet_workers: int = typer.Option(
        1,
        "--fleet-workers",
        help="Maximum parallel repository scans in multi-repo mode. Default 1 (serial). "
        "Capped by ATTACKMAP_FLEET_MAX_WORKERS if set.",
    ),
) -> None:
    repo_paths = [Path(p).resolve() for p in (paths or ["."])]
    for rp in repo_paths:
        if not rp.exists():
            raise typer.BadParameter(f"Path does not exist: {rp}")

    # Validate progress format before either branch, so the fleet path enforces
    # the same option semantics as a single-repo run (#146a).
    if trusted_analyzers_only and os.environ.get(TRUSTED_ONLY_ENV) != "1":
        previous = os.environ.get(TRUSTED_ONLY_ENV)
        os.environ[TRUSTED_ONLY_ENV] = "1"

        def _restore_trust_env() -> None:
            if previous is None:
                os.environ.pop(TRUSTED_ONLY_ENV, None)
            else:
                os.environ[TRUSTED_ONLY_ENV] = previous

        ctx.call_on_close(_restore_trust_env)
    _validate_analyze_options(
        ctx,
        progress_format=progress_format,
        output_format=format,
        llm_provider=llm_provider,
        llm_speed=llm_speed,
        llm_effort=llm_effort,
        llm_backend=llm_backend,
        hunt=hunt,
        verify=verify,
        verify_votes=verify_votes,
        hunt_lenses=hunt_lenses,
        hunt_rounds=hunt_rounds,
        hunt_budget=hunt_budget,
        baseline=baseline,
        diff_output=diff_output,
        secrets_history=secrets_history,
    )

    # Multi-repo fleet mode (#146a): scan each repo independently and assemble a
    # fleet view. Dispatched here so the single-repo path below is untouched.
    if len(repo_paths) > 1:
        _run_fleet(
            repo_paths,
            output=output,
            module=module,
            recall=recall,
            cve=cve,
            no_suppress=no_suppress,
            suppress_file=suppress_file,
            progress_format=progress_format,
            no_progress=no_progress,
            output_format=format,
            install_missing=install_missing,
            suppress_from_ref=suppress_from_ref,
            strict_analyzers=strict_analyzers,
            allow_pr_suppressions=allow_pr_suppressions,
            strict_suppressions=strict_suppressions,
            run_id=run_id,
            max_workers=fleet_workers,
            # Single-repo-only features aren't fleet-aware yet — reject rather
            # than silently ignore, so the user isn't surprised (#146b+ wire them).
            fleet_incompatible={
                "--baseline": baseline is not None,
                "--diff-output": diff_output is not None,
                "--fail-on-new-high": fail_on_new_high,
                "--fail-on-new-suppression": fail_on_new_suppression,
                "--pr-comment": pr_comment is not None,
                "--llm": llm,
                "--hunt": hunt,
                "--remediate": remediate,
                "--triage": triage,
                "--secrets-history": secrets_history > 0,
            },
        )
        return

    selected_analyzers = None
    if module:
        selected_analyzers = _select_modules(module, install_missing)
    request = ScanRequest(
        repo_paths=repo_paths,
        output=Path(output),
        output_format=format,
        analyzers=selected_analyzers,
        recall=recall,
        cve=cve,
        no_suppress=no_suppress,
        suppress_file=suppress_file,
        suppress_from_ref=suppress_from_ref,
        allow_pr_suppressions=allow_pr_suppressions,
        strict_suppressions=strict_suppressions,
        strict_analyzers=strict_analyzers,
        progress_format=progress_format,
        no_progress=no_progress,
        secrets_history=secrets_history,
        baseline=baseline,
        diff_output=diff_output,
        fail_on_new_high=fail_on_new_high,
        fail_on_new_suppression=fail_on_new_suppression,
        pr_comment=pr_comment,
        run_id=run_id,
        llm=llm,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_effort=llm_effort,
        llm_backend=llm_backend,
        llm_speed=llm_speed,
        hunt=hunt,
        verify=verify,
        verify_votes=verify_votes,
        hunt_lenses=hunt_lenses,
        hunt_rounds=hunt_rounds,
        hunt_budget=hunt_budget,
        remediate=remediate,
        triage=triage,
    )
    try:
        summary = execute_scan_request(request)
    except ScanRequestError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if summary.exit_code:
        raise typer.Exit(code=summary.exit_code)



CAPABILITIES_SCHEMA_VERSION = 1


@app.command("capabilities")
def capabilities() -> None:
    """Describe what this CLI supports, for GUIs and wrappers.

    Front-ends (e.g. the macOS app) used to scrape `analyze --help`, which
    breaks when help wording or terminal width changes. This prints a stable
    JSON document instead: the version, the subcommands, every long option
    `analyze` accepts, and whether `analyze` takes multiple repo paths.
    """
    root = typer.main.get_command(app)
    commands = getattr(root, "commands", {})
    analyze_cmd = commands.get("analyze")
    options: set[str] = set()
    multi_repo = False
    for param in getattr(analyze_cmd, "params", []):
        for opt in [*getattr(param, "opts", []), *getattr(param, "secondary_opts", [])]:
            if opt.startswith("--"):
                options.add(opt)
        if getattr(param, "param_type_name", "") == "argument" and getattr(param, "nargs", 1) == -1:
            multi_repo = True
    payload = {
        "schema": CAPABILITIES_SCHEMA_VERSION,
        "version": __version__,
        "commands": sorted(commands),
        "analyze": {"options": sorted(options), "multi_repo": multi_repo},
        "progress_protocol": PROGRESS_PROTOCOL_VERSION,
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command("modules")
def modules(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the installed analyzer modules as a JSON array "
        "(name/display_name/description/scope/ecosystems/enabled_by_default). "
        "Network-free — the remote module-repository section is omitted. "
        "Intended for tool / GUI front-ends that offer analyzer selection.",
    ),
) -> None:
    available_modules = get_available_modules()
    if json_output:
        payload = [
            {
                "name": meta.name,
                "display_name": meta.display_name or meta.name,
                "description": meta.description,
                "scope": meta.scope,
                "ecosystems": list(meta.ecosystems),
                "enabled_by_default": meta.enabled_by_default,
                "priority": meta.priority,
                "experimental": meta.experimental,
            }
            for meta in available_modules
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    if not available_modules:
        typer.echo("No analyzer modules are currently available.")
    else:
        typer.echo("Available analyzer modules (installed, in run order):")
        for module_metadata in available_modules:
            ecosystems = ", ".join(module_metadata.ecosystems) if module_metadata.ecosystems else "none"
            mode = "default" if module_metadata.enabled_by_default else f"opt-in (-m {module_metadata.name})"
            typer.echo(f"- {module_metadata.name}: {module_metadata.description}")
            typer.echo(f"  scope: {module_metadata.scope}")
            typer.echo(f"  ecosystems: {ecosystems}")
            typer.echo(f"  priority: {module_metadata.priority}  runs: {mode}")
            if module_metadata.experimental and module_metadata.enabled_by_default:
                typer.echo("  note: experimental but enabled by default")

    typer.echo("")
    typer.echo("Available module repositories (mlaify GitHub org):")
    try:
        repository_modules = get_available_repository_modules()
    except ValueError as exc:
        typer.echo(f"- Unable to fetch remote module repositories: {exc}")
        return

    if not repository_modules:
        typer.echo("- No module repositories were discovered.")
        return

    for module in repository_modules:
        typer.echo(f"- {module.analyzer_name} ({module.repo_name})")
        typer.echo(f"  repo: {module.web_url}")


@app.command("suggest")
def suggest(
    path: str = typer.Argument(".", help="Path to the repository to inspect."),
    install: bool = typer.Option(
        False,
        "--install",
        help="After printing, offer to `pip install` the missing recommended plugins.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt when used with --install.",
    ),
    show_installed: bool = typer.Option(
        False,
        "--show-installed",
        help="Include already-installed plugins in the output (marked accordingly).",
    ),
) -> None:
    """Recommend analyzer plugins for the shape of the given repository."""
    repo = Path(path).resolve()
    if not repo.exists() or not repo.is_dir():
        typer.echo(f"Path does not exist or is not a directory: {repo}")
        raise typer.Exit(code=1)

    suggestions = detect_ecosystems(repo)
    missing = [s for s in suggestions if not s.installed]
    installed = [s for s in suggestions if s.installed]

    if not suggestions:
        typer.echo(f"No AttackMap plugins matched the shape of {repo}.")
        raise typer.Exit(code=0)

    shown = suggestions if show_installed else missing
    if not shown:
        typer.echo("All recommended plugins are already installed:")
        for s in installed:
            typer.echo(f"  - {s.plugin} (installed)")
        raise typer.Exit(code=0)

    typer.echo(f"Recommended plugins for {repo}:")
    for s in shown:
        tag = " (installed)" if s.installed else ""
        typer.echo(f"  - {s.plugin}{tag}")
        typer.echo(f"      matches: {', '.join(s.matched_signals)}")
        if not s.installed:
            typer.echo(f"      install: {s.pip_install}")

    if not install:
        return
    if not missing:
        typer.echo("Nothing to install — all recommended plugins are already present.")
        return

    typer.echo("")
    typer.echo("The following plugins will be installed via pip:")
    for s in missing:
        typer.echo(f"  - {s.plugin}")
    if not yes and not typer.confirm("Proceed?", default=False):
        typer.echo("Aborted.")
        raise typer.Exit(code=1)

    for s in missing:
        typer.echo(f"Installing {s.plugin}…")
        try:
            install_analyzer_module(s.plugin)
        except Exception as exc:  # noqa: BLE001 — surface pip failures verbatim
            typer.echo(f"  Failed: {exc}")
            raise typer.Exit(code=1) from exc
    typer.echo("Done.")


@app.command("rules")
def rules(
    as_json: bool = typer.Option(False, "--json", help="Emit the rule catalog as JSON."),
) -> None:
    """List every core detector's stable rule id (#223) — the SARIF ruleId and
    the value for `rule:` suppressions and `attackmap:ignore[...]`."""
    from .threat_model import rule_catalog

    catalog = rule_catalog()
    if as_json:
        typer.echo(json.dumps([{"rule_id": r, "title": t, "severity": sev} for r, t, sev in catalog], indent=2))
        return
    width = max(len(r) for r, _, _ in catalog)
    for rule_id, title, severity in catalog:
        typer.echo(f"{rule_id.ljust(width)}  {severity:<7}  {title}")


@app.command("bench")
def bench(
    benchmark: str = typer.Option(
        "evals/benchmark/benchmark.json",
        "--benchmark",
        help="Path to the benchmark manifest (labeled ground-truth corpus).",
    ),
    root: str = typer.Option(
        ".",
        "--root",
        help="Repository root the manifest's case paths are relative to.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Directory to write benchmark-results.md + .json (also printed to stdout).",
    ),
    fail_under: float | None = typer.Option(
        None,
        "--fail-under",
        help="Exit non-zero if any scored detector class falls below this precision/recall (0-1). For CI regression gating.",
    ),
) -> None:
    """Score AttackMap findings against the labeled benchmark corpus (#197).

    The 1.0 precision gate: reports precision/recall/F1 per detector class.
    Contributor/CI tool — run from the repo root (the manifest ships in `evals/`,
    not the installed wheel).
    """
    from .bench import bench_json, load_benchmark, min_scored_metric, render_markdown, run_benchmark

    manifest = Path(benchmark)
    if not manifest.exists():
        typer.echo(f"Benchmark manifest not found: {manifest}")
        typer.echo("Pass --benchmark <path>, or run from a checkout that has evals/benchmark/.")
        raise typer.Exit(code=2)

    results = run_benchmark(load_benchmark(manifest), root)
    markdown = render_markdown(results)
    typer.echo(markdown)

    if output:
        out = Path(output)
        _ensure_output_dir(out)
        _write_text(out / "benchmark-results.md", markdown + "\n")
        _write_text(out / "benchmark-results.json", json.dumps(bench_json(results), indent=2) + "\n")
        typer.echo(f"Written to: {out.resolve()}")

    errored = [r.id for r in results if r.error]
    if errored:
        typer.echo(f"Cases that failed to scan: {', '.join(errored)}")
        raise typer.Exit(code=1)

    if fail_under is not None:
        worst = min_scored_metric(results)
        if worst < fail_under:
            typer.echo(f"FAIL: lowest scored precision/recall {worst:.2f} < --fail-under {fail_under:.2f}")
            raise typer.Exit(code=1)
        typer.echo(f"OK: lowest scored precision/recall {worst:.2f} ≥ --fail-under {fail_under:.2f}")


@app.command("ui")
def ui() -> None:
    """Open the Windows desktop GUI (WebView2 window, loopback-hosted)."""
    from .ui.launch import main

    main()


if __name__ == "__main__":
    app()
