"""Scan options and CLI argument vectors, matching the macOS ScanConfig."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VALUE_FLAGS = {
    "--output",
    "--format",
    "--progress-format",
    "--module",
    "-m",
    "--llm-provider",
    "--llm-model",
    "--llm-effort",
    "--llm-speed",
    "--llm-backend",
    "--suppress-file",
    "--verify-votes",
    "--hunt-lenses",
    "--hunt-rounds",
    "--hunt-budget",
    "--baseline",
    "--diff-output",
    "--pr-comment",
}

JURY_DEFAULTS = {"verifyVotes": 3, "lenses": 1, "rounds": 1, "budget": 0}


@dataclass
class ScanConfig:
    repos: list[Path]
    output: Path
    run_cve: bool = False
    modules: list[str] = field(default_factory=list)
    llm_mode: str = "none"
    provider: str = "claude"
    model: str | None = None
    effort: str | None = None
    fast: bool = False
    recall: bool = False
    no_suppress: bool = False
    suppress_file: Path | None = None
    jury: dict[str, Any] = field(default_factory=dict)
    baseline: Path | None = None
    diff_output: Path | None = None
    fail_on_new_high: bool = False
    pr_comment: Path | None = None
    capabilities: set[str] | None = None

    @property
    def fleet(self) -> bool:
        return len(self.repos) > 1

    def cli_args(self) -> list[str]:
        repos = [str(path.resolve()) for path in self.repos]
        args = ["analyze", *repos, "--format", "all", "--output", str(self.output), "--progress-format", "json"]
        if self.run_cve:
            args.append("--cve")
        if self.recall:
            args.append("--recall")
        if self.no_suppress:
            args.append("--no-suppress")
        if self.suppress_file is not None:
            args.extend(["--suppress-file", str(self.suppress_file)])
        for module in self.modules:
            if module and module.lower() not in {"auto"}:
                args.extend(["--module", module])
        if not self.fleet:
            args.extend(self._llm_flags())
            if self.baseline is not None:
                args.extend(["--baseline", str(self.baseline)])
                if self.diff_output is not None:
                    args.extend(["--diff-output", str(self.diff_output)])
                if self.fail_on_new_high:
                    args.append("--fail-on-new-high")
            if self.pr_comment is not None:
                args.extend(["--pr-comment", str(self.pr_comment)])
        if self.capabilities is not None:
            args = filter_unknown_flags(args, self.capabilities)
        return args

    def _llm_flags(self) -> list[str]:
        mode = self.llm_mode
        if mode in {"none", "None (heuristic only)", ""}:
            return []
        flags: list[str] = []
        if mode == "review":
            flags.append("--llm")
        elif mode == "hunt":
            flags.append("--hunt")
        elif mode in {"huntVerify", "hunt+verify"}:
            flags.extend(["--hunt", "--verify"])
            jury = {**JURY_DEFAULTS, **(self.jury or {})}
            if int(jury.get("verifyVotes", 3)) != 3:
                flags.extend(["--verify-votes", str(jury["verifyVotes"])])
            if int(jury.get("lenses", 1)) != 1:
                flags.extend(["--hunt-lenses", str(jury["lenses"])])
            if int(jury.get("rounds", 1)) != 1:
                flags.extend(["--hunt-rounds", str(jury["rounds"])])
            if int(jury.get("budget", 0)) > 0:
                flags.extend(["--hunt-budget", str(jury["budget"])])
        elif mode == "remediate":
            flags.append("--remediate")
        elif mode == "triage":
            flags.append("--triage")
        elif str(mode).lower().startswith("openai") or str(mode).lower().startswith("anthropic"):
            flags.append("--llm")
        if self.provider == "openai" or str(mode).lower().startswith("openai"):
            flags.extend(["--llm-provider", "openai"])
            if self.model:
                flags.extend(["--llm-model", self.model])
            if self.effort:
                flags.extend(["--llm-effort", self.effort])
        else:
            if self.model:
                flags.extend(["--llm-model", self.model])
            if self.effort:
                flags.extend(["--llm-effort", self.effort])
            if self.fast:
                flags.extend(["--llm-speed", "fast"])
        return flags


def filter_unknown_flags(args: list[str], allowed: set[str]) -> list[str]:
    """Drop analyze options the installed CLI does not advertise."""
    kept: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        # Never drop the interpreter/module prefix that launches attackmap.
        if token == "-m" and i + 1 < len(args) and args[i + 1] == "attackmap":
            kept.extend(["-m", "attackmap"])
            i += 2
            continue
        if token.startswith("--") or token == "-m":
            if token not in allowed:
                i += 2 if token in VALUE_FLAGS else 1
                continue
            kept.append(token)
            if token in VALUE_FLAGS and i + 1 < len(args) and not args[i + 1].startswith("-"):
                kept.append(args[i + 1])
                i += 2
                continue
            i += 1
            continue
        kept.append(token)
        i += 1
    return kept


def analyze_argv(
    repo: Path,
    output: Path,
    *,
    cve: bool = False,
    llm: str = "none",
    modules: str = "auto",
    baseline: Path | None = None,
    llm_mode: str | None = None,
    provider: str = "claude",
    recall: bool = False,
    repos: list[Path] | None = None,
    capabilities: set[str] | None = None,
    **kwargs: Any,
) -> list[str]:
    mode = llm_mode or "none"
    prov = provider
    if llm and llm not in {"none", "None (heuristic only)"}:
        if str(llm).lower().startswith("openai"):
            prov = "openai"
            mode = mode if mode != "none" else "review"
        elif str(llm).lower().startswith("anthropic"):
            prov = "claude"
            mode = mode if mode != "none" else "review"
        elif llm in {"review", "hunt", "huntVerify", "remediate", "triage"}:
            mode = llm
        else:
            mode = "review"
    module_list = [] if modules in {"auto", "Auto", None, ""} else [modules]
    cfg = ScanConfig(
        repos=repos or [repo],
        output=output,
        run_cve=cve,
        modules=module_list,
        llm_mode=mode,
        provider=prov,
        baseline=baseline,
        recall=recall,
        capabilities=capabilities,
        **{k: v for k, v in kwargs.items() if k in ScanConfig.__dataclass_fields__},
    )
    return [sys.executable, "-m", "attackmap", *cfg.cli_args()]
