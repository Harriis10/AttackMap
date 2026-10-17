"""Versioned detector-evaluation corpus infrastructure (AM037, roadmap C27).

Where :mod:`attackmap.bench` scores findings against per-case *expected*
labels, this module adds what C27 demands on top of it:

- a **versioned corpus manifest** (``schema_version`` + ``corpus_version``)
  whose entries carry an explicit ``expectation`` — ``positive`` (the labeled
  weakness is genuinely present), ``negative`` (a near-twin that is genuinely
  *not* vulnerable, e.g. parameterized SQL next to concatenated SQL), or
  ``clean`` (a whole repository with no scored-family weakness at all) — plus a
  one-line ``rationale`` justifying every label from the fixture source;
- a **repository-level split** with a frozen, seeded, deterministic holdout of
  at least 20%, recorded per side (tuning vs holdout) so no tuning-side
  leakage can hide;
- per-family **TP / FP / FN, precision, recall, Wilson score intervals** and
  explicit sample counts, with an ``experimental`` flag for any family holding
  fewer than 30 positive *and* 30 negative labeled cases;
- a report writer (JSON + markdown) that lists **every advertised family in
  every table**, even families with zero labeled cases or poor scores — a
  family may never disappear because it performs badly.

Matching unit (defined in advance, per C27): a case is *matched* when a
finding of the same canonical detector family cites the case's
repository-relative file, confirmed by exact route + method (or, when the
finding cites no route, a line within ``line_window``) — the exact semantics
``bench._matches`` already implements, reused here so both harnesses agree on
what "this finding is about that endpoint" means. Duplicate findings are
deduplicated by their stable rule-aggregate identity (``finding_id``) before
counting, so one rule firing on many lines counts once. The counting unit is
the **labeled expectation**: TP = matched positive, FN = unmatched positive,
FP = violated negative expectation (or a clean repository in which any
scored-family finding fired). Unlike bench — whose precision counts *findings*
and lets one grouped finding over-cite extra routes without penalty — this
per-expectation unit penalizes a finding that fires on a labeled-clean twin,
which is the stricter reading C27 asks for.

This module is pure core: it imports the engine and ``bench`` scan/matching
helpers, never CLI frameworks.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .bench import (
    SCORED_CATEGORIES,
    Expected,
    canonical_category,
    findings_for_repo,
)
from .bench import _matches as _bench_matches  # single shared matching semantics

__all__ = [
    "C27_TARGETS",
    "CaseResult",
    "Corpus",
    "CorpusCase",
    "CorpusError",
    "EXPERIMENTAL_MIN_PER_SIDE",
    "FAMILIES",
    "FamilyMetrics",
    "SplitInfo",
    "wilson_interval",
    "dedupe_findings",
    "load_corpus",
    "render_markdown",
    "report_json",
    "run_evaluation",
    "split_corpus",
]

# --- corpus constants ---------------------------------------------------------

CORPUS_SCHEMA_VERSION = "1.0.0"

#: Detector families this harness scores. Mirrors bench.SCORED_CATEGORIES —
#: the "advertised" set every report must keep visible.
FAMILIES: tuple[str, ...] = SCORED_CATEGORIES

EXPECTATIONS: tuple[str, ...] = ("positive", "negative", "clean")

#: C27 says a family is experimental below 30 positive AND 30 negative cases.
EXPERIMENTAL_MIN_PER_SIDE = 30

#: C27 minimum holdout before tuning (we default above it).
MIN_HOLDOUT_FRACTION = 0.2
DEFAULT_HOLDOUT_FRACTION = 0.3
DEFAULT_SPLIT_SEED = 20261016
DEFAULT_LINE_WINDOW = 4

#: The full C27 release targets, for honest gap reporting in every report.
C27_TARGETS: dict[str, int] = {
    "repositories": 30,
    "positive_cases": 300,
    "negative_cases": 300,
    "clean_repositories": 10,
    "per_family_positive": 30,
    "per_family_negative": 30,
}

Z_95 = 1.959963984540054  # standard normal quantile for a 95% Wilson interval


class CorpusError(ValueError):
    """Raised when a corpus manifest is malformed or fails validation."""


# --- data model --------------------------------------------------------------


@dataclass(frozen=True)
class CorpusCase:
    """One labeled expectation in the corpus.

    ``positive``/``negative`` cases anchor an entity (file + route and/or
    line); ``clean`` cases name a repository expected to produce no
    scored-family findings at all (no entity fields).
    """

    case_id: str
    repository: str
    expectation: str  # positive | negative | clean
    path: str  # fixture path, relative to the corpus root
    family: str | None = None
    file: str | None = None
    line: int | None = None
    route: str | None = None
    method: str | None = None
    rationale: str = ""


@dataclass(frozen=True)
class SplitInfo:
    seed: int
    holdout_fraction: float
    tuning_repos: tuple[str, ...]
    holdout_repos: tuple[str, ...]


@dataclass
class Corpus:
    name: str
    version: str
    schema_version: str
    cases: list[CorpusCase]
    split_seed: int = DEFAULT_SPLIT_SEED
    holdout_fraction: float = DEFAULT_HOLDOUT_FRACTION
    line_window: int = DEFAULT_LINE_WINDOW
    notes: str = ""

    @property
    def repositories(self) -> list[str]:
        return sorted({c.repository for c in self.cases})


# --- manifest loading + validation -------------------------------------------


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise CorpusError(message)


def _validate_case(entry: dict[str, Any], index: int, seen_ids: set[str]) -> CorpusCase:
    where = f"case[{index}]"
    _require(isinstance(entry, dict), f"{where}: entry must be an object")
    for key in ("case_id", "repository", "expectation", "path", "rationale"):
        _require(
            isinstance(entry.get(key), str) and entry[key].strip(),
            f"{where}: '{key}' must be a non-empty string",
        )
    case_id = entry["case_id"]
    _require(case_id not in seen_ids, f"{where}: duplicate case_id {case_id!r}")
    seen_ids.add(case_id)

    expectation = entry["expectation"]
    _require(
        expectation in EXPECTATIONS,
        f"{where}: expectation must be one of {list(EXPECTATIONS)}, got {expectation!r}",
    )

    family = entry.get("family")
    if expectation == "clean":
        _require(family is None, f"{case_id}: clean cases must not declare a family")
        for key in ("file", "route", "line", "method"):
            _require(entry.get(key) is None, f"{case_id}: clean cases must not pin {key}")
    else:
        _require(
            isinstance(family, str) and family in FAMILIES,
            f"{case_id}: unknown family {family!r}; known families: {list(FAMILIES)}",
        )
        _require(
            isinstance(entry.get("file"), str) and entry["file"].strip(),
            f"{case_id}: {expectation} cases must pin a repository-relative 'file'",
        )
        _require(
            entry.get("route") is not None or entry.get("line") is not None,
            f"{case_id}: {expectation} cases must pin a 'route' or 'line' to anchor the entity",
        )
        line = entry.get("line")
        _require(
            line is None or (isinstance(line, int) and line > 0),
            f"{case_id}: 'line' must be a positive integer",
        )

    return CorpusCase(
        case_id=case_id,
        repository=entry["repository"],
        expectation=expectation,
        path=entry["path"],
        family=family,
        file=entry.get("file"),
        line=entry.get("line"),
        route=entry.get("route"),
        method=entry.get("method"),
        rationale=entry["rationale"],
    )


def load_corpus(path: str | Path) -> Corpus:
    """Load and validate a corpus manifest. Raises CorpusError on any defect."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    _require(isinstance(data, dict), "manifest must be a JSON object")
    schema = data.get("schema_version")
    _require(
        schema == CORPUS_SCHEMA_VERSION,
        f"unsupported schema_version {schema!r}; this harness reads {CORPUS_SCHEMA_VERSION}",
    )
    _require(isinstance(data.get("cases"), list) and data["cases"],
             "manifest must define a non-empty 'cases' list")

    fraction = float(data.get("holdout_fraction", DEFAULT_HOLDOUT_FRACTION))
    _require(
        MIN_HOLDOUT_FRACTION <= fraction < 1.0,
        f"holdout_fraction must be >= {MIN_HOLDOUT_FRACTION} and < 1.0, got {fraction}",
    )

    seen_ids: set[str] = set()
    cases = [_validate_case(e, i, seen_ids) for i, e in enumerate(data["cases"])]
    return Corpus(
        name=str(data.get("corpus_name", "unnamed")),
        version=str(data.get("corpus_version", "0.0.0")),
        schema_version=schema,
        cases=cases,
        split_seed=int(data.get("split_seed", DEFAULT_SPLIT_SEED)),
        holdout_fraction=fraction,
        line_window=int(data.get("line_window", DEFAULT_LINE_WINDOW)),
        notes=str(data.get("notes", "")),
    )


# --- repository-level split ---------------------------------------------------


def split_corpus(corpus: Corpus) -> tuple[list[CorpusCase], list[CorpusCase], SplitInfo]:
    """Deterministic repository-level split: sorted repo names, seeded shuffle.

    The holdout is the first ``ceil(n * holdout_fraction)`` repositories of the
    shuffled list. Sorting first makes the split independent of manifest
    ordering; the recorded seed makes it reproducible. A repository never
    appears on both sides, so tuning-side knowledge cannot leak through
    same-repo cases.
    """
    repos = corpus.repositories
    n_hold = math.ceil(len(repos) * corpus.holdout_fraction)
    shuffled = list(repos)
    random.Random(corpus.split_seed).shuffle(shuffled)
    holdout_repos = tuple(sorted(shuffled[:n_hold]))
    tuning_repos = tuple(sorted(shuffled[n_hold:]))
    holdout = set(holdout_repos)
    tuning = [c for c in corpus.cases if c.repository not in holdout]
    held = [c for c in corpus.cases if c.repository in holdout]
    return tuning, held, SplitInfo(
        seed=corpus.split_seed,
        holdout_fraction=corpus.holdout_fraction,
        tuning_repos=tuning_repos,
        holdout_repos=holdout_repos,
    )


# --- statistics ---------------------------------------------------------------


def wilson_interval(successes: int, n: int, z: float = Z_95) -> tuple[float, float] | None:
    """Wilson score interval for a binomial proportion (None when n == 0)."""
    if n <= 0:
        return None
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (p + z2 / (2.0 * n)) / denom
    half = z * math.sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n)) / denom

    def clamp(x: float) -> float:
        x = min(1.0, max(0.0, x))
        if abs(x - 1.0) < 1e-12:  # snap float dust (e.g. 0.9999999999999999)
            return 1.0
        return x

    return (clamp(centre - half), clamp(centre + half))


# --- running ------------------------------------------------------------------


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop duplicate findings by stable rule-aggregate identity.

    Uses the ``finding_id`` the scan pipeline attaches (rule + entity); falls
    back to title only for rule-less output. Duplicates are the documented
    C27 treatment: one detector verdict, counted once.
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for f in findings:
        key = str(f.get("id") or f.get("title") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


@dataclass
class CaseResult:
    case: CorpusCase
    side: str  # "tuning" | "holdout"
    matched: bool | None  # positive/negative: did a same-family finding match?
    error: str | None = None
    matched_by: list[str] = field(default_factory=list)  # titles of matching findings
    clean_violations: dict[str, list[str]] = field(default_factory=dict)  # family -> finding titles


@dataclass
class FamilyMetrics:
    family: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    positives: int = 0  # labeled positive expectations
    negatives: int = 0  # labeled negative expectations (excluding clean repos)
    clean_repos: int = 0  # labeled clean repositories
    matched: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    violated: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return None if denom == 0 else self.tp / denom

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return None if denom == 0 else self.tp / denom

    @property
    def experimental(self) -> bool:
        return self.positives < EXPERIMENTAL_MIN_PER_SIDE or self.negatives < EXPERIMENTAL_MIN_PER_SIDE

    @property
    def precision_ci(self) -> tuple[float, float] | None:
        return wilson_interval(self.tp, self.tp + self.fp)

    @property
    def recall_ci(self) -> tuple[float, float] | None:
        return wilson_interval(self.tp, self.tp + self.fn)


@dataclass
class EvaluationReport:
    corpus: Corpus
    split: SplitInfo
    sides: dict[str, dict[str, FamilyMetrics]]  # side -> family -> metrics
    results: list[CaseResult]

    @property
    def case_counts(self) -> dict[str, int]:
        counts = {"positive": 0, "negative": 0, "clean": 0}
        for c in self.corpus.cases:
            counts[c.expectation] += 1
        return counts


def _expected_for(case: CorpusCase) -> Expected:
    return Expected(
        category=case.family or "",
        file=case.file or "",
        line=case.line,
        route=case.route,
        method=case.method,
    )


def run_evaluation(
    corpus: Corpus,
    root: str | Path,
    analyze: Callable[[str | Path], list[dict[str, Any]]] = findings_for_repo,
) -> EvaluationReport:
    """Scan each corpus repository once and score every labeled expectation.

    Reuses bench's scan path (``findings_for_repo``) and matcher
    (``bench._matches``) so evaluation and benchmark agree on semantics; see
    the module docstring for the matching unit and duplicate treatment.
    """
    root = Path(root)
    tuning, holdout, split = split_corpus(corpus)
    side_of = {}
    for c in tuning:
        side_of[c.case_id] = "tuning"
    for c in holdout:
        side_of[c.case_id] = "holdout"

    findings_cache: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, str] = {}

    def findings_for(case: CorpusCase) -> list[dict[str, Any]]:
        path_key = case.path
        if path_key not in findings_cache:
            case_path = root / case.path
            if not case_path.is_dir():
                # An absent path must not look like a perfectly clean repo.
                errors[path_key] = f"case path not found: {case_path}"
                findings_cache[path_key] = []
            else:
                try:
                    findings_cache[path_key] = dedupe_findings(analyze(case_path))
                except Exception as exc:  # a scan failure is a result, not a crash
                    errors[path_key] = str(exc)
                    findings_cache[path_key] = []
        return findings_cache[path_key]

    results: list[CaseResult] = []
    for case in corpus.cases:
        findings = findings_for(case)
        if case.path in errors:
            results.append(CaseResult(
                case=case, side=side_of[case.case_id], matched=None, error=errors[case.path]))
            continue

        if case.expectation == "clean":
            violations: dict[str, list[str]] = {}
            for family in FAMILIES:
                fired = [f.get("title", "")[:80] for f in findings
                         if canonical_category(f) == family]
                if fired:
                    violations[family] = fired
            results.append(CaseResult(
                case=case, side=side_of[case.case_id], matched=not violations,
                clean_violations=violations))
            continue

        exp = _expected_for(case)
        fam = [f for f in findings if canonical_category(f) == case.family]
        matched_by = [f.get("title", "")[:80] for f in fam if _bench_matches(f, exp, corpus.line_window)]
        results.append(CaseResult(
            case=case, side=side_of[case.case_id], matched=bool(matched_by),
            matched_by=matched_by))

    sides = {
        "tuning": _aggregate([r for r in results if r.side == "tuning"]),
        "holdout": _aggregate([r for r in results if r.side == "holdout"]),
    }
    return EvaluationReport(corpus=corpus, split=split, sides=sides, results=results)


def _aggregate(results: list[CaseResult]) -> dict[str, FamilyMetrics]:
    """Per-family metrics over one split side. Every advertised family gets a
    row even with zero samples — no family disappears because it scores
    poorly or is unpopulated."""
    metrics = {family: FamilyMetrics(family=family) for family in FAMILIES}
    for r in results:
        if r.error:
            continue
        c = r.case
        if c.expectation == "positive":
            fm = metrics[c.family or ""]
            fm.positives += 1
            if r.matched:
                fm.tp += 1
                fm.matched.append(c.case_id)
            else:
                fm.fn += 1
                fm.missed.append(c.case_id)
        elif c.expectation == "negative":
            fm = metrics[c.family or ""]
            fm.negatives += 1
            if r.matched:
                fm.fp += 1
                fm.violated.append(c.case_id)
        else:  # clean repository: one implicit negative expectation per family
            for family, titles in r.clean_violations.items():
                fm = metrics[family]
                fm.clean_repos += 1
                fm.fp += 1
                fm.violated.append(f"{c.case_id} ({len(titles)} finding(s))")
    # Clean repos count as clean-repos for families they did NOT violate too,
    # so sample counts reflect coverage honestly.
    clean_ids = {r.case.case_id for r in results
                 if r.case.expectation == "clean" and not r.error}
    for family in FAMILIES:
        violated_ids = {v.split(" (")[0] for v in metrics[family].violated}
        metrics[family].clean_repos += len(clean_ids - violated_ids)
    return metrics


# --- report writers ----------------------------------------------------------


def _ci(ci: tuple[float, float] | None) -> str:
    return "—" if ci is None else f"[{ci[0]*100:.0f}%, {ci[1]*100:.0f}%]"


def _ratio(x: float | None) -> str:
    return "—" if x is None else f"{x*100:.0f}%"


def _metric_with_ci(x: float | None, ci: tuple[float, float] | None) -> str:
    return "—" if x is None else f"{_ratio(x)} {_ci(ci)}"


def _family_dict(fm: FamilyMetrics) -> dict[str, Any]:
    return {
        "tp": fm.tp,
        "fp": fm.fp,
        "fn": fm.fn,
        "precision": fm.precision,
        "recall": fm.recall,
        "precision_ci_95": fm.precision_ci,
        "recall_ci_95": fm.recall_ci,
        "positives": fm.positives,
        "negatives": fm.negatives,
        "clean_repos": fm.clean_repos,
        "experimental": fm.experimental,
        "matched_cases": fm.matched,
        "missed_cases": fm.missed,
        "violated_cases": fm.violated,
    }


def report_json(report: EvaluationReport) -> dict[str, Any]:
    counts = report.case_counts
    repos = report.corpus.repositories
    return {
        "corpus": {
            "name": report.corpus.name,
            "version": report.corpus.version,
            "schema_version": report.corpus.schema_version,
            "repositories": len(repos),
            "repository_names": repos,
            "positive_cases": counts["positive"],
            "negative_cases": counts["negative"],
            "clean_cases": counts["clean"],
            "line_window": report.corpus.line_window,
            "notes": report.corpus.notes,
        },
        "matching_unit": (
            "expectation unit: family + repository-relative file + exact route/method "
            "(or line within line_window when the finding cites no route); findings "
            "deduplicated by stable finding_id before counting"
        ),
        "split": {
            "seed": report.split.seed,
            "holdout_fraction": report.split.holdout_fraction,
            "tuning_repos": list(report.split.tuning_repos),
            "holdout_repos": list(report.split.holdout_repos),
        },
        "c27_targets": dict(C27_TARGETS),
        "c27_gap": {
            "repositories_short": max(0, C27_TARGETS["repositories"] - len(repos)),
            "positive_cases_short": max(0, C27_TARGETS["positive_cases"] - counts["positive"]),
            "negative_cases_short": max(0, C27_TARGETS["negative_cases"] - counts["negative"]),
            "clean_repositories_short": max(0, C27_TARGETS["clean_repositories"] - counts["clean"]),
        },
        "sides": {
            side: {family: _family_dict(fm) for family, fm in sorted(fams.items())}
            for side, fams in report.sides.items()
        },
        "cases": [
            {
                "case_id": r.case.case_id,
                "repository": r.case.repository,
                "family": r.case.family,
                "expectation": r.case.expectation,
                "side": r.side,
                "matched": r.matched,
                "error": r.error,
                "matched_by": r.matched_by,
                "clean_violations": r.clean_violations,
            }
            for r in report.results
        ],
    }


def _side_table(fams: dict[str, FamilyMetrics]) -> list[str]:
    lines = [
        "| Family | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | P/N/clean samples | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for family in sorted(fams):
        fm = fams[family]
        status = "experimental" if fm.experimental else "supported"
        lines.append(
            f"| `{family}` | {fm.tp} | {fm.fp} | {fm.fn} "
            f"| {_metric_with_ci(fm.precision, fm.precision_ci)} "
            f"| {_metric_with_ci(fm.recall, fm.recall_ci)} "
            f"| {fm.positives}/{fm.negatives}/{fm.clean_repos} | {status} |"
        )
    return lines


def render_markdown(report: EvaluationReport) -> str:
    counts = report.case_counts
    repos = report.corpus.repositories
    fam_total: dict[str, dict[str, int]] = {f: {"p": 0, "n": 0} for f in FAMILIES}
    for c in report.corpus.cases:
        if c.expectation == "positive":
            fam_total[c.family or ""]["p"] += 1
        elif c.expectation == "negative":
            fam_total[c.family or ""]["n"] += 1

    lines: list[str] = [
        f"# AttackMap detector evaluation — corpus `{report.corpus.name}` v{report.corpus.version}",
        "",
        f"Schema {report.corpus.schema_version}. "
        f"{len(report.corpus.cases)} labeled expectations across {len(repos)} repositories "
        f"({counts['positive']} positive, {counts['negative']} negative, "
        f"{counts['clean']} clean-repository cases).",
        "",
        "**Matching unit** (fixed in advance, per C27): a labeled expectation is matched when a "
        "finding of the same canonical family cites the case's repository-relative file, confirmed "
        "by exact route + method, or a line within `line_window` when the finding cites no route. "
        "Findings are deduplicated by stable `finding_id` before counting. TP = matched positive, "
        "FN = unmatched positive, FP = violated negative expectation or clean repo with any "
        "same-family finding. This is stricter than `bench` precision: a grouped finding that "
        "over-cites a labeled-clean twin is penalized here.",
        "",
        "## Split (repository-level, frozen)",
        "",
        f"- seed `{report.split.seed}`, holdout fraction {report.split.holdout_fraction:.0%}",
        f"- tuning repositories ({len(report.split.tuning_repos)}): "
        + (", ".join(report.split.tuning_repos) or "—"),
        f"- holdout repositories ({len(report.split.holdout_repos)}): "
        + (", ".join(report.split.holdout_repos) or "—"),
        "",
        "## Distance to C27 targets",
        "",
        "| Dimension | Target | Delivered | Short |",
        "|---|---|---|---|",
        f"| Repositories | {C27_TARGETS['repositories']} | {len(repos)} | "
        f"{max(0, C27_TARGETS['repositories'] - len(repos))} |",
        f"| Positive cases | {C27_TARGETS['positive_cases']} | {counts['positive']} | "
        f"{max(0, C27_TARGETS['positive_cases'] - counts['positive'])} |",
        f"| Negative cases | {C27_TARGETS['negative_cases']} | {counts['negative']} | "
        f"{max(0, C27_TARGETS['negative_cases'] - counts['negative'])} |",
        f"| Clean repositories | {C27_TARGETS['clean_repositories']} | {counts['clean']} | "
        f"{max(0, C27_TARGETS['clean_repositories'] - counts['clean'])} |",
        "",
        "Every advertised family is listed below regardless of score or sample count. "
        f"A family is **experimental** below {EXPERIMENTAL_MIN_PER_SIDE} positive and "
        f"{EXPERIMENTAL_MIN_PER_SIDE} negative labeled cases (C27); per-family corpus totals:",
        "",
        "| Family | Positive cases | Negative cases | Gap to 30/30 |",
        "|---|---|---|---|",
    ]
    for family in sorted(FAMILIES):
        p, n = fam_total[family]["p"], fam_total[family]["n"]
        lines.append(
            f"| `{family}` | {p} | {n} | "
            f"+{max(0, EXPERIMENTAL_MIN_PER_SIDE - p)} positive / +{max(0, EXPERIMENTAL_MIN_PER_SIDE - n)} negative |"
        )
    for side in ("tuning", "holdout"):
        lines += ["", f"## {side.capitalize()} side", ""]
        lines += _side_table(report.sides[side])
    lines += ["", "## Per-case results", ""]
    for r in report.results:
        if r.error:
            lines.append(f"- `{r.case.case_id}` [{r.side}] — ERROR: {r.error}")
            continue
        if r.case.expectation == "clean":
            state = "clean (no scored-family findings)" if r.matched else (
                "VIOLATED: " + "; ".join(
                    f"{f}: {t}" for f, ts in r.clean_violations.items() for t in ts))
        else:
            state = "matched" if r.matched else (
                "MISSED (positive expectation)" if r.case.expectation == "positive"
                else "respected (no finding fired)")
        lines.append(f"- `{r.case.case_id}` [{r.side}] {r.case.expectation} "
                     f"({r.case.family or 'any family'}): {state}")
    if report.corpus.notes:
        lines += ["", "## Corpus notes", "", report.corpus.notes]
    lines.append("")
    return "\n".join(lines)
