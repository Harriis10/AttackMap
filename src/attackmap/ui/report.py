"""Decode attackmap-report.json for the Windows GUI."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FactorView:
    name: str
    points: int
    detail: str = ""


@dataclass
class ExploitabilityRow:
    subject: str
    route: str
    method: str
    sink_kind: str
    location: str
    score: int
    tier: str
    factors: list[FactorView] = field(default_factory=list)


@dataclass
class GuiReport:
    finding_count: int
    findings: list[dict[str, Any]]
    exploitability: list[ExploitabilityRow]
    attack_paths: list[dict[str, Any]]
    attack_surfaces: list[dict[str, Any]]
    diagrams: dict[str, str]
    review_md: str
    ai_review_md: str
    repo_name: str
    ai_review_requested: bool = False
    new_count: int = 0
    resolved_count: int = 0
    suppressed: list[dict[str, Any]] = field(default_factory=list)
    scan: dict[str, Any] = field(default_factory=dict)
    diff_md: str = ""
    fleet: dict[str, Any] | None = None
    severity_counts: dict[str, int] = field(default_factory=dict)
    top_path: dict[str, Any] | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "findingCount": self.finding_count,
            "findings": self.findings,
            "suppressed": self.suppressed,
            "exploitability": [
                {
                    "subject": r.subject,
                    "route": r.route,
                    "method": r.method,
                    "sinkKind": r.sink_kind,
                    "location": r.location,
                    "score": r.score,
                    "tier": r.tier,
                    "factors": [{"name": f.name, "points": f.points, "detail": f.detail} for f in r.factors],
                }
                for r in self.exploitability
            ],
            "attackPaths": self.attack_paths,
            "attackSurfaces": self.attack_surfaces,
            "diagrams": self.diagrams,
            "reviewMd": self.review_md,
            "aiReviewMd": self.ai_review_md,
            "aiReviewRequested": self.ai_review_requested,
            "repoName": self.repo_name,
            "newCount": self.new_count,
            "resolvedCount": self.resolved_count,
            "scan": {
                **self.scan,
                "secret_hints": [
                    {k: v for k, v in item.items() if k != "evidence_text"}
                    for item in (self.scan.get("secret_hints") or [])
                    if isinstance(item, dict)
                ],
            },
            "diffMd": self.diff_md,
            "fleet": self.fleet,
            "severityCounts": self.severity_counts,
            "topPath": self.top_path,
            "dependencies": self.scan.get("dependencies") or [],
            "vulnerabilities": self.scan.get("vulnerabilities") or [],
            "secrets": [
                {k: v for k, v in item.items() if k != "evidence_text"}
                for item in (self.scan.get("secret_hints") or [])
            ],
            "workflows": self.scan.get("workflow_issues") or [],
            "dataFlows": self.scan.get("taint_chains") or [],
            "analyzerErrors": self.scan.get("analyzer_errors") or [],
            "limitations": self.scan.get("limitations") or [],
        }


def web_root() -> Path:
    return Path(__file__).resolve().parent / "web"


def fixture_report_path() -> Path:
    packaged = Path(__file__).resolve().parent / "fixtures" / "juice-shop-report.json"
    tests = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "ui" / "juice-shop-report.json"
    if tests.is_file():
        return tests
    return packaged


def decode_report(data: dict[str, Any], repo_name: str = "juice-shop") -> GuiReport:
    rows: list[ExploitabilityRow] = []
    for item in data.get("exploitability") or []:
        rows.append(
            ExploitabilityRow(
                subject=item.get("subject") or "",
                route=item.get("route") or "",
                method=item.get("method") or "",
                sink_kind=item.get("sink_kind") or "",
                location=item.get("location") or "",
                score=int(item.get("score") or 0),
                tier=item.get("tier") or "low",
                factors=[
                    FactorView(name=f.get("name") or "", points=int(f.get("points") or 0), detail=f.get("detail") or "")
                    for f in item.get("factors") or []
                ],
            )
        )
    rows.sort(key=lambda r: (-r.score, r.subject))
    diff = data.get("diff") or {}
    findings = list(data.get("findings") or [])
    counts: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity") or "info")
        counts[sev] = counts.get(sev, 0) + 1
    top = None
    if rows:
        top = {
            "subject": rows[0].subject,
            "score": rows[0].score,
            "tier": rows[0].tier,
            "route": rows[0].route,
            "method": rows[0].method,
        }
    return GuiReport(
        finding_count=len(findings),
        findings=findings,
        exploitability=rows,
        attack_paths=list(data.get("attack_paths") or []),
        attack_surfaces=list(data.get("attack_surfaces") or []),
        diagrams={
            "architecture": data.get("architecture_summary") or "",
            "paths": data.get("paths_mermaid") or "",
            "topology": data.get("topology_mermaid") or "",
        },
        review_md=data.get("defensive_review") or "",
        ai_review_md=data.get("defensive_review_llm") or "",
        repo_name=repo_name,
        new_count=int(diff.get("new") or 0),
        resolved_count=int(diff.get("resolved") or 0),
        suppressed=list(data.get("suppressed_findings") or []),
        scan=dict(data.get("scan") or {}),
        diff_md=data.get("diff_md") or "",
        fleet=data.get("fleet"),
        severity_counts=counts,
        top_path=top,
    )


def load_report_file(path: Path, repo_name: str | None = None) -> GuiReport:
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    name = repo_name or path.parent.name
    report = decode_report(data, name)
    parent = path.parent
    report.diagrams["paths"] = _read_text(parent / "attackmap-paths.md") or report.diagrams.get("paths") or ""
    report.diagrams["topology"] = _read_text(parent / "attackmap-topology.md") or report.diagrams.get("topology") or ""
    report.diff_md = _read_text(parent / "attackmap-diff.md") or report.diff_md
    llm_meta_files = [
        "defensive-review-llm.meta.json",
        "vulnerability-hypotheses.meta.json",
        "remediation.meta.json",
        "triage.meta.json",
    ]
    report.ai_review_requested = any((parent / name).is_file() for name in llm_meta_files)
    if not report.ai_review_md:
        report.ai_review_md = _read_text(parent / "defensive-review-llm.md")
    if not report.ai_review_md:
        report.ai_review_md = _read_text(parent / "vulnerability-hypotheses.md")
    if not report.ai_review_md:
        report.ai_review_md = _read_text(parent / "remediation.md")
    if not report.ai_review_md:
        report.ai_review_md = _read_text(parent / "triage.md")
    fleet_path = parent / "fleet-summary.json"
    if fleet_path.is_file():
        report.fleet = json.loads(fleet_path.read_text(encoding="utf-8"))
    return report


def decode_fleet_summary(data: dict[str, Any], repo_name: str = "fleet") -> GuiReport:
    """Build a minimal GuiReport that wraps a fleet summary JSON."""
    return GuiReport(
        finding_count=int(data.get("total_findings") or 0),
        findings=[],
        exploitability=[],
        attack_paths=[],
        attack_surfaces=[],
        diagrams={},
        review_md="",
        ai_review_md="",
        repo_name=repo_name,
        fleet=data,
        severity_counts={},
    )


def load_current_report(base_dir: Path, repo_name: str | None = None) -> GuiReport:
    """Load the report from the promoted generation directory."""
    from .output import current_generation

    gen = current_generation(base_dir)
    if gen is None:
        raise FileNotFoundError(f"no promoted generation in {base_dir}")
    report_path = gen / "attackmap-report.json"
    if report_path.is_file():
        return load_report_file(report_path, repo_name)
    fleet_path = gen / "fleet-summary.json"
    if fleet_path.is_file():
        import json

        data = json.loads(fleet_path.read_text(encoding="utf-8"))
        return decode_fleet_summary(data, repo_name or "fleet")
    raise FileNotFoundError(f"no report or fleet summary in {gen}")


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""
