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
    new_count: int = 0
    resolved_count: int = 0

    def as_json(self) -> dict[str, Any]:
        return {
            "findingCount": self.finding_count,
            "findings": self.findings,
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
            "repoName": self.repo_name,
            "newCount": self.new_count,
            "resolvedCount": self.resolved_count,
        }


def web_root() -> Path:
    here = Path(__file__).resolve()
    packaged = here.parent / "web"
    repo = here.parents[3] / "web"
    if (repo / "index.html").is_file():
        return repo
    return packaged


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
    return GuiReport(
        finding_count=len(data.get("findings") or []),
        findings=list(data.get("findings") or []),
        exploitability=rows,
        attack_paths=list(data.get("attack_paths") or []),
        attack_surfaces=list(data.get("attack_surfaces") or []),
        diagrams={
            "architecture": data.get("architecture_summary") or "",
        },
        review_md=data.get("defensive_review") or "",
        ai_review_md=data.get("defensive_review_llm") or "",
        repo_name=repo_name,
        new_count=int(diff.get("new") or 0),
        resolved_count=int(diff.get("resolved") or 0),
    )


def load_report_file(path: Path, repo_name: str | None = None) -> GuiReport:
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    name = repo_name or path.parent.name
    return decode_report(data, name)
