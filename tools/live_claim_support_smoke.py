"""One-off live LM Studio verification of the AM016 claim-support integration.

Calls the real local model (cyberstag-security-26b-a4b-v1) through the
OpenAI-compatible loopback endpoint on the fresh Juice Shop report and records
the closed-set claim-support metadata that lands on the review result.
Run: .venv/Scripts/python.exe tools/live_claim_support_smoke.py
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

os.environ.setdefault("OPENAI_BASE_URL", "http://127.0.0.1:1234/v1")
os.environ.setdefault("OPENAI_API_KEY", "attackmap-local")

from attackmap.llm_review import generate_llm_review  # noqa: E402
from attackmap.models import AttackPath, AttackSurface, Finding, ScanResult  # noqa: E402

GENERATION = sorted(
    p for p in Path(".pytest_cache/m5-juice-shop").iterdir()
    if p.is_dir() and (p / "attackmap-report.json").exists()
)[-1]
report = json.loads((GENERATION / "attackmap-report.json").read_text(encoding="utf-8"))

start = time.time()
result = generate_llm_review(
    ScanResult.model_validate(report["scan"]),
    [AttackSurface.model_validate(s) for s in report["attack_surfaces"]],
    [Finding.model_validate(f) for f in report["findings"]],
    [AttackPath.model_validate(p) for p in report["attack_paths"]],
    model="cyberstag-security-26b-a4b-v1",
    effort="low",
    max_tokens=4096,
    provider="openai",
    backend="api",
)
elapsed = time.time() - start

rv = result.reference_validation or {}
assessments = rv.get("claim_support_assessments", [])
meta = {
    "generation": str(GENERATION),
    "model": result.model,
    "backend": result.backend,
    "elapsed_seconds": round(elapsed, 2),
    "usage": result.usage,
    "usage_status": result.usage_status,
    "stop_reason": result.stop_reason,
    "markdown_chars": len(result.markdown),
    "claim_support_assessment_count": len(assessments),
    "claim_support_states": sorted({a.get("claim_support") for a in assessments}),
    "claim_support_basis": rv.get("claim_support_basis"),
    "overall_claim_support": rv.get("claim_support"),
    "reference_validation": rv,
}
out = GENERATION / "live-claim-support-smoke.meta.json"
out.write_text(json.dumps(meta, indent=2), encoding="utf-8")
print(json.dumps({k: v for k, v in meta.items() if k != "reference_validation"}, indent=2))
allowed = {"supported_by_cited_evidence", "not_assessed", None}
states = {a.get("claim_support") for a in assessments}
if not states <= allowed:
    raise SystemExit(f"claim-support closed set violated: {states!r}")
print(f"LIVE OK — evidence written to {out}")
